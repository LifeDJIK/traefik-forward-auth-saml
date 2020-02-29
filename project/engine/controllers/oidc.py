#!/usr/bin/python
# coding=utf-8
# pylint: disable=I0011

#   Copyright 2020
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
    OIDC controller
"""

import cherrypy  # pylint: disable=E0401

from oic.oic import Client  # pylint: disable=E0401
from oic.utils.authn.client import CLIENT_AUTHN_METHOD  # pylint: disable=E0401
from oic.oic.message import ProviderConfigurationResponse  # pylint: disable=E0401
from oic.oic.message import RegistrationResponse  # pylint: disable=E0401
from oic.oic.message import AuthorizationResponse  # pylint: disable=E0401
from oic import rndstr  # pylint: disable=E0401

from engine.tools import log


class OidcController:  # pylint: disable=R0903
    """ OIDC controller logic """

    def __init__(self, base_dir, base_path):
        self.base_dir = base_dir
        self.base_path = base_path
        self.settings = cherrypy.config["engine.settings"]
        # Initialize OIDC client
        self.client = self._build_oidc_client()

    #
    # Tools
    #

    def _build_oidc_client(self):
        client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
        provider_config = ProviderConfigurationResponse(
            **self.settings["oidc"]["provider"]["configuration"]
        )
        client.handle_provider_config(provider_config, provider_config["issuer"])
        client.store_registration_info(
            RegistrationResponse(**self.settings["oidc"]["provider"]["registration"])
        )
        return client

    def _build_redirect_url(self):
        #
        for header in [
                "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Uri"
        ]:
            if header not in cherrypy.session:
                return self.settings["auth"]["login_default_redirect_url"]
        #
        proto = cherrypy.session.pop("X-Forwarded-Proto")
        host = cherrypy.session.pop("X-Forwarded-Host")
        port = cherrypy.session.pop("X-Forwarded-Port")
        if (proto == "http" and port != "80") or (proto == "https" and port != "443"):
            port = f":{port}"
        else:
            port = ""
        uri = cherrypy.session.pop("X-Forwarded-Uri")
        #
        return f"{proto}://{host}{port}{uri}"

    #
    # Login/logout endpoints
    #

    @cherrypy.expose
    def login(self):  # pylint: disable=R0201,C0111
        cherrypy.session["state"] = rndstr()
        cherrypy.session["nonce"] = rndstr()
        auth_req = self.client.construct_AuthorizationRequest(request_args={
            "client_id": self.client.client_id,
            "response_type": "code",
            "scope": ["openid"],
            "state": cherrypy.session["state"],
            "nonce": cherrypy.session["nonce"],
            "redirect_uri": self.client.registration_response["redirect_uris"][0],
        })
        login_url = auth_req.request(self.client.authorization_endpoint)
        #
        if self.settings["oidc"]["debug"]:
            log.info("OIDC login URL: %s", login_url)
        #
        raise cherrypy.HTTPRedirect(login_url)

    @cherrypy.expose
    def logout(self, to=None):  # pylint: disable=R0201,C0111,C0103
        return_to = self.settings["auth"]["logout_default_redirect_url"]
        if to is not None and to in self.settings["auth"]["logout_allowed_redirect_urls"]:
            return_to = to
        #
        # try:
        #     endresp = self.client.do_end_session_request(
        #         state=cherrypy.session["state"],
        #         extra_args={
        #             "post_logout_redirect_uri": return_to
        #         }
        #     )
        #     log.info(
        #         "Logout endresp: %s (%s) [%s]",
        #         endresp.status_code, endresp.headers, endresp._content  # pylint: disable=W0212
        #     )
        #     if "Location" in endresp.headers:
        #         return_to = endresp.headers["Location"]
        # except:  # pylint: disable=W0702
        #     log.exception("OIDC exception")
        #
        end_req = self.client.construct_EndSessionRequest(
            state=cherrypy.session["state"],
            request_args={"redirect_uri": return_to}
        )
        logout_url = end_req.request(self.client.end_session_endpoint)
        #
        if self.settings["oidc"]["debug"]:
            log.info("Logout URL: %s", logout_url)
        #
        cherrypy.session.clear()
        cherrypy.session.regenerate()
        #
        raise cherrypy.HTTPRedirect(logout_url)

    #
    # OIDC endpoints
    #

    @cherrypy.expose
    def callback(self, *args, **kvargs):  # pylint: disable=R0201,C0111,W0613
        auth_resp = self.client.parse_response(
            AuthorizationResponse, info=cherrypy.request.query_string, sformat="urlencoded"
        )
        if "state" not in cherrypy.session or auth_resp["state"] != cherrypy.session["state"]:
            raise cherrypy.HTTPRedirect(
                cherrypy.config["engine.settings"]["endpoints"]["access_denied"]
            )
        #
        access_token_resp = self.client.do_access_token_request(
            state=auth_resp["state"],
            request_args={
                "code": auth_resp["code"]
            },
            authn_method="client_secret_basic"
        )
        #
        if self.settings["oidc"]["debug"]:
            log.info("Callback access_token_resp: %s", access_token_resp)
        #
        # userinfo = self.client.do_user_info_request(
        #     state=auth_resp["state"]
        # )
        # userinfo = self.client.do_user_info_request(
        #     access_token=access_token_resp["access_token"]
        # )
        # log.info("Callback userinfo: %s", userinfo)
        #
        redirect_to = self._build_redirect_url()
        session_state = cherrypy.session.pop("state")
        session_nonce = cherrypy.session.pop("nonce")
        id_token = dict(access_token_resp["id_token"])
        #
        cherrypy.session.clear()
        cherrypy.session.regenerate()
        cherrypy.session["state"] = session_state
        cherrypy.session["nonce"] = session_nonce
        cherrypy.session["auth"] = True
        cherrypy.session["auth_errors"] = []
        cherrypy.session["auth_nameid"] = ""
        cherrypy.session["auth_sessionindex"] = ""
        cherrypy.session["auth_attributes"] = id_token
        #
        if self.settings["oidc"]["debug"]:
            log.info("Callback redirect URL: %s", redirect_to)
        #
        raise cherrypy.HTTPRedirect(redirect_to)
