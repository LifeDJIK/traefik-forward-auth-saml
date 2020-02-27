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
    SAML controller
"""

from urllib.parse import urlsplit, urlunsplit, parse_qs
import cherrypy  # pylint: disable=E0401

from engine.tools import log

from onelogin.saml2.response import OneLogin_Saml2_Response  # pylint: disable=E0401
from onelogin.saml2.constants import OneLogin_Saml2_Constants  # pylint: disable=E0401
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML  # pylint: disable=E0401
from onelogin.saml2.auth import OneLogin_Saml2_Auth  # pylint: disable=E0401
from onelogin.saml2.utils import OneLogin_Saml2_Utils  # pylint: disable=E0401
from lxml import etree  # pylint: disable=E0401
import xmlsec  # pylint: disable=E0401


class SamlController:  # pylint: disable=R0903
    """ SAML controller logic """

    def __init__(self, base_dir, base_path):
        self.base_dir = base_dir
        self.base_path = base_path
        self.settings = cherrypy.config["engine.settings"]
        # Patch python3-saml to support multiple same-name attributes
        self._patch_python3_saml()

    #
    # Tools
    #

    def _patch_python3_saml(self):
        # Patched get_attributes
        def __get_attributes(self):
            """
            Gets the Attributes from the AttributeStatement element.
            EncryptedAttributes are not supported
            """
            attributes = {}
            attribute_nodes = self._OneLogin_Saml2_Response__query_assertion(
                '/saml:AttributeStatement/saml:Attribute'
            )
            for attribute_node in attribute_nodes:
                attr_name = attribute_node.get('Name')
                values = []
                for attr in attribute_node.iterchildren(
                        '{%s}AttributeValue' % OneLogin_Saml2_Constants.NSMAP['saml']
                ):
                    attr_text = OneLogin_Saml2_XML.element_text(attr)
                    if attr_text:
                        attr_text = attr_text.strip()
                        if attr_text:
                            values.append(attr_text)
                    # Parse any nested NameID children
                    for nameid in attr.iterchildren(
                            '{%s}NameID' % OneLogin_Saml2_Constants.NSMAP['saml']
                    ):
                        values.append({
                            'NameID': {
                                'Format': nameid.get('Format'),
                                'NameQualifier': nameid.get('NameQualifier'),
                                'value': nameid.text
                            }
                        })
                if attr_name in attributes.keys():
                    for value in values:
                        if value not in attributes[attr_name]:
                            attributes[attr_name].append(value)
                else:
                    attributes[attr_name] = values
            return attributes
        # Set patched version
        OneLogin_Saml2_Response.get_attributes = __get_attributes

    @staticmethod
    def _sign_saml_request(request, saml_auth, saml_security):
        sign_algorithm_transform_map = {
            OneLogin_Saml2_Constants.DSA_SHA1: xmlsec.constants.TransformDsaSha1,
            OneLogin_Saml2_Constants.RSA_SHA1: xmlsec.constants.TransformRsaSha1,
            OneLogin_Saml2_Constants.RSA_SHA256: xmlsec.constants.TransformRsaSha256,
            OneLogin_Saml2_Constants.RSA_SHA384: xmlsec.constants.TransformRsaSha384,
            OneLogin_Saml2_Constants.RSA_SHA512: xmlsec.constants.TransformRsaSha512
        }
        digest_algorithm_transform_map = {
            OneLogin_Saml2_Constants.SHA1: xmlsec.constants.TransformSha1,
            OneLogin_Saml2_Constants.SHA256: xmlsec.constants.TransformSha256,
            OneLogin_Saml2_Constants.SHA384: xmlsec.constants.TransformSha384,
            OneLogin_Saml2_Constants.SHA512: xmlsec.constants.TransformSha512
        }
        #
        request_root = etree.fromstring(request)
        xmlsec.tree.add_ids(request_root, ["ID"])
        signature_node = xmlsec.template.create(
            request_root,
            xmlsec.constants.TransformExclC14N,
            sign_algorithm_transform_map.get(
                saml_security.get("signatureAlgorithm", OneLogin_Saml2_Constants.RSA_SHA1),
                xmlsec.constants.TransformRsaSha1
            )
        )
        request_root.insert(1, signature_node)
        reference_node = xmlsec.template.add_reference(
            signature_node,
            digest_algorithm_transform_map.get(
                saml_security.get("digestAlgorithm", OneLogin_Saml2_Constants.SHA1),
                xmlsec.constants.TransformSha1
            ),
            uri=f"#{request_root.get('ID')}"
        )
        xmlsec.template.add_transform(reference_node, xmlsec.constants.TransformEnveloped)
        xmlsec.template.add_transform(reference_node, xmlsec.constants.TransformExclC14N)
        xmlsec.template.add_x509_data(xmlsec.template.ensure_key_info(signature_node))
        signature_ctx = xmlsec.SignatureContext()
        signature_ctx.key = xmlsec.Key.from_memory(
            saml_auth.get_settings().get_sp_key(), xmlsec.constants.KeyDataFormatPem
        )
        signature_ctx.key.load_cert_from_memory(
            saml_auth.get_settings().get_sp_cert(), format=xmlsec.constants.KeyDataFormatPem
        )
        signature_ctx.sign(signature_node)
        request = OneLogin_Saml2_Utils.b64encode(etree.tostring(request_root))
        return request

    @staticmethod
    def _get_forwarded_header(request, header, default):
        if header in request.headers:
            return request.headers[header]
        return cherrypy.session.pop(header, default)

    @staticmethod
    def _prepare_request_object(request):
        proto = SamlController._get_forwarded_header(
            request, "X-Forwarded-Proto",
            request.scheme
        )
        host = SamlController._get_forwarded_header(
            request, "X-Forwarded-Host",
            request.headers["Host"] if "Host" in request.headers else ""
        )
        port = SamlController._get_forwarded_header(
            request, "X-Forwarded-Port",
            "443" if proto == "https" else "80"
        )
        script = SamlController._get_forwarded_header(
            request, "X-Forwarded-Uri",
            request.script_name + request.path_info
        )
        data = request.params.copy()
        return {
            "https": "on" if proto == "https" else "off",
            "http_host": host,
            "server_port": port,
            "script_name": script,
            "get_data": data,
            "post_data": data,
            # "lowercase_urlencoding": True,
            # "request_uri": "",
            # "query_string": "",
        }

    #
    # Login/logout endpoints
    #

    @cherrypy.expose
    @cherrypy.tools.template(name="saml/saml_post.html")
    def login(self):  # pylint: disable=R0201,C0111
        # Create login request object
        saml_auth = OneLogin_Saml2_Auth(
            self._prepare_request_object(cherrypy.request),
            self.settings["saml"]
        )
        login_redirect_url = saml_auth.login()
        # Redirect in case of HTTP-REDIRECT binding
        if self.settings["saml"]["idp"]["singleSignOnService"]["binding"] != \
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":
            raise cherrypy.HTTPRedirect(login_redirect_url)
        # Prepare request for HTTP-POST
        parsed_url = urlsplit(login_redirect_url)
        saml_post_action = urlunsplit(parsed_url._replace(query=""))
        saml_post_parameters = parse_qs(parsed_url.query)
        saml_security = saml_auth.get_settings().get_security_data()
        request = OneLogin_Saml2_Utils.decode_base64_and_inflate(
            saml_post_parameters["SAMLRequest"][0]
        )
        # Prepare signed request if needed
        if saml_security.get("authnRequestsSigned", False):
            request = self._sign_saml_request(request, saml_auth, saml_security)
        # Perform HTTP-POST binding
        return [{
            "action": saml_post_action,
            "parameters": [
                {"name": "SAMLRequest", "value": request},
                {"name": "RelayState", "value": saml_post_parameters["RelayState"][0]}
            ]
        }]

    @cherrypy.expose
    @cherrypy.tools.template(name="saml/saml_post.html")
    def logout(self, to=None):  # pylint: disable=R0201,C0111,C0103
        # Check and set return_to
        return_to = self.settings["auth"]["logout_default_redirect_url"]
        if to is not None and to in self.settings["auth"]["logout_allowed_redirect_urls"]:
            return_to = to
        # Create logout request object
        saml_auth = OneLogin_Saml2_Auth(
            self._prepare_request_object(cherrypy.request),
            self.settings["saml"]
        )
        logout_redirect_url = saml_auth.logout(return_to=return_to)
        # Redirect in case of HTTP-REDIRECT binding
        if self.settings["saml"]["idp"]["singleLogoutService"]["binding"] != \
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":
            raise cherrypy.HTTPRedirect(logout_redirect_url)
        # Prepare request for HTTP-POST
        parsed_url = urlsplit(logout_redirect_url)
        saml_post_action = urlunsplit(parsed_url._replace(query=""))
        saml_post_parameters = parse_qs(parsed_url.query)
        saml_security = saml_auth.get_settings().get_security_data()
        request = OneLogin_Saml2_Utils.decode_base64_and_inflate(
            saml_post_parameters["SAMLRequest"][0]
        )
        # Prepare signed request if needed
        if saml_security.get("logoutRequestSigned", False):
            request = self._sign_saml_request(request, saml_auth, saml_security)
        # Perform HTTP-POST binding
        return [{
            "action": saml_post_action,
            "parameters": [
                {"name": "SAMLRequest", "value": request},
                {"name": "RelayState", "value": saml_post_parameters["RelayState"][0]}
            ]
        }]

    #
    # SAML endpoints
    #

    @cherrypy.expose
    def acs(self, *args, **kvargs):  # pylint: disable=R0201,C0111
        if self.settings["saml"]["debug"]:
            log.info("===== ACS =====")
            log.info("ACS args: %s", args)
            log.info("ACS kvargs: %s", kvargs)
            log.info("ACS headers: %s", cherrypy.request.headers)
        #
        saml_auth = OneLogin_Saml2_Auth(
            self._prepare_request_object(cherrypy.request),
            self.settings["saml"]
        )
        saml_auth.process_response()
        #
        if self.settings["saml"]["debug"]:
            log.info("ACS auth: %s", saml_auth.is_authenticated())
            log.info("ACS err: %s", saml_auth.get_errors())
            log.info("ACS attrs: %s", saml_auth.get_attributes())
            log.info("ACS NameID: %s", saml_auth.get_nameid())
            log.info("ACS SessionIndex: %s", saml_auth.get_session_index())
        #
        cherrypy.session.clear()
        cherrypy.session.regenerate()
        cherrypy.session["auth"] = saml_auth.is_authenticated()
        cherrypy.session["auth_errors"] = saml_auth.get_errors()
        cherrypy.session["auth_nameid"] = saml_auth.get_nameid()
        cherrypy.session["auth_sessionindex"] = saml_auth.get_session_index()
        cherrypy.session["auth_attributes"] = saml_auth.get_attributes()
        #
        loop_urls = [
            cherrypy.request.base + cherrypy.request.script_name + "/acs",
            cherrypy.request.base + cherrypy.request.script_name + "/login",
            cherrypy.request.base + \
                (self.settings["endpoints"]["root"] + "/login").replace("//", "/"),
        ]
        if "RelayState" in cherrypy.request.params and \
                cherrypy.request.params["RelayState"] not in loop_urls:
            raise cherrypy.HTTPRedirect(cherrypy.request.params["RelayState"])
        raise cherrypy.HTTPRedirect(self.settings["auth"]["login_default_redirect_url"])

    @cherrypy.expose
    def sls(self, *args, **kvargs):  # pylint: disable=R0201,C0111
        if self.settings["saml"]["debug"]:
            log.info("===== SLS =====")
            log.info("SLS args: %s", args)
            log.info("SLS kvargs: %s", kvargs)
            log.info("SLS headers: %s", cherrypy.request.headers)
        #
        saml_auth = OneLogin_Saml2_Auth(
            self._prepare_request_object(cherrypy.request),
            self.settings["saml"]
        )
        saml_auth.process_slo()
        #
        if self.settings["saml"]["debug"]:
            log.info("SLS auth: %s", saml_auth.is_authenticated())
            log.info("SLS err: %s", saml_auth.get_errors())
            log.info("SLS attrs: %s", saml_auth.get_attributes())
            log.info("SLS NameID: %s", saml_auth.get_nameid())
            log.info("SLS SessionIndex: %s", saml_auth.get_session_index())
        #
        cherrypy.session.clear()
        cherrypy.session.regenerate()
        #
        loop_urls = [
            cherrypy.request.base + cherrypy.request.script_name + "/sls",
            cherrypy.request.base + cherrypy.request.script_name + "/logout",
            cherrypy.request.base + \
                (self.settings["endpoints"]["root"] + "/logout").replace("//", "/"),
        ]
        if "RelayState" in cherrypy.request.params and \
                cherrypy.request.params["RelayState"] not in loop_urls:
            raise cherrypy.HTTPRedirect(cherrypy.request.params["RelayState"])
        raise cherrypy.HTTPRedirect(self.settings["auth"]["logout_default_redirect_url"])
