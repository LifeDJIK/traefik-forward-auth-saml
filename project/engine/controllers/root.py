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
    Root controller
"""

import importlib
import cherrypy  # pylint: disable=E0401

from engine.tools import log


class RootController:  # pylint: disable=R0903
    """ Root controller logic """

    def __init__(self, base_dir, base_path):
        self.base_dir = base_dir
        self.base_path = base_path
        self.settings = cherrypy.config["engine.settings"]

    #
    # Traefik ForwardAuth endpoint
    #

    @cherrypy.expose
    def auth(self, target=None, scope=None):  # pylint: disable=R0201,C0111
        # Check if need to login
        if not cherrypy.session.get("auth", False) and not self.settings["global"]["disable_auth"]:
            # Redirect to login
            for header in [
                    "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Uri"
            ]:
                if header in cherrypy.request.headers:
                    cherrypy.session[header] = cherrypy.request.headers[header]
            raise cherrypy.HTTPRedirect(
                self.settings["auth"].get(
                    "auth_redirect",
                    cherrypy.request.base + cherrypy.request.script_name + "/login"
                )
            )
        if target is None:
            target = "raw"
        # Map auth response
        result = "OK"
        try:
            mapper = importlib.import_module(f"engine.mappers.{target}")
            result = mapper.auth(self.settings, scope)
        except:  # pylint: disable=W0702
            log.exception("Failed to map auth data")
        return result

    #
    # Login/logout endpoints
    #

    @cherrypy.expose
    def login(self):  # pylint: disable=R0201,C0111
        raise cherrypy.HTTPRedirect(self.settings["auth"]["login_handler"])

    @cherrypy.expose
    def logout(self, to=None):  # pylint: disable=R0201,C0111,C0103
        raise cherrypy.HTTPRedirect(
            self.settings["auth"]["logout_handler"] + (f"?to={to}" if to is not None else "")
        )
