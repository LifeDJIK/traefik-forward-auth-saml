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

import cherrypy  # pylint: disable=E0401


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
    def auth(self, target=None):  # pylint: disable=R0201,C0111
        # Check if need to login
        if not cherrypy.session.get("auth", False):
            for header in [
                    "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Uri"
            ]:
                if header in cherrypy.request.headers:
                    cherrypy.session[header] = cherrypy.request.headers[header]
            raise cherrypy.HTTPRedirect(
                cherrypy.request.base + cherrypy.request.script_name + "/login"
            )
        # Set headers for reply
        if target is None or target == "raw":
            cherrypy.response.headers["X-Auth-Session-Endpoint"] = \
                cherrypy.request.base + self.settings["endpoints"]["info"] + "/raw"
            cherrypy.response.headers["X-Auth-Session-Name"] = cherrypy.serving.request.config.get(
                "tools.sessions.name",
                "session_id"
            )
            cherrypy.response.headers["X-Auth-Session-Id"] = cherrypy.session.id
        return "OK"

    #
    # Login/logout endpoints
    #

    @cherrypy.expose
    def login(self):  # pylint: disable=R0201,C0111
        raise cherrypy.HTTPRedirect(self.settings["auth"]["login_handler"])

    @cherrypy.expose
    def logout(self, to=None):  # pylint: disable=R0201,C0111,C0103
        raise cherrypy.HTTPRedirect(self.settings["auth"]["logout_handler"])
