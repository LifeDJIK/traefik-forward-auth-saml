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
    Info controller
"""

import cherrypy  # pylint: disable=E0401


class InfoController:  # pylint: disable=R0903
    """ Info controller logic """

    def __init__(self, base_dir, base_path, settings):
        self.base_dir = base_dir
        self.base_path = base_path
        self.settings = settings

    #
    # Backend auth/user info endpoint
    #

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def raw(self):  # pylint: disable=R0201,C0111
        result = dict()
        result["auth"] = cherrypy.session.get("auth", False)
        result["auth_errors"] = cherrypy.session.get("auth_errors", list())
        result["auth_nameid"] = cherrypy.session.get("auth_nameid", "")
        result["auth_sessionindex"] = cherrypy.session.get("auth_sessionindex", "")
        result["auth_attributes"] = cherrypy.session.get("auth_attributes", dict())
        return result
