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
    Mapper: raw
"""

import cherrypy  # pylint: disable=E0401


def auth(scope):
    """ Map auth data """
    _ = scope
    cherrypy.response.headers["X-Auth-Session-Endpoint"] = \
        cherrypy.request.base + cherrypy.config["engine.settings"]["endpoints"]["info"] + "/query"
    cherrypy.response.headers["X-Auth-Session-Name"] = cherrypy.serving.request.config.get(
        "tools.sessions.name",
        "session_id"
    )
    cherrypy.response.headers["X-Auth-Session-Id"] = cherrypy.session.id
    return "OK"


def info(scope):
    """ Map info data """
    _ = scope
    result = dict()
    result["auth"] = cherrypy.session.get("auth", False)
    result["auth_errors"] = cherrypy.session.get("auth_errors", list())
    result["auth_nameid"] = cherrypy.session.get("auth_nameid", "")
    result["auth_sessionindex"] = cherrypy.session.get("auth_sessionindex", "")
    result["auth_attributes"] = cherrypy.session.get("auth_attributes", dict())
    return result
