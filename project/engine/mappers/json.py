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
    Mapper: json
"""

import urllib
import cherrypy  # pylint: disable=E0401
import jsonpath_rw  # pylint: disable=E0401

from engine.mappers import raw
from engine.tools import log


def auth(scope):
    """ Map auth data """
    cherrypy.response.headers["X-Auth-Session-Endpoint"] = \
        cherrypy.request.base + cherrypy.config["engine.settings"]["endpoints"]["info"] + \
        f"/query?target=json&scope={urllib.parse.quote_plus(scope)}"
    cherrypy.response.headers["X-Auth-Session-Name"] = cherrypy.serving.request.config.get(
        "tools.sessions.name",
        "session_id"
    )
    cherrypy.response.headers["X-Auth-Session-Id"] = cherrypy.session.id
    return "OK"


def info(scope):
    """ Map info data """
    if scope not in cherrypy.config["engine.settings"]["mappers"]["json"]:
        raise cherrypy.HTTPRedirect(
            cherrypy.config["engine.settings"]["endpoints"]["access_denied"]
        )
    auth_info = raw.info(scope)
    result = dict()
    result["raw"] = auth_info
    try:
        for key, path in cherrypy.config["engine.settings"]["mappers"]["json"][scope].items():
            result[key] = jsonpath_rw.parse(path).find(auth_info)[0].value
    except:  # pylint: disable=W0702
        log.exception("Failed to set scope data")
    return result
