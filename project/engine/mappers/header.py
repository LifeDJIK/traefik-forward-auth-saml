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
    Mapper: header
"""

import cherrypy  # pylint: disable=E0401
import jsonpath_rw  # pylint: disable=E0401

from engine.mappers import raw
from engine.tools import log


def auth(scope):
    """ Map auth data """
    if scope not in cherrypy.config["engine.settings"]["mappers"]["header"]:
        raise cherrypy.HTTPRedirect(
            cherrypy.config["engine.settings"]["endpoints"]["access_denied"]
        )
    raw.auth(scope)  # Set "raw" headers too
    auth_info = info(scope)
    try:
        for header, path in cherrypy.config["engine.settings"]["mappers"]["header"][scope].items():
            cherrypy.response.headers[header] = jsonpath_rw.parse(path).find(auth_info)[0].value
    except:  # pylint: disable=W0702
        log.exception("Failed to set scope headers")
    return "OK"


def info(scope):
    """ Map info data """
    return raw.info(scope)
