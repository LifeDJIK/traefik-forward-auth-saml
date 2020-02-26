#!/usr/bin/python
# coding=utf-8
# pylint: disable=I0011,R0201,R0903,C0111

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
    Project helpers for CherryPy
"""

import html
import urllib

from xml.sax import saxutils

import cherrypy  # pylint: disable=E0401
from cherrypy._cpcompat import tonative  # pylint: disable=E0401

from engine.tools import log


def register_controller(cls, path, base, server_config, *args, **kvargs):
    cherrypy.tree.mount(cls(base, path, *args, **kvargs), path, server_config)


def hide_banners():
    cherrypy.__version__ = ""
    cherrypy.config.update({
        "response.headers.server": ""
    })
    cherrypy._cperror._HTTPErrorTemplate = cherrypy._cperror._HTTPErrorTemplate.replace(  # pylint: disable=W0212
        "Powered by <a href=\"http://www.cherrypy.org\">CherryPy %(version)s</a>\n",
        ""
    )


def error_handler(status, message, traceback, version):
    _ = traceback, version
    log.warning("Engine error: %s: %s", status, message)
    response = cherrypy.serving.response
    response.status = 303
    response.headers["Content-Type"] = "text/html;charset=utf-8"
    response.headers["Location"] = urllib.parse.urljoin(
        cherrypy.url(), tonative(
            cherrypy.config["engine.settings"]["endpoints"]["access_denied"], "utf-8"
        )
    )
    data = "This resource can be found at <a href=%s>%s</a>." % (
        saxutils.quoteattr(cherrypy.response.headers["Location"]),
        html.escape(cherrypy.response.headers["Location"], quote=False)
    )
    response.headers.pop("Content-Length", None)
    return data


def exception_handler():
    # log.exception("Engine exception")  # Already logged by CherryPy
    raise cherrypy.HTTPRedirect(cherrypy.config["engine.settings"]["endpoints"]["access_denied"])
