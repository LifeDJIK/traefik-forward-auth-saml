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
    Project tools for CherryPy
"""

import cherrypy  # pylint: disable=E0401


def jinja2_template(name):
    context = cherrypy.response.body or [{}]
    if not isinstance(context, list) or not isinstance(context[0], dict):
        return
    cherrypy.response.body = cherrypy.engine.publish(
        "render-template",
        name,
        context[0]
    ).pop().encode("utf-8")


def secure_headers():
    headers = cherrypy.response.headers
    headers["X-Frame-Options"] = "DENY"
    headers["X-XSS-Protection"] = "1; mode=block"
    headers["Content-Security-Policy"] = "default-src='self'"
