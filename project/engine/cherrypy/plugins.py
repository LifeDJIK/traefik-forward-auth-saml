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
    Project plugins for CherryPy
"""

from cherrypy.process.plugins import SimplePlugin  # pylint: disable=E0401
from jinja2 import Environment  # pylint: disable=C0411,E0401


class Jinja2Plugin(SimplePlugin):
    """ Jinja2 template engine plugin """

    def __init__(self, bus, **kvargs):
        SimplePlugin.__init__(self, bus)
        self.environment = Environment(autoescape=True, **kvargs)

    def start(self):  # pylint: disable=C0111
        self.bus.log("Starting Jinja2 plugin")
        self.bus.subscribe("render-template", self.render_template)

    def stop(self):  # pylint: disable=C0111
        self.bus.log("Stopping Jinja2 plugin")
        self.bus.unsubscribe("render-template", self.render_template)

    def render_template(self, template, context):  # pylint: disable=C0111
        return self.environment.get_template(template).render(context)
