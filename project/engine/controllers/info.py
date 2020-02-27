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

import importlib
import cherrypy  # pylint: disable=E0401

from engine.tools import log


class InfoController:  # pylint: disable=R0903
    """ Info controller logic """

    def __init__(self, base_dir, base_path):
        self.base_dir = base_dir
        self.base_path = base_path
        self.settings = cherrypy.config["engine.settings"]

    #
    # Backend auth/user info endpoint
    #

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def query(self, target=None):  # pylint: disable=R0201,C0111
        if target is None:
            target = "raw"
        # Check for forced info
        if "forced_info" in self.settings["global"] and \
                target in self.settings["global"]["forced_info"]:
            return self.settings["global"]["forced_info"][target]
        # Map info for target
        result = dict()
        try:
            mapper = importlib.import_module(f"engine.mappers.{target}")
            result = mapper.info(self.settings)
        except:  # pylint: disable=W0702
            log.exception("Failed to map info data")
        return result
