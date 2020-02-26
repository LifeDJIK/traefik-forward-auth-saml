#!/usr/bin/python
# coding=utf-8
# pylint: disable=I0011,R0201,R0903,C0111,C0413,E1101

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
    Project entry point
"""


import os
import logging
import yaml  # pylint: disable=E0401
import jinja2  # pylint: disable=E0401
import cherrypy  # pylint: disable=E0401

from engine.tools import jinja2_template
from engine.tools import secure_headers

cherrypy.tools.template = cherrypy.Tool("before_finalize", jinja2_template)
cherrypy.tools.secureheaders = cherrypy.Tool("before_finalize", secure_headers, priority=60)

from engine.plugins import Jinja2Plugin
from engine.controllers.root import RootController
from engine.controllers.info import InfoController


def main():
    """ Entry point """
    # Initialize logging
    logging.basicConfig(
        level=logging.INFO,
        datefmt="%Y.%m.%d %H:%M:%S %Z",
        format="%(asctime)s - %(levelname)8s - %(name)s - %(message)s",
    )
    # Load settings
    settings_file = os.environ.get("CONFIG_FILENAME", None)
    if not settings_file:
        logging.error("Settings file path not set. Please set CONFIG_FILENAME")
        return
    with open(settings_file, "rb") as file:
        settings = yaml.load(file, Loader=yaml.SafeLoader)
    # Set paths and create plugins
    base = os.path.dirname(os.path.realpath(__file__))
    jinja2_base = os.path.join(base, "templates")
    jinja2_plugin = Jinja2Plugin(
        cherrypy.engine,
        loader=jinja2.FileSystemLoader(jinja2_base)
    )
    # Set config and start plugins
    cherrypy.config.update({
        "tools.staticdir.root": base,
        "tools.staticfile.root": base
    })
    cherrypy.config.update(settings.get("server", dict()))
    jinja2_plugin.subscribe()
    # Create and mount application trees
    root_path = settings.get("server", dict()).get("endpoints", dict()).get(
        "root", "/forward-auth"
    )
    root_instance = RootController(base, root_path, settings)
    cherrypy.tree.mount(root_instance, root_path, settings.get("server", dict()))
    #
    info_path = settings.get("server", dict()).get("endpoints", dict()).get(
        "info", "/forward-auth/info"
    )
    info_instance = InfoController(base, root_path, settings)
    cherrypy.tree.mount(info_instance, info_path, settings.get("server", dict()))
    # Hide banners if requested
    if settings.get("server", dict()).get("security", dict()).get("hide_banners", False):
        cherrypy.__version__ = ""
        cherrypy.config.update({
            "response.headers.server": ""
        })
        cherrypy._cperror._HTTPErrorTemplate = cherrypy._cperror._HTTPErrorTemplate.replace(  # pylint: disable=W0212
            "Powered by <a href=\"http://www.cherrypy.org\">CherryPy %(version)s</a>\n",
            ""
        )
    # Finally run the engine
    cherrypy.engine.start()
    cherrypy.engine.block()


if __name__ == "__main__":
    # Call entry point
    main()
