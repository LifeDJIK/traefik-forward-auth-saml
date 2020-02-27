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
import importlib

import yaml  # pylint: disable=E0401
import jinja2  # pylint: disable=E0401
import cherrypy  # pylint: disable=E0401

from engine.tools import log, config
from engine.cherrypy import helpers, tools, plugins

cherrypy.tools.template = cherrypy.Tool("before_finalize", tools.jinja2_template)
cherrypy.tools.secureheaders = cherrypy.Tool("before_finalize", tools.secure_headers, priority=60)

from engine.controllers.root import RootController
from engine.controllers.info import InfoController
from engine.controllers.saml import SamlController



def main():
    """ Entry point """
    # Initialize base logging
    log.init()
    # Load settings
    settings_data = None
    # Load settings from seed
    settings_seed = os.environ.get("CONFIG_SEED", None)
    if settings_seed and ":" in settings_seed:
        settings_seed_tag = settings_seed[:settings_seed.find(":")]
        settings_seed_data = settings_seed[len(settings_seed_tag)+1:]
        try:
            seed = importlib.import_module(f"engine.seeds.{settings_seed_tag}")
            settings_data = seed.unseed(settings_seed_data)
        except:  # pylint: disable=W0702
            log.exception("Failed to unseed settings, skipping seed")
    else:
        log.info("Settings seed is empty or invalid, skipping")
    # Load settings from file
    if settings_data is None:
        settings_file = os.environ.get("CONFIG_FILENAME", None)
        if not settings_file:
            log.error("Settings file path not set. Please set CONFIG_FILENAME")
            return
        with open(settings_file, "rb") as file:
            settings_data = file.read()
    # Parse settings
    settings = yaml.load(os.path.expandvars(settings_data), Loader=yaml.SafeLoader)
    settings = config.config_substitution(settings, config.vault_secrets(settings))
    # Enable debug logging if requested
    if settings["global"]["debug"]:
        log.init(debug_logging=True)
    # Set paths and create plugins
    base = os.path.dirname(os.path.realpath(__file__))
    jinja2_plugin = plugins.Jinja2Plugin(
        cherrypy.engine,
        loader=jinja2.FileSystemLoader(os.path.join(base, "templates"))
    )
    # Set config
    cherrypy.config.update({
        "engine.settings": settings,
        "tools.staticdir.root": base,
        "tools.staticfile.root": base
    })
    server_config = settings["server"]
    cherrypy.config.update(server_config)
    # Start plugins
    jinja2_plugin.subscribe()
    # Create and mount application trees
    helpers.register_controller(RootController, settings["endpoints"]["root"], base, server_config)
    helpers.register_controller(InfoController, settings["endpoints"]["info"], base, server_config)
    if "saml" in settings:
        helpers.register_controller(
            SamlController, settings["endpoints"]["saml"], base, server_config
        )
    # Set error handlers
    cherrypy.config.update({
        "error_page.default": helpers.error_handler,
        "request.error_response": helpers.exception_handler,
    })
    # Hide banners
    helpers.hide_banners()
    # Finally run the engine
    cherrypy.engine.start()
    cherrypy.engine.block()


if __name__ == "__main__":
    # Call entry point
    main()
