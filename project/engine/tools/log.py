#!/usr/bin/python
# coding=utf-8
# pylint: disable=I0011,E0401

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
    Logging tool
"""

import logging
import inspect

from engine import constants


def init(debug_logging=False):
    """ Initialize logging """
    logging.basicConfig(
        level=logging.DEBUG if debug_logging else logging.INFO,
        datefmt=constants.LOG_DATE_FORMAT,
        format=constants.LOG_FORMAT,
    )
    logging.raiseExceptions = False


def get_outer_logger():
    """ Get logger for callers context (for use in this module) """
    return logging.getLogger(
        inspect.currentframe().f_back.f_back.f_globals["__name__"]
    )


def debug(msg, *args, **kwargs):
    """ Logs a message with level DEBUG """
    return get_outer_logger().debug(msg, *args, **kwargs)


def info(msg, *args, **kwargs):
    """ Logs a message with level INFO """
    return get_outer_logger().info(msg, *args, **kwargs)


def warning(msg, *args, **kwargs):
    """ Logs a message with level WARNING """
    return get_outer_logger().warning(msg, *args, **kwargs)


def error(msg, *args, **kwargs):
    """ Logs a message with level ERROR """
    return get_outer_logger().error(msg, *args, **kwargs)


def critical(msg, *args, **kwargs):
    """ Logs a message with level CRITICAL """
    return get_outer_logger().critical(msg, *args, **kwargs)


def log(lvl, msg, *args, **kwargs):
    """ Logs a message with integer level lvl """
    return get_outer_logger().log(lvl, msg, *args, **kwargs)


def exception(msg, *args, **kwargs):
    """ Logs a message with level ERROR inside exception handler """
    return get_outer_logger().exception(msg, *args, **kwargs)
