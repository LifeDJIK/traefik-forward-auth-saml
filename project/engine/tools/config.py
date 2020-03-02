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
    Configuration tools
"""

import os
import re

import hvac  # pylint: disable=E0401

from engine.tools import log


def config_substitution(obj, secrets):
    """ Allows to use raw environmental variables and secrets inside YAML/JSON config """
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            obj[config_substitution(key, secrets)] = \
                config_substitution(obj.pop(key), secrets)
    if isinstance(obj, list):
        for index, item in enumerate(obj):
            obj[index] = config_substitution(item, secrets)
    if isinstance(obj, str):
        if re.match(r"^\$\![a-zA-Z_][a-zA-Z0-9_]*$", obj.strip()) \
                and obj.strip()[2:] in os.environ:
            return os.environ[obj.strip()[2:]]
        if re.match(r"^\$\=\S*$", obj.strip()):
            obj_key = obj.strip()[2:]
            obj_value = secrets.get(obj_key, None)
            if obj_value is not None:
                return obj_value
    return obj


def vault_secrets(settings):
    """ Get secrets from HashiCorp Vault """
    if "vault" not in settings:
        return dict()
    config = settings["vault"]
    client = hvac.Client(
        url=config["url"],
        verify=config.get("ssl_verify", False),
        namespace=config.get("namespace", None)
    )
    if "auth_token" in config:
        client.token = config["auth_token"]
    if "auth_username" in config:
        client.auth_userpass(
            config.get("auth_username"), config.get("auth_password", "")
        )
    if "auth_role_id" in config:
        client.auth_approle(
            config.get("auth_role_id"), config.get("auth_secret_id", "")
        )
    if not client.is_authenticated():
        log.error("Vault authentication failed")
        return dict()
    return client.secrets.kv.v2.read_secret_version(
        path=config.get("secrets_path", "secrets"),
        mount_point=config.get("secrets_mount_point", "kv")
    ).get("data", dict()).get("data", dict())
