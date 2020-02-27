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
    Seed: minio
"""

import base64
import yaml
import minio  # pylint: disable=E0401
import urllib3  # pylint: disable=E0401


def unseed(seed_data):
    """ Unseed settings data from seed """
    config = yaml.load(base64.b64decode(seed_data), Loader=yaml.SafeLoader)
    http_client = None
    if not config.get("ssl_verify", False):
        http_client = urllib3.PoolManager(
            timeout=urllib3.Timeout.DEFAULT_TIMEOUT,
            cert_reqs="CERT_NONE",
            maxsize=10,
            retries=urllib3.Retry(
                total=5,
                backoff_factor=0.2,
                status_forcelist=[500, 502, 503, 504]
            )
        )
    if isinstance(config.get("ssl_verify", False), str):
        http_client = urllib3.PoolManager(
            timeout=urllib3.Timeout.DEFAULT_TIMEOUT,
            cert_reqs="CERT_REQUIRED",
            ca_certs=config["ssl_verify"],
            maxsize=10,
            retries=urllib3.Retry(
                total=5,
                backoff_factor=0.2,
                status_forcelist=[500, 502, 503, 504]
            )
        )
    client = minio.Minio(
        endpoint=config["endpoint"],
        access_key=config.get("access_key", None),
        secret_key=config.get("secret_key", None),
        secure=config.get("secure", True),
        region=config.get("region", None),
        http_client=http_client
    )
    return client.get_object(config["bucket"], config["object"]).read()
