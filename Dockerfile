FROM python:3.7-alpine
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
WORKDIR /usr/src/app

COPY requirements.txt ./
RUN set -x \
  && apk add --update --no-cache libxml2 libxslt xmlsec \
  && apk add --update --no-cache --virtual .build-deps g++ python-dev libxml2-dev libxslt-dev xmlsec-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-deps \
  && rm -f requirements.txt

COPY project/ ./
CMD [ "python", "./project.py" ]
