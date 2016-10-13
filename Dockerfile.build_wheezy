# Copyright (c) 2015 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The wheezy build container is used to build calicoctl with older versions
# of glibc (2.13).
FROM python:2.7.12-wheezy
MAINTAINER Tom Denham <tom@projectcalico.org>

WORKDIR /code/

RUN apt-get update && \
    apt-get install -qy python-dev python-pip git libffi-dev libssl-dev procps && rm -rf /var/lib/apt/lists/*

# Install the python packages needed for building binaries for Calico Python components.
# Git is installed to allow pip installation from a Github repository.
RUN pip --no-cache-dir install --upgrade pip
ADD build-requirements-frozen.txt /code/
RUN pip --no-cache-dir install -r build-requirements-frozen.txt
ADD . /tmp/pycalico
RUN pip --no-cache-dir install /tmp/pycalico
