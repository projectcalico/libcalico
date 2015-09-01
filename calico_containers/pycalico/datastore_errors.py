# Copyright 2015 Metaswitch Networks
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

# The various Exceptions that can be raised by datastore.py are collected here
from pycalico import PyCalicoError


class DataStoreError(PyCalicoError):
    """
    General Datastore exception.
    """
    pass


class NoEndpointForContainer(DataStoreError):
    """
    Tried to get the endpoint associated with a container that has no
    endpoints.
    """
    pass


class ProfileNotInEndpoint(DataStoreError):
    """
    Attempting to remove a profile that is not in the container endpoint
    profile list.
    """
    def __init__(self, profile_name):
        self.profile_name = profile_name


class ProfileAlreadyInEndpoint(DataStoreError):
    """
    Attempting to append a profile that is already in the container endpoint
    profile list.
    """
    def __init__(self, profile_name):
        self.profile_name = profile_name


class MultipleEndpointsMatch(DataStoreError):
    """
    More than one endpoint was found for the specified criteria.
    """
    pass


class PoolNotFound(DataStoreError):
    """
    IPPool cannot be found or it has not been configured correctly
    """
    def __init__(self, ip):
        self.ip = ip
