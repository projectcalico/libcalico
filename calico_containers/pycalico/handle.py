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


from netaddr import IPNetwork
import json
import logging

from pycalico import PyCalicoError

_log = logging.getLogger(__name__)
_log.addHandler(logging.NullHandler())


class AllocationHandle(object):
    """
    An allocation handle tracks the blocks and number of addresses allocated
    with a particular handle ID.  This allows fast releasing of those IPs
    using the handle ID.
    """
    HANDLE_ID = "id"
    BLOCK = "block"

    def __init__(self, handle_id):
        """

        :param handle_id: The ID for this handle, must be a string.
        :return: AllocationHandle
        """

        self.handle_id = handle_id
        self.db_result = None

        self.block = {}
        """
        Stores the number of allocated addresses, by block CIDR.
        """

    def to_json(self):
        """
        Convert to a JSON representation for writing to etcd.
        """

        json_dict = {AllocationHandle.HANDLE_ID: self.handle_id,
                     AllocationHandle.BLOCK: self.block}
        return json.dumps(json_dict)

    @classmethod
    def from_etcd_result(cls, etcd_result):
        """
        Convert a JSON representation into an instance of AllocationHandle.
        """
        json_dict = json.loads(etcd_result.value)
        handle_id = json_dict[AllocationHandle.HANDLE_ID]
        handle = cls(handle_id)
        handle.db_result = etcd_result

        block = json_dict[AllocationHandle.BLOCK]

        handle.block = block

        return handle

    def update_result(self):
        """
        Return the EtcdResult with any changes to the object written to
        result.value.
        :return:
        """
        self.db_result.value = self.to_json()
        return self.db_result

    def increment_block(self, block_cidr, num):
        """
        Increment the address count for the given block.
        :param block_cidr: Block ID as IPNetwork in CIDR format.
        :param num: Amount to increment
        :return: New count
        """
        assert isinstance(block_cidr, IPNetwork)
        block_id = str(block_cidr)
        cur = self.block.get(block_id, 0)
        new = cur + num
        self.block[block_id] = new
        return new

    def decrement_block(self, block_cidr, num):
        """
        Decrement the address count for the given block.
        :param block_cidr: Block ID as IPNetwork in CIDR format.
        :param num: Amount to decrement
        :return: New count
        """
        assert isinstance(block_cidr, IPNetwork)
        block_id = str(block_cidr)
        try:
            cur = self.block[block_id]
        except KeyError:
            raise AddressCountTooLow("Tried to decrement block %s by %s, but "
                                     "it isn't linked to handle %s" %
                                     (block_id, num, self.handle_id))
        else:
            new = cur - num
            if new < 0:
                raise AddressCountTooLow("Tried to decrement block %s by %s, "
                                         "but it only has %s addresses on"
                                         " handle %s" % (block_id, num, cur,
                                                         self.handle_id))
            if new == 0:
                del self.block[block_id]
            else:
                self.block[block_id] = new
            return new

    def is_empty(self):
        """
        Return True if there are no allocations, False otherwise.
        """
        return len(self.block) == 0


class HandleError(PyCalicoError):
    """
    Base error class for IPAM AllocationHandles.
    """
    pass


class AddressCountTooLow(HandleError):
    """
    Tried to decrement the address count for a block, but it was too low to
    decrement without going below zero.
    """
    pass
