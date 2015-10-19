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

from netaddr import IPAddress, IPNetwork
import socket
import json
import logging
from pycalico import PyCalicoError

_log = logging.getLogger(__name__)

BITS_BY_VERSION = {4: 32, 6: 128}
BLOCK_SIZE_BITS = 6
BLOCK_PREFIXLEN = {4: 32 - BLOCK_SIZE_BITS,
                   6: 128 - BLOCK_SIZE_BITS}
BLOCK_SIZE = 2 ** BLOCK_SIZE_BITS
PREFIX_MASK = {4: (IPAddress("255.255.255.255") ^ (BLOCK_SIZE - 1)),
               6: (IPAddress("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ^
                   (BLOCK_SIZE - 1))}


class AllocationBlock(object):
    """
    A block of IP addresses from which to allocate for IPAM clients.

    Blocks are identified by IP prefix.  Each block is a single, keyed object
    in etcd and the value of the block object in the datastore encodes all the
    allocations for all the IP addresses within that prefix.

    Thus, allocations and releases of IP addresses correspond to changes in the
    block's value.  Compare-and-swap atomicity is used to ensure allocations
    and releases are consistent operations.

    If another process updates the Block in the data store, then we will fail
    to write this one.  The owning code will need to
     - drop the invalid instance,
     - re-read a new instance from the data store,
     - recompute the required modifications, and
     - try the compare-and-swap operation again.
    """
    CIDR = "cidr"
    AFFINITY = "affinity"
    HOST_AFFINITY_T = "host:%s"
    ALLOCATIONS = "allocations"
    ATTRIBUTES = "attributes"
    ATTR_HANDLE_ID = "handle_id"
    ATTR_SECONDARY = "secondary"

    def __init__(self, cidr_prefix, host_affinity):
        assert isinstance(cidr_prefix, IPNetwork)
        assert cidr_prefix.cidr == cidr_prefix

        # Make sure the block is the right size.
        assert cidr_prefix.prefixlen == (BLOCK_PREFIXLEN[cidr_prefix.version])
        self.cidr = cidr_prefix
        self.db_result = None

        self.host_affinity = host_affinity
        """
        Both to minimize collisions, where multiple hosts attempt to change a
        single block, and to support route aggregation, each block has affinity
        to a single Calico host.  That host does not hold exclusive rights to
        modify the block; any host may still do that.  The host with affinity
        simply uses the block as the place where it first searches if the user
        asked to have the IP assigned automatically.
        """

        self.allocations = [None] * BLOCK_SIZE
        """
        A fixed length array with one entry for every address in the block.
        None means unallocated.  A non-negative integer indicates the address
        is allocated, and is the index into the `attributes` array for the
        attributes assigned to the allocation.
        """

        self.attributes = []
        """
        List of dictionaries of attributes for allocations.

        Each has the format:
        {
            ATTR_PRIMARY: <primary handle key>,
            ATTR_SECONDARY: {...}
        }
        """

    def to_json(self):
        """
        Convert to a JSON representation for writing to etcd.
        """

        json_dict = {AllocationBlock.CIDR: str(self.cidr),
                     AllocationBlock.AFFINITY:
                         AllocationBlock.HOST_AFFINITY_T % self.host_affinity,
                     AllocationBlock.ALLOCATIONS: self.allocations,
                     AllocationBlock.ATTRIBUTES: self.attributes}
        return json.dumps(json_dict)

    @classmethod
    def from_etcd_result(cls, etcd_result):
        """
        Convert a JSON representation into an instance of AllocationBlock.
        """
        json_dict = json.loads(etcd_result.value)
        cidr_prefix = IPNetwork(json_dict[AllocationBlock.CIDR])

        # Parse out the host.  For now, it's in the form host:<hostname>
        affinity = json_dict[AllocationBlock.AFFINITY]
        assert affinity[:5] == "host:"
        host_affinity = affinity[5:]

        block = cls(cidr_prefix, host_affinity)
        block.db_result = etcd_result

        # Process & check allocations
        allocations = json_dict[AllocationBlock.ALLOCATIONS]
        assert len(allocations) == BLOCK_SIZE
        block.allocations = allocations

        # Process & check attributes
        attributes = json_dict[AllocationBlock.ATTRIBUTES]
        block.attributes = attributes
        assert (block._verify_attributes())

        return block

    def update_result(self):
        """
        Return the EtcdResult with any changes to the object written to
        result.value.
        :return:
        """
        self.db_result.value = self.to_json()
        return self.db_result

    def auto_assign(self, num, handle_id, attributes, hostname, affinity_check=True):
        """
        Automatically pick and assign the given number of IP addresses.

        :param num: Number of addresses to request
        :param handle_id: allocation handle ID for this request.  You can
        query this key using get_assignments_by_handle() or release all
        addresses with this key using release_by_handle().
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :param hostname: The hostname to use for affinity in
        assigning IP addresses.
        :param affinity_check: If true, verify that this block's affinity is
        this host and throw a NoHostAffinityWarning if it isn't.  Set to false
        to disable this check.
        :return: List of assigned addresses.  When the block is at or near
        full, this method may return fewer than requested IPs.
        """
        assert num >= 0

        if affinity_check and hostname != self.host_affinity:
            raise NoHostAffinityWarning("Host affinity is %s" %
                                        self.host_affinity)

        ordinals = []
        # Walk the allocations until we find enough.
        for o in xrange(BLOCK_SIZE):
            if len(ordinals) == num:
                break
            if self.allocations[o] is None:
                ordinals.append(o)

        ips = []
        if ordinals:
            # We found some addresses, now we need to set up attributes.
            attr_index = self._find_or_add_attrs(handle_id, attributes)

            # Perform the allocation.
            for o in ordinals:
                assert self.allocations[o] is None
                self.allocations[o] = attr_index

                # Convert ordinal to IP.
                ip = IPAddress(self.cidr.first + o, version=self.cidr.version)
                ips.append(ip)
        return ips

    def assign(self, address, handle_id, attributes):
        """
        Assign the given address.  Throws AlreadyAssignedError if the address
        is taken.

        :param address: IPAddress to assign.
        :param handle_id: allocation handle ID for this request.  You can
        query this key using get_assignments_by_handle() or release all addresses
        with this key using release_by_handle().
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :return: None.
        """
        assert isinstance(address, IPAddress)
        # Convert to an ordinal
        ordinal = int(address - self.cidr.first)
        assert 0 <= ordinal <= BLOCK_SIZE, "Address not in block."

        # Check if allocated
        if self.allocations[ordinal] is not None:
            raise AlreadyAssignedError("%s is already assigned in block %s" % (
                address, self.cidr))

        # Set up attributes
        attr_index = self._find_or_add_attrs(handle_id, attributes)
        self.allocations[ordinal] = attr_index
        return

    def count_free_addresses(self):
        """
        Count the number of free addresses in this block.
        :return: Number of free addresses.
        """
        count = 0
        for a in self.allocations:
            if a is None:
                count += 1
        return count

    def release(self, addresses):
        """
        Release the given addresses.

        :param addresses: Set of IPAddresses to release.
        :return: (unallocated, handles_with_counts) Where:
          - unallocted is a set of IPAddresses.  If any of the requested
            addresses were not allocated, they are returned so the caller can
            handle appropriately.
          - handles_with_counts is a dictionary of handle_ids and the number of
            addresses released for that handle.  They are returned so the
            caller can decrement the affected handles.
        """
        assert isinstance(addresses, (set, frozenset))
        deleting_ref_counts = {}
        ordinals = []
        unallocated = set()
        handles_with_counts = {}
        for address in addresses:
            assert isinstance(address, IPAddress)
            # Convert to an ordinal
            ordinal = int(address - self.cidr.first)
            assert 0 <= ordinal <= BLOCK_SIZE, "Address not in block."

            # Check if allocated
            attr_idx = self.allocations[ordinal]
            if attr_idx is None:
                _log.warning("Asked to release %s in block %s, but it was not "
                             "allocated.", address, self.cidr)
                unallocated.add(address)
                continue
            ordinals.append(ordinal)
            old_count = deleting_ref_counts.get(attr_idx, 0)
            deleting_ref_counts[attr_idx] = old_count + 1

            # Increment our count of addresses by handle.
            handle_id = self.\
                attributes[attr_idx][AllocationBlock.ATTR_HANDLE_ID]
            handle_count = handles_with_counts.setdefault(handle_id, 0)
            handle_count += 1
            handles_with_counts[handle_id] = handle_count

        # Compute which attributes need to be cleaned up.  We do this by
        # reference counting.  If we're deleting all the references, then it
        # needs to be cleaned up.
        attr_indexes_to_delete = set()
        ref_counts = self._get_attribute_ref_counts()
        for idx, refs in deleting_ref_counts.iteritems():
            if ref_counts[idx] == refs:
                attr_indexes_to_delete.add(idx)

        # Delete attributes if necessary
        if attr_indexes_to_delete:
            self._delete_attributes(attr_indexes_to_delete, ordinals)

        # All attributes updated.  Finally, release all the requested
        # addressses.
        for ordinal in ordinals:
            self.allocations[ordinal] = None

        return unallocated, handles_with_counts

    def release_by_handle(self, handle_id):
        """
        Release all addresses with the given handle ID.
        :param handle_id: The handle ID to release.
        :return: Number of addresses released.
        """
        attr_indexes_to_delete = self._get_attr_indexes_by_handle(handle_id)

        if attr_indexes_to_delete:
            # Get the ordinals of IPs to release
            ordinals = []
            for o in xrange(BLOCK_SIZE):
                if self.allocations[o] in attr_indexes_to_delete:
                    ordinals.append(o)

            # Clean and renumber remaining attributes.
            self._delete_attributes(attr_indexes_to_delete, ordinals)

            # Release the addresses.
            for ordinal in ordinals:
                self.allocations[ordinal] = None
            return len(ordinals)
        else:
            # Nothing to release.
            return 0

    def get_ip_assignments_by_handle(self, handle_id):
        """
        Get the IP Addresses assigned to a particular handle.
        :param handle_id: The handle ID to search for.
        :return: List of IPAddress objects.
        """
        attr_indexes = self._get_attr_indexes_by_handle(handle_id)
        ips = []
        for o in xrange(BLOCK_SIZE):
                if self.allocations[o] in attr_indexes:
                    ip = IPAddress(self.cidr.first + o,
                                   version=self.cidr.version)
                    ips.append(ip)
        return ips

    def get_attributes_for_ip(self, address):
        """
        Get the attributes and handle ID for an IP address.

        :param address: The IPAddress object to query.
        :return: (handle_id, attributes)
        """
        assert isinstance(address, IPAddress)
        # Convert to an ordinal
        ordinal = int(address - self.cidr.first)
        assert 0 <= ordinal <= BLOCK_SIZE, "Address not in block."

        # Check if allocated
        attr_index = self.allocations[ordinal]
        if attr_index is None:
            raise AddressNotAssignedError("%s is not assigned in block %s" % (
                address, self.cidr))
        else:
            # Allocated.  Look up attributes.
            assert isinstance(attr_index, int)
            attr = self.attributes[attr_index]
            return (attr[AllocationBlock.ATTR_HANDLE_ID],
                    attr[AllocationBlock.ATTR_SECONDARY])

    def _get_attr_indexes_by_handle(self, handle_id):
        """
        Get the attribute indexes for a given handle.
        :param handle_id: The handle ID to search for.
        :return: List of attribute indexes.
        """
        attr_indexes = []
        for ii, attr in enumerate(self.attributes):
            if attr[AllocationBlock.ATTR_HANDLE_ID] == handle_id:
                attr_indexes.append(ii)
        return attr_indexes

    def _delete_attributes(self, attr_indexes_to_delete, ordinals):
        """
        Delete some attributes (used during release processing).

        This removes the attributes from the self.attributes list, and updates
        the allocation list with the new indexes.

        :param attr_indexes_to_delete: set of indexes of attributes to delete
        :param ordinals: list of ordinals of IPs to release (for debugging)
        :return: None.
        """
        new_indexes = range(len(self.attributes))
        new_attributes = []
        y = 0  # next free slot in new attributes list.
        for x in xrange(len(self.attributes)):
            if x in attr_indexes_to_delete:
                # current attr at x being deleted.
                new_indexes[x] = None
            else:
                # current attr at x is kept.
                new_indexes[x] = y
                y += 1
                new_attributes.append(self.attributes[x])
        self.attributes = new_attributes

        # Spin through all the allocations and update indexes
        for i in xrange(BLOCK_SIZE):
            if self.allocations[i] is not None:
                new_index = new_indexes[self.allocations[i]]
                self.allocations[i] = new_index
                # If the new index is None, we better be releasing that
                # address
                assert new_index is not None or i in ordinals

    def _get_attribute_ref_counts(self):
        """
        Walk the allocations and get a dictionary of reference counts to each
        set of attributes.
        """
        ref_counts = {}
        for a in self.allocations:
            old_counts = ref_counts.get(a, 0)
            ref_counts[a] = old_counts + 1
        return ref_counts

    def _find_or_add_attrs(self, primary_key, attributes):
        """
        Check if the key and attributes match existing and return the index, or
        if they don't exist, add them and return the index.
        """
        assert json.dumps(attributes), \
            "Attributes aren't JSON serializable."
        attr = {AllocationBlock.ATTR_HANDLE_ID: primary_key,
                AllocationBlock.ATTR_SECONDARY: attributes}
        attr_index = None
        for index, exist_attr in enumerate(self.attributes):
            if cmp(attr, exist_attr) == 0:
                attr_index = index
                break
        if attr_index is None:
            # Attributes are new, add them.
            attr_index = len(self.attributes)
            self.attributes.append(attr)
        return attr_index

    def _verify_attributes(self):
        """
        Verify the integrity of attribute & allocations.

        This is a debug-only function to detect errors.
        """
        attr_indexes = set(self.allocations)
        max_attr = max(attr_indexes)
        if max_attr is None:
            # Empty block.  Just assert empty attrs and exit.
            assert len(self.attributes) == 0
            return True

        # All attributes present?
        assert len(self.attributes) == max_attr + 1

        # All attributes actually used?
        for x in xrange(max_attr + 1):
            assert x in attr_indexes

        # All assignments point to attributes or None.
        for assignment in self.allocations:
            assert assignment is None or isinstance(assignment, int)
        return True


def get_block_cidr_for_address(address):
    """
    Get the block ID to which a given address belongs.
    :param address: IPAddress
    """
    prefix = PREFIX_MASK[address.version] & address
    block_id = "%s/%s" % (prefix, BLOCK_PREFIXLEN[address.version])
    return IPNetwork(block_id)


class BlockError(PyCalicoError):
    """
    Base exception class for AllocationBlocks.
    """
    pass


class NoHostAffinityWarning(BlockError):
    """
    Tried to auto-assign in a block this host didn't own.  This exception can
    be explicitly disabled.
    """
    pass


class AlreadyAssignedError(BlockError):
    """
    Tried to assign an address, but the address is already taken.
    """
    pass


class AddressNotAssignedError(BlockError):
    """
    Tried to query an address that isn't assigned.
    """
    pass
