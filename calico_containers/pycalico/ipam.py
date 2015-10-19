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

from etcd import EtcdKeyNotFound, EtcdAlreadyExist, EtcdCompareFailed

from netaddr import IPAddress, IPNetwork
import socket
import logging
import random

from pycalico.datastore_datatypes import IPPool
from pycalico.datastore import DatastoreClient
from pycalico.datastore import (IPAM_HOST_AFFINITY_PATH,
                                IPAM_BLOCK_PATH,
                                IPAM_HANDLE_PATH)
from pycalico.datastore_errors import DataStoreError, PoolNotFound
from pycalico.block import (AllocationBlock,
                            get_block_cidr_for_address,
                            BLOCK_PREFIXLEN,
                            AlreadyAssignedError,
                            AddressNotAssignedError)
from pycalico.handle import (AllocationHandle,
                             AddressCountTooLow)

_log = logging.getLogger(__name__)

RETRIES = 100


class BlockHandleReaderWriter(DatastoreClient):
    """
    Can read and write allocation blocks and handles to the data store, as well
    as related bits of state.

    This class keeps etcd specific code from being in the main IPAMClient
    class.
    """

    def _read_block(self, block_cidr):
        """
        Read the block from the data store.
        :param block_cidr: The IPNetwork identifier for a block.
        :return: An AllocationBlock object
        """
        key = _block_datastore_key(block_cidr)
        try:
            result = self.etcd_client.read(key)
        except EtcdKeyNotFound:
            raise KeyError(str(block_cidr))
        block = AllocationBlock.from_etcd_result(result)
        return block

    def _compare_and_swap_block(self, block):
        """
        Write the block using an atomic Compare-and-swap.
        """

        # If the block has a db_result, CAS against that.
        if block.db_result is not None:
            _log.debug("CAS Update block %s", block)
            try:
                self.etcd_client.update(block.update_result())
            except EtcdCompareFailed:
                raise CASError(str(block.cidr))
        else:
            _log.debug("CAS Write new block %s", block)
            key = _block_datastore_key(block.cidr)
            value = block.to_json()
            try:
                self.etcd_client.write(key, value, prevExist=False)
            except EtcdAlreadyExist:
                raise CASError(str(block.cidr))

    def _get_affine_blocks(self, host, version, pool):
        """
        Get the blocks for which this host has affinity.

        :param host: The host name to get affinity for.
        :param version: 4 for IPv4, 6 for IPv6.
        :param pool: Limit blocks to a specific pool, or pass None to find all
        blocks for the specified version.
        """
        # Construct the path
        path = IPAM_HOST_AFFINITY_PATH % {"hostname": host,
                                          "version": version}
        block_ids = []
        try:
            result = self.etcd_client.read(path).children
            for child in result:
                packed = child.key.split("/")
                if len(packed) == 9:
                    # block_ids are encoded 192.168.1.0/24 -> 192.168.1.0-24
                    # in etcd.
                    block_ids.append(IPNetwork(packed[8].replace("-", "/")))
        except EtcdKeyNotFound:
            # Means the path is empty.
            pass

        # If pool specified, filter to only include ones in the pool.
        if pool is not None:
            assert isinstance(pool, IPPool)
            block_ids = [cidr for cidr in block_ids if cidr in pool]

        return block_ids

    def _new_affine_block(self, host, version, pool):
        """
        Create and register a new affine block for the host.

        :param host: The host name to get a block for.
        :param version: 4 for IPv4, 6 for IPv6.
        :param pool: Limit blocks to a specific pool, or pass None to find all
        blocks for the specified version.
        :return: The block CIDR of the new block.
        """
        # Get the pools and verify we got a valid one, or none.
        ip_pools = self.get_ip_pools(version)
        if pool is not None:
            if pool not in ip_pools:
                raise ValueError("Requested pool %s is not configured or has"
                                 "wrong attributes" % pool)
            # Confine search to only the one pool.
            ip_pools = [pool]

        for pool in ip_pools:
            for block_cidr in pool.cidr.subnet(BLOCK_PREFIXLEN[version]):
                block_id = str(block_cidr)
                _log.debug("Checking if block %s is free.", block_id)
                key = _block_datastore_key(block_cidr)
                try:
                    _ = self.etcd_client.read(key)
                except EtcdKeyNotFound:
                    _log.debug("Found block %s free.", block_id)
                    try:
                        self._claim_block_affinity(host, block_cidr)
                    except HostAffinityClaimedError:
                        # Failed to claim the block because some other host
                        # has it.
                        _log.debug("Failed to claim block %s", block_cidr)
                        continue
                    # Success!
                    return block_cidr
        raise NoFreeBlocksError()

    def _claim_block_affinity(self, host, block_cidr):
        """
        Claim a block we think is free.
        """
        block_id = str(block_cidr)
        path = IPAM_HOST_AFFINITY_PATH % {"hostname": host,
                                          "version": block_cidr.version}
        key = path + block_id.replace("/", "-")
        self.etcd_client.write(key, "")

        # Create the block.
        block = AllocationBlock(block_cidr, host)
        try:
            self._compare_and_swap_block(block)
        except CASError:
            # Block exists.  Read it back to find out its host affinity
            block = self._read_block(block_cidr)
            if block.host_affinity == host:
                # Block is now claimed by us.  Some other process on this host
                # must have claimed it.
                _log.debug("Block %s already claimed by us. Success.",
                           block_cidr)
                return

            # Some other host beat us to claiming this block.  Clean up.
            self.etcd_client.delete(key)

            # Throw a key error to let the caller know the block wasn't free
            # after all.

            raise HostAffinityClaimedError("Block %s already claimed by %s",
                                           block_id, block.host_affinity)
        # successfully created the block.  Done.
        return

    def _random_blocks(self, excluded_ids, version, pool):
        """
        Get an list of block CIDRs, in random order.

        :param excluded_ids: List of IDs that should be excluded.
        :param version: The IP version 4, or 6.
        :param pool: IPPool to get blocks from, or None to use all pools
        :return: An iterator of block CIDRs.
        """

        # Get the pools and verify we got a valid one, or none.
        ip_pools = self.get_ip_pools(version)
        if pool is not None:
            if pool not in ip_pools:
                raise ValueError("Requested pool %s is not configured or has"
                                 "wrong attributes" % pool)
            # Confine search to only the one pool.
            ip_pools = [pool]

        random_blocks = []
        i = 0
        for pool in ip_pools:
            for block_cidr in pool.cidr.subnet(BLOCK_PREFIXLEN[version]):
                if block_cidr not in excluded_ids:
                    # add this block.  We use an "inside-out" Fisher-Yates
                    # shuffle to randomize the list as we create it.  See
                    # http://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
                    j = random.randint(0, i)
                    if j != i:
                        random_blocks.append(random_blocks[j])
                        random_blocks[j] = block_cidr
                    else:
                        random_blocks.append(block_cidr)
                    i += 1
        return random_blocks

    def _increment_handle(self, handle_id, block_cidr, amount):
        """
        Increment the allocation count on the given handle for the given block
        by the given amount.
        """
        for _ in xrange(RETRIES):
            try:
                handle = self._read_handle(handle_id)
            except KeyError:
                # handle doesn't exist.  Create it.
                handle = AllocationHandle(handle_id)

            _ = handle.increment_block(block_cidr, amount)

            try:
                self._compare_and_swap_handle(handle)
            except CASError:
                # CAS failed.  Retry.
                continue
            else:
                # success!
                return
        raise RuntimeError("Max retries hit.")  # pragma: no cover

    def _decrement_handle(self, handle_id, block_cidr, amount):
        """
        Decrement the allocation count on the given handle for the given block
        by the given amount.
        """
        for _ in xrange(RETRIES):
            try:
                handle = self._read_handle(handle_id)
            except KeyError:
                # This is bad.  The handle doesn't exist, which means something
                # really wrong has happened, like DB corruption.
                _log.error("Can't decrement block %s on handle %s; it doesn't "
                           "exist.", str(block_cidr), handle_id)
                raise

            try:
                handle.decrement_block(block_cidr, amount)
            except AddressCountTooLow:
                # This is also bad.  The handle says it has fewer than the
                # requested amount of addresses allocated on the block.  This
                # means the DB is corrupted.
                _log.error("Can't decrement block %s on handle %s; too few "
                           "allocated.", str(block_cidr), handle_id)
                raise

            try:
                self._compare_and_swap_handle(handle)
            except CASError:
                continue
            else:
                # Success!
                return
        raise RuntimeError("Max retries hit.")  # pragma: no cover

    def _read_handle(self, handle_id):
        """
        Read the handle with the given handle ID from the data store.
        :param handle_id: The handle ID to read.
        :return: AllocationHandle object.
        """
        key = _handle_datastore_key(handle_id)
        try:
            result = self.etcd_client.read(key)
        except EtcdKeyNotFound:
            raise KeyError(handle_id)
        handle = AllocationHandle.from_etcd_result(result)
        return handle

    def _compare_and_swap_handle(self, handle):
        """
        Write the handle using an atomic Compare-and-swap.
        """
        # If the handle has a db_result, CAS against that.
        if handle.db_result is not None:
            _log.debug("Handle %s exists.", handle.handle_id)
            if handle.is_empty():
                # Handle is now empty.  Delete it instead of an update.
                _log.debug("Handle %s is empty.", handle.handle_id)
                key = _handle_datastore_key(handle.handle_id)
                try:
                    self.etcd_client.delete(
                        key,
                        prevIndex=handle.db_result.modifiedIndex)
                except EtcdAlreadyExist:
                    raise CASError(handle.handle_id)
            else:
                _log.debug("Handle %s is not empty.", handle.handle_id)
                try:
                    self.etcd_client.update(handle.update_result())
                except EtcdCompareFailed:
                    raise CASError(handle.handle_id)
        else:
            _log.debug("CAS Write new handle %s", handle.handle_id)
            assert not handle.is_empty(), "Don't write empty handle."
            key = _handle_datastore_key(handle.handle_id)
            value = handle.to_json()
            try:
                self.etcd_client.write(key, value, prevExist=False)
            except EtcdAlreadyExist:
                raise CASError(handle.handle_id)


class CASError(DataStoreError):
    """
    Compare-and-swap atomic update failed.
    """
    pass


class NoFreeBlocksError(DataStoreError):
    """
    Tried to get a new block but there are none available.
    """
    pass


class HostAffinityClaimedError(DataStoreError):
    """
    Tried to set the host affinity of a block which already has a host that
    claims affinity.
    """
    pass


def _block_datastore_key(block_cidr):
    """
    Translate a block_id into a datastore key.
    :param block_cidr: IPNetwork representing the block
    :return: etcd key as string.
    """
    path = IPAM_BLOCK_PATH % {'version': block_cidr.version}
    return path + str(block_cidr).replace("/", "-")


def _handle_datastore_key(handle_id):
    """
    Translate a handle_id into a datastore key.
    :param handle_id: String key
    :return: etcd key as string.
    """
    return IPAM_HANDLE_PATH + handle_id


class IPAMClient(BlockHandleReaderWriter):

    def auto_assign_ips(self, num_v4, num_v6, handle_id, attributes,
                        hostname, pool=(None, None)):
        """
        Automatically pick and assign the given number of IPv4 and IPv6
        addresses.

        :param num_v4: Number of IPv4 addresses to request
        :param num_v6: Number of IPv6 addresses to request
        :param handle_id: allocation handle ID for this request.  You can query
        this key using get_assignments_by_handle() or release all addresses
        with this key using release_by_handle().
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :param hostname: The hostname to use for affinity in
        assigning IP addresses.
        :param pool: (optional) tuple of (v4 pool, v6 pool); if supplied, the
        pool(s) to assign from,  If None, automatically choose a pool.
        :return: A tuple of (v4_address_list, v6_address_list).  When IPs in
        configured pools are at or near exhaustion, this method may return
        fewer than requested addresses.
        """
        assert isinstance(handle_id, str) or handle_id is None

        _log.info("Auto-assign %d IPv4, %d IPv6 addrs",
                  num_v4, num_v6)
        v4_address_list = self._auto_assign(4, num_v4, handle_id,
                                            attributes, pool[0], hostname)
        _log.info("Auto-assigned IPv4s %s",
                  [str(addr) for addr in v4_address_list])
        v6_address_list = self._auto_assign(6, num_v6, handle_id,
                                            attributes, pool[1], hostname)
        _log.info("Auto-assigned IPv6s %s",
                  [str(addr) for addr in v6_address_list])
        return v4_address_list, v6_address_list

    def _auto_assign(self, ip_version, num, handle_id,
                     attributes, pool, hostname):
        """
        Auto assign addresses from a specific IP version.

        Hosts automatically register themselves as the owner of a block the
        first time they request an auto-assigned IP.  For auto-assignment, a
        host will allocate from a block it owns, or if all their currently
        owned blocks get full, it will register itself as the owner of a new
        block.  If all blocks are owned, and all the host's own blocks are
        full, it will pick blocks at random until it can fulfil the request.
        If you're really, really out of addresses, it will fail the request.

        :param ip_version: 4 or 6, the IP version number.
        :param num: Number of addresses to assign.
        :param handle_id: allocation handle ID for this request.
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :param pool: (optional) if supplied, the pool to assign from,  If None,
        automatically choose a pool.
        :param hostname: The hostname to use for affinity in assigning IP
        addresses.
        :return:
        """
        assert isinstance(handle_id, str) or handle_id is None

        block_list = self._get_affine_blocks(hostname,
                                             ip_version,
                                             pool)
        block_ids = iter(block_list)
        allocated_ips = []

        num_remaining = num
        while num_remaining > 0:
            try:
                block_id = block_ids.next()
            except StopIteration:
                _log.info("Ran out of affine blocks for %s in pool %s",
                          hostname, pool)
                break
            ips = self._auto_assign_block(block_id,
                                          num_remaining,
                                          handle_id,
                                          attributes,
                                          hostname)
            allocated_ips.extend(ips)
            num_remaining = num - len(allocated_ips)

        # If there are still addresses to allocate, then we've run out of
        # blocks with affinity.  Try to fullfil address request by allocating
        # new blocks.
        retries = RETRIES
        while num_remaining > 0 and retries > 0:
            retries -= 1
            try:
                new_block = self._new_affine_block(hostname,
                                                   ip_version,
                                                   pool)
                # If successful, this creates the block and registers it to us.
            except NoFreeBlocksError:
                _log.info("Could not get new host affinity block for %s in "
                          "pool %s", hostname, pool)
                break
            ips = self._auto_assign_block(new_block,
                                          num_remaining,
                                          handle_id,
                                          attributes,
                                          hostname)
            allocated_ips.extend(ips)
            num_remaining = num - len(allocated_ips)
        if retries == 0:  # pragma: no cover
            raise RuntimeError("Hit Max Retries.")

        # If there are still addresses to allocate, we've now tried all blocks
        # with some affinity to us, and tried (and failed) to allocate new
        # ones.  Our last option is a random hunt through any blocks we haven't
        # yet tried.
        if num_remaining > 0:
            random_blocks = iter(self._random_blocks(block_list,
                                                     ip_version,
                                                     pool))
        while num_remaining > 0:
            try:
                block_id = random_blocks.next()
            except StopIteration:
                _log.warning("All addresses exhausted in pool %s", pool)
                break
            ips = self._auto_assign_block(block_id,
                                          num_remaining,
                                          handle_id,
                                          attributes,
                                          hostname,
                                          affinity_check=False)
            allocated_ips.extend(ips)
            num_remaining = num - len(allocated_ips)

        return allocated_ips

    def _auto_assign_block(self, block_cidr, num, handle_id, attributes,
                           hostname, affinity_check=True):
        """
        Automatically pick IPs from a block and commit them to the data store.

        :param block_cidr: The identifier for the block to read.
        :param num: The number of IPs to assign.
        :param handle_id: allocation handle ID for this request.
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :param hostname: The hostname to use for affinity in
        assigning IP addresses.
        :param affinity_check: True to enable checking the host has the
        affinity to the block, False to disable this check, for example, while
        randomly searching after failure to get affine block.
        :return: List of assigned IPs.
        """
        assert isinstance(handle_id, str) or handle_id is None
        _log.debug("Auto-assigning from block %s", block_cidr)
        for i in xrange(RETRIES):
            _log.debug("Auto-assign from %s, retry %d", block_cidr, i)
            block = self._read_block(block_cidr)
            unconfirmed_ips = block.auto_assign(num=num,
                                                handle_id=handle_id,
                                                attributes=attributes,
                                                hostname=hostname,
                                                affinity_check=affinity_check)
            if len(unconfirmed_ips) == 0:
                _log.debug("Block %s is full.", block_cidr)
                return []

            # If using a handle, increment the handle by the number of
            # confirmed IPs.
            if handle_id is not None:
                self._increment_handle(handle_id,
                                       block_cidr,
                                       len(unconfirmed_ips))

            try:
                self._compare_and_swap_block(block)
            except CASError:
                _log.debug("CAS failed on block %s", block_cidr)
                if handle_id is not None:
                    self._decrement_handle(handle_id,
                                           block_cidr,
                                           len(unconfirmed_ips))
            else:
                return unconfirmed_ips
        raise RuntimeError("Hit Max Retries.")

    def assign_ip(self, address, handle_id, attributes, hostname):
        """
        Assign the given address.  Throws AlreadyAssignedError if the address
        is taken.

        :param address: IPAddress to assign.
        :param handle_id: allocation handle ID for this request.  You can
        query this key using get_assignments_by_handle() or release all
        addresses with this handle_id using release_by_handle().
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :param hostname: the hostname to use for affinity if the
        block containing the IP address has no host affinity.
        :return: None.
        """
        assert isinstance(handle_id, str) or handle_id is None
        assert isinstance(address, IPAddress)
        block_cidr = get_block_cidr_for_address(address)

        for _ in xrange(RETRIES):
            try:
                block = self._read_block(block_cidr)
            except KeyError:
                _log.debug("Block %s doesn't exist.", block_cidr)
                pools = self.get_ip_pools(address.version)
                if any([address in pool for pool in pools]):
                    _log.debug("Create and claim block %s.",
                               block_cidr)
                    try:
                        self._claim_block_affinity(hostname,
                                                   block_cidr)
                    except HostAffinityClaimedError:
                        _log.debug("Someone else claimed block %s before us.",
                                   block_cidr)
                        continue
                    # Block exists now, retry writing to it.
                    _log.debug("Claimed block %s", block_cidr)
                    continue
                else:
                    raise ValueError("%s is not in any configured pool" %
                                     address)

            # Try to assign.  Throws exception if already assigned -- let it.
            block.assign(address, handle_id, attributes)

            # If using a handle, increment by one IP
            if handle_id is not None:
                self._increment_handle(handle_id, block_cidr, 1)

            # Try to commit.
            try:
                self._compare_and_swap_block(block)
                return  # Success!
            except CASError:
                _log.debug("CAS failed on block %s", block_cidr)
                if handle_id is not None:
                    self._decrement_handle(handle_id,
                                           block_cidr,
                                           1)
        raise RuntimeError("Hit max retries.")

    def release_ips(self, addresses):
        """
        Release the given addresses.

        :param addresses: Set of IPAddresses to release (ok to mix IPv4 and
        IPv6).
        :return: Set of addresses that were already unallocated.
        """
        assert isinstance(addresses, (set, frozenset))
        _log.info("Releasing addresses %s", [str(addr) for addr in addresses])
        unallocated = set()
        # sort the addresses into blocks
        addrs_by_block = {}
        for address in addresses:
            block_cidr = get_block_cidr_for_address(address)
            addrs = addrs_by_block.setdefault(block_cidr, set())
            addrs.add(address)

        # loop through blocks, CAS releasing.
        for block_cidr, addresses in addrs_by_block.iteritems():
            unalloc_block = self._release_block(block_cidr, addresses)
            unallocated = unallocated.union(unalloc_block)
        return unallocated

    def _release_block(self, block_cidr, addresses):
        """
        Release the given addresses from the block, using compare-and-swap to
        write the block.
        :param block_cidr: IPNetwork identifying the block
        :param addresses: List of addresses to release.
        :return: List of addresses that were already unallocated.
        """
        _log.debug("Releasing %d adddresses from block %s",
                   len(addresses), block_cidr)

        for _ in xrange(RETRIES):
            try:
                block = self._read_block(block_cidr)
            except KeyError:
                _log.debug("Block %s doesn't exist.", block_cidr)
                # OK to return, all addresses must be released already.
                return addresses
            (unallocated, handles) = block.release(addresses)
            assert len(unallocated) <= len(addresses)
            if len(unallocated) == len(addresses):
                # All the addresses are already unallocated.
                return addresses
            # Try to commit
            try:
                self._compare_and_swap_block(block)
            except CASError:
                continue
            else:
                # Success!  Decrement handles.
                for handle_id, amount in handles.iteritems():
                    if handle_id is not None:
                        # Skip the None handle, it's a special value meaning
                        # the addresses were not allocated with a handle.
                        self._decrement_handle(handle_id, block_cidr, amount)

                return unallocated

        raise RuntimeError("Hit Max retries.")  # pragma: no cover

    def get_ip_assignments_by_handle(self, handle_id):
        """
        Return a list of IPAddresses assigned to the key.
        :param handle_id: Key to query e.g. used on assign_ip() or
        auto_assign_ips().
        :return: List of IPAddresses
        """
        assert isinstance(handle_id, str)
        handle = self._read_handle(handle_id)  # Can throw KeyError, let it.

        ip_assignments = []
        for block_str in handle.block:
            block_cidr = IPNetwork(block_str)
            try:
                block = self._read_block(block_cidr)
            except KeyError:
                _log.warning("Couldn't read block %s referenced in handle %s.",
                             block_str, handle_id)
                continue
            ips = block.get_ip_assignments_by_handle(handle_id)
            ip_assignments.extend(ips)
        return ip_assignments

    def release_ip_by_handle(self, handle_id):
        """
        Release all addresses assigned to the key.

        :param handle_id: Key to query, e.g. used on assign_ip() or
        auto_assign_ips().
        :return: None.
        """
        assert isinstance(handle_id, str)
        handle = self._read_handle(handle_id)  # Can throw KeyError, let it.

        # Loop through blocks, releasing.
        for block_str in handle.block:
            block_cidr = IPNetwork(block_str)
            self._release_ip_by_handle_block(handle_id, block_cidr)

    def _release_ip_by_handle_block(self, handle_id, block_cidr):
        """
        Release all address in a block with the given handle ID.
        :param handle_id: The handle ID to find addresses with.
        :param block_cidr: The block to release addresses on.
        :return: None
        """
        for _ in xrange(RETRIES):
            try:
                block = self._read_block(block_cidr)
            except KeyError:
                # Block doesn't exist, so all addresses are already
                # unallocated.  This can happen if the handle is overestimating
                # the number of assigned addresses, which is a transient, but
                # expected condition.
                return

            num_release = block.release_by_handle(handle_id)
            if num_release == 0:
                # Block didn't have any addresses with this handle, so all
                # so all addresses are already unallocated.  This can happen if
                # the handle is overestimating the number of assigned
                # addresses, which is a transient, but expected condition.
                return

            try:
                self._compare_and_swap_block(block)
            except CASError:
                # Failed to update, retry.
                continue

            # Successfully updated block, update the handle if necessary.
            if handle_id is not None:
                # Skip the None handle, it's a special value meaning
                # the addresses were not allocated with a handle.
                self._decrement_handle(handle_id, block_cidr, num_release)
                return
        raise RuntimeError("Hit Max retries.")  # pragma: no cover

    def get_assignment_attributes(self, address):
        """
        Return the attributes of a given address.

        :param address: IPAddress to query.
        :return: The attributes for the address as passed to auto_assign() or
        assign().
        """
        assert isinstance(address, IPAddress)
        block_cidr = get_block_cidr_for_address(address)

        try:
            block = self._read_block(block_cidr)
        except KeyError:
            _log.warning("Couldn't read block %s for requested address %s",
                         block_cidr, address)
            raise AddressNotAssignedError("%s is not assigned." % address)
        else:
            _, attributes = block.get_attributes_for_ip(address)
            return attributes

    def assign_address(self, pool, address, hostname):
        """
        Deprecated in favor of assign_ip().

        Attempt to assign an IPAddress in a pool.
        Fails if the address is already assigned.
        The directory for storing assignments in this pool must already exist.
        :param IPPool or IPNetwork pool: The pool that the assignment is from.
        If pool is None, get the pool from datastore
        :param IPAddress address: The address to assign.
        :param hostname: The hostname to use for affinity in
        assigning IP addresses.
        :return: True if the allocation succeeds, false otherwise. An
        exception is thrown for any error conditions.
        :rtype: bool
        """
        pool = pool or self.get_pool(address)
        if pool is None:
            raise PoolNotFound("IP address %s does not belong to any "
                                 "configured pools" % address)

        if isinstance(pool, IPPool):
            pool = pool.cidr
        assert isinstance(pool, IPNetwork)
        assert isinstance(address, IPAddress)

        try:
            self.assign_ip(address, None, {}, hostname)
            return True
        except AlreadyAssignedError:
            return False
        # Other exceptions indicate error conditions.

    def unassign_address(self, pool, address):
        """
        Deprecated in favor of release_ips()

        Unassign an IP from a pool.
        :param IPPool or IPNetwork pool: The pool that the assignment is from.
        If the pool is None, get the pool from datastore
        :param IPAddress address: The address to unassign.
        :return: True if the address was unassigned, false otherwise. An
        exception is thrown for any error conditions.
        :rtype: bool
        """
        pool = pool or self.get_pool(address)
        if pool is None:
            raise PoolNotFound("IP address %s does not belong to any "
                                 "configured pools" % address)

        if isinstance(pool, IPPool):
            pool = pool.cidr
        assert isinstance(pool, IPNetwork)
        assert isinstance(address, IPAddress)

        err = self.release_ips({address})
        if err:
            return False
        else:
            return True
