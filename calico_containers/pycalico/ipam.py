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
from collections import deque

from etcd import EtcdKeyNotFound, EtcdAlreadyExist, EtcdCompareFailed

from netaddr import IPAddress, IPNetwork
import logging
import random

from pycalico.datastore_datatypes import IPPool, IPAMConfig
from pycalico.datastore import DatastoreClient, handle_errors
from pycalico.datastore import (IPAM_HOSTS_PATH,
                                IPAM_HOST_PATH,
                                IPAM_HOST_AFFINITY_PATH,
                                IPAM_BLOCK_PATH,
                                IPAM_HANDLE_PATH,
                                IPAM_CONFIG_PATH)
from pycalico.datastore_errors import (DataStoreError,
                                       PoolNotFound,
                                       InvalidBlockSizeError)
from pycalico.block import (AllocationBlock,
                            get_block_cidr_for_address,
                            validate_block_size,
                            BLOCK_PREFIXLEN,
                            AddressNotAssignedError,
                            NoHostAffinityError)
from pycalico.handle import (AllocationHandle,
                             AddressCountTooLow)
from pycalico.util import get_hostname

_log = logging.getLogger(__name__)
_log.addHandler(logging.NullHandler())

RETRIES = 100

KEY_ERROR_RETRIES = 3


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
            # Use quorum=True to ensure we don't get stale reads.  Without this
            # we allow many subtle race conditions, such as creating a block,
            # then later reading it and finding it doesn't exist.
            result = self.etcd_client.read(key, quorum=True)
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

    def _delete_block(self, block):
        """
        Delete a block using an atomic delete operation.

        Raises CASError if the block has been modified.
        """
        try:
            self.etcd_client.delete(
                block.db_result.key,
                prevIndex=block.db_result.modifiedIndex)
        except EtcdCompareFailed:
            raise CASError(str(block.cidr))

    def _get_affine_blocks(self, host, version, pool):
        """
        Get the blocks for which this host has affinity.

        :param host: The host ID to get affinity for.
        :param version: 4 for IPv4, 6 for IPv6.
        :param pool: Limit blocks to a specific pool, or pass None to find all
        blocks for the specified version.
        """
        # Construct the path
        path = IPAM_HOST_AFFINITY_PATH % {"host": host,
                                          "version": version}
        block_ids = []
        try:
            result = self.etcd_client.read(path, quorum=True).children
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

    def _get_host_block_pairs(self, pool):
        """
        Get the affine blocks and corresponding host for all affine blocks
        within the specified pool.

        :param pool: Limit blocks to a specific pool,
        :return: List of tuples (host, cidr)
        """
        assert isinstance(pool, IPPool)

        # Construct the path
        hosts_and_blocks = []
        try:
            result = self.etcd_client.read(IPAM_HOSTS_PATH,
                                           quorum=True,
                                           recursive=True).leaves
            for child in result:
                packed = child.key.split("/")
                if len(packed) == 9:
                    # block_ids are encoded 192.168.1.0/24 -> 192.168.1.0-24
                    # in etcd.
                    host = packed[5]
                    block_id = IPNetwork(packed[8].replace("-", "/"))
                    if block_id in pool:
                        hosts_and_blocks.append((host, block_id))
        except EtcdKeyNotFound:
            # Means the path is empty.
            pass

        return hosts_and_blocks

    def _new_affine_block(self, host, version, pool, ipam_config):
        """
        Create and register a new affine block for the host.

        :param host: The host ID to get a block for.
        :param version: 4 for IPv4, 6 for IPv6.
        :param pool: Limit blocks to a specific pool, or pass None to find all
        blocks for the specified version.
        :param ipam_config: The global IPAM configuration.
        :return: The block CIDR of the new block.
        """
        # Walk the affine blocks in a somewhat random way but seed the RNG
        # from our hostname so that multiple concurrent invocations on the
        # same host will try to claim the same blocks.
        for block_cidr in self._random_blocks(version=version,
                                              pool=pool,
                                              seed=host):
            block_id = str(block_cidr)
            _log.debug("Checking if block %s is free.", block_id)
            key = _block_datastore_key(block_cidr)
            try:
                _ = self.etcd_client.read(key, quorum=True)
            except EtcdKeyNotFound:
                _log.debug("Found block %s free.", block_id)
                try:
                    self._claim_block_affinity(host, block_cidr,
                                               ipam_config)
                except HostAffinityClaimedError:
                    # Failed to claim the block because some other host
                    # has it.
                    _log.debug("Failed to claim block %s", block_cidr)
                    continue
                # Success!
                return block_cidr
        raise NoFreeBlocksError()

    def _claim_block_affinity(self, host, block_cidr, ipam_config):
        """
        Claim a block we think is free.
        :param host: The host ID to get a block for.
        :param block_cidr: The block CIDR.
        :param ipam_config: The global IPAM configuration.
        """
        key = _block_host_key(host, block_cidr)
        self.etcd_client.write(key, "")

        # Create the block.
        block = AllocationBlock(block_cidr, host,
                                ipam_config.strict_affinity)
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
            try:
                self.etcd_client.delete(key)
            except EtcdKeyNotFound:
                # A race exists where another process on the same host could
                # have already deleted the key. This is fine as long as the key
                # no longer exists.
                pass

            # Throw a HostAffinityClaimedError to let the caller know the block
            # wasn't free after all.
            raise HostAffinityClaimedError("Block %s already claimed by %s",
                                           block_cidr, block.host_affinity)

        # successfully created the block.  Done.
        return

    def _release_block_affinity(self, host, block_cidr):
        """
        Release a block we think is owned by the specified host.

        If there are no IPs assigned in the block then delete the block.  If
        there are IPs assigned, remove affinity of the block from the host.

        Raises HostAffinityClaimedError if the block is claimed by a
        different host.
        Raises KeyError if the block does not exist.
        """
        for _ in xrange(RETRIES):
            block = self._read_block(block_cidr)
            if block.host_affinity != host:
                _log.info("Block host affinity is %s (expected %s) - not "
                          "releasing", block.host_affinity, host)
                raise HostAffinityClaimedError(
                          "Block %s is claimed by %s",
                          block_cidr, block.host_affinity)

            try:
                if block.is_empty():
                    # The block is empty, so just delete the block.
                    _log.debug("Block is empty - delete block")
                    self._delete_block(block)
                else:
                    # The block is not empty so remove affinity from the block.
                    # This prevents the host automatically assigning from this
                    # block unless we are allowed to overflow into non-affine
                    # blocks when affine blocks are exhausted, and provided the
                    # block is still valid (i.e has a corresponding IP Pool).
                    block.host_affinity = None
                    self._compare_and_swap_block(block)
            except CASError:
                # CAS failed.  Retry.
                continue

            # We removed or updated the block successfully, so update the host
            # configuration to remove the CIDR.
            _log.debug("Removed affinity for block - deleting host key.")
            key = _block_host_key(host, block_cidr)
            try:
                self.etcd_client.delete(key)
            except EtcdKeyNotFound:
                pass
            return

        raise RuntimeError("Max retries hit.")  # pragma: no cover

    def _random_blocks(self, version, pool=None, excluded_ids=None, seed=None):
        """
        Generate block CIDRs, in pseudo-random order.

        :param version: The IP version 4, or 6.
        :param pool: IPPool to get blocks from, or None to use all pools
        :param excluded_ids: Set of IDs that should be excluded or None.
        :param seed: Seed for the RNG, or None to have the RNG self-seed.
        :raises PoolNotFound if pool is set to a non-existent pool.
        :return: An iterator of block CIDRs.
        """
        excluded_ids = excluded_ids or set()
        # Get the pools and verify we got a valid one, or none.
        ip_pools = self.get_ip_pools(version, ipam=True, include_disabled=False)
        if pool is not None:
            if pool not in ip_pools:
                raise PoolNotFound("Requested pool %s is not configured or has"
                                   "wrong attributes" % pool)
            # Confine search to only the one pool.
            ip_pools = [pool]
        cidrs = [p.cidr for p in ip_pools]
        for block_cidr in _random_subnets_from_cidrs(cidrs,
                                                     BLOCK_PREFIXLEN[version],
                                                     seed=seed):
            if block_cidr not in excluded_ids:
                yield block_cidr

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
            result = self.etcd_client.read(key, quorum=True)
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
                except EtcdCompareFailed:
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

    def _read_blocks(self):
        """
        Read all the allocated blocks.
        :return: Tuple of
                 (List of IPv4 AllocationBlocks,
                  List of IPv6 AllocationBlocks)
        """
        blocks = {}
        for version in (4, 6):
            blocks_path = IPAM_BLOCK_PATH % {"version": version}
            try:
                leaves = self.etcd_client.read(blocks_path,
                                               quorum=True,
                                               recursive=True).leaves
            except EtcdKeyNotFound:
                # Path doesn't exist.
                blocks[version] = []
            else:
                # Convert the leaf values to AllocationBlocks.  We need to
                # handle an empty leaf value because when no pools are
                # configured the recursive read returns the parent directory.
                blocks[version] = [AllocationBlock.from_etcd_result(leaf) for leaf in leaves
                                                                          if leaf.value]
        return blocks[4], blocks[6]

    @handle_errors
    def get_ipam_config(self):
        """
        Return the deployment specific IPAM configuration.

        :param host: The host ID of the config to return.
        :return: An IPAMConfig object.
        """
        try:
            result = self.etcd_client.read(IPAM_CONFIG_PATH)
        except EtcdKeyNotFound:
            _log.debug("No IPAM Config stored - return default")
            return IPAMConfig()
        else:
            return IPAMConfig.from_json(result.value)

    @handle_errors
    def set_ipam_config(self, config):
        """
        Set the deployment-specific IPAM configuration.

        The IPAM configuration may not be changed whilst there are allocation
        blocks configured.  An IPAMConf

        :param config: An IPAMConfig object.
        """
        assert isinstance(config, IPAMConfig)
        current = self.get_ipam_config()
        if current == config:
            _log.debug("Configuration has not changed")
            return

        if not config.strict_affinity and not config.auto_allocate_blocks:
            raise IPAMConfigConflictError("Cannot disable 'strict_affinity' "
                "and 'auto_allocate_blocks' at the same time.")

        # For simplicity, we do not allow the IPAM configuration to be changed
        # once there are IPAM blocks configured.  This is to prevent mismatches
        # in the assignments (e.g. a block is marked as non-strict but the
        # global setting is changed to strict - in this case we should update
        # existing blocks to strict, but without additional information about
        # who owns which IP, it is not possible).
        blocksv4, blocksv6 = self._read_blocks()
        if blocksv4 or blocksv6:
            _log.warning("Cannot change IPAM config while allocations exist")
            raise IPAMConfigConflictError("Unable to change global IPAM "
                "configuration due to existing IP allocations.")

        self.etcd_client.write(IPAM_CONFIG_PATH, config.to_json())


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
    Tried to set or remove the host affinity of a block which has affinity
    claimed by a different host.
    """
    pass


class IPAMConfigConflictError(DataStoreError):
    """
    Attempt to change IPAM configuration that conflict with existing
    allocations.
    """
    pass


def _block_datastore_key(block_cidr):
    """
    Translate a block CIDR into a datastore key.
    :param block_cidr: IPNetwork representing the block
    :return: etcd key as a string.
    """
    path = IPAM_BLOCK_PATH % {'version': block_cidr.version}
    return path + str(block_cidr).replace("/", "-")


def _block_host_key(host, block_cidr):
    """
    Translate a block CIDR into the host specific block key.  Presence of the
    key in the datastore indicates that a host has affinity to a specific
    block.  No additional data is stored at this key, the true source is the
    block itself.
    :param block_cidr: IPNetwork representing the block
    :return: etcd key as a string.
    """
    block_id = str(block_cidr)
    path = IPAM_HOST_AFFINITY_PATH % {"host": host,
                                      "version": block_cidr.version}
    return path + block_id.replace("/", "-")


def _handle_datastore_key(handle_id):
    """
    Translate a handle_id into a datastore key.
    :param handle_id: String key
    :return: etcd key as string.
    """
    return IPAM_HANDLE_PATH + handle_id


class IPAMClient(BlockHandleReaderWriter):

    @handle_errors
    def auto_assign_ips(self, num_v4, num_v6, handle_id, attributes,
                        pool=(None, None), host=None):
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
        :param pool: (optional) Tuple of (v4 pool, v6 pool); if supplied, the
        pool(s) to assign from,  If None, automatically choose a pool.
        :param host: (optional) The host ID to use for affinity in assigning IP
        addresses.  Defaults to the hostname returned by get_hostname().
        :return: A tuple of (v4_address_list, v6_address_list).  When IPs in
        configured pools are at or near exhaustion, this method may return
        fewer than requested addresses.
        """
        assert isinstance(handle_id, str) or handle_id is None

        host = host or get_hostname()

        _log.info("Auto-assign %d IPv4, %d IPv6 addrs",
                  num_v4, num_v6)
        v4_address_list = self._auto_assign(4, num_v4, handle_id, attributes,
                                            pool[0], host)
        _log.info("Auto-assigned IPv4s %s",
                  [str(addr) for addr in v4_address_list])
        v6_address_list = self._auto_assign(6, num_v6, handle_id, attributes,
                                            pool[1], host)
        _log.info("Auto-assigned IPv6s %s",
                  [str(addr) for addr in v6_address_list])
        return v4_address_list, v6_address_list

    def _auto_assign(self, ip_version, num, handle_id,
                     attributes, pool, host):
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
        :param host: The host ID to use for affinity in assigning IP addresses.
        :return:
        """
        assert isinstance(handle_id, str) or handle_id is None
        # Start by trying to assign from one of the host-affine blocks.  We
        # always do strict checking at this stage, so it doesn't matter whether
        # globally we have strict_affinity or not.
        _log.info("Looking for %s IPs in already-allocated affine blocks.",
                  num)
        host_blocks = self._get_affine_blocks(host, ip_version, pool)
        num_remaining = num
        allocated_ips = self._allocate_ips_explicit_blocks(
            host_blocks,
            num_remaining,
            attributes,
            handle_id,
            host
        )
        num_remaining = num - len(allocated_ips)
        if len(allocated_ips) < num:
            # Still addresses to allocate, we've run out of blocks with
            # affinity.  Before we can assign new blocks or assign in
            # non-affine blocks, we need to check that our IPAM configuration
            # allows that.
            ipam_config = self.get_ipam_config()

            # If we can auto allocate blocks, try to fulfill address request by
            # allocating new blocks.
            if ipam_config.auto_allocate_blocks:
                _log.info("Attempt to allocate %s IPs from new affine blocks",
                          num_remaining)
                ips_from_new_blocks = self._allocate_ips_from_new_blocks(
                    num_remaining,
                    attributes,
                    handle_id,
                    host,
                    ip_version,
                    pool,
                    ipam_config
                )
                allocated_ips.extend(ips_from_new_blocks)
                num_remaining = num - len(allocated_ips)

            if num_remaining > 0:
                # We've run out of IPs in our blocks and failed to allocate new
                # blocks.  If we're allowed, try to grab IPs from random
                # blocks.
                if not ipam_config.strict_affinity:
                    _log.info("Still need to allocate %s IPs; strict affinity"
                              "disabled, trying random blocks.", num_remaining)
                    ips_from_random_blocks = self._allocate_ips_no_affinity(
                        num_remaining,
                        attributes,
                        handle_id,
                        host,
                        ip_version,
                        pool,
                        excluded_blocks=set(host_blocks)
                    )
                    allocated_ips.extend(ips_from_random_blocks)
        _log.info("Allocated %s of %s requested IPs", len(allocated_ips), num)
        return allocated_ips

    def _allocate_ips_explicit_blocks(self, blocks, num, attributes, handle_id,
                                      host):
        """Tries to allocate IPs from the explicitly-listed blocks.

        :param list blocks: Blocks to allocate from (for example, the affine
        blocks for a host).
        :param num: Number to try to allocate.
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :param handle_id: Handle ID to associate with the allocations.
        :param host: The host ID to use for affinity in assigning IP addresses.
        :return: list of allocated IPs or an empty list if none were available.
        """
        # Copy the list so we can use it as a retry queue.
        remaining_host_blocks = deque(blocks)
        key_errors = 0
        allocated_ips = []
        while len(allocated_ips) < num:
            try:
                block_id = remaining_host_blocks.popleft()
            except IndexError:
                _log.info("No free IPs in pre-existing affine blocks for "
                          "host %s", host)
                break
            num_remaining = num - len(allocated_ips)
            try:
                ips = self._auto_assign_ips_in_block(block_id,
                                                     num_remaining,
                                                     handle_id,
                                                     attributes,
                                                     host)
            except KeyError:
                # In certain rare race conditions, _get_affine_blocks above
                # can return block_ids that don't exist (due to multiple IPAM
                # clients on this host running simultaneously).  If that
                # happens, requeue the block_id for a retry, since we expect
                # the other IPAM client to shortly create the block.  To stop
                # endless looping we limit the number of KeyErrors that will
                # generate a retry.
                _log.warning("Tried to auto-assign to block %s.  Doesn't "
                             "exist.", block_id)
                key_errors += 1
                if key_errors <= KEY_ERROR_RETRIES:
                    _log.debug("Queueing block %s for retry.", block_id)
                    remaining_host_blocks.append(block_id)
                else:
                    _log.warning("Stopping retry of block %s.", block_id)
                continue
            except NoHostAffinityError:
                # In certain rare race conditions, _get_affine_blocks above
                # can return block_ids that don't actually have affinity to
                # this host (due to multiple IPAM clients on this host running
                # simultaneously).  If that happens, just move to the next one.
                _log.warning("No host affinity on block %s; skipping.",
                             block_id)
                continue
            allocated_ips.extend(ips)
        return allocated_ips

    def _allocate_ips_from_new_blocks(self, num, attributes, handle_id,
                                      host, ip_version, pool, ipam_config):
        """Attempts to allocate new affine block(s) for the given host and
        then to allocate IPs from them.

        :param num: Number to try to allocate.
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :param handle_id: Handle ID to associate with the allocations.
        :param host: The host ID to use for affinity in assigning IP addresses.
        :param ip_version: IP version to use when choosing a pool.
        :param pool: IP pool to choose from, or None for "any pool".
        :param ipam_config: Pre-loaded IPAM config object.
        :return: list of allocated IPs or an empty list if none were available.
        """
        retries = RETRIES
        allocated_ips = []
        while len(allocated_ips) < num and retries > 0:
            retries -= 1
            try:
                new_block = self._new_affine_block(host,
                                                   ip_version,
                                                   pool,
                                                   ipam_config)
                # If successful, this creates the block and registers it to
                # us.
            except NoFreeBlocksError:
                _log.info("Could not get new host affinity block for %s in "
                          "pool %s", host, pool)
                break
            num_remaining = num - len(allocated_ips)
            ips = self._auto_assign_ips_in_block(new_block,
                                                 num_remaining,
                                                 handle_id,
                                                 attributes,
                                                 host)
            allocated_ips.extend(ips)
        if retries == 0:  # pragma: no cover
            raise RuntimeError("Hit Max Retries.")
        return allocated_ips

    def _allocate_ips_no_affinity(self, num, attributes, handle_id,
                                  host, ip_version, pool,
                                  excluded_blocks):
        """Tries to allocate IP addresses from any available block, without
        affinity.

        :param num: Number to try to allocate.
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :param handle_id: Handle ID to associate with the allocations.
        :param host: The host ID to use for affinity in assigning IP addresses.
        :param ip_version: IP version to use when choosing a pool.
        :param pool: IP pool to choose from, or None for "any pool".
        :param excluded_blocks: set of blocks to exclude from the search, for
               example, to exclude blocks that we've already looked in.
        :return: list of allocated IPs or an empty list if none were available.
        """
        # Note that this processing simply takes all of the IP pools and breaks
        # them up into block-sized CIDRs, then searches through each CIDR in a
        # random order.  This algorithm does not work if we disallow
        # auto-allocation of blocks because the allocated blocks may be
        # sparsely populated in the pools resulting in a very slow search for
        # free addresses.
        #
        # If we need to support non-strict affinity and no auto-allocation of
        # blocks, then we should query the actual allocation blocks and assign
        # from those.
        _log.debug("Attempt to allocate from non-affine random block")
        random_blocks = self._random_blocks(version=ip_version, pool=pool,
                                            excluded_ids=excluded_blocks,
                                            seed=host)
        allocated_ips = []
        while len(allocated_ips) < num:
            try:
                block_id = next(random_blocks)
            except StopIteration:
                _log.warning("All addresses exhausted in pool %s", pool)
                break
            num_remaining = num - len(allocated_ips)
            ips = self._auto_assign_ips_in_block(block_id,
                                                 num_remaining,
                                                 handle_id,
                                                 attributes,
                                                 host,
                                                 affinity_check=False)
            allocated_ips.extend(ips)
        return allocated_ips

    def _auto_assign_ips_in_block(self, block_cidr, num, handle_id, attributes,
                                  host, affinity_check=True):
        """
        Automatically pick IPs from a block and commit them to the data store.

        :param block_cidr: The identifier for the block to read.
        :param num: The number of IPs to assign.
        :param handle_id: allocation handle ID for this request.
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :param host: The host ID to use for affinity in assigning IP addresses.
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
                                                host=host,
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

    @handle_errors
    def assign_ip(self, address, handle_id, attributes, host=None):
        """
        Assign the given address.  Throws AlreadyAssignedError if the address
        is taken.  If the strict_affinity option is set to True, this
        throws a NoHostAffinityError if the address is in a block owned by a
        different host.

        :param address: IPAddress to assign.
        :param handle_id: allocation handle ID for this request.  You can
        query this key using get_assignments_by_handle() or release all
        addresses with this handle_id using release_by_handle().
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :param host: (optional) The host ID to use for affinity in assigning IP
        addresses.  Defaults to the hostname returned by get_hostname().
        :return: None.
        """
        assert isinstance(handle_id, str) or handle_id is None
        assert isinstance(address, IPAddress)
        host = host or get_hostname()
        block_cidr = get_block_cidr_for_address(address)
        ipam_config = None

        for _ in xrange(RETRIES):
            try:
                block = self._read_block(block_cidr)
            except KeyError:
                _log.debug("Block %s doesn't exist.", block_cidr)
                if self._validate_cidr_in_pools(block_cidr):
                    _log.debug("Create and claim block %s.",
                               block_cidr)

                    # We need the IPAM config, so get it once now.
                    if ipam_config is None:
                        _log.debug("Querying IPAM config")
                        ipam_config = self.get_ipam_config()

                    try:
                        self._claim_block_affinity(host, block_cidr,
                                                   ipam_config)
                    except HostAffinityClaimedError:
                        _log.debug("Someone else claimed block %s before us.",
                                   block_cidr)
                        continue
                    # Block exists now, retry writing to it.
                    _log.debug("Claimed block %s", block_cidr)
                    continue
                else:
                    raise PoolNotFound("%s is not in any configured pool" %
                                       address)

            # Try to assign.  Throws AlreadyAssignedError if already assigned,
            # or a NoHostAffinityError if the block requires strict host
            # affinity and the host affinity does not match the host.
            block.assign(address, handle_id, attributes, host)

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

    @handle_errors
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
            unalloc_block = self._release_ips_from_block(block_cidr, addresses)
            unallocated = unallocated.union(unalloc_block)
        return unallocated

    def _release_ips_from_block(self, block_cidr, addresses):
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
                # If the block is now empty and there is no host affinity to
                # the block then delete the block, otherwise just update the
                # block configuration.
                if block.is_empty() and not block.host_affinity:
                    _log.debug("Deleting empty non-affine block")
                    self._delete_block(block)
                else:
                    _log.debug("Updating assignments in block")
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

    def _validate_cidr_in_pools(self, cidr):
        """
        Validate a CIDR is fully covered by one of the configured IP pools.
        Raises a PoolNotFound exception if the CIDR is not valid.

        :param cidr: (IPNetwork) The CIDR to check.
        """
        pools = self.get_ip_pools(cidr.version, ipam=True, include_disabled=False)
        return any([cidr in pool for pool in pools])

    @handle_errors
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

    @handle_errors
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

    @handle_errors
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

    @handle_errors
    def claim_affinity(self, cidr, host=None):
        """
        Claim affinity for the blocks covered by the requested CIDR.

        :param cidr: The CIDR covering the blocks to be released.  Raises a
        InvalidBlockSizeError if the CIDR is smaller than the minimum allowable
        block size.
        :param host: (optional) The host ID to use for affinity in assigning IP
        addresses.  Defaults to the hostname returned by get_hostname().

        :return: A tuple of:
                 ([IPNetwork<blocks claimed>],
                  [IPNetwork<blocks that were claimed by another host>])
        """
        assert isinstance(cidr, IPNetwork)
        if not validate_block_size(cidr):
            _log.info("Requested CIDR %s is too small", cidr)
            raise InvalidBlockSizeError("The requested CIDR is smaller than "
                                        "the minimum block size.")

        host = host or get_hostname()

        if not self._validate_cidr_in_pools(cidr):
            _log.info("Requested CIDR %s is not in a configured pool", cidr)
            raise PoolNotFound("Requested CIDR is not in a configured IP "
                               "Pool.")

        claimed = []
        unclaimed = []

        # Get the IPAM configuration.  We need this when claiming block
        # affinities.
        ipam_config = self.get_ipam_config()

        for block_cidr in cidr.subnet(BLOCK_PREFIXLEN[cidr.version]):
            try:
                self._claim_block_affinity(host, block_cidr, ipam_config)
            except HostAffinityClaimedError:
                unclaimed.append(block_cidr)
                break
            else:
                claimed.append(block_cidr)

        return claimed, unclaimed

    @handle_errors
    def release_affinity(self, cidr, host=None):
        """
        :param cidr: The CIDR covering the blocks to be released.  Raises a
        InvalidBlockSizeError if the CIDR is smaller than the minimum allowable
        block size.
        :param host: (optional) The host ID to compare against the affinity of
        each block that is being released.

        :return: A tuple of:
                 ([IPNetwork<blocks released>],
                  [IPNetwork<blocks that were not claimed>],
                  [IPNetwork<blocks that were claimed by another host>])
        """
        assert isinstance(cidr, IPNetwork)
        if not validate_block_size(cidr):
            _log.info("Requested CIDR %s is too small", cidr)
            raise InvalidBlockSizeError("The requested CIDR is smaller than "
                                        "the minimum block size.")
        host = host or get_hostname()

        released = []
        not_claimed = []
        claimed_by_other = []

        for block_cidr in cidr.subnet(BLOCK_PREFIXLEN[cidr.version]):
            try:
                self._release_block_affinity(host, block_cidr)
            except HostAffinityClaimedError:
                claimed_by_other.append(block_cidr)
            except KeyError:
                not_claimed.append(block_cidr)
            else:
                released.append(block_cidr)

        return released, not_claimed, claimed_by_other

    @handle_errors
    def release_host_affinities(self, host):
        """
        Release affinities for all blocks owned by the host.

        :param host: (optional) The host ID to compare against the affinity of
        each block that is being released.
        """
        host = host or get_hostname()

        # Find all of the affine blocks that are listed for the host, and
        # release affinity for each.  Note that the host may over-estimate
        # which blocks it has affinity for so ignore any error indicating that
        # the block is owned by another host - we simply won't release that
        # block.
        _log.debug("Releasing affinities for %s", host)
        for version in (4, 6):
            cidrs = self._get_affine_blocks(host, version, None)
            for cidr in cidrs:
                try:
                    self._release_block_affinity(host, cidr)
                except HostAffinityClaimedError:
                    _log.info("Affine block %s is not owned by host %s - skip",
                              cidr, host)

    @handle_errors
    def release_pool_affinities(self, pool):
        """
        Release affinities for all blocks in the specified pool.
        :param pool: The IP Pool.

        This may throw KeyError and HostAffinityClaimedError if another
        IPAM user is making conflicting changes.
        """
        for _ in range(KEY_ERROR_RETRIES):
            retry = False
            for host, block_cidr in self._get_host_block_pairs(pool):
                try:
                    self._release_block_affinity(host, block_cidr)
                except (KeyError, HostAffinityClaimedError):
                    # Hit a conflict - carry on with remaining CIDRs, but retry
                    # once we have finished with the current CIDR list.
                    retry = True

            if not retry:
                return

        # Too may retries - re-raise the last exception.
        raise

    @handle_errors
    def remove_ipam_host(self, host):
        """
        Remove an IPAM host.  This removes all host affinities from the
        existing allocation blocks, and removes the host specific IPAM data.

        This method does not release individual IP address assigned by the
        host - the IP addresses need to be released separately.

        :param host: (optional) The host ID.
        :return: nothing.
        """
        # Get the host if not specified.
        host = host or get_hostname()

        # Release host affinities before removing the host tree,
        self.release_host_affinities(host)

        # Remove the host ipam tree.
        host_path = IPAM_HOST_PATH % {"host": host}
        try:
            self.etcd_client.delete(host_path, dir=True, recursive=True)
        except EtcdKeyNotFound:
            pass


# Choice of steps to take when iterating over the subnets.  Must all be
# coprime to powers of 2.  Since we choose a random start point and a random
# step, repeat collisions are very unlikely.
STEPS = [1, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59]


def _random_subnets_from_cidr(cidr, prefixlen, rnd=random):
    """
    Generates the subnets of the given CIDR with the given prefix length
    in a pseudo-random order with no repeats.

    :param IPNetwork cidr: The large CIDR, from which to pick the
    prefixlen-length CIDRs.
    :param int prefixlen: The desired length of output CIDR.
    :param random.Random rnd: Random number generator to use.  Defaults to the
    standard library's built-in instance.
    """
    if not (0 <= prefixlen <= cidr._module.width):
        raise ValueError('CIDR prefix /%d invalid for IPv%d!' \
                         % (prefixlen, cidr.version))

    if not cidr.prefixlen <= prefixlen:
        # Don't return anything.
        raise StopIteration

    # Calculate number of subnets to be returned.
    max_subnets = 2 ** (prefixlen - cidr.prefixlen)

    base_subnet_addr = str(cidr.cidr.ip)  # Throws away the .1 in 10.0.0.1/8.
    num_returned = 0
    # Choose our step and initial position randomly.  We avoid using
    # rnd.shuffle() because that would require us to generate the whole list
    # of CIDRs, and there could be millions of those!
    #
    # Since the steps are chosen to be co-prime to powers of 2 and
    # max_subnets is a power of 2, we'll cycle through every possible subnet.
    #
    # Proof by contradiction: if we don't hit every number, we'd cycle through
    # a subset of the values, so we'd have:
    #
    #   n * step == 0 (MOD max_subnets),  for 0 < n < max_subnets
    #
    # So max_subnets would have to divide n * step.
    # However, step has no power-of-2 factors so max_subnets must divide n.
    # However, we assumed 0 < n < max_subnets, which is a contradiction.
    step = rnd.choice(STEPS)
    position = rnd.randint(0, max_subnets - 1)
    while num_returned < max_subnets:
        subnet = IPNetwork('%s/%d' % (base_subnet_addr, prefixlen),
                           cidr.version)
        subnet.value += (subnet.size * position)
        subnet.prefixlen = prefixlen
        num_returned += 1
        position = (position + step) % max_subnets
        yield subnet


def _random_subnets_from_cidrs(cidrs, prefixlen, seed=None):
    """
    Generates the subnets of the given CIDRs with the given prefix length
    in a pseudo-random order with no repeats.

    :param cidrs: List of CIDRs.
    :param prefixlen: Length of subnets to generate.
    :param seed: Seed for the random number generator; any hashable object or
    None to use the standard library's seeding strategy.
    """
    rnd = random.Random(seed)
    # Make a generator for the subnet CIDRs in each pool.  We'll pick CIDRs
    # from each generator in turn so that we spread the subnets evenly between
    # pools.
    pool_subnets = deque([_random_subnets_from_cidr(cidr, prefixlen, rnd=rnd)
                          for cidr in cidrs])
    num_generated = 0
    while pool_subnets:
        # Shuffle the per-pool generators each time we cycle through them.
        if num_generated % len(pool_subnets) == 0:
            rnd.shuffle(pool_subnets)
        # Pop the generator at the head of the queue, if it runs out of
        # entries, we'll drop it.  Otherwise we'll put it back on the queue.
        subnet_generator = pool_subnets.popleft()
        try:
            subnet = next(subnet_generator)
        except StopIteration:
            continue
        else:
            yield subnet
            pool_subnets.append(subnet_generator)
        num_generated += 1
