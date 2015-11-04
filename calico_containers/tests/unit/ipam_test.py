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
import copy
from netaddr import IPNetwork, IPAddress
from nose.tools import *
from mock import patch, ANY, call, Mock
import unittest
import json
from etcd import EtcdResult, Client, EtcdAlreadyExist, EtcdKeyNotFound, EtcdCompareFailed

from pycalico.ipam import (IPAMClient, BlockHandleReaderWriter,
                           CASError, NoFreeBlocksError, _block_datastore_key,
                           _handle_datastore_key)
from pycalico.datastore_errors import PoolNotFound
from pycalico.block import AllocationBlock, AddressNotAssignedError, BLOCK_SIZE
from pycalico.handle import AllocationHandle, AddressCountTooLow
from pycalico.datastore_datatypes import IPPool
from block_test import (_test_block_empty_v4, _test_block_empty_v6,
                        BLOCK_V6_1, BLOCK_V4_1)

network = IPNetwork("192.168.25.0/24")
BLOCK_V4_2 = IPNetwork("10.11.45.0/26")
BLOCK_V4_3 = IPNetwork("10.11.47.0/26")


class TestIPAMClient(unittest.TestCase):

    def setUp(self):
        self.client = IPAMClient()
        self.m_etcd_client = Mock(spec=Client)
        self.client.etcd_client = self.m_etcd_client

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign(self, m_get_hostname):
        """
        Mainline test of auto assign.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return [BLOCK_V4_1,
                    BLOCK_V4_2]

        block = _test_block_empty_v4()
        m_result = Mock(spec=EtcdResult)
        m_result.value = block.to_json()
        self.m_etcd_client.read.return_value = m_result

        with patch("pycalico.ipam.BlockHandleReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(1, 0, None, {})
            assert_list_equal([IPAddress("10.11.12.0")], ipv4s)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign_dual(self, m_get_hostname):
        """
        Test of auto assign with both IPv4 and IPv6 requests.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            assert ip_version in [4, 6]
            if ip_version == 4:
                return [BLOCK_V4_1,
                        BLOCK_V4_2]
            else:
                return [IPNetwork("2001:abcd:def0::/122"),
                        IPNetwork("2001:abcd:def0::4500/122")]

        block0 = _test_block_empty_v4()
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        block1 = _test_block_empty_v6()
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block1.to_json()
        self.m_etcd_client.read.side_effect = [m_result0, m_result1]

        with patch("pycalico.ipam.BlockHandleReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(1, 2, None, {})
            assert_list_equal([IPAddress("10.11.12.0")], ipv4s)
            assert_list_equal([IPAddress("2001:abcd:def0::"),
                               IPAddress("2001:abcd:def0::1")], ipv6s)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign_1st_block_full(self, m_get_hostname):
        """
        Test auto assign when 1st block is full.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return [BLOCK_V4_1, BLOCK_V4_2]

        block0 = _test_block_empty_v4()
        _ = block0.auto_assign(256, None, {}, affinity_check=False)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        block1 = _test_block_empty_v4()
        block1.cidr = BLOCK_V4_2
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block1.to_json()

        self.m_etcd_client.read.side_effect = [m_result0, m_result1]

        with patch("pycalico.ipam.BlockHandleReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(1, 0, None, {})
            assert_list_equal([IPAddress("10.11.45.0")], ipv4s)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign_span_blocks(self, m_get_hostname):
        """
        Test auto assign when 1st block has fewer than requested addresses.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return [BLOCK_V4_1, BLOCK_V4_2]

        # 1st block has 2 free addresses.
        block0 = _test_block_empty_v4()
        _ = block0.auto_assign(BLOCK_SIZE-2, None, {}, affinity_check=False)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        # 2nd block is empty.
        block1 = _test_block_empty_v4()
        block1.cidr = BLOCK_V4_2
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block1.to_json()

        self.m_etcd_client.read.side_effect = [m_result0, m_result1]

        with patch("pycalico.ipam.BlockHandleReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(4, 0, None, {})
            assert_list_equal([BLOCK_V4_1[-2],
                               BLOCK_V4_1[-1],
                               BLOCK_V4_2[0],
                               BLOCK_V4_2[1]], ipv4s)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign_not_enough_addrs(self, m_get_hostname):
        """
        Test auto assign when there aren't enough addresses, and no free
        blocks.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return [BLOCK_V4_1, BLOCK_V4_2]

        def m_get_ip_pools(self, version):
            # The two claimed blocks are the only pools.
            return [IPPool(BLOCK_V4_1), IPPool(BLOCK_V4_2)]

        # 1st block has 2 free addresses.
        block0 = _test_block_empty_v4()
        _ = block0.auto_assign(BLOCK_SIZE-2, None, {}, affinity_check=False)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        # 2nd block has 1 free address.
        block1 = _test_block_empty_v4()
        _ = block1.auto_assign(BLOCK_SIZE-1, None, {}, affinity_check=False)
        block1.cidr = BLOCK_V4_2
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block1.to_json()

        # Total of 4 reads: first two are checking blocks with affinity
        # second two are trying to find free blocks in the pool (but there
        # aren't any).
        self.m_etcd_client.read.side_effect = [m_result0, m_result1,
                                               m_result0, m_result1]

        with patch("pycalico.ipam.BlockHandleReaderWriter._get_affine_blocks",
                   m_get_affine_blocks),\
             patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(4, 0, None, {})
            assert_list_equal([BLOCK_V4_1[-2],
                               BLOCK_V4_1[-1],
                               BLOCK_V4_2[-1]], ipv4s)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign_cas_fails(self, m_get_hostname):
        """
        Test auto assign when 1st block compare-and-swap fails.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return [BLOCK_V4_1, BLOCK_V4_2]

        # 1st read, 1st block has 2 free addresses.
        block0 = _test_block_empty_v4()
        _ = block0.auto_assign(BLOCK_SIZE-2, None, {}, affinity_check=False)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        # 2nd read, 1st block has 1 free addresses.
        _ = block0.auto_assign(1, None, {}, affinity_check=False)
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block0.to_json()
        # 2nd block is empty.
        block1 = _test_block_empty_v4()
        block1.cidr = BLOCK_V4_2
        m_result2 = Mock(spec=EtcdResult)
        m_result2.value = block1.to_json()

        # Read three times, update 3 times.
        self.m_etcd_client.read.side_effect = [m_result0, m_result1, m_result2]
        self.m_etcd_client.update.side_effect = [EtcdCompareFailed(),
                                                 None,
                                                 None]

        with patch("pycalico.ipam.BlockHandleReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(4, 0, None, {})
            assert_list_equal([BLOCK_V4_1[-1],
                               BLOCK_V4_2[0],
                               BLOCK_V4_2[1],
                               BLOCK_V4_2[2]], ipv4s)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign_with_handle_cas_failure(self, m_gethostname):
        """
        Test of auto assign with an existing handle, and transient CAS errors.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return [BLOCK_V4_1,
                    BLOCK_V4_2]

        # Initialise the block assignment.
        block = _test_block_empty_v4()
        m_resultb = Mock(spec=EtcdResult)
        m_resultb.value = block.to_json()
        m_resultb.key = "/calico/ipam/v2/assignment/ipv4/block/10.11.12.0-26"

        # Initialise the handle assignment
        handle_id = "handle_id_1"
        handle0 = AllocationHandle(handle_id)
        handle0.increment_block(BLOCK_V4_1, 1)
        m_resulth = Mock(spec=EtcdResult)
        m_resulth.value = handle0.to_json()
        m_resulth.key = _handle_datastore_key(handle_id)
        m_resulth.modifiedIndex = 55555

        # Read returns appropriate result based on key.
        read_results = {m_resultb.key: m_resultb,
                        m_resulth.key: m_resulth}
        def read(key, quorum):
            """ Return a copy of the current stored value depending on key."""
            assert quorum
            return copy.copy(read_results[key])
        self.m_etcd_client.read.side_effect = read

        # Fail the block updates a couple of times and then succeed.
        # Similarly fail one of the handle updates.  For each failed block
        # update the handle will be incremented and decremented, for the
        # successful block update, the handle will be incremented.
        side_effs = {m_resultb.key:  # Block updates
                       [EtcdCompareFailed(),  # 1. Fail
                        EtcdCompareFailed(),  # 2. Fail
                        None],  # 3. Success
                     m_resulth.key:  # Handle updates
                       [EtcdCompareFailed(), None, None,  # 1. Inc Fail, Inc, Dec
                        None, None,  # 2. Inc, Dec
                        None]}  # 3. Inc.
        def update(result):
            """Either raise an exception or update the current stored value."""
            side_eff = side_effs[result.key].pop(0)
            if side_eff:
                raise side_eff
            read_results[result.key].value = result.value
        self.m_etcd_client.update.side_effect = update

        with patch("pycalico.ipam.BlockHandleReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(1, 0, handle_id, {})
            assert_list_equal([IPAddress("10.11.12.0")], ipv4s)

        # Validate the handle data stored.  We should have two reserved in the
        # block now.
        handle = AllocationHandle.from_etcd_result(m_resulth)
        self.assertEqual(handle.handle_id, handle_id)
        self.assertEqual(handle.block, {"10.11.12.0/26": 2})

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign_persistent_cas(self, m_get_hostname):
        """
        Test of auto assign with persistent CAS errors.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return [BLOCK_V4_1,
                    BLOCK_V4_2]

        # Initialise the block assignment.
        block = _test_block_empty_v4()
        m_resultb = Mock(spec=EtcdResult)
        m_resultb.value = block.to_json()
        m_resultb.key = "/calico/ipam/v2/assignment/ipv4/block/10.11.12.0-24"

        def read(key, quorum):
            """ Return a copy of the current stored value depending on key."""
            assert quorum
            return copy.copy(m_resultb)
        self.m_etcd_client.read.side_effect = read
        self.m_etcd_client.update.side_effect = EtcdCompareFailed()

        with patch("pycalico.ipam.BlockHandleReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            self.assertRaises(RuntimeError, self.client.auto_assign_ips,
                              1, 0, None, {})

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign_no_blocks(self, m_get_hostname):
        """
        Test auto assign when we haven't allocated blocks yet, but there are
        free blocks available.

        Order of operations
            1 Read first subnet in pool.  Doesn't exist.
            2 Write to affinity store for this host.
            3 Write an empty block
            4 Read back the block
            5 CAS update with allocated ips.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return []

        def m_get_ip_pools(self, version):
            return [IPPool("192.168.0.0/16")]

        # Reads on 1, 4
        block = AllocationBlock(IPNetwork("192.168.0.0/26"), "test_host1")
        m_result = Mock(spec=EtcdResult)
        m_result.value = block.to_json()
        self.m_etcd_client.read.side_effect = [EtcdKeyNotFound(), m_result]


        with patch("pycalico.ipam.BlockHandleReaderWriter._get_affine_blocks",
                   m_get_affine_blocks),\
             patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(4, 0, None, {})
            assert_equal(self.m_etcd_client.read.call_count, 2)
            assert_list_equal([IPAddress("192.168.0.0"),
                               IPAddress("192.168.0.1"),
                               IPAddress("192.168.0.2"),
                               IPAddress("192.168.0.3")], ipv4s)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign_random_blocks(self, m_get_hostname):
        """
        Test auto assign when all blocks our blocks are full and all other
        blocks already have host affinity.
        """

        affine_blocks = [BLOCK_V4_1,
                         BLOCK_V4_2]

        def m_get_affine_blocks(self, host, ip_version, pool):
            return affine_blocks

        rando_blocks = set()

        def m_read_block(self, block_cidr):
            if block_cidr in affine_blocks:
                # All our blocks are full.
                block = AllocationBlock(block_cidr, "test_host1")
                block.auto_assign(256, None, {})
            else:
                # Other blocks are not.
                block = AllocationBlock(block_cidr, "test_host2")
                rando_blocks.add(block)
            return block

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/18")]

        with patch("pycalico.ipam.BlockHandleReaderWriter._get_affine_blocks",
                   m_get_affine_blocks),\
             patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools),\
             patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   m_read_block):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(4, 0, None, {})
            assert_equal(len(ipv4s), 4)
            assert_equal(len(rando_blocks), 1)
            rando_block = rando_blocks.pop()
            for ip in ipv4s:
                assert_true(ip in rando_block.cidr)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign_bad_affinity(self, m_get_hostname):
        """
        Test auto assign when _get_affine_blocks returns some blocks that
        don't exist or don't actually have host affinity.

        This is a race condition that occurs because _get_affine_blocks only
        checks the IPAM_HOST_AFFINITY_PATH to determine what blocks have
        affinity to the host; it does not actually read the blocks themselves
        to check affinity.

        The race occurs because while attempting to allocate a new block with
        affinity to this host, the IPAM client first writes to the
        IPAM_HOST_AFFINITY_PATH before it writes to the block itself.  If
        multiple IPAM clients are running on behalf of the host, the race can
        go something like this:

        1. Client A is allocating a new affine block, and writes the block_id
           to IPAM_HOST_AFFINITY_PATH.
        2. Client B needs to assign an address, so it reads the
           IPAM_HOST_AFFINITY_PATH.
        3. Client B attempts to read the block.  This fails, throwing a
           KeyError.
        4. Client A writes the new block.

        If 4 happened before 3 we'd be fine.

        Or consider a related scenario.

        1. Client A is allocating a new affine block, and writes the block_id
           to IPAM_HOST_AFFINITY_PATH.
        2. Client B needs to assign an address, so it reads the
           IPAM_HOST_AFFINITY_PATH.
        3. A different host claims affinity for the block, and writes the new
           block.
        4. Client A attempts to write the block and fails, and cleans up the
           IPAM_HOST_AFFINITY_PATH.
        5. Client B attempts to read the block, but when it tries to auto
           assign from the block, it fails because a different host has
           affinity.  This throws a NoHostAffinityWarning.

        """

        affine_blocks = [BLOCK_V4_1,
                         BLOCK_V4_2,
                         BLOCK_V4_3]

        def m_get_affine_blocks(self, host, ip_version, pool):
            return affine_blocks

        def m_read_block(self, block_cidr):
            if block_cidr is BLOCK_V4_1:
                # This block doesn't yet exist.
                raise KeyError()
            elif block_cidr is BLOCK_V4_2:
                # This block exists, but we don't have host affinity to it.
                block = AllocationBlock(BLOCK_V4_2, "test_host2")
            elif block_cidr is BLOCK_V4_3:
                # This block exists and we have host affinity.  Allocated IPs
                # should come from this block.
                block = AllocationBlock(BLOCK_V4_3, "test_host1")
            else:
                # Success on BLOCK_V4_3, so no additional blocks should be
                # read.
                assert_true(False)
            return block

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/18")]

        with patch("pycalico.ipam.BlockHandleReaderWriter._get_affine_blocks",
                   m_get_affine_blocks),\
             patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools),\
             patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   m_read_block):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(4, 0, None, {})
            assert_equal(len(ipv4s), 4)
            for ip in ipv4s:
                assert_true(ip in BLOCK_V4_3)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign_affinity_key_err_retries(self, m_get_hostname):
        """
        Test auto assign when _get_affine_blocks returns some blocks that
        don't exist and we hit the maximum number of retries.
        """

        affine_blocks = [BLOCK_V4_1]

        def m_get_affine_blocks(self, host, ip_version, pool):
            return affine_blocks

        # 4 attempts to read BLOCK_V4_1, then one attempt to read
        # first_free_block
        first_free_block = IPNetwork("10.11.0.0/26")
        block = AllocationBlock(first_free_block, "test_host1")
        m_read_block = Mock()
        m_read_block.side_effect = [KeyError(),
                                    KeyError(),
                                    KeyError(),
                                    KeyError(),
                                    block]
        # Note that _get_new_affine_block calls etcd_client.read() directly.
        self.m_etcd_client.read.side_effect = EtcdKeyNotFound()

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/18")]

        with patch("pycalico.ipam.BlockHandleReaderWriter._get_affine_blocks",
                   m_get_affine_blocks),\
             patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools),\
             patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   m_read_block):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(4, 0, None, {})
            assert_equal(len(ipv4s), 4)
            for ip in ipv4s:
                assert_true(ip in first_free_block)
            m_read_block.assert_has_calls([
                call(BLOCK_V4_1),
                call(BLOCK_V4_1),
                call(BLOCK_V4_1),
                call(BLOCK_V4_1),
                call(first_free_block)
            ])

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_assign(self, m_get_hostname):
        """
        Mainline test of assign_ip().
        """

        block = _test_block_empty_v4()
        m_result = Mock(spec=EtcdResult)
        m_result.value = block.to_json()
        self.m_etcd_client.read.return_value = m_result

        ip0 = IPAddress("10.11.12.55")
        self.client.assign_ip(ip0, None, {})
        self.m_etcd_client.update.assert_called_once_with(m_result)

        # Assert the JSON shows the address allocated.
        json_dict = json.loads(m_result.value)
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_assign_cas_fails(self, m_get_hostname):
        """
        Test assign_ip() when the compare-and-swap fails.
        """

        block = _test_block_empty_v4()
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block.to_json()
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block.to_json()
        self.m_etcd_client.read.side_effect = [m_result0, m_result1]

        # First update fails, then succeeds.
        self.m_etcd_client.update.side_effect = [EtcdCompareFailed(),
                                                 None]

        ip0 = IPAddress("10.11.12.55")
        self.client.assign_ip(ip0, None, {})
        self.m_etcd_client.update.assert_has_calls([call(m_result0),
                                                    call(m_result1)])

        # Assert the JSON shows the address allocated.
        json_dict = json.loads(m_result1.value)
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_assign_with_handle_cas_fails(self, m_get_hostname):
        """
        Test assign_ip() using a handle when the compare-and-swap fails.
        """

        # Initialise the block assignment.
        block = _test_block_empty_v4()
        m_resultb = Mock(spec=EtcdResult)
        m_resultb.value = block.to_json()
        m_resultb.key = "/calico/ipam/v2/assignment/ipv4/block/10.11.12.0-26"

        # Initialise the handle assignment
        handle_id = "handle_id_1"
        handle0 = AllocationHandle(handle_id)
        handle0.increment_block(IPNetwork("10.11.13.0/26"), 5)
        m_resulth = Mock(spec=EtcdResult)
        m_resulth.value = handle0.to_json()
        m_resulth.key = _handle_datastore_key(handle_id)
        m_resulth.modifiedIndex = 55555

        # Read returns appropriate result based on key.
        read_results = {m_resultb.key: m_resultb,
                        m_resulth.key: m_resulth}
        def read(key, quorum):
            """ Return a copy of the current stored value depending on key."""
            assert quorum
            return copy.copy(read_results[key])
        self.m_etcd_client.read.side_effect = read

        # Fail the block updates a couple of times and then succeed.
        # Similarly fail one of the handle updates.  For each failed block
        # update the handle will be incremented and decremented, for the
        # successful block update, the handle will be incremented.
        side_effs = {m_resultb.key:                     # Block updates
                       [EtcdCompareFailed(),                   # 1. Fail
                        EtcdCompareFailed(),                   # 2. Fail
                        None],                          # 3. Success
                     m_resulth.key:                     # Handle updates
                       [EtcdCompareFailed(), None, None,       # 1. Inc Fail, Inc, Dec
                        None, None,                     # 2. Inc, Dec
                        None]}                          # 3. Inc.
        def update(result):
            """Either raise an exception or update the current stored value."""
            side_eff = side_effs[result.key].pop(0)
            if side_eff:
                raise side_eff
            read_results[result.key].value = result.value
        self.m_etcd_client.update.side_effect = update

        ip0 = IPAddress("10.11.12.55")
        self.client.assign_ip(ip0, handle_id, {})

        # Assert the Block JSON shows the address allocated, and the handle
        # JSON shows the assignment.
        block = AllocationBlock.from_etcd_result(m_resultb)
        expected_allocations = [None if ii != 55 else 0
                                for ii in range(BLOCK_SIZE)]
        assert_equal(block.allocations, expected_allocations)

        handle = AllocationHandle.from_etcd_result(m_resulth)
        self.assertEqual(handle.handle_id, handle_id)
        self.assertDictEqual(handle.block, {"10.11.12.0/26": 1,
                                            "10.11.13.0/26": 5})

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_assign_persistent_cas_fails(self, m_get_hostname):
        """
        Test assign_ip() when the compare-and-swap fails persistently.
        """

        block = _test_block_empty_v4()
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block.to_json()
        def read(key, quorum):
            assert quorum
            return copy.copy(m_result0)
        self.m_etcd_client.read.side_effect = read

        # First update fails, then succeeds.
        self.m_etcd_client.update.side_effect = EtcdCompareFailed()

        ip0 = IPAddress("10.11.12.55")
        self.assertRaises(RuntimeError, self.client.assign_ip, ip0, None, {})

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_assign_new_block(self, m_get_hostname):
        """
        Test assign_ip() when address is in a block that hasn't been written.
        """

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        # 1st read, doesn't exist.  2nd read, does exist, empty.
        block = AllocationBlock(BLOCK_V4_1, "test_host1")
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block.to_json()
        self.m_etcd_client.read.side_effect = [EtcdKeyNotFound(), m_result0]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            ip0 = IPAddress("10.11.12.55")
            self.client.assign_ip(ip0, None, {})

        # Verify we wrote a new block
        # Two calls to write() -- one for recording affinity, the other the
        # block itself
        assert_equal(self.m_etcd_client.write.call_count, 2)
        (args, kwargs) = self.m_etcd_client.write.call_args
        assert_dict_equal({"prevExist": False}, kwargs)

        # Allocation is via update
        self.m_etcd_client.update.assert_called_once_with(m_result0)
        json_dict = json.loads(m_result0.value)
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)
        assert_dict_equal({"prevExist": False}, kwargs)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_assign_new_block_cas_error(self, m_get_hostname):
        """
        Test assign_ip() when address is in a new block.

        Order of events:
            1 Attempt to read the block.  It doesn't exist.
            2 Write block affinity
            3 Attempt to write a new block --- false because someone else wrote
              it before us.
            4 Re-read the block.
            5 Back out 2.
            6 Re-read the block.
            7 Compare-and-swap new allocation with read from 3.
        """

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        # 2nd read.
        block = _test_block_empty_v4()
        block.assign(IPAddress("10.11.12.56"), None, {})
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block.to_json()

        # Reads at 1, 4, 6
        self.m_etcd_client.read.side_effect = [EtcdKeyNotFound(),
                                               m_result1,
                                               m_result1]

        # Writes are 2, 3, 5 above.
        self.m_etcd_client.write.side_effect = [None,
                                                EtcdAlreadyExist(),
                                                None]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            ip0 = IPAddress("10.11.12.55")
            self.client.assign_ip(ip0, None, {})

        # Assert the JSON shows the address allocated.
        json_dict = json.loads(m_result1.value)
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_assign_not_in_pools(self, m_get_hostname):
        """
        Test assign_ip() when address is not in configured pools.
        """

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        # block doesn't exist.
        self.m_etcd_client.read.side_effect = EtcdKeyNotFound()

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            ip0 = IPAddress("10.12.12.55")
            assert_raises(ValueError, self.client.assign_ip, ip0, None, {})

        # Verify we did not write anything.
        assert_false(self.m_etcd_client.write.called)
        assert_false(self.m_etcd_client.update.called)

    def test_assign_address(self):
        """
        Mainline test of assign_address().
        """

        block = _test_block_empty_v4()
        m_result = Mock(spec=EtcdResult)
        m_result.value = block.to_json()
        self.m_etcd_client.read.return_value = m_result

        ip0 = IPAddress("10.11.12.55")
        pool = IPPool("10.11.0.0/16")
        success = self.client.assign_address(pool, ip0)
        assert_true(success)
        self.m_etcd_client.update.assert_called_once_with(m_result)

        # Assert the JSON shows the address allocated.
        json_dict = json.loads(m_result.value)
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)

    def test_assign_address_no_pool(self):
        """
        Test assign_address when there are no IPPools in the data store.
        """

        self.m_etcd_client.read.side_effect = EtcdKeyNotFound

        ip0 = IPAddress("10.11.12.55")
        self.assertRaises(PoolNotFound, self.client.assign_address, None, ip0)

    def test_assign_address_fails(self):
        """
        Test assign_address() when it fails.
        """
        ip0 = IPAddress("10.11.12.55")

        block = _test_block_empty_v4()
        block.assign(ip0, None, {})
        m_result = Mock(spec=EtcdResult)
        m_result.value = block.to_json()
        self.m_etcd_client.read.return_value = m_result

        pool = IPPool("10.11.0.0/16")
        success = self.client.assign_address(pool, ip0)
        assert_false(success)
        assert_false(self.m_etcd_client.update.called)

    def test_unassign_address_no_pool(self):
        """
        Test unassign_address() where there are no IPPools in the data store.
        """

        self.m_etcd_client.read.side_effect = EtcdKeyNotFound

        ip0 = IPAddress("10.11.12.55")
        self.assertRaises(PoolNotFound, self.client.unassign_address,
                          None, ip0)

    def test_release_basic(self):
        """
        Basic test of release_ip
        """
        ip4 = BLOCK_V4_1[13]
        ip6 = BLOCK_V6_1[35]
        m_result4 = Mock(spec=EtcdResult)
        m_result6 = Mock(spec=EtcdResult)
        def m_read_block(self, block_cidr):
            block4 = _test_block_empty_v4()
            block4.assign(ip4, None, {})
            block4.db_result = m_result4
            if block_cidr == block4.cidr:
                return block4
            block6 = _test_block_empty_v6()
            block6.assign(ip6, None, {})
            block6.db_result = m_result6
            if block_cidr == block6.cidr:
                return block6
            assert_true(False, "Unexpected block CIDR")

        with patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   m_read_block):
            ips = {ip4, ip6}
            err = self.client.release_ips(ips)
            assert_set_equal(err, set())

        self.m_etcd_client.update.assert_has_calls([call(m_result4),
                                                    call(m_result6)],
                                                   any_order=True)

    def test_release_already_unallocated(self):
        """
        Test release_ip when already unallocated.
        """
        ip4 = BLOCK_V4_1[13]
        ip6 = BLOCK_V6_1[45]
        m_result4 = Mock(spec=EtcdResult)
        m_result6 = Mock(spec=EtcdResult)
        def m_read_block(self, block_cidr):
            block4 = _test_block_empty_v4()
            block4.db_result = m_result4
            if block_cidr == block4.cidr:
                return block4
            block6 = _test_block_empty_v6()
            block6.db_result = m_result6
            if block_cidr == block6.cidr:
                return block6
            assert_true(False, "Unexpected block CIDR")

        with patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   m_read_block):
            ips = {ip4, ip6}
            err = self.client.release_ips(ips)
            assert_set_equal(err, ips)


    def test_release_no_block(self):
        """
        Test release_ip when one block doesn't exist.
        """
        ip4 = BLOCK_V4_1[13]
        ip6 = BLOCK_V6_1[45]
        m_result6 = Mock(spec=EtcdResult)
        def m_read_block(self, block_cidr):
            if block_cidr == IPNetwork("10.11.12/26"):
                raise KeyError
            block6 = _test_block_empty_v6()
            block6.assign(ip6, None, {})
            block6.db_result = m_result6
            if block_cidr == block6.cidr:
                return block6
            assert_true(False, "Unexpected block CIDR")

        with patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   m_read_block):
            ips = {ip4, ip6}
            err = self.client.release_ips(ips)
            assert_set_equal(err, {ip4})

        # Assert we only wrote IPv6 block.
        self.m_etcd_client.update.assert_called_once_with(m_result6)

    def test_release_multiple(self):
        """
        Test of release_ip with multiple addresses in multiple blocks
        """
        ip4s = {BLOCK_V4_1[13],
                BLOCK_V4_1[60]}
        ip6s = {BLOCK_V6_1[45],
                BLOCK_V6_1[62]}
        m_result4 = Mock(spec=EtcdResult)
        m_result6 = Mock(spec=EtcdResult)
        def m_read_block(self, block_cidr):
            block4 = _test_block_empty_v4()
            for ip4 in ip4s:
                block4.assign(ip4, None, {})
            block4.db_result = m_result4
            if block_cidr == block4.cidr:
                return block4
            block6 = _test_block_empty_v6()
            for ip6 in ip6s:
                block6.assign(ip6, None, {})
            block6.db_result = m_result6
            if block_cidr == block6.cidr:
                return block6
            assert_true(False, "Unexpected block CIDR")

        with patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   m_read_block):
            ips = ip4s.union(ip6s)
            err = self.client.release_ips(ips)
            assert_set_equal(err, set())

        self.m_etcd_client.update.assert_has_calls([call(m_result4),
                                                    call(m_result6)],
                                                   any_order=True)
        json_4 = json.loads(m_result4.value)
        assert_equal(json_4["allocations"][13], None)
        assert_equal(json_4["allocations"][60], None)
        json_6 = json.loads(m_result6.value)
        assert_equal(json_6["allocations"][45], None)
        assert_equal(json_6["allocations"][62], None)

    def test_release_cas_error(self):
        """
        Test of release_ip when there is a CAS error.
        """
        ip4 = BLOCK_V4_1[13]
        ip6 = BLOCK_V6_1[45]
        m_result4 = Mock(spec=EtcdResult)
        m_result6 = Mock(spec=EtcdResult)

        def m_read_block(self, block_cidr):
            block4 = _test_block_empty_v4()
            block4.assign(ip4, None, {})
            block4.db_result = m_result4
            if block_cidr == block4.cidr:
                return block4
            block6 = _test_block_empty_v6()
            block6.assign(ip6, None, {})
            block6.db_result = m_result6
            if block_cidr == block6.cidr:
                return block6
            assert_true(False, "Unexpected block CIDR")

        # Throw an error the first time we write the v4 block, then allow.
        call_count = {4: 0, 6: 0}

        def m_compare_and_swap_block(self, block):
            call_count[block.cidr.version] += 1
            if block.cidr.version == 6:
                return
            else:
                # CAS error on first call
                if call_count[4] == 1:
                    raise CASError()
                else:
                    return

        with patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   m_read_block),\
             patch("pycalico.ipam.BlockHandleReaderWriter._compare_and_swap_block",
                   m_compare_and_swap_block):
            ips = {ip4, ip6}
            err = self.client.release_ips(ips)
            assert_set_equal(err, set())

        assert_dict_equal(call_count, {4: 2, 6: 1})

    def test_release_with_handle(self):
        """
        Basic test of release_ip where blocks have handles allocated.
        """
        # Create the blocks and mock out _read_block
        cidr4 = BLOCK_V4_1
        cidr6 = IPNetwork("2001:abcd:def0::/122")
        ip4 = BLOCK_V4_1[13]
        ip6 = BLOCK_V6_1[45]
        handle_id = "handle_id_1"

        m_resultb4 = Mock(spec=EtcdResult)
        m_resultb6 = Mock(spec=EtcdResult)
        block4 = _test_block_empty_v4()
        block4.assign(ip4, handle_id, {})
        block4.db_result = m_resultb4
        m_resultb4.key = "fake/ipv4key"
        block6 = _test_block_empty_v6()
        block6.assign(ip6, handle_id, {})
        block6.db_result = m_resultb6
        m_resultb6.key = "fake/ipv6key"

        def m_read_block(self, block_cidr):
            if block_cidr == block4.cidr:
                return block4
            if block_cidr == block6.cidr:
                return block6
            assert_true(False, "Unexpected block CIDR")

        # Create the handle and mock out read.
        handle0 = AllocationHandle(handle_id)
        handle0.increment_block(cidr4, 5)
        handle0.increment_block(cidr6, 3)

        m_resulth = Mock(spec=EtcdResult)
        m_resulth.value = handle0.to_json()
        m_resulth.key = _handle_datastore_key(handle_id)
        self.m_etcd_client.read.return_value = m_resulth

        with patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   m_read_block):
            ips = {ip4, ip6}
            err = self.client.release_ips(ips)
            assert_set_equal(err, set())

        self.m_etcd_client.update.assert_has_calls([call(m_resulth),
                                                    call(m_resultb4),
                                                    call(m_resultb6)],
                                                   any_order=True)

        # Check handle counts.
        handle = AllocationHandle.from_etcd_result(m_resulth)
        self.assertEqual(handle.block[str(cidr4)], 4)
        self.assertEqual(handle.block[str(cidr6)], 2)

    def test_release_ip_by_handle_cas_error(self):
        """
        Basic test of release_ip_by_handle with a single CAS error.
        """
        # Create the blocks.
        cidr4 = BLOCK_V4_1
        cidr6 = IPNetwork("2001:abcd:def0::/122")
        ip4 = BLOCK_V4_1[13]
        ip6 = BLOCK_V6_1[45]
        handle_id = "handle_id_1"

        m_resultb4 = Mock(spec=EtcdResult)
        m_resultb6 = Mock(spec=EtcdResult)
        block4 = _test_block_empty_v4()
        block4.assign(ip4, handle_id, {})
        m_resultb4.key = _block_datastore_key(cidr4)
        m_resultb4.value = block4.to_json()
        block6 = _test_block_empty_v6()
        block6.assign(ip6, handle_id, {})
        m_resultb6.key = _block_datastore_key(cidr6)
        m_resultb6.value = block6.to_json()

        # Create the handle and mock.
        handle0 = AllocationHandle(handle_id)
        handle0.increment_block(cidr4, 1)
        handle0.increment_block(cidr6, 1)

        m_resulth = Mock(spec=EtcdResult)
        m_resulth.value = handle0.to_json()
        m_resulth.key = _handle_datastore_key(handle_id)
        m_resulth.modifiedIndex = 55555

        # Mock out read.  We return a copy of the data so that it only gets
        # updated in the update() function.
        read_results = {m_resulth.key: m_resulth,
                        m_resultb4.key: m_resultb4,
                        m_resultb6.key: m_resultb6}
        def read(key, quorum):
            assert quorum
            return copy.copy(read_results[key])
        self.m_etcd_client.read.side_effect = read

        # Mock out update, so we can fail the first one.  We should then get
        # a successful update for the block, an update for the handle, an
        # update for the next block.  The handle is then deleted.
        update_errors = [EtcdCompareFailed(), None, None, None]

        def update(result):
            error = update_errors.pop(0)
            if error:
                raise error
            read_results[result.key].value = result.value
        self.m_etcd_client.update.side_effect = update

        self.client.release_ip_by_handle(handle_id)

        # Check update was called the expected number of times and with the
        # correct parameters.
        self.assertEqual(update_errors, [])

        # Check that delete was called for the handle.
        self.m_etcd_client.delete.assert_called_once_with(m_resulth.key,
                                                          prevIndex=55555)

    def test_release_ip_by_handle_no_block(self):
        """
        Test of release_ip_by_handle when referenced block does not exist.
        """
        # Create the blocks.
        cidr4 = BLOCK_V4_1
        cidr6 = IPNetwork("2001:abcd:def0::/122")
        handle_id = "handle_id_1"

        # Create the handle and mock.
        handle0 = AllocationHandle(handle_id)
        handle0.increment_block(cidr4, 1)
        handle0.increment_block(cidr6, 1)

        m_resulth = Mock(spec=EtcdResult)
        m_resulth.value = handle0.to_json()
        m_resulth.key = _handle_datastore_key(handle_id)
        m_resulth.modifiedIndex = 55555

        # Mock out read for the handle.
        self.m_etcd_client.read.return_value = m_resulth

        with patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   side_effect=KeyError):
            self.client.release_ip_by_handle(handle_id)

        self.assertEqual(self.m_etcd_client.update.call_count, 0)

    def test_release_ip_by_handle_no_ips(self):
        """
        Test of release_ip_by_handle when referenced block has no handle IPs.
        """
        # Create the blocks.
        cidr4 = BLOCK_V4_1
        ip4 = BLOCK_V4_1[13]
        handle_id = "handle_id_1"

        m_resultb4 = Mock(spec=EtcdResult)
        block4 = _test_block_empty_v4()
        block4.assign(ip4, None, {})
        m_resultb4.key = _block_datastore_key(cidr4)
        m_resultb4.value = block4.to_json()

        # Create the handle and mock.
        handle0 = AllocationHandle(handle_id)
        handle0.increment_block(cidr4, 1)

        m_resulth = Mock(spec=EtcdResult)
        m_resulth.value = handle0.to_json()
        m_resulth.key = _handle_datastore_key(handle_id)
        m_resulth.modifiedIndex = 55555

        # Mock out read.
        read_results = {m_resulth.key: m_resulth,
                        m_resultb4.key: m_resultb4}
        def read(key, quorum):
            assert quorum
            return read_results[key]
        self.m_etcd_client.read.side_effect = read

        self.client.release_ip_by_handle(handle_id)
        self.assertEqual(self.m_etcd_client.update.call_count, 0)

    def test_unassign_address(self):
        """
        Basic test of unassign_address
        """
        ip4 = BLOCK_V4_1[13]
        m_result4 = Mock(spec=EtcdResult)

        def m_read_block(_self, block_cidr):
            block4 = _test_block_empty_v4()
            block4.assign(ip4, None, {})
            block4.db_result = m_result4
            if block_cidr == block4.cidr:
                return block4
            assert_true(False, "Unexpected block CIDR")

        with patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   m_read_block):
            pool = IPPool("10.11.0.0/16")
            success = self.client.unassign_address(pool, ip4)
            assert_true(success)

        self.m_etcd_client.update.assert_called_once_with(m_result4)

    def test_unassign_address_fails(self):
        """
        Test of unassign_address when it fails
        """
        ip4 = BLOCK_V4_1[13]
        m_result4 = Mock(spec=EtcdResult)

        def m_read_block(_self, block_cidr):
            block4 = _test_block_empty_v4()
            block4.db_result = m_result4
            if block_cidr == block4.cidr:
                return block4
            assert_true(False, "Unexpected block CIDR")

        with patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   m_read_block):
            pool = IPPool("10.11.0.0/16")
            success = self.client.unassign_address(pool, ip4)
            assert_false(success)

        assert_false(self.m_etcd_client.update.called)

    def test_get_ip_assignments_by_handle(self):
        """
        Test get_ip_assignments_by_handle() mainline.
        """
        # Create the blocks and mock out _read_block
        cidr4 = BLOCK_V4_1
        cidr6 = IPNetwork("2001:abcd:def0::/122")
        ip4 = BLOCK_V4_1[13]
        ip6 = BLOCK_V6_1[45]
        handle_id0 = "handle_id_1"

        block4 = _test_block_empty_v4()
        block4.assign(ip4, handle_id0, {})
        block6 = _test_block_empty_v6()
        block6.assign(ip6, handle_id0, {})

        def m_read_block(_self, block_cidr):
            if block_cidr == block4.cidr:
                return block4
            if block_cidr == block6.cidr:
                return block6
            assert_true(False, "Unexpected block CIDR")

        # Create the handle and mock out read.
        handle0 = AllocationHandle(handle_id0)
        handle0.increment_block(cidr4, 5)
        handle0.increment_block(cidr6, 3)

        def m_read_handle(_self, handle_id):
            assert_equal(handle_id0, handle_id)
            return handle0

        with patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   m_read_block), \
            patch("pycalico.ipam.BlockHandleReaderWriter._read_handle",
                  m_read_handle):
            expected_ips = [ip4, ip6]
            ips = self.client.get_ip_assignments_by_handle(handle_id0)
            assert_items_equal(expected_ips, ips)

        # Test when block doesn't exist.
        with patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   side_effect=KeyError), \
            patch("pycalico.ipam.BlockHandleReaderWriter._read_handle",
                  m_read_handle):
            ips = self.client.get_ip_assignments_by_handle(handle_id0)
            assert_list_equal([], ips)

    def test_get_assignment_attributes(self):
        """
        Test get_assignment_attributes() mainline.
        """
        # Create the blocks and mock out _read_block
        ip4 = BLOCK_V4_1[13]
        ip6 = BLOCK_V6_1[45]
        handle_id4 = "handle_id_4"
        handle_id6 = "handle_id_6"
        attr4 = {"aaa": "bbb"}
        attr6 = {"ccd": "ddd"}

        block4 = _test_block_empty_v4()
        block4.assign(ip4, handle_id4, attr4)
        block6 = _test_block_empty_v6()
        block6.assign(ip6, handle_id6, attr6)

        def m_read_block(_self, block_cidr):
            if block_cidr == block4.cidr:
                return block4
            if block_cidr == block6.cidr:
                return block6
            raise KeyError(str(block_cidr))

        with patch("pycalico.ipam.BlockHandleReaderWriter._read_block",
                   m_read_block):
            attr = self.client.get_assignment_attributes(ip4)
            assert_dict_equal(attr, attr4)
            attr = self.client.get_assignment_attributes(ip6)
            assert_dict_equal(attr, attr6)

            assert_raises(AddressNotAssignedError,
                          self.client.get_assignment_attributes,
                          IPAddress("10.11.13.13"))


class TestBlockHandleReaderWriter(unittest.TestCase):

    def setUp(self):
        self.client = BlockHandleReaderWriter()
        self.m_etcd_client = Mock(spec=Client)
        self.client.etcd_client = self.m_etcd_client

    def test_get_affine_blocks(self):
        """
        Test _get_affine_blocks mainline.
        """
        expected_ids = ["192.168.3.0/26", "192.168.5.0/26"]

        # Return some blocks.
        def m_read(path, quorum):
            assert quorum
            assert path == "/calico/ipam/v2/host/test_host/ipv4/block/"
            result = Mock(spec=EtcdResult)
            children = []
            for net in expected_ids:
                node = Mock(spec=EtcdResult)
                node.value = ""
                node.key = path + net.replace("/", "-")
                children.append(node)
            result.children = iter(children)
            return result
        self.m_etcd_client.read.side_effect = m_read

        block_ids = self.client._get_affine_blocks("test_host", 4, None)
        assert_list_equal(block_ids, map(IPNetwork, expected_ids))

    def test_get_affine_blocks_empty(self):
        """
        Test _get_affine_blocks when there are no stored blocks.
        """
        expected_ids = []

        # Return some blocks.
        def m_read(path, quorum):
            assert quorum
            assert path == "/calico/ipam/v2/host/test_host/ipv4/block/"
            result = Mock(spec=EtcdResult)
            result.children = iter([])
            return result
        self.m_etcd_client.read.side_effect = m_read

        block_ids = self.client._get_affine_blocks("test_host", 4, None)
        assert_list_equal(block_ids, expected_ids)

    def test_get_affine_blocks_key_error(self):
        """
        Test _get_affine_blocks when the host key doesn't exist.
        """
        expected_ids = []

        self.m_etcd_client.read.side_effect = EtcdKeyNotFound()

        block_ids = self.client._get_affine_blocks("test_host", 4, None)
        assert_list_equal(block_ids, expected_ids)

    def test_get_affine_blocks_pool(self):
        """
        Test _get_affine_blocks when filtering by IPPool
        """
        expected_ids = [IPNetwork("10.10.1.0/26")]
        returned_ids = ["192.168.3.0/26", "10.10.1.0/26"]

        # Return some blocks.
        def m_read(path, quorum):
            assert quorum
            assert path == "/calico/ipam/v2/host/test_host/ipv4/block/"
            result = Mock(spec=EtcdResult)
            children = []
            for net in returned_ids:
                node = Mock(spec=EtcdResult)
                node.value = ""
                node.key = path + net.replace("/", "-")
                children.append(node)
            result.children = iter(children)
            return result
        self.m_etcd_client.read.side_effect = m_read

        ip_pool = IPPool(IPNetwork("10.0.0.0/8"))
        block_ids = self.client._get_affine_blocks("test_host", 4, ip_pool)
        assert_list_equal(block_ids, expected_ids)

    def test_claim_block_affinity_already_owned(self):
        """
        Test _claim_block_affinity() when we already own the block

        Order of events
        1 Write host affinity
        2 Try to write the new block, but this fails.
        3 Read the block, check its affinity
        """

        block = _test_block_empty_v4()
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block.to_json()

        # Reads at 3
        self.m_etcd_client.read.return_value = m_result0

        # Write at 1, 2
        self.m_etcd_client.write.side_effect = [None, EtcdAlreadyExist()]

        self.client._claim_block_affinity(block.host_affinity,
                                          block.cidr)

        key = _block_datastore_key(block.cidr)
        value = block.to_json()
        self.m_etcd_client.write.assert_has_calls([call(ANY, ""),
                                                   call(key, value,
                                                        prevExist=False)])
        self.m_etcd_client.read.assert_called_once_with(key, quorum=True)

    def test_new_affine_block_race(self):
        """
        Test _new_affine_block when another host claims it between reading
        and writing.

        1 Read shows block is free (EtcdKeyNotFound)
        2 Write host affinity
        3 Try to write the new block, but this fails
        4 Re-read the block, discover another host owns it
        5 Delete key from 2
        6 Read next block, find it free
        7 Write host affinity
        8 Try to write the new block, success
        """

        block = AllocationBlock(IPNetwork("10.11.0.0/26"), "test_host1")
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block.to_json()

        # Reads at 1, 4, 6
        self.m_etcd_client.read.side_effect = [
            EtcdKeyNotFound(),  # 1
            m_result0,  # 4
            EtcdKeyNotFound()  # 6
        ]
        # Write at 2, 3, 7, 8
        self.m_etcd_client.write.side_effect = [
            None,  # 2
            EtcdAlreadyExist(),  # 3
            None,  # 7
            None  # 8
        ]

        def m_get_ip_pools(_self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):

            cidr = self.client._new_affine_block("test_host2", 4, None)
            assert_equal(cidr, IPNetwork("10.11.0.64/26"))

            # 1st block write is the .0.0 block, but with test_host2 affinity.
            key0 = _block_datastore_key(block.cidr)
            block.host_affinity = "test_host2"
            value0 = block.to_json()

            # 2nd block write is the .0.64 block.
            block1 = AllocationBlock(cidr, "test_host2")
            key1 = _block_datastore_key(cidr)
            value1 = block1.to_json()

            self.m_etcd_client.write.assert_has_calls([
                call(ANY, ""),
                call(key0, value0, prevExist=False),
                call(ANY, ""),
                call(key1, value1, prevExist=False)
            ])

    def test_new_affine_block_bad_pool(self):
        """
        Test _new_affine_block when the pool given doesn't match.
        """

        def m_get_ip_pools(_self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            assert_raises(ValueError,
                          self.client._new_affine_block,
                          "test_host1", 4, IPPool("10.11.0.0/8"))

    def test_new_affine_block_good_pool(self):
        """
        Test _new_affine_block limits to a single pool if requested.
        """

        def m_get_ip_pools(_self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        # Reads are always successful
        self.m_etcd_client.read.return_value = Mock(spec=AllocationBlock)

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            assert_raises(NoFreeBlocksError,
                          self.client._new_affine_block,
                          "test_host1", 4, IPPool("10.11.0.0/16"))

            # Two /16 pools means 2048 blocks to try.  Assert that we only
            # work the one pool, or 1024 blocks.
            assert_equal(self.m_etcd_client.read.call_count, 1024)

            # Spot check last call is the last subnet in 10.11.0.0/16 pool.
            assert_equal(self.m_etcd_client.read.call_args[0][0],
                         _block_datastore_key(IPNetwork("10.11.255.192/26")))

    def test_random_blocks(self):
        """
        Test _random_blocks() mainline.
        """
        def m_get_ip_pools(_self, version):
            return [IPPool("10.11.0.0/16")]

        excluded_ids = [IPNetwork("10.11.23.0/26"),
                        BLOCK_V4_2,
                        IPNetwork("10.45.45.0/26")]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            random_blocks = self.client._random_blocks(excluded_ids, 4, None)

            # Excluded 3, but only 2 in the pool, so 1024 - 2 = 1022 blocks.
            assert_equal(len(random_blocks), 1022)

            # Assert we correctly exclude IDs
            for cidr in excluded_ids:
                assert_not_in(cidr, random_blocks)

            # Spot check some cidrs
            assert_in(IPNetwork("10.11.0.0/26"), random_blocks)
            assert_in(IPNetwork("10.11.1.0/26"), random_blocks)
            assert_in(IPNetwork("10.11.255.192/26"), random_blocks)
            assert_in(IPNetwork("10.11.127.0/26"), random_blocks)

            # check we aren't doing something stupid, like returning the same
            # order every time.
            random_blocks2 = self.client._random_blocks(excluded_ids, 4, None)
            assert_equal(len(random_blocks2), 1022)

            differs = False
            for ii in range(len(random_blocks2)):
                assert_in(random_blocks2[ii], random_blocks)
                if random_blocks[ii] != random_blocks2[ii]:
                    differs = True
            assert_true(differs)

    def test_random_blocks_bad_pool(self):
        """
        Test _random_blocks when the requested pool isn't in IPPools.
        """

        def m_get_ip_pools(_self, version):
            return [IPPool("10.11.0.0/16"),
                    IPPool("192.168.0.0/16")]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            assert_raises(ValueError, self.client._random_blocks,
                          [], 4, IPPool("10.1.0.0/16"))

    def test_random_blocks_good_pool(self):
        """
        Test _random_blocks() when restricted to a single pool.
        """
        def m_get_ip_pools(_self, version):
            return [IPPool("10.45.0.0/16"),
                    IPPool("10.11.0.0/16")]

        excluded_ids = [IPNetwork("10.11.23.0/26"),
                        BLOCK_V4_2,
                        IPNetwork("10.45.45.0/26")]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            random_blocks = self.client._random_blocks(excluded_ids, 4,
                                                       IPPool("10.11.0.0/16"))

            # Excluded 3, but only 2 in the pool, so 1024 - 2 = 1022 blocks.
            assert_equal(len(random_blocks), 1022)

            # Assert we correctly exclude IDs
            for cidr in excluded_ids:
                assert_not_in(cidr, random_blocks)

            # Spot check some cidrs
            assert_in(IPNetwork("10.11.0.0/26"), random_blocks)
            assert_in(IPNetwork("10.11.1.0/26"), random_blocks)
            assert_in(IPNetwork("10.11.255.192/26"), random_blocks)
            assert_in(IPNetwork("10.11.127.0/26"), random_blocks)

    def test_increment_handle_exists(self):
        """
        Test _increment_handle() when the handle exists.

        """

        handle_id = "handle_id_1"
        block_cidr = BLOCK_V4_1
        amount = 10

        handle = AllocationHandle(handle_id)
        m_result = Mock(spec=EtcdResult)
        m_result.value = handle.to_json()
        self.m_etcd_client.read.return_value = m_result

        self.client._increment_handle(handle_id, block_cidr, amount)

        assert_equal(self.m_etcd_client.read.call_count, 1)
        self.m_etcd_client.update.assert_called_once_with(m_result)

        # Verify we incremented the handle.
        handle2 = AllocationHandle.from_etcd_result(m_result)
        assert_equal(handle2.decrement_block(block_cidr, amount), 0)

    def test_increment_handle_doesnt_exist(self):
        """
        Test _increment_handle() when the handle doesn't exist.

        """

        handle_id = "handle_id_1"
        block_cidr = BLOCK_V4_1
        amount = 10

        self.m_etcd_client.read.side_effect = EtcdKeyNotFound()

        self.client._increment_handle(handle_id, block_cidr, amount)

        assert_equal(self.m_etcd_client.read.call_count, 1)

        handle = AllocationHandle(handle_id)
        handle.increment_block(block_cidr, amount)
        self.m_etcd_client.write.assert_called_once_with(ANY,
                                                         handle.to_json(),
                                                         prevExist=False)

    def test_increment_handle_exists_cas_error(self):
        """
        Test _increment_handle() when it exists, but there is a CAS error.

        """

        handle_id = "handle_id_1"
        block_cidr = BLOCK_V4_1
        amount = 10

        handle0 = AllocationHandle(handle_id)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = handle0.to_json()

        handle1 = AllocationHandle(handle_id)
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = handle1.to_json()
        self.m_etcd_client.read.side_effect = [m_result0, m_result1]

        # Fail, then success.
        self.m_etcd_client.update.side_effect = [CASError(),
                                                 None]

        self.client._increment_handle(handle_id, block_cidr, amount)

        assert_equal(self.m_etcd_client.read.call_count, 2)
        assert_equal(self.m_etcd_client.update.call_count, 2)

        # Verify we incremented the handle.
        handle2 = AllocationHandle.from_etcd_result(m_result1)
        assert_equal(handle2.decrement_block(block_cidr, amount), 0)

    def test_increment_handle_doesnt_exist_cas_error(self):
        """
        Test _increment_handle() when it doesn't exist, but there is a CAS
        error.
        """
        handle_id = "handle_id_1"
        block_cidr = BLOCK_V4_1
        amount = 10

        handle1 = AllocationHandle(handle_id)
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = handle1.to_json()
        self.m_etcd_client.read.side_effect = [EtcdKeyNotFound(), m_result1]

        # Write fails, update succeeds.
        self.m_etcd_client.write.side_effect = CASError()

        self.client._increment_handle(handle_id, block_cidr, amount)

        assert_equal(self.m_etcd_client.read.call_count, 2)
        assert_equal(self.m_etcd_client.write.call_count, 1)
        self.m_etcd_client.update.assert_called_once_with(m_result1)

        # Verify we incremented the handle.
        handle2 = AllocationHandle.from_etcd_result(m_result1)
        assert_equal(handle2.decrement_block(block_cidr, amount), 0)

    def test_decrement_handle_exists(self):
        """
        Test _decrement_handle when it exists.
        """

        handle_id = "handle_id_1"
        block_cidr = BLOCK_V4_1
        amount = 10

        handle0 = AllocationHandle(handle_id)
        handle0.increment_block(block_cidr, amount*2)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = handle0.to_json()

        self.m_etcd_client.read.return_value = m_result0

        self.client._decrement_handle(handle_id, block_cidr, amount)
        self.m_etcd_client.update.assert_called_once_with(m_result0)

        # Assert we decremented the handle
        handle2 = AllocationHandle.from_etcd_result(m_result0)
        assert_equal(handle2.decrement_block(block_cidr, amount), 0)

    def test_decrement_handle_does_not_exist(self):
        """
        Test _decrement_handle when it does not exist.
        """

        handle_id = "handle_id_1"
        block_cidr = BLOCK_V4_1
        amount = 10
        self.m_etcd_client.read.side_effect = KeyError

        self.assertRaises(KeyError, self.client._decrement_handle,
                          handle_id, block_cidr, amount)
        self.assertEqual(self.m_etcd_client.update.call_count, 0)

    def test_decrement_handle_empty(self):
        """
        Test _decrement_handle when it empties the handle.
        """

        handle_id = "handle_id_1"
        block_cidr = BLOCK_V4_1
        amount = 10

        handle0 = AllocationHandle(handle_id)
        handle0.increment_block(block_cidr, amount)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = handle0.to_json()
        m_result0.modifiedIndex = 55555

        self.m_etcd_client.read.return_value = m_result0

        self.client._decrement_handle(handle_id, block_cidr, amount)
        self.m_etcd_client.delete.assert_called_once_with(ANY,
                                                          prevIndex=55555)

    def test_decrement_handle_corrupt_count(self):
        """
        Test _decrement_handle when it decrements the address count below 0.
        """

        handle_id = "handle_id_1"
        block_cidr = BLOCK_V4_1
        amount = 10

        handle0 = AllocationHandle(handle_id)
        handle0.increment_block(block_cidr, amount)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = handle0.to_json()
        m_result0.modifiedIndex = 55555

        self.m_etcd_client.read.return_value = m_result0

        self.assertRaises(AddressCountTooLow, self.client._decrement_handle,
                          handle_id, block_cidr, amount + 1)
        self.assertEqual(self.m_etcd_client.delete.call_count, 0)

    def test_decrement_handle_cas_error_empty(self):
        """
        Test _decrement_handle when it maxes out CAS errors.
        """

        handle_id = "handle_id_1"
        block_cidr = BLOCK_V4_1
        amount = 10

        def read(*args, **kwargs):
            handle0 = AllocationHandle(handle_id)
            handle0.increment_block(block_cidr, amount)
            m_result0 = Mock(spec=EtcdResult)
            m_result0.value = handle0.to_json()
            m_result0.modifiedIndex = 55555
            return m_result0

        self.m_etcd_client.read.side_effect = read
        self.m_etcd_client.delete.side_effect = EtcdAlreadyExist

        self.assertRaises(RuntimeError, self.client._decrement_handle,
                          handle_id, block_cidr, amount)

    def test_compare_and_swap_handle_cas_error_update(self):
        """
        Test _compare_and_swap_handle hitting a CAS error on an update.
        """
        handle_id = "handle_id_1"
        block_cidr = BLOCK_V4_1
        amount = 10

        handle0 = AllocationHandle(handle_id)
        handle0.db_result = Mock(spec=EtcdResult)
        handle0.db_result.value = handle0.to_json()
        handle0.db_result.modifiedIndex = 55555
        handle0.increment_block(block_cidr, amount)
        self.m_etcd_client.update.side_effect = EtcdCompareFailed()

        self.assertRaises(CASError, self.client._compare_and_swap_handle,
                          handle0)

    def test_compare_and_swap_handle_cas_error_new(self):
        """
        Test _compare_and_swap_handle hitting a CAS error on adding a new
        handle.
        """
        handle_id = "handle_id_1"
        block_cidr = BLOCK_V4_1
        amount = 10

        handle0 = AllocationHandle(handle_id)
        handle0.increment_block(block_cidr, amount)
        self.m_etcd_client.write.side_effect = EtcdAlreadyExist

        self.assertRaises(CASError, self.client._compare_and_swap_handle,
                          handle0)
