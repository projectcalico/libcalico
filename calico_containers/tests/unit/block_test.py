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
from netaddr import IPNetwork, IPAddress
from nose.tools import *
from nose_parameterized import parameterized
from mock import patch, Mock
import unittest
import json
from pycalico.block import (AllocationBlock,
                            BLOCK_SIZE,
                            NoHostAffinityWarning,
                            AlreadyAssignedError,
                            AddressNotAssignedError,
                            get_block_cidr_for_address)
from etcd import EtcdResult

network = IPNetwork("192.168.25.0/26")

BLOCK_V4_1 = IPNetwork("10.11.12.0/26")
BLOCK_V6_1 = IPNetwork("2001:abcd:def0::/122")

class TestAllocationBlock(unittest.TestCase):
    def test_init_block_id(self):

        host = "test_host"
        block = AllocationBlock(network, host)
        assert_equal(block.host_affinity, host)
        assert_equal(block.cidr, network)
        assert_equal(block.count_free_addresses(), BLOCK_SIZE)

    def test_to_json(self):
        host = "test_host"
        block = AllocationBlock(network, host)

        # Set up an allocation
        attr = {
            AllocationBlock.ATTR_HANDLE_ID: "test_key",
            AllocationBlock.ATTR_SECONDARY: {
                "key1": "value1",
                "key2": "value2"
            }
        }
        block.attributes.append(attr)
        block.allocations[5] = 0
        assert_equal(block.count_free_addresses(), BLOCK_SIZE - 1)

        # Read out the JSON
        json_str = block.to_json()
        json_dict = json.loads(json_str)
        assert_equal(json_dict[AllocationBlock.CIDR], str(network))
        assert_equal(json_dict[AllocationBlock.AFFINITY], "host:test_host")
        assert_dict_equal(json_dict[AllocationBlock.ATTRIBUTES][0],
                          attr)
        expected_allocations = [None] * BLOCK_SIZE
        expected_allocations[5] = 0
        assert_list_equal(json_dict[AllocationBlock.ALLOCATIONS],
                          expected_allocations)

        # Verify we can read the JSON back in.
        result = Mock(spec=EtcdResult)
        result.value = json_str
        block2 = AllocationBlock.from_etcd_result(result)
        assert_equal(block2.to_json(), json_str)

    def test_from_etcd_result(self):

        result = Mock(spec=EtcdResult)

        # Build a JSON object for the Block
        attr0 = {
            AllocationBlock.ATTR_HANDLE_ID: "test_key1",
            AllocationBlock.ATTR_SECONDARY: {
                "key1": "value11",
                "key2": "value21"
            }
        }
        attr1 = {
            AllocationBlock.ATTR_HANDLE_ID: "test_key2",
            AllocationBlock.ATTR_SECONDARY: {
                "key1": "value12",
                "key2": "value22"
            }
        }
        allocations = [None] * BLOCK_SIZE
        allocations[0] = 0
        allocations[1] = 0
        allocations[2] = 1
        json_dict = {
            AllocationBlock.CIDR: str(network),
            AllocationBlock.AFFINITY: "host:Sammy Davis, Jr.",
            AllocationBlock.ALLOCATIONS: allocations,
            AllocationBlock.ATTRIBUTES: [attr0, attr1]
        }
        result.value = json.dumps(json_dict)

        block = AllocationBlock.from_etcd_result(result)
        assert_equal(block.count_free_addresses(), BLOCK_SIZE - 3)
        assert_equal(block.db_result, result)
        assert_equal(block.cidr, network)
        assert_equal(block.host_affinity, "Sammy Davis, Jr.")
        assert_list_equal(block.allocations[:3], [0, 0, 1])
        assert_dict_equal(block.attributes[0], attr0)
        assert_dict_equal(block.attributes[1], attr1)

        # Verify we can get JSON back out.
        json_str = block.to_json()
        assert_equal(result.value, json_str)

    def test_update_result(self):

        result = Mock(spec=EtcdResult)

        # Build a JSON object for the Block
        attr0 = {
            AllocationBlock.ATTR_HANDLE_ID: "test_key1",
            AllocationBlock.ATTR_SECONDARY: {
                "key1": "value11",
                "key2": "value21"
            }
        }
        attr1 = {
            AllocationBlock.ATTR_HANDLE_ID: "test_key2",
            AllocationBlock.ATTR_SECONDARY: {
                "key1": "value12",
                "key2": "value22"
            }
        }
        allocations = [None] * BLOCK_SIZE
        allocations[0] = 0
        allocations[1] = 0
        allocations[2] = 1
        json_dict = {
            AllocationBlock.CIDR: str(network),
            AllocationBlock.AFFINITY: "host:Sammy Davis, Jr.",
            AllocationBlock.ALLOCATIONS: allocations,
            AllocationBlock.ATTRIBUTES: [attr0, attr1]
        }
        result.value = json.dumps(json_dict)

        block = AllocationBlock.from_etcd_result(result)

        # Modify the block.
        block.allocations[3] = 1

        # Get the update.  It should be the same result object, but with the
        # value set to the new JSON.
        block_json_str = block.to_json()
        updated = block.update_result()
        assert_equal(updated, result)
        assert_equal(result.value, block_json_str)

        # Verify the update appears in the JSON
        block_json_dict = json.loads(block_json_str)
        json_dict[AllocationBlock.ALLOCATIONS][3] = 1
        assert_dict_equal(block_json_dict, json_dict)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign_v4(self, m_get_hostname):
        block0 = _test_block_empty_v4()

        attr = {"key21": "value1", "key22": "value2"}
        ips = block0.auto_assign(1, "key2", attr)
        assert_list_equal([BLOCK_V4_1[0]], ips)
        assert_equal(block0.attributes[0][AllocationBlock.ATTR_HANDLE_ID],
                     "key2")
        assert_dict_equal(block0.attributes[0][AllocationBlock.ATTR_SECONDARY],
                          attr)
        assert_equal(block0.count_free_addresses(), BLOCK_SIZE - 1)

        # Allocate again from the first block, with a different key.
        ips = block0.auto_assign(3, "key3", attr)
        assert_list_equal([BLOCK_V4_1[1],
                           BLOCK_V4_1[2],
                           BLOCK_V4_1[3]], ips)
        assert_equal(block0.attributes[1][AllocationBlock.ATTR_HANDLE_ID],
                     "key3")
        assert_dict_equal(block0.attributes[1][AllocationBlock.ATTR_SECONDARY],
                          attr)
        assert_equal(block0.count_free_addresses(), BLOCK_SIZE - 4)

        # Allocate with different attributes.
        ips = block0.auto_assign(3, "key3", {})
        assert_list_equal([BLOCK_V4_1[4],
                           BLOCK_V4_1[5],
                           BLOCK_V4_1[6]], ips)
        assert_equal(block0.attributes[2][AllocationBlock.ATTR_HANDLE_ID],
                     "key3")
        assert_dict_equal(block0.attributes[2][AllocationBlock.ATTR_SECONDARY],
                          {})
        assert_equal(block0.count_free_addresses(), BLOCK_SIZE - 7)

        # Allocate 3 from a new block.
        block1 = _test_block_empty_v4()
        ips = block1.auto_assign(3, "key2", attr)
        assert_list_equal([BLOCK_V4_1[0],
                           BLOCK_V4_1[1],
                           BLOCK_V4_1[2]], ips)
        assert_equal(block1.count_free_addresses(), BLOCK_SIZE - 3)

        # Allocate again with same keys.
        ips = block1.auto_assign(3, "key2", attr)
        assert_list_equal([BLOCK_V4_1[3],
                           BLOCK_V4_1[4],
                           BLOCK_V4_1[5]], ips)
        assert_equal(block1.count_free_addresses(), BLOCK_SIZE - 6)
        # Assert we didn't create another attribute entry.
        assert_equal(len(block1.attributes), 1)

        # Test allocating 0 IPs with a new key.
        ips = block1.auto_assign(0, "key3", attr)
        assert_list_equal(ips, [])
        assert_equal(len(block1.attributes), 1)
        assert_equal(block1.count_free_addresses(), BLOCK_SIZE - 6)

        # Allocate addresses, so the block is nearly full
        ips = block1.auto_assign(BLOCK_SIZE - 8, None, {})
        assert_equal(len(ips), BLOCK_SIZE - 8)
        assert_equal(block1.count_free_addresses(), 2)

        # Allocate 4 addresses.  Only 2 addresses left.
        ips = block1.auto_assign(4, None, {})
        assert_list_equal([BLOCK_V4_1[-2],
                           BLOCK_V4_1[-1]], ips)
        assert_equal(block1.count_free_addresses(), 0)

        # Block is now full, further attempts return no addresses
        ips = block1.auto_assign(4, None, {})
        assert_list_equal([], ips)

        # Test that we can cope with already allocated addresses that aren't
        # sequential.
        block2 = _test_block_not_empty_v4()
        ips = block2.auto_assign(4, None, {})
        assert_list_equal([BLOCK_V4_1[0],
                           BLOCK_V4_1[1],
                           BLOCK_V4_1[3],
                           BLOCK_V4_1[5]], ips)
        assert_equal(block2.count_free_addresses(), BLOCK_SIZE - 6)


    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_auto_assign_v6(self, m_get_hostname):
        block0 = _test_block_empty_v6()

        attr = {"key21": "value1", "key22": "value2"}
        ips = block0.auto_assign(1, "key2", attr)
        assert_list_equal([BLOCK_V6_1[0]], ips)
        assert_equal(block0.attributes[0][AllocationBlock.ATTR_HANDLE_ID],
                     "key2")
        assert_dict_equal(block0.attributes[0][AllocationBlock.ATTR_SECONDARY],
                          attr)
        assert_equal(block0.count_free_addresses(), BLOCK_SIZE - 1)

        # Allocate again from the first block, with a different key.
        ips = block0.auto_assign(3, "key3", attr)
        assert_list_equal([BLOCK_V6_1[1],
                           BLOCK_V6_1[2],
                           BLOCK_V6_1[3]], ips)
        assert_equal(block0.attributes[1][AllocationBlock.ATTR_HANDLE_ID],
                     "key3")
        assert_dict_equal(block0.attributes[1][AllocationBlock.ATTR_SECONDARY],
                          attr)
        assert_equal(block0.count_free_addresses(), BLOCK_SIZE - 4)

        # Allocate with different attributes.
        ips = block0.auto_assign(3, "key3", {})
        assert_list_equal([BLOCK_V6_1[4],
                           BLOCK_V6_1[5],
                           BLOCK_V6_1[6]], ips)
        assert_equal(block0.attributes[2][AllocationBlock.ATTR_HANDLE_ID],
                     "key3")
        assert_dict_equal(block0.attributes[2][AllocationBlock.ATTR_SECONDARY],
                          {})
        assert_equal(block0.count_free_addresses(), BLOCK_SIZE - 7)

        # Allocate 3 from a new block.
        block1 = _test_block_empty_v6()
        ips = block1.auto_assign(3, "key2", attr)
        assert_list_equal([BLOCK_V6_1[0],
                           BLOCK_V6_1[1],
                           BLOCK_V6_1[2]], ips)
        assert_equal(block1.count_free_addresses(), BLOCK_SIZE - 3)

        # Allocate again with same keys.
        ips = block1.auto_assign(3, "key2", attr)
        assert_list_equal([BLOCK_V6_1[3],
                           BLOCK_V6_1[4],
                           BLOCK_V6_1[5]], ips)
        assert_equal(block1.count_free_addresses(), BLOCK_SIZE - 6)
        # Assert we didn't create another attribute entry.
        assert_equal(len(block1.attributes), 1)

        # Test allocating 0 IPs with a new key.
        ips = block1.auto_assign(0, "key3", attr)
        assert_list_equal(ips, [])
        assert_equal(len(block1.attributes), 1)
        assert_equal(block1.count_free_addresses(), BLOCK_SIZE - 6)

        # Allocate addresses, so the block is nearly full
        ips = block1.auto_assign(BLOCK_SIZE - 8, None, {})
        assert_equal(len(ips), BLOCK_SIZE - 8)
        assert_equal(block1.count_free_addresses(), 2)

        # Allocate 4 addresses.  248+3+3 = 254, so only 2 addresses left
        ips = block1.auto_assign(4, None, {})
        assert_list_equal([BLOCK_V6_1[-2],
                           BLOCK_V6_1[-1]], ips)
        assert_equal(block1.count_free_addresses(), 0)

        # Block is now full, further attempts return no addresses
        ips = block1.auto_assign(4, None, {})
        assert_list_equal([], ips)

        # Test that we can cope with already allocated addresses that aren't
        # sequential.
        block2 = _test_block_not_empty_v6()
        assert_equal(block2.count_free_addresses(), BLOCK_SIZE - 2)
        ips = block2.auto_assign(4, None, {})
        assert_list_equal([BLOCK_V6_1[0],
                           BLOCK_V6_1[1],
                           BLOCK_V6_1[3],
                           BLOCK_V6_1[5]], ips)
        assert_equal(block2.count_free_addresses(), BLOCK_SIZE - 6)

        # Test ordinal math still works for small IPv6 addresses
        sm_cidr = IPNetwork("::1234:5600/122")
        block3 = AllocationBlock(sm_cidr, "test_host1")
        ips = block3.auto_assign(4, None, {})
        assert_list_equal([sm_cidr[0],
                           sm_cidr[1],
                           sm_cidr[2],
                           sm_cidr[3]], ips)
        assert_equal(block3.count_free_addresses(), BLOCK_SIZE - 4)

    @patch("pycalico.block.get_hostname", return_value="not_the_right_host")
    def test_auto_assign_wrong_host(self, m_get_hostname):
        block0 = _test_block_empty_v4()
        assert_raises(NoHostAffinityWarning, block0.auto_assign, 1, None, {})

        # Disable the check.
        ips = block0.auto_assign(1, None, {}, affinity_check=False)
        assert_list_equal([BLOCK_V4_1[0]], ips)

    def test_assign_v4(self):
        block0 = _test_block_empty_v4()

        ip0 = BLOCK_V4_1[2]
        attr = {"key21": "value1", "key22": "value2"}
        block0.assign(ip0, "key0", attr)

        # Try to assign the same address again.
        assert_raises(AlreadyAssignedError, block0.assign, ip0, "key0", attr)

    def test_assign_v6(self):
        block0 = _test_block_empty_v6()

        ip0 = BLOCK_V6_1[2]
        attr = {"key21": "value1", "key22": "value2"}
        block0.assign(ip0, "key0", attr)

        # Try to assign the same address again.
        assert_raises(AlreadyAssignedError, block0.assign, ip0, "key0", attr)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_release_v4(self, m_get_hostname):
        """
        Mainline test of releasing addresses from a block
        """
        block0 = _test_block_not_empty_v4()
        ip = BLOCK_V4_1[13]
        block0.assign(ip, None, {})

        (err, handles) = block0.release({ip})
        assert_set_equal(err, set())
        assert_is_none(block0.allocations[13])
        assert_equal(len(block0.attributes), 1)

        # New assignments with different attrs, increases number of attrs to 2
        ips0 = block0.auto_assign(5, "test_key", {"test": "value"})
        ips1 = block0.auto_assign(5, "test_key", {"test": "value"})
        assert_equal(len(block0.attributes), 2)

        # Release half, still 2 unique attrs
        (err, handles) = block0.release(set(ips0))
        assert_set_equal(err, set())
        assert_equal(len(block0.attributes), 2)

        # Reassign 5, should be the same 5 just released.
        ips2 = block0.auto_assign(5, "test_key", {"test": "value"})
        assert_list_equal(ips2, ips0)
        assert_equal(len(block0.attributes), 2)

        # Assign additional addresses with new key, 3 attrs stored.
        ips3 = block0.auto_assign(2, "test_key2", {})
        assert_equal(len(block0.attributes), 3)
        assert_equal(block0.allocations[11], 1)
        assert_equal(block0.allocations[12], 2)

        # Release all IPs with 2nd set of attrs, reduced to 2 and renumbered.
        (err, handles) = block0.release(set(ips2 + ips1))
        assert_set_equal(err, set())
        assert_equal(len(block0.attributes), 2)
        assert_equal(block0.allocations[11], None)
        assert_equal(block0.allocations[12], 1)

        # Check that release with already released IP returns the bad IP, but
        # releases the others.
        bad_ips = {BLOCK_V4_1[0]}
        (err, handles) = block0.release(set(ips3).union(bad_ips))
        assert_set_equal(err, bad_ips)
        assert_equal(block0.allocations[12], None)
        assert_equal(block0.allocations[13], None)

    @patch("pycalico.block.get_hostname", return_value="test_host1")
    def test_release_v6(self, m_get_hostname):
        """
        Mainline test of releasing addresses from a block
        """
        block0 = _test_block_not_empty_v6()
        ip = IPAddress("2001:abcd:def0::13")
        block0.assign(ip, None, {})

        (err, handles) = block0.release({ip})
        assert_set_equal(err, set())
        assert_is_none(block0.allocations[13])
        assert_equal(len(block0.attributes), 1)

        # New assignments with different attrs, increases number of attrs to 2
        ips0 = block0.auto_assign(5, "test_key", {"test": "value"})
        ips1 = block0.auto_assign(5, "test_key", {"test": "value"})
        assert_equal(len(block0.attributes), 2)

        # Release half, still 2 unique attrs
        (err, handles) = block0.release(set(ips0))
        assert_set_equal(err, set())
        assert_equal(len(block0.attributes), 2)

        # Reassign 5, should be the same 5 just released.
        ips2 = block0.auto_assign(5, "test_key", {"test": "value"})
        assert_list_equal(ips2, ips0)
        assert_equal(len(block0.attributes), 2)

        # Assign additional addresses with new key, 3 attrs stored.
        ips3 = block0.auto_assign(2, "test_key2", {})
        assert_equal(len(block0.attributes), 3)
        assert_equal(block0.allocations[11], 1)
        assert_equal(block0.allocations[12], 2)

        # Release all IPs with 2nd set of attrs, reduced to 2 and renumbered.
        (err, handles) = block0.release(set(ips2 + ips1))
        assert_set_equal(err, set())
        assert_equal(len(block0.attributes), 2)
        assert_equal(block0.allocations[11], None)
        assert_equal(block0.allocations[12], 1)

        # Check that release with already released IP returns the bad IP, but
        # releases the others.
        bad_ips = {IPAddress("2001:abcd:def0::")}
        (err, handles) = block0.release(set(ips3).union(bad_ips))
        assert_set_equal(err, bad_ips)
        assert_equal(block0.allocations[12], None)
        assert_equal(block0.allocations[13], None)

    def test_get_ip_assignments_by_handle(self):
        """
        Mainline test for get_ip_assignments_by_handle()
        """
        block0 = _test_block_not_empty_v4()
        ips = block0.get_ip_assignments_by_handle("key1")
        assert_list_equal(ips, [IPAddress("10.11.12.2"),
                                IPAddress("10.11.12.4")])

        ip0 = IPAddress("10.11.12.56")
        block0.assign(ip0, None, {})
        ips = block0.get_ip_assignments_by_handle(None)
        assert_list_equal(ips, [ip0])

        ips = block0.get_ip_assignments_by_handle("this_handle_doesnt_exist")
        assert_list_equal(ips, [])

    def test_get_attributes_for_ip(self):
        """
        Mainline test for get_attributes_for_ip()
        """
        block0 = _test_block_not_empty_v4()
        (handle, attrs) = block0.get_attributes_for_ip(IPAddress("10.11.12.2"))
        assert_equal(handle, "key1")
        assert_dict_equal(attrs, {"key21": "value1", "key22": "value2"})

        ip0 = IPAddress("10.11.12.56")
        attr0 = {"a": 1, "b": 2, "c": 3}
        handle0 = "key0"
        block0.assign(ip0, handle0, attr0)
        (handle, attr) = block0.get_attributes_for_ip(ip0)
        assert_equal(handle, handle0)
        assert_dict_equal(attr, attr0)

        ip1 = IPAddress("10.11.12.57")
        assert_raises(AddressNotAssignedError,
                      block0.get_attributes_for_ip, ip1)


class TestGetBlockCIDRForAddress(unittest.TestCase):

    @parameterized.expand([
        (IPAddress("192.168.3.7"),
         IPNetwork("192.168.3.0/26")),
        (IPAddress("10.34.11.75"),
         IPNetwork("10.34.11.64/26")),
        (IPAddress("2001:abee:beef::1234"),
         IPNetwork("2001:abee:beef::1200/122")),
        (IPAddress("2001:abee:beef::"),
         IPNetwork("2001:abee:beef::/122")),
    ])
    def test_get_block_cidr(self, address, cidr):
        """
        Test get_block_cidr_for_address
        """
        block_id = get_block_cidr_for_address(address)
        assert_equal(block_id, cidr)


def _test_block_empty_v4():
    block = AllocationBlock(BLOCK_V4_1, "test_host1")
    return block


def _test_block_not_empty_v4():
    block = _test_block_empty_v4()

    attr = {AllocationBlock.ATTR_HANDLE_ID: "key1",
            AllocationBlock.ATTR_SECONDARY: {"key21": "value1",
                                             "key22": "value2"}}
    block.attributes.append(attr)
    block.allocations[2] = 0
    block.allocations[4] = 0
    return block


def _test_block_empty_v6():
    block = AllocationBlock(BLOCK_V6_1, "test_host1")
    return block


def _test_block_not_empty_v6():
    block = _test_block_empty_v6()

    attr = {AllocationBlock.ATTR_HANDLE_ID: "key1",
            AllocationBlock.ATTR_SECONDARY: {"key21": "value1",
                                             "key22": "value2"}}
    block.attributes.append(attr)
    block.allocations[2] = 0
    block.allocations[4] = 0
    return block
