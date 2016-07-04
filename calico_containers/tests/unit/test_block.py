# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
                            NoHostAffinityError,
                            AlreadyAssignedError,
                            AddressNotAssignedError,
                            get_block_cidr_for_address,
                            validate_block_size)
from etcd import EtcdResult

network = IPNetwork("192.168.25.0/26")

BLOCK_V4_1 = IPNetwork("10.11.12.0/26")
BLOCK_V6_1 = IPNetwork("2001:abcd:def0::/122")
TEST_HOST = "test_host1"

class TestAllocationBlock(unittest.TestCase):
    def test_init_block_id(self):

        host = "test_host"
        block = AllocationBlock(network, host, False)
        assert_equal(block.host_affinity, host)
        assert_equal(block.cidr, network)
        assert_equal(block.count_free_addresses(), BLOCK_SIZE)

    def test_to_json(self):
        host = "test_host"
        block = AllocationBlock(network, host, False)

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
        block.unallocated.remove(5)
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
        expected_unallocated = [o for o in range(BLOCK_SIZE)
                                       if o != 5]
        assert_list_equal(json_dict[AllocationBlock.ALLOCATIONS],
                          expected_allocations)
        assert_list_equal(json_dict[AllocationBlock.UNALLOCATED],
                          expected_unallocated)

        # Verify we can read the JSON back in.
        result = Mock(spec=EtcdResult)
        result.value = json_str
        block2 = AllocationBlock.from_etcd_result(result)
        assert_equal(block2.to_json(), json_str)

    def test_from_etcd_result_no_unallocated(self):
        """
        Test the from_etcd_result processing when the allocation order is
        missing (this is allowed since it is a new field).
        """
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
        allocations[4] = 1
        json_dict = {
            AllocationBlock.CIDR: str(network),
            AllocationBlock.AFFINITY: "host:Sammy Davis, Jr.",
            AllocationBlock.STRICT_AFFINITY: True,
            AllocationBlock.ALLOCATIONS: allocations,
            AllocationBlock.ATTRIBUTES: [attr0, attr1]
        }
        result.value = json.dumps(json_dict)

        block = AllocationBlock.from_etcd_result(result)
        assert_equal(block.count_free_addresses(), BLOCK_SIZE - 3)
        assert_equal(block.db_result, result)
        assert_equal(block.cidr, network)
        assert_equal(block.host_affinity, "Sammy Davis, Jr.")
        assert_true(block.strict_affinity)
        assert_list_equal(block.allocations[:5], [0, 0, None, None, 1])
        assert_dict_equal(block.attributes[0], attr0)
        assert_dict_equal(block.attributes[1], attr1)

        # Verify the allocation order is correctly calculated from the
        # unassigned entries.
        unallocated = [o for o in range(BLOCK_SIZE)
                              if o not in (0, 1, 4)]
        assert_list_equal(block.unallocated, unallocated)

        # Verify we can get JSON back out.
        json_dict[AllocationBlock.UNALLOCATED] = unallocated
        assert_equal(json.dumps(json_dict), block.to_json())

    def test_from_etcd_result(self):
        """
        Mainline test of from_etcd_result()
        """

        result = Mock(spec=EtcdResult)

        # Build a JSON object for the Block.  Assume the strict_affinity flag is
        # not present so that we default the value (to False).
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
        unallocated = list(range(3, BLOCK_SIZE))
        json_dict = {
            AllocationBlock.CIDR: str(network),
            AllocationBlock.AFFINITY: "host:Sammy Davis, Jr.",
            AllocationBlock.ALLOCATIONS: allocations,
            AllocationBlock.ATTRIBUTES: [attr0, attr1],
            AllocationBlock.UNALLOCATED: unallocated
        }
        result.value = json.dumps(json_dict)

        block = AllocationBlock.from_etcd_result(result)
        assert_equal(block.count_free_addresses(), BLOCK_SIZE - 3)
        assert_equal(block.db_result, result)
        assert_equal(block.cidr, network)
        assert_equal(block.host_affinity, "Sammy Davis, Jr.")
        assert_false(block.strict_affinity)
        assert_list_equal(block.allocations[:3], [0, 0, 1])
        assert_dict_equal(block.attributes[0], attr0)
        assert_dict_equal(block.attributes[1], attr1)

        # Verify we can get JSON back out.  Note that the strict affinity flag
        # will now be present.
        json_dict[AllocationBlock.STRICT_AFFINITY] = False
        json_str = block.to_json()
        assert_equal(json.dumps(json_dict), json_str)

        # Modify the allocation order in the JSON so that it does not match
        # the allocations, and check the various unallocated asserts.
        # Check repeats
        json_dict[AllocationBlock.UNALLOCATED] = unallocated + [3]
        result.value = json.dumps(json_dict)
        self.assertRaises(AssertionError,
                          AllocationBlock.from_etcd_result, result)
        # Check invalid entry
        json_dict[AllocationBlock.UNALLOCATED] = unallocated + [0]
        result.value = json.dumps(json_dict)
        self.assertRaises(AssertionError,
                          AllocationBlock.from_etcd_result, result)
        # Check missing entry
        json_dict[AllocationBlock.UNALLOCATED] = unallocated[1:]
        result.value = json.dumps(json_dict)
        self.assertRaises(AssertionError,
                          AllocationBlock.from_etcd_result, result)

    def test_update_result_from_pre_unallocated(self):
        """
        Test mainline update_result() processing.

        This includes a check to ensure that updating a block that is stored
        without the allocation order is then correctly updated to include the
        allocation order.
        """

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
            AllocationBlock.AFFINITY: "",   # Test a block with no affinity
            AllocationBlock.STRICT_AFFINITY: False,
            AllocationBlock.ALLOCATIONS: allocations,
            AllocationBlock.ATTRIBUTES: [attr0, attr1]
        }
        result.value = json.dumps(json_dict)

        block = AllocationBlock.from_etcd_result(result)

        # Verify the block has no affinity
        assert_equal(block.host_affinity, None)

        # Verify that the allocation order is correctly initialised.
        unallocated = list(range(3, BLOCK_SIZE))
        assert_list_equal(block.unallocated, unallocated)

        # Modify the block (and the expected allocation order)
        block.allocations[3] = 1
        block.unallocated.remove(3)
        unallocated.remove(3)

        # Get the update.  It should be the same result object, but with the
        # value set to the new JSON.
        block_json_str = block.to_json()
        updated = block.update_result()
        assert_equal(updated, result)
        assert_equal(result.value, block_json_str)

        # Verify the update appears in the JSON and that the JSON now includes
        # the allocation order.
        json_dict[AllocationBlock.UNALLOCATED] = unallocated
        block_json_dict = json.loads(block_json_str)
        json_dict[AllocationBlock.ALLOCATIONS][3] = 1
        assert_dict_equal(block_json_dict, json_dict)

    def test_auto_assign_v4(self):
        block0 = _test_block_empty_v4()

        attr = {"key21": "value1", "key22": "value2"}
        ips = block0.auto_assign(1, "key2", attr, TEST_HOST)
        assert_list_equal([BLOCK_V4_1[0]], ips)
        assert_equal(block0.attributes[0][AllocationBlock.ATTR_HANDLE_ID],
                     "key2")
        assert_dict_equal(block0.attributes[0][AllocationBlock.ATTR_SECONDARY],
                          attr)
        assert_equal(block0.count_free_addresses(), BLOCK_SIZE - 1)

        # Allocate again from the first block, with a different key.
        ips = block0.auto_assign(3, "key3", attr, TEST_HOST)
        assert_list_equal([BLOCK_V4_1[1],
                           BLOCK_V4_1[2],
                           BLOCK_V4_1[3]], ips)
        assert_equal(block0.attributes[1][AllocationBlock.ATTR_HANDLE_ID],
                     "key3")
        assert_dict_equal(block0.attributes[1][AllocationBlock.ATTR_SECONDARY],
                          attr)
        assert_equal(block0.count_free_addresses(), BLOCK_SIZE - 4)

        # Allocate with different attributes.
        ips = block0.auto_assign(3, "key3", {}, TEST_HOST)
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
        ips = block1.auto_assign(3, "key2", attr, TEST_HOST)
        assert_list_equal([BLOCK_V4_1[0],
                           BLOCK_V4_1[1],
                           BLOCK_V4_1[2]], ips)
        assert_equal(block1.count_free_addresses(), BLOCK_SIZE - 3)

        # Allocate again with same keys.
        ips = block1.auto_assign(3, "key2", attr, TEST_HOST)
        assert_list_equal([BLOCK_V4_1[3],
                           BLOCK_V4_1[4],
                           BLOCK_V4_1[5]], ips)
        assert_equal(block1.count_free_addresses(), BLOCK_SIZE - 6)
        # Assert we didn't create another attribute entry.
        assert_equal(len(block1.attributes), 1)

        # Test allocating 0 IPs with a new key.
        ips = block1.auto_assign(0, "key3", attr, TEST_HOST)
        assert_list_equal(ips, [])
        assert_equal(len(block1.attributes), 1)
        assert_equal(block1.count_free_addresses(), BLOCK_SIZE - 6)

        # Allocate addresses, so the block is nearly full
        ips = block1.auto_assign(BLOCK_SIZE - 8, None, {}, TEST_HOST)
        assert_equal(len(ips), BLOCK_SIZE - 8)
        assert_equal(block1.count_free_addresses(), 2)

        # Allocate 4 addresses.  Only 2 addresses left.
        ips = block1.auto_assign(4, None, {}, TEST_HOST)
        assert_list_equal([BLOCK_V4_1[-2],
                           BLOCK_V4_1[-1]], ips)
        assert_equal(block1.count_free_addresses(), 0)

        # Block is now full, further attempts return no addresses
        ips = block1.auto_assign(4, None, {}, TEST_HOST)
        assert_list_equal([], ips)

        # Test that we can cope with already allocated addresses that aren't
        # sequential.
        block2 = _test_block_not_empty_v4()
        ips = block2.auto_assign(4, None, {}, TEST_HOST)
        assert_list_equal([BLOCK_V4_1[0],
                           BLOCK_V4_1[1],
                           BLOCK_V4_1[3],
                           BLOCK_V4_1[5]], ips)
        assert_equal(block2.count_free_addresses(), BLOCK_SIZE - 6)


    def test_auto_assign_v6(self):
        block0 = _test_block_empty_v6()

        attr = {"key21": "value1", "key22": "value2"}
        ips = block0.auto_assign(1, "key2", attr, TEST_HOST)
        assert_list_equal([BLOCK_V6_1[0]], ips)
        assert_equal(block0.attributes[0][AllocationBlock.ATTR_HANDLE_ID],
                     "key2")
        assert_dict_equal(block0.attributes[0][AllocationBlock.ATTR_SECONDARY],
                          attr)
        assert_equal(block0.count_free_addresses(), BLOCK_SIZE - 1)

        # Allocate again from the first block, with a different key.
        ips = block0.auto_assign(3, "key3", attr, TEST_HOST)
        assert_list_equal([BLOCK_V6_1[1],
                           BLOCK_V6_1[2],
                           BLOCK_V6_1[3]], ips)
        assert_equal(block0.attributes[1][AllocationBlock.ATTR_HANDLE_ID],
                     "key3")
        assert_dict_equal(block0.attributes[1][AllocationBlock.ATTR_SECONDARY],
                          attr)
        assert_equal(block0.count_free_addresses(), BLOCK_SIZE - 4)

        # Allocate with different attributes.
        ips = block0.auto_assign(3, "key3", {}, TEST_HOST)
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
        ips = block1.auto_assign(3, "key2", attr, TEST_HOST)
        assert_list_equal([BLOCK_V6_1[0],
                           BLOCK_V6_1[1],
                           BLOCK_V6_1[2]], ips)
        assert_equal(block1.count_free_addresses(), BLOCK_SIZE - 3)

        # Allocate again with same keys.
        ips = block1.auto_assign(3, "key2", attr, TEST_HOST)
        assert_list_equal([BLOCK_V6_1[3],
                           BLOCK_V6_1[4],
                           BLOCK_V6_1[5]], ips)
        assert_equal(block1.count_free_addresses(), BLOCK_SIZE - 6)
        # Assert we didn't create another attribute entry.
        assert_equal(len(block1.attributes), 1)

        # Test allocating 0 IPs with a new key.
        ips = block1.auto_assign(0, "key3", attr, TEST_HOST)
        assert_list_equal(ips, [])
        assert_equal(len(block1.attributes), 1)
        assert_equal(block1.count_free_addresses(), BLOCK_SIZE - 6)

        # Allocate addresses, so the block is nearly full
        ips = block1.auto_assign(BLOCK_SIZE - 8, None, {}, TEST_HOST)
        assert_equal(len(ips), BLOCK_SIZE - 8)
        assert_equal(block1.count_free_addresses(), 2)

        # Allocate 4 addresses.  248+3+3 = 254, so only 2 addresses left
        ips = block1.auto_assign(4, None, {}, TEST_HOST)
        assert_list_equal([BLOCK_V6_1[-2],
                           BLOCK_V6_1[-1]], ips)
        assert_equal(block1.count_free_addresses(), 0)

        # Block is now full, further attempts return no addresses
        ips = block1.auto_assign(4, None, {}, TEST_HOST)
        assert_list_equal([], ips)

        # Test that we can cope with already allocated addresses that aren't
        # sequential.
        block2 = _test_block_not_empty_v6()
        assert_equal(block2.count_free_addresses(), BLOCK_SIZE - 2)
        ips = block2.auto_assign(4, None, {}, TEST_HOST)
        assert_list_equal([BLOCK_V6_1[0],
                           BLOCK_V6_1[1],
                           BLOCK_V6_1[3],
                           BLOCK_V6_1[5]], ips)
        assert_equal(block2.count_free_addresses(), BLOCK_SIZE - 6)

        # Test ordinal math still works for small IPv6 addresses
        sm_cidr = IPNetwork("::1234:5600/122")
        block3 = AllocationBlock(sm_cidr, "test_host1", False)
        ips = block3.auto_assign(4, None, {}, TEST_HOST)
        assert_list_equal([sm_cidr[0],
                           sm_cidr[1],
                           sm_cidr[2],
                           sm_cidr[3]], ips)
        assert_equal(block3.count_free_addresses(), BLOCK_SIZE - 4)

    def test_auto_assign_wrong_host(self):
        block0 = _test_block_empty_v4()
        assert_raises(NoHostAffinityError, block0.auto_assign, 1, None, {},
                      "DifferentHost")

        # Disable the check.
        ips = block0.auto_assign(1, None, {}, TEST_HOST, affinity_check=False)
        assert_list_equal([BLOCK_V4_1[0]], ips)

    def test_assign_v4(self):
        block0 = _test_block_empty_v4()

        ip0 = BLOCK_V4_1[2]
        attr = {"key21": "value1", "key22": "value2"}
        block0.assign(ip0, "key0", attr, TEST_HOST)

        # Try to assign the same address again.
        assert_raises(AlreadyAssignedError, block0.assign,
                      ip0, "key0", attr, TEST_HOST)

    def test_assign_v6(self):
        block0 = _test_block_empty_v6()

        ip0 = BLOCK_V6_1[2]
        attr = {"key21": "value1", "key22": "value2"}
        block0.assign(ip0, "key0", attr, TEST_HOST)

        # Try to assign the same address again.
        assert_raises(AlreadyAssignedError, block0.assign,
                      ip0, "key0", attr, TEST_HOST)

    def test_assign_v4_strict_affinity(self):
        """
        Test attempting to assign with strict affinity raises an error.
        """
        block0 = _test_block_empty_v4()
        block0.strict_affinity = True

        # Test assign() raises an exception.
        ip0 = BLOCK_V4_1[2]
        attr = {"key21": "value1", "key22": "value2"}
        assert_raises(NoHostAffinityError, block0.assign,
                      ip0, "key0", attr, "Not test host")

        # Test auto_assign() raises an exception regardless of the value of
        # affinity_check.
        assert_raises(NoHostAffinityError, block0.auto_assign,
                      1, "key0", attr, "Not test host", affinity_check=True)
        assert_raises(NoHostAffinityError, block0.auto_assign,
                      1, "key0", attr, "Not test host", affinity_check=False)

    def test_release_v4(self):
        """
        Mainline test of releasing addresses from a block.  This tests that
        numbers just released are not assigned automatically.
        """
        block0 = _test_block_not_empty_v4()
        ip = BLOCK_V4_1[13]
        block0.assign(ip, None, {}, TEST_HOST)

        # We have released 13. Ordinals 2 and 4 are still assigned.
        (err, handles) = block0.release({ip})
        assert_set_equal(err, set())
        assert_is_none(block0.allocations[13])
        assert_equal(13, block0.unallocated[-1])
        assert_equal(len(block0.attributes), 1)
        assert_equal(len(block0.unallocated), 62)

        # New assignments with different attrs, increases number of attrs to 2
        # Assigned ordinals will be [0, 1, 3, 5, 6] and [7, 8, 9, 10, 11].
        ips0 = block0.auto_assign(5, "test_key", {"test": "value"}, TEST_HOST)
        ips1 = block0.auto_assign(5, "test_key", {"test": "value"}, TEST_HOST)
        assert_equal(len(block0.attributes), 2)

        # Release half, still 2 unique attrs
        (err, handles) = block0.release(set(ips0))
        assert_set_equal(err, set())
        assert_equal(len(block0.attributes), 2)

        # Assign 5, should be the next available 5: [12, 14, 15, 16, 17].
        ips2 = block0.auto_assign(5, "test_key", {"test": "value"}, TEST_HOST)
        assert_not_equal(ips2, ips0)
        assert_list_equal(ips2, [BLOCK_V4_1[12],
                                 BLOCK_V4_1[14],
                                 BLOCK_V4_1[15],
                                 BLOCK_V4_1[16],
                                 BLOCK_V4_1[17]])
        assert_equal(len(block0.attributes), 2)

        # Assign additional addresses with new key, 3 attrs stored.
        ips3 = block0.auto_assign(2, "test_key2", {}, TEST_HOST)
        assert_equal(len(block0.attributes), 3)
        assert_equal(block0.allocations[17], 1)
        assert_equal(block0.allocations[18], 2)

        # Release all IPs with 2nd set of attrs, reduced to 2 and renumbered.
        (err, handles) = block0.release(set(ips2 + ips1))
        assert_set_equal(err, set())
        assert_equal(len(block0.attributes), 2)
        assert_equal(block0.allocations[17], None)
        assert_equal(block0.allocations[18], 1)

        # Check that release with already released IP returns the bad IP, but
        # releases the others.
        bad_ips = {BLOCK_V4_1[0]}
        (err, handles) = block0.release(set(ips3).union(bad_ips))
        assert_set_equal(err, bad_ips)
        assert_equal(block0.allocations[17], None)
        assert_equal(block0.allocations[18], None)

    def test_release_v6(self):
        """
        Mainline test of releasing addresses from a block
        """
        block0 = _test_block_not_empty_v6()
        ip = IPAddress("2001:abcd:def0::000d")
        block0.assign(ip, None, {}, TEST_HOST)
        assert_is_not_none(block0.allocations[13])

        # We have released 13. Ordinals 2 and 4 are still assigned.
        (err, handles) = block0.release({ip})
        assert_set_equal(err, set())
        assert_is_none(block0.allocations[13])
        assert_equal(len(block0.attributes), 1)

        # New assignments with different attrs, increases number of attrs to 2
        # Assigned ordinals will be [0, 1, 3, 5, 6] and [7, 8, 9, 10, 11].
        ips0 = block0.auto_assign(5, "test_key", {"test": "value"}, TEST_HOST)
        ips1 = block0.auto_assign(5, "test_key", {"test": "value"}, TEST_HOST)
        assert_equal(len(block0.attributes), 2)

        # Release half, still 2 unique attrs
        (err, handles) = block0.release(set(ips0))
        assert_set_equal(err, set())
        assert_equal(len(block0.attributes), 2)

        # Assign 5, should be the next available 5: [12, 14, 15, 16, 17].
        ips2 = block0.auto_assign(5, "test_key", {"test": "value"}, TEST_HOST)
        assert_not_equal(ips2, ips0)
        assert_list_equal(ips2, [BLOCK_V6_1[12],
                                 BLOCK_V6_1[14],
                                 BLOCK_V6_1[15],
                                 BLOCK_V6_1[16],
                                 BLOCK_V6_1[17]])
        assert_equal(len(block0.attributes), 2)

        # Assign additional addresses with new key, 3 attrs stored.
        ips3 = block0.auto_assign(2, "test_key2", {}, TEST_HOST)
        assert_equal(len(block0.attributes), 3)
        assert_equal(block0.allocations[17], 1)
        assert_equal(block0.allocations[18], 2)

        # Release all IPs with 2nd set of attrs, reduced to 2 and renumbered.
        (err, handles) = block0.release(set(ips2 + ips1))
        assert_set_equal(err, set())
        assert_equal(len(block0.attributes), 2)
        assert_equal(block0.allocations[17], None)
        assert_equal(block0.allocations[18], 1)

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
        block0.assign(ip0, None, {}, TEST_HOST)
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
        block0.assign(ip0, handle0, attr0, TEST_HOST)
        (handle, attr) = block0.get_attributes_for_ip(ip0)
        assert_equal(handle, handle0)
        assert_dict_equal(attr, attr0)

        ip1 = IPAddress("10.11.12.57")
        assert_raises(AddressNotAssignedError,
                      block0.get_attributes_for_ip, ip1)

    def test_release_by_handle(self):
        """
        Mainline test for release_by_handle()
        """
        block = _test_block_not_empty_v4()
        block.release_by_handle("key1")

        # Check allocations indicate the IPs are now released.
        assert_is_none(block.allocations[2])
        assert_is_none(block.allocations[4])

        # Check that the unallocated list has the released ordinals appended.
        assert_list_equal(block.unallocated[-2:], [2, 4])


class TestBlockFunctions(unittest.TestCase):

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

    def test_validate_block_size(self):
        """
        Test validate_block_size()
        """
        assert_equal(validate_block_size(IPNetwork("1.2.3.4/1")), True)
        assert_equal(validate_block_size(IPNetwork("1.2.3.4/26")), True)
        assert_equal(validate_block_size(IPNetwork("1.2.3.4/27")), False)
        assert_equal(validate_block_size(IPNetwork("1.2.3.4/32")), False)


def _test_block_empty_v4():
    block = AllocationBlock(BLOCK_V4_1, "test_host1", False)
    return block


def _test_block_not_empty_v4():
    block = _test_block_empty_v4()

    attr = {AllocationBlock.ATTR_HANDLE_ID: "key1",
            AllocationBlock.ATTR_SECONDARY: {"key21": "value1",
                                             "key22": "value2"}}
    block.attributes.append(attr)
    block.allocations[2] = 0
    block.allocations[4] = 0
    block.unallocated.remove(2)
    block.unallocated.remove(4)
    return block


def _test_block_empty_v6():
    block = AllocationBlock(BLOCK_V6_1, "test_host1", False)
    return block


def _test_block_not_empty_v6():
    block = _test_block_empty_v6()

    attr = {AllocationBlock.ATTR_HANDLE_ID: "key1",
            AllocationBlock.ATTR_SECONDARY: {"key21": "value1",
                                             "key22": "value2"}}
    block.attributes.append(attr)
    block.allocations[2] = 0
    block.allocations[4] = 0
    block.unallocated.remove(2)
    block.unallocated.remove(4)
    return block
