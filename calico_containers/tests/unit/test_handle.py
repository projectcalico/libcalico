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
from nose.tools import *
from mock import Mock
import unittest
import json
from pycalico.handle import (AllocationHandle, AddressCountTooLow)
from etcd import EtcdResult


class TestAllocationHandle(unittest.TestCase):

    def test_to_json(self):

        handle = AllocationHandle("test_id")

        expected_json = {AllocationHandle.HANDLE_ID: "test_id",
                         AllocationHandle.BLOCK: {}}
        json_str = handle.to_json()
        json_result = json.loads(json_str)
        assert_dict_equal(expected_json, json_result)

        block_cidr = IPNetwork("10.11.12.0/24")
        handle.increment_block(block_cidr, 5)

        expected_json[AllocationHandle.BLOCK]["10.11.12.0/24"] = 5
        json_str = handle.to_json()
        json_result = json.loads(json_str)
        assert_dict_equal(expected_json, json_result)

        block_cidr2 = IPNetwork("10.11.45.0/24")
        handle.increment_block(block_cidr2, 20)

        expected_json[AllocationHandle.BLOCK]["10.11.45.0/24"] = 20
        json_str = handle.to_json()
        json_result = json.loads(json_str)
        assert_dict_equal(expected_json, json_result)

    def test_from_etcd_result(self):

        block_dict = {
            "10.23.24.0/24": 50,
            "10.23.35.0/24": 60
        }
        json_dict = {
            AllocationHandle.HANDLE_ID: "test_id2",
            AllocationHandle.BLOCK: block_dict
        }
        m_result = Mock(spec=EtcdResult)
        m_result.value = json.dumps(json_dict)

        handle = AllocationHandle.from_etcd_result(m_result)

        assert_dict_equal(block_dict, handle.block)
        assert_equal(m_result, handle.db_result)

        # Convert to JSON and back
        m_result.value = handle.to_json()
        handle2 = AllocationHandle.from_etcd_result(m_result)
        assert_equal(block_dict, handle2.block)

    def test_update_result(self):

        block_dict = {
            "10.23.24.0/24": 50,
            "10.23.35.0/24": 60
        }
        json_dict = {
            AllocationHandle.HANDLE_ID: "test_id2",
            AllocationHandle.BLOCK: block_dict
        }
        m_result = Mock(spec=EtcdResult)
        m_result.value = json.dumps(json_dict)

        handle = AllocationHandle.from_etcd_result(m_result)
        handle.decrement_block(IPNetwork("10.23.35.0/24"), 15)

        result = handle.update_result()
        assert_equal(result, m_result)
        result_json = json.loads(result.value)
        assert_equal(result_json[AllocationHandle.BLOCK]["10.23.35.0/24"],
                     45)

    def test_inc_dec_block(self):
        block = [IPNetwork("10.11.12.0/24"),
                 IPNetwork("2001:abcd:def0::/120"),
                 IPNetwork("192.168.1.0")]

        handle = AllocationHandle("tst_id1")

        result = handle.increment_block(block[0], 20)
        assert_equal(result, 20)

        result = handle.decrement_block(block[0], 15)
        assert_equal(result, 5)

        assert_raises(AddressCountTooLow,
                      handle.decrement_block, block[1], 1)

        result = handle.increment_block(block[1], 1)
        assert_equal(result, 1)

        result = handle.increment_block(block[2], 10)
        assert_equal(result, 10)

        result = handle.decrement_block(block[1], 1)
        assert_equal(result, 0)
        assert_false(str(block[1]) in handle.block)

        assert_raises(AddressCountTooLow,
                      handle.decrement_block, block[2], 11)

        result = handle.decrement_block(block[2], 10)
        assert_equal(result, 0)
        assert_false(str(block[2]) in handle.block)

        result = handle.decrement_block(block[0], 5)
        assert_equal(result, 0)
        assert_false(str(block[0]) in handle.block)

