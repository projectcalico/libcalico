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

import os
import unittest

from nose.tools import *
from mock import patch, call, ANY, Mock

from pycalico.netns import (create_veth, remove_veth, veth_exists, IP_CMD_TIMEOUT,
                            CalledProcessError, Route, increment_metrics,
                            Namespace)


class TestVeth(unittest.TestCase):

    @patch("pycalico.netns.check_output", autospec=True)
    def test_create_veth(self, m_check_output):
        """
        Test creating a veth (pair).
        """
        create_veth("veth1", "temp_name")
        check_output_1 = call(['ip', 'link', 'add', "veth1", 'type',
                             'veth','peer', 'name', "temp_name"],
                            timeout=IP_CMD_TIMEOUT)
        check_output_2 = call(['ip', 'link', 'set', "veth1", 'up'],
                            timeout=IP_CMD_TIMEOUT)
        m_check_output.assert_has_calls([check_output_1, check_output_2])

    @patch("pycalico.netns.veth_exists", autospec=True)
    @patch("pycalico.netns.check_output", autospec=True)
    def test_remove_veth_success(self, m_check_output, m_veth_exists):
        """
        Test remove_veth returns True for successfully removing a veth.
        """
        m_veth_exists.return_value = True;
        self.assertTrue(remove_veth("veth1"))
        m_veth_exists.assert_called_once_with("veth1")
        m_check_output.assert_called_once_with(['ip', 'link', 'del', "veth1"],
                                             timeout=IP_CMD_TIMEOUT)

    @patch("pycalico.netns.veth_exists", autospec=True)
    @patch("pycalico.netns.check_output", autospec=True)
    def test_remove_veth_no_veth(self, m_check_output, m_veth_exists):
        """
        Test remove_veth returns False when veth doesn't exist.
        """
        m_veth_exists.return_value = False;
        self.assertFalse(remove_veth("veth1"))
        m_veth_exists.assert_called_once_with("veth1")
        self.assertFalse(m_check_output.called)

    @patch('__builtin__.open', autospec=True)
    @patch("pycalico.netns.check_call", autospec=True)
    def test_veth_exists_true(self, m_check_call, m_open):
        """
        Test veth_exists returns True if no error occurs.
        """
        self.assertTrue(veth_exists("veth1"))
        m_open.assert_called_once_with(os.devnull, 'w')
        m_check_call.assert_called_once_with(["ip", "link", "show", "veth1"],
                                             stderr=ANY,
                                             stdout=ANY)

    @patch('__builtin__.open', autospec=True)
    @patch("pycalico.netns.check_call", autospec=True)
    def test_veth_exists_false(self, m_check_call, m_open):
        """
        Test veth_exists returns True if no error occurs.
        """
        m_check_call.side_effect = CalledProcessError(1, "test")
        self.assertFalse(veth_exists("veth1"))
        m_open.assert_called_once_with(os.devnull, 'w')
        m_check_call.assert_called_once_with(["ip", "link", "show", "veth1"],
                                             stderr=ANY,
                                             stdout=ANY)


class TestRoute(unittest.TestCase):
    def test_metric(self):
        """
        Test that a Route object correctly parses the metric of a route
        """
        self.assertEqual(Route("default via 172.24.114.1 dev eth0").metric, 0)
        self.assertEqual(Route("default via 172.24.114.1 dev eth0 metric 0").metric, 0)
        self.assertEqual(Route("172.17.0.0/16 dev eth0 metric 1").metric, 1)
        self.assertEqual(Route("172.17.0.0/16 dev eth0 metric 240").metric, 240)

    def test_default(self):
        """
        Test that a route object correctly flags if the route is a default route or not
        """
        self.assertTrue(Route("default via 172.24.114.1 dev eth0 metric 1").default)
        self.assertFalse(Route("172.17.0.0/16 dev eth0 metric 1").default)

    def test_increment_metric(self):
        """
        Test that a route object correctly returns an incremented metric route.
        """
        route = Route("default via 172.24.114.1 dev eth0")
        self.assertEqual(str(route), "default via 172.24.114.1 dev eth0 metric 0")

        route.metric += 1
        self.assertEqual(str(route),
                         "default via 172.24.114.1 dev eth0 metric 1")

        route.metric += 1
        self.assertEqual(str(route),
                        "default via 172.24.114.1 dev eth0 metric 2")

    @patch('pycalico.netns.NamedNamespace')
    def test_metrics_increment(self, m_namespace):
        """
        Test that route metrics are incremented properly.
        """
        mock_ns = Mock()
        m_namespace().__enter__.return_value = mock_ns

        mock_ns.check_output.return_value = "default via 172.24.114.1 dev eth0\n" \
                                      "default via 172.24.114.2 dev eth0 metric 1"

        expected_calls = [call(['ip', 'route', 'add', 'default', 'via',
                                '172.24.114.2', 'dev', 'eth0', 'metric', '2']),
                          call(['ip', 'route', 'del', 'default', 'via',
                                '172.24.114.2', 'dev', 'eth0', 'metric', '1']),
                          call(['ip', 'route', 'add', 'default', 'via',
                                '172.24.114.1', 'dev', 'eth0', 'metric', '1']),
                          call(['ip', 'route', 'del', 'default', 'via',
                                '172.24.114.1', 'dev', 'eth0', 'metric', '0'])]

        increment_metrics("test_ns")
        mock_ns.check_output.assert_has_calls(expected_calls, any_order=False)

    @patch('pycalico.netns.NamedNamespace')
    def test_max_metric(self, m_namespace):
        """
        Test that route metrics are not incremented beyond the max metric value.
        """
        mock_ns = Mock()
        m_namespace().__enter__.return_value = mock_ns

        max_metric = 0xFFFFFFFF

        ip_route_output = "default via 172.24.114.1 dev eth0\n" \
                          "default via 172.24.114.2 dev eth0 metric %d\n" \
                          "default via 172.24.114.3 dev eth0 metric %d" % \
                          (max_metric - 1, max_metric)
        mock_ns.check_output.return_value = ip_route_output

        expected_calls = [call(['ip', 'route', 'add', 'default', 'via',
                                '172.24.114.1', 'dev', 'eth0', 'metric', '1']),
                          call(['ip', 'route', 'del', 'default', 'via',
                                '172.24.114.1', 'dev', 'eth0', 'metric', '0'])]

        increment_metrics("test_ns")
        mock_ns.check_output.assert_has_calls(expected_calls, any_order=False)
