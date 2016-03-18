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

import unittest
from mock import patch
from subprocess import CalledProcessError, check_output
from pycalico.util import get_host_ips, validate_characters, validate_ports, validate_icmp_type, validate_hostname_port, \
    validate_cidr_versions, validate_ip, validate_cidr
from nose_parameterized import parameterized

MOCK_IP_ADDR = \
"""
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:73:c8:d0 brd ff:ff:ff:ff:ff:ff
    inet 172.24.114.18/24 brd 172.24.114.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 2620:104:4008:69:8d7c:499f:2f04:9e55/64 scope global temporary dynamic 
       valid_lft 603690sec preferred_lft 84690sec
    inet6 2620:104:4008:69:a00:27ff:fe73:c8d0/64 scope global dynamic 
       valid_lft 604698sec preferred_lft 86298sec
    inet6 fe80::a00:27ff:fe73:c8d0/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
    inet 172.17.42.1/24 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::188f:d6ff:fe1f:1482/64 scope link 
       valid_lft forever preferred_lft forever
"""

MOCK_IP_ADDR_DOCKER_NONE = \
"""
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:73:c8:d0 brd ff:ff:ff:ff:ff:ff
    inet 172.24.114.18/24 brd 172.24.114.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 2620:104:4008:69:8d7c:499f:2f04:9e55/64 scope global temporary dynamic
       valid_lft 603690sec preferred_lft 84690sec
    inet6 2620:104:4008:69:a00:27ff:fe73:c8d0/64 scope global dynamic
       valid_lft 604698sec preferred_lft 86298sec
    inet6 fe80::a00:27ff:fe73:c8d0/64 scope link
       valid_lft forever preferred_lft forever
3: docker0@NONE: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 00:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
    inet 172.17.43.1/24 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::188f:d6ff:fe1f:1483/64 scope link
       valid_lft forever preferred_lft forever
"""

MOCK_IP_ADDR_LOOPBACK = \
"""
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
"""


class TestUtil(unittest.TestCase):

    @patch("pycalico.util.check_output", autospec=True)
    def test_get_host_ips_standard(self, m_check_output):
        '''Test general case for get_host_ips'''
        # Test IPv4
        m_check_output.return_value = MOCK_IP_ADDR
        addrs = get_host_ips(version=4)
        m_check_output.assert_called_once_with(["ip", "-4", "addr"])
        m_check_output.reset_mock()
        self.assertEquals(addrs, ['172.24.114.18', '172.17.42.1'])

        # Test IPv6
        addrs = get_host_ips(version=6)
        m_check_output.assert_called_once_with(["ip", "-6", "addr"])
        m_check_output.reset_mock()
        self.assertEquals(addrs, ['2620:104:4008:69:8d7c:499f:2f04:9e55',
                                  '2620:104:4008:69:a00:27ff:fe73:c8d0',
                                  'fe80::a00:27ff:fe73:c8d0',
                                  'fe80::188f:d6ff:fe1f:1482'])

    @patch("pycalico.util.check_output", autospec=True)
    def test_get_host_ips_loopback_only(self, m_check_output):
        '''Test get_host_ips with loopback'''
        # Test IPv4
        m_check_output.return_value = MOCK_IP_ADDR_LOOPBACK
        addrs = get_host_ips(version=4)
        m_check_output.assert_called_once_with(["ip", "-4", "addr"])
        m_check_output.reset_mock()
        self.assertEquals(addrs, [])

        # Test IPv6
        addrs = get_host_ips(version=6)
        m_check_output.assert_called_once_with(["ip", "-6", "addr"])
        m_check_output.reset_mock()
        self.assertEquals(addrs, [])

    @patch("pycalico.util.check_output", autospec=True)
    def test_get_host_ips_exclude_docker(self, m_check_output):
        '''Test get_host_ips exclude "docker0"'''
        # Test IPv4
        m_check_output.return_value = MOCK_IP_ADDR
        addrs = get_host_ips(version=4, exclude=["docker0"])
        m_check_output.assert_called_once_with(["ip", "-4", "addr"])
        m_check_output.reset_mock()
        self.assertEquals(addrs, ['172.24.114.18'])

        # Test IPv6
        addrs = get_host_ips(version=6, exclude=["docker0"])
        m_check_output.assert_called_once_with(["ip", "-6", "addr"])
        m_check_output.reset_mock()
        self.assertEquals(addrs, ['2620:104:4008:69:8d7c:499f:2f04:9e55',
                                  '2620:104:4008:69:a00:27ff:fe73:c8d0',
                                  'fe80::a00:27ff:fe73:c8d0'])

    @patch("pycalico.util.check_output", autospec=True)
    def test_get_host_ips_exclude_empty(self, m_check_output):
        '''Test get_host_ips exclude empty list'''
        # Test IPv4
        m_check_output.return_value = MOCK_IP_ADDR
        addrs = get_host_ips(version=4, exclude=["^$"])
        m_check_output.assert_called_once_with(["ip", "-4", "addr"])
        m_check_output.reset_mock()
        self.assertEquals(addrs, ['172.24.114.18', '172.17.42.1'])

        # Test IPv6
        addrs = get_host_ips(version=6, exclude=["^$"])
        m_check_output.assert_called_once_with(["ip", "-6", "addr"])
        m_check_output.reset_mock()
        self.assertEquals(addrs, ['2620:104:4008:69:8d7c:499f:2f04:9e55',
                                  '2620:104:4008:69:a00:27ff:fe73:c8d0',
                                  'fe80::a00:27ff:fe73:c8d0',
                                  'fe80::188f:d6ff:fe1f:1482'])

    @patch("pycalico.util.check_output", autospec=True)
    def test_get_host_ips_exclude_docker_prefix(self, m_check_output):
        '''Test get_host_ips exclude "docker0.*'''
        # Test IPv4
        m_check_output.return_value = MOCK_IP_ADDR_DOCKER_NONE
        addrs = get_host_ips(version=4, exclude=["docker0.*"])
        m_check_output.assert_called_once_with(["ip", "-4", "addr"])
        m_check_output.reset_mock()
        self.assertEquals(addrs, ['172.24.114.18'])

        # Test IPv6
        addrs = get_host_ips(version=6, exclude=["docker0.*"])
        m_check_output.assert_called_once_with(["ip", "-6", "addr"])
        m_check_output.reset_mock()
        self.assertEquals(addrs, ['2620:104:4008:69:8d7c:499f:2f04:9e55',
                                  '2620:104:4008:69:a00:27ff:fe73:c8d0',
                                  'fe80::a00:27ff:fe73:c8d0'])

    @patch("pycalico.util.check_output", autospec=True)
    def test_get_host_ips_fail_check_output(self, m_check_output):
        '''Test get_host_ip failing to check output of ip addr'''
        m_check_output.side_effect = CalledProcessError(returncode=1, cmd=check_output(["ip", "-4", "addr"]))
        with self.assertRaises(SystemExit):
            addrs = get_host_ips(version=4)

    @parameterized.expand([
        ([2, 5, '114'], True),
        (['89:133', 19], True),
        ([15, 66, -144], False),
        (['-1:5'], False),
        (['15:77:66'], False),
        (['one', 'two'], False)
    ])
    def test_validate_ports(self, input_list, expected_result):
        """
        Test validate_ports function
        """
        test_result = validate_ports(input_list)
        self.assertEqual(expected_result, test_result)

    @parameterized.expand([
        (300, False),
        (15, True),
        (255, False),
        (-7, False),
        ('one', False),
        ('43', True)
    ])
    def test_validate_icmp_type(self, input_list, expected_result):
        """
        Test validate_icmp_type function
        """
        test_result = validate_icmp_type(input_list)
        self.assertEqual(expected_result, test_result)

    @parameterized.expand([
        ('abcdefghijklmnopqrstuvwxyz', True),
        ('0123456789', True),
        ('profile_1', True),
        ('profile-1', True),
        ('profile 1', False),
        ('profile.1', True),
        ('!', False),
        ('@', False),
        ('#', False),
        ('$', False),
        ('%', False),
        ('^', False),
        ('&', False),
        ('*', False),
        ('()', False)
    ])
    def test_validate_characters(self, input_string, expected_result):
        """
        Test validate_characters function
        """
        with patch('sys.exit', autospec=True) as m_sys_exit:
            # Call method under test
            test_result = validate_characters(input_string)

            # Assert expected result
            self.assertEqual(expected_result, test_result)

    @parameterized.expand([
        ('1.2.3.4', False),
        ('', False),
        ('abcde', False),
        ('aa:bb::cc:1234', False),
        ('aa::256', False),
        (':1234', False),
        ('aa...bb:256', False),
        ('aa:256', True),
        ('1.2.3.244:256', True),
        ('1.2.a.244:256', True),
        ('-asr:100', False),
        ('asr-:100', False),
        ('asr-temp-test.thr.yes-33:100', True),
        ('asr-temp-test.-thr.yes-33:100', False),
        ('asr-temp-test.thr-.yes-33:100', False),
        ('asr-temp-test.thr-.yes-33:100', False),
        ('validhostname:0', False),
        ('validhostname:65536', False),
        ('validhostname:1', True),
        ('validhostname:65535', True),
        ('#notvalidhostname:65535', False),
        ('verylong' * 100 + ':200', False),
        ('12.256.122.43:aaa', False),
        (12345, False),
        (("1.2.3.244:256",), False)
    ])
    def test_validate_hostname_port(self, input_string, expected_result):
        """
        Test validate_hostname_port function.

        This also tests validate_hostname which is invoked from
        validate_hostname_port.
        """
        test_result = validate_hostname_port(input_string)

        # Assert expected result
        self.assertEqual(expected_result, test_result)

    @parameterized.expand([
        ('127.a.0.1', False),
        ('aa:bb::zz', False),
        ('1.2.3.4', True),
        ('1.2.3.0/24', True),
        ('aa:bb::ff', True),
        ('1111:2222:3333:4444:5555:6666:7777:8888', True),
        ('4294967295', False)
    ])
    def test_validate_cidr(self, cidr, expected_result):
        """
        Test validate_cidr function in calico_ctl utils
        """
        # Call method under test
        test_result = validate_cidr(cidr)

        # Assert
        self.assertEqual(expected_result, test_result)

    @parameterized.expand([
        (["1.2.3.4"], 4, True),
        (["1.2.3.4"], None, True),
        (["aa:bb::zz"], 6, False),
        (["aa:bb::zz"], None, False),
        (["10.0.0.1", "11.0.0.1", "11.0.0.1"], 4, True),
        (["10.0.0.1", "11.0.0.1", "11.0.0.1"], None, True),
        (["1111:2222:3333:4444:5555:6666:7777:8888", "a::b"], 6, True),
        (["1111:2222:3333:4444:5555:6666:7777:8888", "a::b", "1234::1"],
                                                                    None, True),
        (["127.1.0.1", "dead:beef"], None, False),
        (["aa:bb::zz"], 4, False),
        (["1.2.3.4"], 6, False),
        (["0bad:beef", "1.2.3.4"], 4, False),
        (["0bad:beef", "1.2.3.4"], 6, False),
        (["0bad:beef", "1.2.3.4"], None, False),
    ])
    def test_validate_cidr_versions(self, cidr_list, ip_version, expected_result):
        """
        Test validate_cidr_versions function in calico_ctl utils
        """
        # Call method under test
        test_result = validate_cidr_versions(cidr_list,
                                                   ip_version=ip_version)

        # Assert
        self.assertEqual(expected_result, test_result)

    @parameterized.expand([
        ('1.2.3.4', 4, True),
        ('1.2.3.4', 6, False),
        ('1.2.3.4', 4, True),
        ('1.2.3.0/24', 4, False),
        ('aa:bb::ff', 4, False),
        ('aa:bb::ff', 6, True),
        ('1111:2222:3333:4444:5555:6666:7777:8888', 6, True),
    ])
    def test_validate_ip(self, ip, version, expected_result):
        """
        Test validate_ip function in calico_ctl utils
        """
        # Call method under test
        test_result = validate_ip(ip, version)

        # Assert
        self.assertEqual(expected_result, test_result)
