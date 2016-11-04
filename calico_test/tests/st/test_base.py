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
import json
import yaml
import logging
import subprocess
from pprint import pformat
from unittest import TestCase

from deepdiff import DeepDiff

from tests.st.utils.utils import (get_ip, ETCD_SCHEME, ETCD_CA, ETCD_CERT,
                                  ETCD_KEY, debug_failures, ETCD_HOSTNAME_SSL)

HOST_IPV6 = get_ip(v6=True)
HOST_IPV4 = get_ip()

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)

# Disable spammy logging from the sh module
sh_logger = logging.getLogger("sh")
sh_logger.setLevel(level=logging.CRITICAL)


class TestBase(TestCase):
    """
    Base class for test-wide methods.
    """

    def setUp(self):
        """
        Clean up before every test.
        """
        self.ip = HOST_IPV4

        # Delete /calico if it exists. This ensures each test has an empty data
        # store at start of day.
        self.curl_etcd("calico", options=["-XDELETE"])

        # Disable Usage Reporting to usage.projectcalico.org
        # We want to avoid polluting analytics data with unit test noise
        self.curl_etcd("calico/v1/config/UsageReportingEnabled",
                       options=["-XPUT -d value=False"])

        # Log a newline to ensure that the first log appears on its own line.
        logger.info("")

    @debug_failures
    def assert_connectivity(self, pass_list, fail_list=None, retries=0,
                            type_list=None):
        """
        Assert partial connectivity graphs between workloads.

        :param pass_list: Every workload in this list should be able to ping
        every other workload in this list.
        :param fail_list: Every workload in pass_list should *not* be able to
        ping each workload in this list. Interconnectivity is not checked
        *within* the fail_list.
        :param retries: The number of retries.
        :param type_list: list of types to test.  If not specified, defaults to
        icmp only.
        """
        if type_list is None:
            type_list = ['icmp', 'tcp', 'udp']
        if fail_list is None:
            fail_list = []

        for source in pass_list:
            for dest in pass_list:
                if 'icmp' in type_list:
                    source.assert_can_ping(dest.ip, retries)
                if 'tcp' in type_list:
                    source.assert_can_tcp(dest.ip, retries)
                if 'udp' in type_list:
                    source.assert_can_udp(dest.ip, retries)
            for dest in fail_list:
                if 'icmp' in type_list:
                    source.assert_cant_ping(dest.ip, retries)
                if 'tcp' in type_list:
                    source.assert_cant_tcp(dest.ip, retries)
                if 'udp' in type_list:
                    source.assert_cant_udp(dest.ip, retries)

    @debug_failures
    def assert_ip_connectivity(self, workload_list, ip_pass_list,
                               ip_fail_list=None, type_list=None):
        """
        Assert partial connectivity graphs between workloads and given ips.

        This function is used for checking connectivity for ips that are
        explicitly assigned to containers when added to calico networking.

        :param workload_list: List of workloads used to check connectivity.
        :param ip_pass_list: Every workload in workload_list should be able to
        ping every ip in this list.
        :param ip_fail_list: Every workload in workload_list should *not* be
        able to ping any ip in this list. Interconnectivity is not checked
        *within* the fail_list.
        :param type_list: list of types to test.  If not specified, defaults to
        icmp only.
        """
        if type_list is None:
            type_list = ['icmp']
        if ip_fail_list is None:
            ip_fail_list = []
        for workload in workload_list:
            for ip in ip_pass_list:
                if 'icmp' in type_list:
                    workload.assert_can_ping(ip)
                if 'tcp' in type_list:
                    workload.assert_can_tcp(ip)
                if 'udp' in type_list:
                    workload.assert_can_udp(ip)

            for ip in ip_fail_list:
                if 'icmp' in type_list:
                    workload.assert_cant_ping(ip)
                if 'tcp' in type_list:
                    workload.assert_cant_tcp(ip)
                if 'udp' in type_list:
                    workload.assert_cant_udp(ip)

    def curl_etcd(self, path, options=None, recursive=True):
        """
        Perform a curl to etcd, returning JSON decoded response.
        :param path:  The key path to query
        :param options:  Additional options to include in the curl
        :param recursive:  Whether we want recursive query or not
        :return:  The JSON decoded response.
        """
        if options is None:
            options = []
        if ETCD_SCHEME == "https":
            # Etcd is running with SSL/TLS, require key/certificates
            rc = subprocess.check_output(
                "curl --cacert %s --cert %s --key %s "
                "-sL https://%s:2379/v2/keys/%s?recursive=%s %s"
                % (ETCD_CA, ETCD_CERT, ETCD_KEY, ETCD_HOSTNAME_SSL,
                   path, str(recursive).lower(), " ".join(options)),
                shell=True)
        else:
            rc = subprocess.check_output(
                "curl -sL http://%s:2379/v2/keys/%s?recursive=%s %s"
                % (self.ip, path, str(recursive).lower(), " ".join(options)),
                shell=True)

        return json.loads(rc.strip())

    def check_data_in_datastore(self, host, data, resource, yaml_format=True):
        if yaml_format:
            out = host.calicoctl(
                "get %s --output=yaml" % resource)
            output = yaml.safe_load(out)
        else:
            out = host.calicoctl(
                "get %s --output=json" % resource)
            output = json.loads(out)
        self.assert_same(data, output)

    @staticmethod
    def assert_same(thing1, thing2):
        """
        Compares two things.  Debug logs the differences between them before
        asserting that they are the same.
        """
        assert cmp(thing1, thing2) == 0, \
            "Items are not the same.  Difference is:\n %s" % \
            pformat(DeepDiff(thing1, thing2), indent=2)

    @staticmethod
    def writeyaml(filename, data):
        with open(filename, 'w') as f:
            text = yaml.dump(data, default_flow_style=False)
            logger.debug("Writing %s: \n%s" % (filename, text))
            f.write(text)

    @staticmethod
    def writejson(filename, data):
        with open(filename, 'w') as f:
            text = json.dumps(data,
                              sort_keys=True,
                              indent=2,
                              separators=(',', ': '))
            logger.debug("Writing %s: \n%s" % (filename, text))
            f.write(text)
