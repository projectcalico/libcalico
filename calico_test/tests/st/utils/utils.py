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
import functools
import logging
import socket
import sys
import time
import unittest
from time import sleep
import os
import pdb
from subprocess import check_output, STDOUT
from subprocess import CalledProcessError
from exceptions import CommandExecError
from unittest.case import SkipTest
import re
import json
import yaml
from pycalico.util import get_host_ips

LOCAL_IP_ENV = "MY_IP"
LOCAL_IPv6_ENV = "MY_IPv6"
logger = logging.getLogger(__name__)

ETCD_SCHEME = os.environ.get("ETCD_SCHEME", "http")
ETCD_CA = os.environ.get("ETCD_CA_CERT_FILE", "")
ETCD_CERT = os.environ.get("ETCD_CERT_FILE", "")
ETCD_KEY = os.environ.get("ETCD_KEY_FILE", "")
ETCD_HOSTNAME_SSL = "etcd-authority-ssl"
firstlogger_time = None


def log_banner(msg, *args, **kwargs):
    # Calculate elapsed hours, minutes and seconds since first log.
    global firstlogger_time
    time_now = time.time()
    if not firstlogger_time:
        firstlogger_time = time_now
    time_now -= firstlogger_time
    elapsed_hms = "%02d:%02d:%02d " % (time_now / 3600,
                                       (time_now % 3600) / 60,
                                       time_now % 60)

    level = kwargs.pop("level", logging.INFO)
    msg = elapsed_hms + str(msg) % args
    banner = "+" + ("-" * (len(msg) + 2)) + "+"
    logger.log(level, "\n" +
               banner + "\n"
                        "| " + msg + " |\n" +
               banner)


def decorate_with_hooks(test_method):
    """
    Wraps each test_method with calls to the test hooks.
    """

    @functools.wraps(test_method)
    def call_test_hooks(self):
        """
        Calls the test_method. If the test fails or succeeds, runs the
        on_failure hook or the on_success hook defined in the test class.
        """
        try:
            log_banner("TEST STARTING: %s", self.id())
            test_method(self)
        except KeyboardInterrupt:
            log_banner("TEST INTERRUPTED: %s", self.id(),
                       level=logging.WARNING)
            raise
        except SkipTest:
            log_banner("TEST SKIPPED: %s", self.id())
            raise
        except Exception as e:
            e_trace = sys.exc_info()[2]
            logger.exception("Test %s failed with exception", self.id())
            log_banner("TEST FAILED: %s", self.id(),
                       level=logging.ERROR)
            self.on_failure(test_id=self.id())
            raise e, None, e_trace
        else:
            log_banner("TEST SUCCEEDED: %s", self.id())
            self.on_success()
        finally:
            log_banner("TEST CLEAN-UP DONE: %s", self.id())

    return call_test_hooks


class ResultsWithHooks(type):
    """
    Metaclass that decorates all test_* class methods with decorate_with_hooks.
    """
    def __new__(cls, name, bases, dct):
        for attr, value in dct.iteritems():
            if attr.startswith("test_") and hasattr(value, '__module__'):
                dct[attr] = decorate_with_hooks(value)
        return super(ResultsWithHooks, cls).__new__(cls, name, bases, dct)


class TestWithHooks(unittest.TestCase):
    """
    Base unittest class implementing success and failure hooks.
    """

    __metaclass__ = ResultsWithHooks

    @classmethod
    def on_success(cls):
        """
        The test completed without raising an exception.
        """
        logger.info("Test succeeded")

    @classmethod
    def on_failure(cls, test_id=None):
        """
        The test raised an exception.
        """
        cls.get_diags()
        logger.info("Test failed.")

    @classmethod
    def get_diags(cls):
        logger.debug("You should be overriding get_diags!")


def get_ip(v6=False):
    """
    Return a string of the IP of the hosts interface.
    Try to get the local IP from the environment variables.  This allows
    testers to specify the IP address in cases where there is more than one
    configured IP address for the test system.
    """
    env = LOCAL_IPv6_ENV if v6 else LOCAL_IP_ENV
    ip = os.environ.get(env)
    if not ip:
        try:
            logger.debug("%s not set; try to auto detect IP.", env)
            socket_type = socket.AF_INET6 if v6 else socket.AF_INET
            s = socket.socket(socket_type, socket.SOCK_DGRAM)
            remote_ip = "2001:4860:4860::8888" if v6 else "8.8.8.8"
            s.connect((remote_ip, 0))
            ip = s.getsockname()[0]
            s.close()
        except BaseException:
            # Failed to connect, just try to get the address from the interfaces
            version = 6 if v6 else 4
            ips = get_host_ips(version)
            if ips:
                ip = str(ips[0])
    else:
        logger.debug("Got local IP from %s=%s", env, ip)

    return ip


def log_and_run(command):

    def log_output(results):
        lines = results.split("\n")
        for line in lines:
            logger.info("  # %s", line)

    try:
        logger.info(command)
        results = check_output(command, shell=True, stderr=STDOUT).rstrip()
        log_output(results)
        return results
    except CalledProcessError as e:
        # Wrap the original exception with one that gives a better error
        # message (including command output).
        logger.info("  # Return code: %s", e.returncode)
        log_output(e.output.rstrip())
        raise CommandExecError(e)


def retry_until_success(function, retries=10, ex_class=Exception):
    """
    Retries function until no exception is thrown. If exception continues,
    it is reraised.

    :param function: the function to be repeatedly called
    :param retries: the maximum number of times to retry the function.
    A value of 0 will run the function once with no retries.
    :param ex_class: The class of expected exceptions.
    :returns: the value returned by function
    """
    for retry in range(retries + 1):
        try:
            result = function()
        except ex_class:
            if retry < retries:
                sleep(1)
            else:
                raise
        else:
            # Successfully ran the function
            return result


def debug_failures(fn):
    """
    Decorator function to decorate assertion methods to pause the live system
    when an assertion fails, allowing the user to debug the problem.
    :param fn: The function to decorate.
    :return: The decorated function.
    """

    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            if (os.getenv("DEBUG_FAILURES") is not None and
                    os.getenv("DEBUG_FAILURES").lower() == "true"):
                logger.error("TEST FAILED:\n%s\nEntering DEBUG mode."
                             % e.message)
                pdb.set_trace()
            else:
                raise

    return wrapped


@debug_failures
def check_bird_status(host, expected):
    """
    Check the BIRD status on a particular host to see if it contains the
    expected BGP status.

    :param host: The host object to check.
    :param expected: A list of tuples containing:
        (peertype, ip address, state)
    where 'peertype' is one of "Global", "Mesh", "Node",  'ip address' is
    the IP address of the peer, and state is the expected BGP state (e.g.
    "Established" or "Idle").
    """
    output = host.calicoctl("node status")
    lines = output.split("\n")
    for (peertype, ipaddr, state) in expected:
        for line in lines:
            # Status table format is of the form:
            # +--------------+-------------------+-------+----------+-------------+
            # | Peer address |     Peer type     | State |  Since   |     Info    |
            # +--------------+-------------------+-------+----------+-------------+
            # | 172.17.42.21 | node-to-node mesh |   up  | 16:17:25 | Established |
            # | 10.20.30.40  |       global      | start | 16:28:38 |   Connect   |
            # |  192.10.0.0  |   node specific   | start | 16:28:57 |   Connect   |
            # +--------------+-------------------+-------+----------+-------------+
            #
            # Splitting based on | separators results in an array of the
            # form:
            # ['', 'Peer address', 'Peer type', 'State', 'Since', 'Info', '']
            columns = re.split("\s*\|\s*", line.strip())
            if len(columns) != 7:
                continue

            if type(state) is not list:
                state = [state]

            # Find the entry matching this peer.
            if columns[1] == ipaddr and columns[2] == peertype:

                # Check that the connection state is as expected.  We check
                # that the state starts with the expected value since there
                # may be additional diagnostic information included in the
                # info field.
                if any(columns[5].startswith(s) for s in state):
                    break
                else:
                    msg = "Error in BIRD status for peer %s:\n" \
                          "Expected: %s; Actual: %s\n" \
                          "Output:\n%s" % (ipaddr, state, columns[5],
                                           output)
                    raise AssertionError(msg)
        else:
            msg = "Error in BIRD status for peer %s:\n" \
                  "Type: %s\n" \
                  "Expected: %s\n" \
                  "Output: \n%s" % (ipaddr, peertype, state, output)
            raise AssertionError(msg)


@debug_failures
def assert_number_endpoints(host, expected):
    """
    Check that a host has the expected number of endpoints in Calico
    Parses the "calicoctl endpoint show" command for number of endpoints.
    Raises AssertionError if the number of endpoints does not match the
    expected value.

    :param host: DockerHost object
    :param expected: int, number of expected endpoints
    :return: None
    """
    hostname = host.get_hostname()
    out = host.calicoctl("get workloadEndpoint -o yaml")
    output = yaml.safe_load(out)
    actual = 0
    for endpoint in output:
        if endpoint['metadata']['node'] == hostname:
            actual += 1

    if int(actual) != int(expected):
        msg = "Incorrect number of endpoints: \n" \
              "Expected: %s; Actual: %s" % (expected, actual)
        raise AssertionError(msg)


@debug_failures
def assert_profile(host, profile_name):
    """
    Check that profile is registered in Calico
    Parse "calicoctl profile show" for the given profilename

    :param host: DockerHost object
    :param profile_name: String of the name of the profile
    :return: Boolean: True if found, False if not found
    """
    out = host.calicoctl("get -o yaml profile")
    output = yaml.safe_load(out)
    found = False
    for profile in output:
        if profile['metadata']['name'] == profile_name:
            found = True
            break

    if not found:
        raise AssertionError("Profile %s not found in Calico" % profile_name)


def get_profile_name(host, network):
    """
    Get the profile name from Docker
    A profile is created in Docker for each Network object.
    The profile name is a randomly generated string.

    :param host: DockerHost object
    :param network: Network object
    :return: String: profile name
    """
    info_raw = host.execute("docker network inspect %s" % network.name)
    info = json.loads(info_raw)

    # Network inspect returns a list of dicts for each network being inspected.
    # We are only inspecting 1, so use the first entry.
    return info[0]["Id"]


@debug_failures
def assert_network(host, network):
    """
    Checks that the given network is in Docker
    Raises an exception if the network is not found

    :param host: DockerHost object
    :param network: Network object
    :return: None
    """
    try:
        host.execute("docker network inspect %s" % network.name)
    except CommandExecError:
        raise AssertionError("Docker network %s not found" % network.name)
