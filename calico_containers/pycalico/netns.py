# Copyright (c) 2015 Metaswitch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import socket
import logging
import os
import errno
import uuid
import re
from copy import copy

from subprocess32 import check_output, check_call, CalledProcessError, STDOUT
from netaddr import IPAddress

_log = logging.getLogger(__name__)
_log.addHandler(logging.NullHandler())

HOSTNAME = socket.gethostname()

PREFIX_LEN = {4: 32, 6: 128}
"""The IP address prefix length to assign, by IP version."""

IP_CMD_TIMEOUT = 5
"""How long to wait (seconds) for IP commands to complete."""

MAX_METRIC = 0xFFFFFFFF
"""Max valid value of a route's metric"""

def setup_logging(logfile, level=logging.INFO):
    _log.setLevel(level)
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s %(lineno)d: %(message)s')
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(formatter)
    _log.addHandler(handler)
    handler = logging.handlers.TimedRotatingFileHandler(logfile,
                                                        when='D',
                                                        backupCount=10)
    handler.setLevel(level)
    handler.setFormatter(formatter)
    _log.addHandler(handler)


def increment_metrics(namespace):
    """
    If any default route has a metric of 0, increase the metric of 
    all default routes by 1, so long as it can be done without breaking
    uniqueness or surpassing the max metric value.
    :param namespace: The Networking namespace of the container.
    :return: None. Raises CalledProcessError on error.
    """
    with NamedNamespace(namespace) as ns:
        # Gather all default routes
        routes = ns.check_output(["ip", "route"]).split("\n")
        default_routes = {}
        for route in routes:
            route = Route(route)
            if route.default:
                default_routes[route.metric] = route

        # Increment default routes (if a 0-metric default exists)
        if 0 in default_routes:
            # Order routes descending by metric so, while incrementing,
            # no 2 routes temporarily have the same metric.
            descending_routes = sorted(default_routes.items(),
                                       key=lambda metric: -metric[0])
            assigned_metrics = []
            for metric, route in descending_routes:
                if metric + 1 >= MAX_METRIC or metric + 1 in assigned_metrics:
                    # Don't increment this metric
                    assigned_metrics.append(metric)
                else:
                    # Increment this metric.
                    original_route = copy(route)
                    route.metric += 1

                    ns.check_output(["ip", "route", "add"] + str(route).split())
                    ns.check_output(["ip", "route", "del"] +
                                    str(original_route).split())
                    assigned_metrics.append(metric + 1)


def create_veth(veth_name_host, veth_name_ns_temp):
    """
    Create the veth (pair).
    :param veth_name_host: The name of the veth interface
    :param veth_name_ns_temp: The temporary interface name of the veth that will be
    moved into the namespace.
    :return: None. Raises CalledProcessError on error.
    """
    # Create the veth
    _log.debug("Creating veth %s in temp_ns: %s", veth_name_host, veth_name_ns_temp)
    check_output(['ip', 'link',
                'add', veth_name_host,
                'type', 'veth',
                'peer', 'name', veth_name_ns_temp],
               timeout=IP_CMD_TIMEOUT)

    # Set the host end of the veth to 'up' so felix notices it.
    check_output(['ip', 'link', 'set', veth_name_host, 'up'],
               timeout=IP_CMD_TIMEOUT)


def remove_veth(veth_name_host):
    """
    Remove the veth (pair).
    :param veth_name_host: The name of the veth interface.
    :return: True if veth was removed.  False if veth does not exist.
             Raises CalledProcessError on error.
    """
    # The veth removal is best effort. If it fails then just log.
    if not veth_exists(veth_name_host):
        return False
    check_output(['ip', 'link', 'del', veth_name_host],
               timeout=IP_CMD_TIMEOUT)
    return True


def veth_exists(veth_name_host):
    """
    Check if the veth exists on the host.
    :param veth_name_host: The name of the veth interface.
    :return: True if veth exists, False if veth does not exist
    """
    # Suppress output
    with open(os.devnull, 'w') as fnull:
        try:
            check_call(["ip", "link", "show", veth_name_host],
                       stderr=fnull,
                       stdout=fnull)
            return True
        except CalledProcessError:
            # veth does not exist
            return False


def move_veth_into_ns(namespace, veth_name_ns_temp, veth_name_ns):
    """
    Move the veth into the namespace.

    :param namespace: The Namespace to move the veth into.
    :type namespace Namespace
    :param veth_name_ns_temp: The temporary interface name of the veth that will be
    moved into the namespace.
    :param veth_name_ns: The name of the interface in the namespace.
    :return: None. Raises CalledProcessError on error.
    """
    with NamedNamespace(namespace) as ns:
        _log.debug("Moving temp interface %s into ns %s.", veth_name_ns_temp, ns.name)
        # Create the veth pair and move one end into container:
        check_output(["ip", "link", "set", veth_name_ns_temp,
                    "netns", ns.name],
                   timeout=IP_CMD_TIMEOUT)
        ns.check_output(["ip", "link", "set", "dev", veth_name_ns_temp,
                       "name", veth_name_ns])
        ns.check_output(["ip", "link", "set", veth_name_ns, "up"])


def set_veth_mac(veth_name_host, mac):
    """
    Set the veth MAC address.
    :param veth_name_host: The name of the veth.
    :param mac: The MAC address.
    :return: None. Raises CalledProcessError on error.
    """
    #TODO MAC should be an EUI object.
    check_output(['ip', 'link', 'set',
                'dev', veth_name_host,
                'address', mac],
               timeout=IP_CMD_TIMEOUT)


def add_ns_default_route(namespace, next_hop, veth_name_ns):
    """
    Add a default route to the namespace.

    :param namespace: The namespace to operate in.
    :type namespace Namespace
    :param next_hop: The next hop IP used as the default route in the namespace.
    :param veth_name_ns: The name of the interface in the namespace.
    :return: None. Raises CalledProcessError on error.
    """
    assert isinstance(next_hop, IPAddress)
    with NamedNamespace(namespace) as ns:
        # Connected route to next hop & default route.
        ns.check_output(["ip", "-%s" % next_hop.version, "route", "replace",
                       str(next_hop), "dev", veth_name_ns])
        ns.check_output(["ip", "-%s" % next_hop.version, "route", "replace",
                      "default", "via", str(next_hop), "dev", veth_name_ns])


def get_ns_veth_mac(namespace, veth_name_ns):
    """
    Return the MAC address of the interface in the namespace.

    :param namespace: The namespace to operate in.
    :type namespace Namespace
    :param veth_name_ns: The name of the interface in the namespace.
    :return: The MAC address as a string. Raises CalledProcessError on error.
    """
    with NamedNamespace(namespace) as ns:
        # Get the MAC address.
        mac = ns.check_output(["cat", "/sys/class/net/%s/address" % veth_name_ns]).strip()
    #TODO MAC should be an EUI object.
    return mac


def add_ip_to_ns_veth(namespace, ip, veth_name_ns):
    """
    Add an IP to an interface in a namespace.

    :param namespace: The namespace to operate in.
    :type namespace Namespace
    :param ip: The IPAddress to add.
    :param veth_name_ns: The interface to add the address to.
    :return: None. Raises CalledProcessError on error.
    """
    with NamedNamespace(namespace) as ns:
        ns.check_output(["ip", "-%s" % ip.version, "addr", "add",
                       "%s/%s" % (ip, PREFIX_LEN[ip.version]),
                       "dev", veth_name_ns])


def remove_ip_from_ns_veth(namespace, ip, veth_name_ns):
    """
    Remove an IP from an interface in a namespace.

    :param namespace: The namespace to operate in.
    :type namespace Namespace
    :param ip: The IPAddress to remove.
    :param veth_name_ns: The interface to remove the address from.
    :return: None. raises CalledProcessError on error.
    """
    assert isinstance(ip, IPAddress)
    with NamedNamespace(namespace) as ns:
        ns.check_output(["ip", "-%s" % ip.version, "addr", "del",
                       "%s/%s" % (ip, PREFIX_LEN[ip.version]),
                       "dev", veth_name_ns])


class Route(object):
    def __init__(self, route_output):
        self.route_output = route_output
        self.default = route_output.startswith("default")
        match = re.search('metric\s+(\d+)', route_output)
        self.metric = int(match.group(1)) if match else 0

    def __str__(self):
        route_without_metric = re.sub('metric\s+\d+', '', self.route_output)
        return "{} metric {}".format(route_without_metric, self.metric)


class NamedNamespace(object):
    """
    Create a named namespace to allow us to run commands
    from within the namespace using standard `ip netns exec`.

    An alternative approach would be to use nsenter, which allows us to exec
    directly in a PID namespace.  However, this is not installed by default
    on some OSs that we need to support.
    """
    def __init__(self, namespace):
        """
        Create a NamedNamespace from a Namespace object.

        :param namespace: The source namespace to link to.
        :type namespace Namespace
        """
        self.name = uuid.uuid1().hex
        self.ns_path = namespace.path
        self.nsn_dir = "/var/run/netns/%s" % self.name
        if not os.path.exists(self.ns_path):
            raise NamespaceError("Namespace pseudofile %s does not exist." %
                                 self.ns_path)

    def __enter__(self):
        """
        Add the appropriate configuration to name the namespace.  This links
        the PID to the namespace name.
        """
        _log.debug("Creating link between namespace %s and PID %s",
                   self.name, self.ns_path)
        try:
            os.makedirs("/var/run/netns")
        except os.error as oserr:
            if oserr.errno != errno.EEXIST:
                _log.error("Unable to create /var/run/netns dir")
                raise
        os.symlink(self.ns_path, self.nsn_dir)
        return self

    def __exit__(self, _type, _value, _traceback):
        try:
            os.unlink(self.nsn_dir)
        except BaseException:
            _log.exception("Failed to remove link: %s", self.nsn_dir)
        return False

    def check_output(self, command):
        """
        Run a command within the named namespace.
        :param command: The command to run.
        :param shell: Whether this is a shell command.
        :param timeout: Command timeout in seconds.
        """
        command = self._get_nets_command(command)
        _log.debug("Run command: %s", command)
        return check_output(command, timeout=IP_CMD_TIMEOUT, stderr=STDOUT)

    def _get_nets_command(self, command):
        """
        Construct the netns command to execute.

        :param command: The command to execute.  This may either be a list or a
        single string.
        :return: The command to execute wrapped in the appropriate netns exec.
        If the original command was in list format, this returns a list,
        otherwise returns as a single string.
        """
        assert isinstance(command, list)
        return ["ip", "netns", "exec", self.name] + command


class NamespaceError(Exception):
    """
    Error creating or manipulating a network namespace.
    """
    pass


class Namespace(object):
    def __init__(self, path):
        self.path = path


class PidNamespace(Namespace):
    def __init__(self, pid):
        super(PidNamespace, self).__init__("/proc/%s/ns/net" % pid)
