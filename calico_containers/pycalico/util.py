import socket
import sys
import os
import re
from netaddr import IPNetwork
from subprocess import check_output, CalledProcessError

HOSTNAME_ENV = "HOSTNAME"

"""
Compile Regexes
"""
# Splits into groups that start w/ no whitespace and contain all lines below that start w/ whitespace
INTERFACE_SPLIT_RE = re.compile(r'(\d+:.*(?:\n\s+.*)+)')
# Grabs interface name
IFACE_RE = re.compile(r'^\d+: (\S+):')
# Grabs v4 addresses
IPV4_RE = re.compile(r'inet ((?:\d+\.){3}\d+)\/\d+')
# Grabs v6 addresses
IPV6_RE = re.compile(r'inet6 ([a-fA-F\d:]+)\/\d{1,3}')

def generate_cali_interface_name(prefix, ep_id):
    """Helper method to generate a name for a calico veth, given the endpoint ID

    This takes a prefix, and then truncates the EP ID.

    :param prefix: T
    :param ep_id:
    :return:
    """
    if len(prefix) > 4:
        raise ValueError('Prefix must be 4 characters or less.')
    return prefix + ep_id[:11]


def get_host_ips(version=4, exclude=None):
    """
    Gets all IP addresses assigned to this host.

    Ignores Loopback Addresses

    This function is fail-safe and will return an empty array instead of
    raising any exceptions.

    :param version: Desired version of IP addresses. Can be 4 or 6. defaults to 4
    :param exclude: list of interface name regular expressions to ignore
                    (ex. ["^lo$","docker0.*"])
    :return: List of string representations of IP Addresses.
    """
    exclude = exclude or []
    ip_addrs = []

    # Select Regex for IPv6 or IPv4.
    IP_RE = IPV4_RE if version is 4 else IPV6_RE

    # Call `ip addr`.
    try:
        ip_addr_output = check_output(["ip", "-%d" % (version), "addr"])
    except CalledProcessError, OSError:
        print "Call to 'ip addr' Failed"
        sys.exit(1)

    # Separate interface blocks from ip addr output and iterate.
    for iface_block in INTERFACE_SPLIT_RE.findall(ip_addr_output):
        # Try to get the interface name from the block
        match = IFACE_RE.match(iface_block)
        iface = match.group(1)
        # Ignore the interface if it is explicitly excluded
        if match and not any(re.match(regex, iface) for regex in exclude):
            # Iterate through Addresses on interface.
            for address in IP_RE.findall(iface_block):
                # Append non-loopback addresses.
                if not IPNetwork(address).ip.is_loopback():
                    ip_addrs.append(address)

    return ip_addrs

def get_hostname():
    """
    Gets the hostname. This will be the hostname returned by socket.gethostname,
    but can be overridden by passing in the $HOSTNAME environment variable.
    However, though most shells appear to have $HOSTNAME set, it is actually not
    passed into subshells, so calicoctl will not see a set $HOSTNAME unless
    the user has explicitly set it in their environment, thus defaulting
    this function to return socket.gethostname.
    :return: String representation of the hostname.
    """
    try:
        return os.environ[HOSTNAME_ENV]
    except KeyError:
        # The user does not have a set $HOSTNAME. Since this is a common
        # scenario, return socekt.gethostname instead of just erroring.
        return socket.gethostname()