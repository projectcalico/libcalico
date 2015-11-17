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

def validate_ports(port_list):
    """
    Checks whether a list of ports are within range of 0 and 65535.
    The port list must include a number or a number range.

    A valid number range must be two numbers delimited by a colon with the
    second number higher than the first. Both numbers must be within range.
    If a number range is invalid, the function will return False.

    :param port_list:
    :return: a Boolean: True if in range, False if not in range
    """
    in_range = True
    for port in port_list:
        if ":" in str(port):
            ports = port.split(":")
            in_range = (len(ports) == 2) and (int(ports[0]) < int(ports[1])) \
                       and validate_ports(ports)
        else:
            try:
                in_range = 0 <= int(port) < 65536
            except ValueError:
                in_range = False
        if not in_range:
            break

    return in_range

def validate_characters(input_string):
    """
    Validate that characters in string are supported by Felix.
    Felix supports letters a-z, numbers 0-9, and symbols _.-

    :param input_string: string to be validated
    :return: Boolean: True if valid, False if invalid
    """
    # List of valid characters that Felix permits
    valid_chars = '[a-zA-Z0-9_\.\-]'

    # Check for invalid characters
    if not re.match("^%s+$" % valid_chars, input_string):
        return False
    else:
        return True

def validate_icmp_type(icmp_type):
    """
    Validate that icmp_type is an integer between 0 and 255.
    If not return False.

    :param icmp_type:
    :return: Boolean: True if valid icmp type, False if not
    """
    try:
        valid = 0 <= int(icmp_type) < 255
    except ValueError:
        valid = False
    return valid
