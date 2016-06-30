#!/usr/bin/python
# Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

"""General utility functions"""

import socket
import sys
import os
import re
import logging
from subprocess import check_output, CalledProcessError

import netaddr
from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError


_log = logging.getLogger(__name__)  # pylint: disable=invalid-name
_log.addHandler(logging.NullHandler())

HOSTNAME_ENV = "HOSTNAME"

"""
Compile Regexes
"""
# Splits into groups that start w/ no whitespace and contain all lines below
# that start w/ whitespace
INTERFACE_SPLIT_RE = re.compile(r'(\d+:.*(?:\n\s+.*)+)')
# Grabs interface name
IFACE_RE = re.compile(r'^\d+: (\S+):')
# Grabs v4 addresses
IPV4_RE = re.compile(r'inet ((?:\d+\.){3}\d+)/\d+')
# Grabs v6 addresses
IPV6_RE = re.compile(r'inet6 ([a-fA-F\d:]+)/\d{1,3}')


class ValidationError(ValueError):
    """Base class for all validation errors"""
    pass


class AddrValidationError(ValidationError, AddrFormatError):
    """Error when passed value cannot be converted to an IP Address"""
    pass


class CharValidationError(ValidationError):
    """
    Error when passed string includes incompatible characters or is
    missing required ones.
    """
    pass


class RangeValidationError(ValidationError):
    """Error when passed value is outside the range of valid values"""
    pass


class TypeValidationError(ValidationError):
    """Error when passed value is an invalid type"""
    pass


class VersionMismatchError(ValidationError):
    """Error when passed IP Version does not match the CIDR/IP"""
    pass


def _return_bool(func, *args, **kwargs):
    """
    Simple function to catch exceptions and return a Bool

    :param func: The function being run
    :param *args: All positional args being passed to func
    :param **kwargs: All key-value args being passed to func
    :return: True if function succeeds, False if exception is raised
    :rtype: bool
    """
    try:
        func(*args, **kwargs)
    except ValidationError:
        return False
    else:
        return True


def generate_cali_interface_name(prefix, ep_id):
    """
    Helper method to generate a name for a calico veth, given the endpoint ID

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

    :param version: Desired IP address version. Can be 4 or 6. defaults to 4
    :param exclude: list of interface name regular expressions to ignore
                    (ex. ["^lo$","docker0.*"])
    :return: List of IPAddress objects.
    """
    exclude = exclude or []
    ip_addrs = []

    # Select Regex for IPv6 or IPv4.
    ip_re = IPV4_RE if version is 4 else IPV6_RE

    # Call `ip addr`.
    try:
        ip_addr_output = check_output(["ip", "-%d" % version, "addr"])
    except (CalledProcessError, OSError):
        print("Call to 'ip addr' Failed")
        sys.exit(1)

    # Separate interface blocks from ip addr output and iterate.
    for iface_block in INTERFACE_SPLIT_RE.findall(ip_addr_output):
        # Try to get the interface name from the block
        match = IFACE_RE.match(iface_block)
        iface = match.group(1)
        # Ignore the interface if it is explicitly excluded
        if match and not any(re.match(regex, iface) for regex in exclude):
            # Iterate through Addresses on interface.
            for address in ip_re.findall(iface_block):
                # Append non-loopback addresses.
                if not IPNetwork(address).ip.is_loopback():
                    ip_addrs.append(IPAddress(address))

    return ip_addrs


def get_hostname():
    """
    This will be the hostname returned by socket.gethostname,
    but can be overridden by passing in the $HOSTNAME environment variable.
    Though most shells appear to have $HOSTNAME set, it is actually not
    passed into subshells, so calicoctl will not see a set $HOSTNAME unless
    the user has explicitly set it in their environment, thus defaulting
    this function to return socket.gethostname.
    :return: String representation of the hostname.
    """
    try:
        return os.environ[HOSTNAME_ENV]
    except KeyError:
        # The user does not have a set $HOSTNAME. Since this is a common
        # scenario, return socket.gethostname instead of just erroring.
        return socket.gethostname()


def validate_asn(asn):
    """
    DEPRECATED (use verify_asn)

    Validate the format of a 2-byte or 4-byte autonomous system number

    :param asn: User input of AS number
    :type asn: str
    :return: True if valid format, False if invalid format
    :rtype: bool
    """
    return _return_bool(verify_asn, asn)


def verify_asn(asn):
    """
    Validate the format of a 2-byte or 4-byte autonomous system number

    :param asn: User input of AS number
    :type asn: str
    :return: None
    :rtype: None
    """

    try:
        asn_str = str(asn)
    except ValueError:
        raise TypeValidationError("AS Number cannot be converted to a "
                                  "string (''{0}'' given)".format(asn))

    if "." in asn_str:
        left_asn, right_asn = asn_str.split(".")

        try:
            left_asn_int = int(left_asn)
            right_asn_int = int(right_asn)
        except ValueError:
            raise TypeValidationError("ASDOT notation incorrect. ASDOT "
                                      "should consist of two intergers "
                                      "separated by a period "
                                      "('{0}' given)".format(asn))

        if not 0 <= left_asn_int <= 65535:
            raise RangeValidationError("Left side of ASDOT not in range "
                                       "('{0}' given)".format(left_asn))
        elif not 0 <= right_asn_int <= 65535:
            raise RangeValidationError("Right side of ASDOT not in range "
                                       "('{0}' given)".format(right_asn))
    else:
        try:
            asn_int = int(asn)
        # Passing a tuple == TypeError, passing "a" == ValueError
        except (TypeError, ValueError):
            raise TypeValidationError("ASPLAIN number could not be "
                                      "converted to an int. "
                                      "('{0}' given)".format(asn))

        if not 0 <= asn_int <= 4294967295:
            raise RangeValidationError("ASPLAIN number not in range ('{0}' "
                                       "given)".format(asn))


def validate_characters(input_string):
    """
    DEPRECATED (use verify_characters)

    Validate that characters in string are supported by Felix.
    Felix supports letters a-z, numbers 0-9, and symbols _.-

    :param input_string: to be validated
    :type input_string: str
    :return: returns True if valid, False if invalid
    :rtype: bool
    """
    return _return_bool(verify_characters, input_string)


def verify_characters(input_string):
    """
    Validate that characters in string are supported by Felix.
    Felix supports letters a-z, numbers 0-9, and symbols _.-

    :param input_string: string to be validated
    :type input_string: str
    :return: None
    :rtype: None
    """
    # List of valid characters that Felix permits
    valid_chars = r'[a-zA-Z0-9_\.\-]'

    # Check for invalid characters
    if not re.match("^%s+$" % valid_chars, input_string):
        raise CharValidationError("Invalid string. Felix only supports "
                                  "alphanumeric and the symbols '_', '.', "
                                  "and '-' ('{0}' given)".format(input_string))


def validate_cidr(cidr):
    """
    DEPRECATED (use verify_cidr)

    Validate cidr is in correct CIDR notation

    :param cidr: IP addr and associated routing prefix
    :type cidr: str
    :return: True if valid IP, False if invalid
    :rtype: bool
    """
    return _return_bool(verify_cidr, cidr)


def verify_cidr(cidr):
    """
    Validate cidr is in correct CIDR notation

    :param cidr: IP addr and associated routing prefix
    :type cidr: str
    :return: None
    :rtype: None
    """
    try:
        netaddr.IPNetwork(cidr)
    except (AddrFormatError, ValueError) as exc:
        # Some versions of Netaddr have a bug causing them to return a
        # ValueError rather than an AddrFormatError, so catch both.
        raise AddrValidationError("CIDR is invalid. " + str(exc).capitalize())


def validate_cidr_versions(cidrs, ip_version=None):
    """
    DEPRECATED (use verify_cidr_versions)

    Validate CIDR versions match each other and (if specified) the given IP
    version.

    :param cidrs: List of CIDRs whose versions need verification
    :param ip_version: Expected IP version that CIDRs should use (4, 6, None)
                       If None, CIDRs should all have same IP version
    :type cidrs: list, tuple
    :type ip_version: int, str, None
    :return: True if versions match each other and ip_version, False otherwise
    :rtype: bool
    """
    return _return_bool(verify_cidr_versions, cidrs, ip_version)


def verify_cidr_versions(cidrs, ip_version=None):
    """
    Validate CIDR versions match each other and (if specified) the given IP
    version.

    :param cidrs: List of CIDRs whose versions need verification
    :param ip_version: Expected IP version that CIDRs should use (4, 6, None)
                       If None, CIDRs should all have same IP version
    :type cidrs: list, tuple
    :type ip_version: int, str, None
    :return: None
    :rtype: None
    """
    for cidr in cidrs:
        try:
            network = netaddr.IPNetwork(cidr)
        except (AddrFormatError, ValueError) as exc:
            # Some versions of Netaddr have a bug causing them to return a
            # ValueError rather than an AddrFormatError, so catch both.
            raise AddrValidationError("CIDR is invalid. {}"
                                      "".format(str(exc).capitalize()))

        if ip_version is None:
            ip_version = network.version
        else:
            try:
                ip_version_int = int(ip_version)
            except (TypeError, ValueError):
                TypeValidationError("IP Version could not be converted to an "
                                    "int ('{0}' given)".format(ip_version))
            if ip_version_int not in (4, 6):
                raise RangeValidationError("IP Version invalid. Only 4 and 6 "
                                           "are valid versions, and '{0}' "
                                           "was given.".format(ip_version))

            if ip_version_int != network.version:
                raise VersionMismatchError("IP Version does not match "
                                           "CIDR(s).")


def validate_hostname(hostname):
    """
    DEPRECATED (use verify_hostname)

    Validates a hostname string.  This allows standard hostnames and IP
    addresses.

    :param hostname: The hostname to validate.
    :type hostname: str
    :return: True if valid, False if invalid
    :rtype: bool
    """
    return _return_bool(verify_hostname, hostname)


def verify_hostname(hostname):
    """
    Validates a hostname string.  This allows standard hostnames and IP
    addresses.

    :param hostname: The hostname to validate.
    :type hostname: str
    :return: None
    :rtype: None
    """
    # Hostname length is limited.
    if not isinstance(hostname, str):
        err_mess = "Hostname must be a string, not {0}".format(hostname)
        _log.error(err_mess)
        raise TypeValidationError(err_mess)

    hostname_len = len(hostname)

    if not 0 < hostname_len < 255:
        err_mess = ("Hostname length can only be 1 to 254 chars long (length "
                    "{0} given)".format(hostname_len))
        _log.error(err_mess)
        raise RangeValidationError(err_mess)

    # NOTE: The real limit in DNS is 255 octets (253 chars) or 254 chars
    #       if you include the root domain (i.e. a period on the end). RFC1035
    if hostname_len == 254 and not hostname.endswith('.'):
        err_mess = ("Hostname length can only be 1 to 254 chars long, and "
                    "only 254 chars if it includes the root domain. Passed "
                    "hostname is 254 chars with no trailing dot. ('{0}' given)"
                    "".format(hostname))
        _log.error(err_mess)
        raise RangeValidationError(err_mess)

    if ':' in hostname:
        try:
            IPAddress(hostname)
        except (AddrFormatError, ValueError):
            err_mess = ("Hostname '{0}' has a colon in it, but is not a valid "
                        "IPv6 address. Thus, it is not DNS resolvable or "
                        "routable.".format(hostname))
            _log.error(err_mess)
            raise CharValidationError(err_mess)
        else:
            # Hostname is a valid IP Address. Skipping regex
            return

    # Hostname labels may consist of numbers, letters and hyphens, but may not
    # end or begin with a hyphen.
    allowed = re.compile(r"(?!-)[a-z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    for part in hostname.split('.'):
        if not allowed.match(part):
            err_mess = ("Hostname labels (parts delimited by periods) may "
                        "only consist of numbers, letters, and hyphens (but "
                        "may not end or begin with a hyphen). Each label must "
                        "also be between 1 and 63 chars long. ('{0}' given)"
                        "".format(part))
            _log.error(err_mess)
            raise CharValidationError(err_mess)


def validate_hostname_port(hostname_port):
    """
    DEPRECATED (use verify_hostname_part)

    Validate the hostname and port format.  (<HOSTNAME>:<PORT>)
    An IPv4 address is a valid hostname.

    :param hostname_port: The hostname:port  to verify
    :type hostname_port: str
    :return: True if valid, False if invalid
    :rtype: bool
    """
    return _return_bool(verify_hostname_port, hostname_port)


def verify_hostname_port(hostname_port):
    """
    Validate the hostname and port format.  (<HOSTNAME>:<PORT>)
    An IPv4 address is a valid hostname.

    :param hostname_port: The hostname:port to verify
    :type hostname_port: str
    :return: None
    :rtype: None
    """
    # Should contain a single ":" separating hostname and port
    if not isinstance(hostname_port, str):
        err_mess = ("Must provide string for hostname:port validation, not "
                    "{0}".format(type(hostname_port)))
        _log.error(err_mess)
        raise TypeValidationError(err_mess)

    try:
        hostname, port = hostname_port.rsplit(":", 1)
    except ValueError:
        err_mess = ("Must provide a string splittable by ':' for "
                    "hostname-port. ('{0} given')".format(hostname_port))
        _log.error(err_mess)
        raise CharValidationError(err_mess)

    # Check the hostname format.
    verify_hostname(hostname)

    # Check port range.
    try:
        port_int = int(port)
    except ValueError:
        err_mess = ("Port must be able to convert to an integer. ('{0}' given)"
                    "".format(port))
        _log.error(err_mess)
        raise TypeValidationError(err_mess)

    if not 1 <= port_int <= 65535:
        err_mess = ("Provided port {0} must be from 1 to 65535."
                    "".format(port))
        _log.error(err_mess)
        raise RangeValidationError(err_mess)


def validate_icmp_type(icmp_type):
    """
    DEPRECATED (use verify_icmp_type)

    Validate that icmp_type is an integer from 0 to 255.
    If not return False.

    :param icmp_type: int value representing an icmp type
    :type icmp_type: str, int
    :return: True if valid icmp type, False if not
    :rtype: bool
    """
    return _return_bool(verify_icmp_type, icmp_type)


def verify_icmp_type(icmp_type):
    """
    Validate that icmp_type is an integer from 0 to 255.
    If not return False.

    :param icmp_type: int value representing an icmp type
    :type icmp_type: int, str
    :return: None
    :rtype: None
    """
    try:
        icmp_type_int = int(icmp_type)
    except (TypeError, ValueError):
        raise TypeValidationError("ICMP type is invalid. '{0}' could not "
                                  "be converted to an int.".format(icmp_type))
    if not 0 <= icmp_type_int <= 255:
        raise RangeValidationError("ICMP type is invalid. Value must be "
                                   "between 0 and 255 ('{0}' given)."
                                   "".format(icmp_type))


def validate_ip(ip_addr, version=None):
    """
    DEPRECATED (use verify_ip)

    Validate that ip_addr is a valid IPv4 or IPv6 address

    :param ip_addr: IP address to be validated
    :param version: 4 or 6
    :type ip_addr: str
    :type version: int, str, None
    :return: True if valid, False if invalid.
    :rtype: bool
    """
    assert version in (4, 6)  # For backward compatibility

    return _return_bool(verify_ip, ip_addr, version)


def verify_ip(ip_addr, version=None):
    """
    Validate that ip_addr is a valid IPv4 or IPv6 address

    :param ip_addr: IP address to be validated
    :param version: 4 or 6
    :type ip_addr: str
    :type version: int, str, None
    :return: None
    :rtype: None
    """
    if version:
        try:
            version_int = int(version)
        except (TypeError, ValueError):
            raise TypeValidationError("Version could not be converted to "
                                      "an integer. ('{0}' as given)."
                                      "".format(version))

        if version_int not in (4, 6):
            raise RangeValidationError("Version is invalid. Should be 4 or "
                                       "6, but '{0}' was given."
                                       "".format(version))

    # NOTE: Most integers will work here, due to netaddr's internal
    #       index, which might be misleading.
    try:
        address = IPAddress(ip_addr)
    except (AddrFormatError, ValueError):
        raise AddrValidationError("'{0}' is not a valid IP address.")

    if version and address.version != version_int:
        raise VersionMismatchError("'{0}' is not a valid IPv{1} address."
                                   "".format(ip_addr, version))


def validate_port_str(port_str):
    """
    DEPRECATED (use verify_port_str)

    Checks whether the command line word specifying a set of ports is valid.

    :param port_str: A comma delimited list of ports and port ranges
    :type port_str: str
    :return: returns True if ports are in range, False if not in range
    :rtype: bool
    """
    return validate_ports(port_str.split(","))


def verify_port_str(port_str):
    """
    Checks whether the command line word specifying a set of ports is valid
    and raises if not.

    :param port_str: A comma delimited list of ports and port ranges
    :type port_str: str
    :return: None
    :rtype: None
    """
    return verify_ports(port_str.split(","))


def validate_ports(port_list):
    """
    DEPRECATED (use verify_ports)

    Checks whether a list of ports are within range of 0 and 65535.
    The port list must include a number or a number range.

    A valid number range must be two numbers delimited by a colon with the
    second number higher than the first. Both numbers must be within range.
    If a number range is invalid, the function will raise ValueError.

    :param port_list: A collection of ports and port ranges
    :type port_list: list, tuple
    :return: returns True if passed, False if exception raised
    :rtype: bool
    """
    return _return_bool(verify_ports, port_list)


def verify_ports(port_list):
    """
    Checks whether a list of ports are within range of 0 and 65535.
    The port list must include a number or a number range.

    A valid number range must be two numbers delimited by a colon with the
    second number higher than the first. Both numbers must be within range.
    If a number range is invalid, the function will raise ValueError.

    :param port_list: A collection of ports and port ranges
    :type port_list: list, tuple
    :return: None
    :rtype: None
    """
    for port in port_list:
        if ":" in str(port):
            ports = port.split(":")

            try:
                port1_int = int(ports[0])
            except ValueError:
                raise TypeValidationError("Port on left side of range could "
                                          "not be converted to an int ('{0}' "
                                          "given).".format(port))
            try:
                port2_int = int(ports[1])
            except ValueError:
                raise TypeValidationError("Port on right side of range could "
                                          "not be converted to an int ('{0}' "
                                          "given).".format(port))

            if not ((len(ports) == 2) and port1_int < port2_int and
                    validate_ports(ports)):
                raise RangeValidationError("Port range is invalid. Values "
                                           "must be from 0 to 65535 ('{0}' "
                                           "given).".format(port))
        else:
            try:
                port_int = int(port)
            except:
                raise TypeValidationError("Unable to convert port to an "
                                          "integer ('{0}' given)".format(port))
            if not 0 <= port_int <= 65535:
                raise RangeValidationError("Port is invalid. Value must be "
                                           "from 0 to 65535 ('{0}' given)."
                                           "".format(port))

def get_ipv6_link_local(interface_name):
    """
    Runs IP routing commands to extract the currently assigned IPv6 link-local
    address for an interface in this namespace.

    :param interface_name: Name fo the target interface.
    :return: A string represention of the link local address, or None (if one isn't assigned).
    Will throw exception if not interface information exists for that name.
    """
    # Find which link local was assigned to the ipv6 interface
    try:
        ip_addr_output = check_output(["ip", "-6", "addr", "show", "dev", interface_name])
    except (CalledProcessError, OSError, AttributeError) as e:
        _log.debug("Failed to get IPv6 address for veth: %s. Error: %s",
                interface_name, e)
    _log.debug("Searching for linklocal of %s in: %s", interface_name, ip_addr_output)

    try:
        next_hop_6 = re.search(IPV6_RE, ip_addr_output).group(1)
    except AttributeError:
        _log.warning("No nexthop found for interface %s", interface_name)
        return None

    _log.info("Got nexthop %s for interface %s", next_hop_6, interface_name)
    return next_hop_6
