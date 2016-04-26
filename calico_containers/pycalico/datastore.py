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

import json
import os
import uuid
import etcd
import re
from etcd import EtcdKeyNotFound, EtcdException, EtcdNotFile, EtcdKeyError

from netaddr import IPNetwork, IPAddress, AddrFormatError

from pycalico.datastore_datatypes import Rules, BGPPeer, IPPool, \
    Endpoint, Profile, Rule, IF_PREFIX, IPAMConfig, Policy
from pycalico.datastore_errors import DataStoreError, \
    ProfileNotInEndpoint, ProfileAlreadyInEndpoint, MultipleEndpointsMatch
from pycalico.util import get_hostname, validate_hostname_port

ETCD_AUTHORITY_DEFAULT = "127.0.0.1:2379"
ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"
ETCD_ENDPOINTS_ENV = "ETCD_ENDPOINTS"

# Secure etcd with SSL environment variables and paths
ETCD_SCHEME_DEFAULT = "http"
ETCD_SCHEME_ENV = "ETCD_SCHEME"
ETCD_KEY_FILE_ENV = "ETCD_KEY_FILE"
ETCD_CERT_FILE_ENV = "ETCD_CERT_FILE"
ETCD_CA_CERT_FILE_ENV = "ETCD_CA_CERT_FILE"

# etcd paths for Calico workloads, endpoints and IPAM.
CALICO_V_PATH = "/calico/v1"
CONFIG_PATH = CALICO_V_PATH + "/config/"
CONFIG_IF_PREF_PATH = CONFIG_PATH + "InterfacePrefix"
HOSTS_PATH = CALICO_V_PATH + "/host/"
HOST_PATH = HOSTS_PATH + "%(hostname)s/"
HOST_CONFIG_PATH = HOST_PATH + "config/"
HOST_CONFIG_KEY_PATH = HOST_CONFIG_PATH + "%(config_param)s"
ORCHESTRATOR_PATH = HOST_PATH + "workload/%(orchestrator_id)s/"
WORKLOAD_PATH = ORCHESTRATOR_PATH + "%(workload_id)s/"
LOCAL_ENDPOINTS_PATH = WORKLOAD_PATH + "endpoint/"
ENDPOINT_PATH = LOCAL_ENDPOINTS_PATH + "%(endpoint_id)s"
PROFILES_PATH = CALICO_V_PATH + "/policy/profile/"
PROFILE_PATH = PROFILES_PATH + "%(profile_id)s/"
TAGS_PATH = PROFILE_PATH + "tags"
RULES_PATH = PROFILE_PATH + "rules"
TIER_PATH = CALICO_V_PATH + "/policy/tier/%(tier_name)s"
POLICY_PATH = TIER_PATH + "/policy/%(policy_name)s/"
IP_POOLS_PATH = CALICO_V_PATH + "/ipam/v%(version)s/pool/"
IP_POOL_KEY = IP_POOLS_PATH + "%(pool)s"

# Felix IPv4 host value.
# @TODO This is a throw-back to the previous datamodel, and the field is badly
# @TODO named.  New PR will sort out the naming in calico-docker and felix.
HOST_IPV4_PATH = HOST_PATH + "bird_ip"

# etcd paths for BGP specific configuration
BGP_V_PATH = "/calico/bgp/v1/"
BGP_GLOBAL_PATH = BGP_V_PATH + "global/"
BGP_GLOBAL_PEERS_PATH = BGP_GLOBAL_PATH + "peer_v%(version)s/"
BGP_GLOBAL_PEER_PATH = BGP_GLOBAL_PEERS_PATH + "%(peer_ip)s"
BGP_NODE_DEF_AS_PATH = BGP_GLOBAL_PATH + "as_num"
BGP_NODE_MESH_PATH = BGP_GLOBAL_PATH + "node_mesh"
BGP_HOSTS_PATH = BGP_V_PATH + "host/"
BGP_HOST_PATH = BGP_HOSTS_PATH + "%(hostname)s/"
BGP_HOST_IPV4_PATH = BGP_HOST_PATH + "ip_addr_v4"
BGP_HOST_IPV6_PATH = BGP_HOST_PATH + "ip_addr_v6"
BGP_HOST_AS_PATH = BGP_HOST_PATH + "as_num"
BGP_HOST_PEERS_PATH = BGP_HOST_PATH + "peer_v%(version)s/"
BGP_HOST_PEER_PATH = BGP_HOST_PATH + "peer_v%(version)s/%(peer_ip)s"

# Grabs hostname from etcd datastore keys
HOSTNAME_IP_DATASTORE_RE = re.compile(BGP_HOSTS_PATH + "(.*)/ip_addr_v[46]")
HOSTNAME_ANY_BGP_DATASTORE_RE = re.compile(BGP_HOSTS_PATH +"(.*)/" +
                                         "(ip_addr_v[46]|peer_v[46]/.*|as_num)")

# Global configuration
IP_IN_IP_PATH = CONFIG_PATH + "IpInIpEnabled"
LOG_SEVERITY_FILE_PATH = CONFIG_PATH + "LogSeverityFile"
LOG_SEVERITY_SCREEN_PATH = CONFIG_PATH + "LogSeverityScreen"
LOG_FILE_PATH_PATH = CONFIG_PATH + "LogFilePath"

# The default node AS number.
DEFAULT_AS_NUM = 64511

# The default node mesh configuration.
DEFAULT_NODE_MESH = {"enabled": True}

# Default logging configuration.
DEFAULT_LOG_SEVERITY_FILE = "none"
DEFAULT_LOG_SEVERITY_SCREEN = "info"
DEFAULT_LOG_FILE_PATH = "none"

# Global IP in IP disabled and enabled values.  By default, IPIP is disabled
# and only enabled when the first IP Pool with IPIP is configured.
IP_IN_IP_DISABLED = "false"
IP_IN_IP_ENABLED = "true"

# IPAM paths
IPAM_V_PATH = "/calico/ipam/v2/"
IPAM_CONFIG_PATH = IPAM_V_PATH + "config"
IPAM_HOSTS_PATH = IPAM_V_PATH + "host"
IPAM_HOST_PATH = IPAM_HOSTS_PATH + "/%(host)s"
IPAM_HOST_AFFINITY_PATH = IPAM_HOST_PATH + "/ipv%(version)d/block/"
IPAM_BLOCK_PATH = IPAM_V_PATH + "assignment/ipv%(version)d/block/"
IPAM_HANDLE_PATH = IPAM_V_PATH + "handle/"


def handle_errors(fn):
    """
    Decorator function to decorate Datastore API methods to handle common
    exception types and re-raise as datastore specific errors.
    :param fn: The function to decorate.
    :return: The decorated function.
    """
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except EtcdException as e:
            # Don't leak out etcd exceptions.
            raise DataStoreError("%s: Error accessing etcd (%s).  Is etcd "
                                 "running?" % (fn.__name__, e.message))
    return wrapped


class DatastoreClient(object):
    """
    An datastore client that exposes high level Calico operations needed by the
    calico CLI.
    """

    def __init__(self):
        etcd_endpoints = os.getenv(ETCD_ENDPOINTS_ENV, '')
        etcd_authority = os.getenv(ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT)
        etcd_scheme = os.getenv(ETCD_SCHEME_ENV, ETCD_SCHEME_DEFAULT)
        etcd_key = os.getenv(ETCD_KEY_FILE_ENV, '')
        etcd_cert = os.getenv(ETCD_CERT_FILE_ENV, '')
        etcd_ca = os.getenv(ETCD_CA_CERT_FILE_ENV, '')

        addr_env = None
        scheme_env = None
        etcd_addrs_raw = []
        if etcd_endpoints:
            # ETCD_ENDPOINTS specified: use it to determine scheme and etcd
            # location.
            endpoints = [x.strip() for x in etcd_endpoints.split(",")]
            try:
                scheme = None
                for e in endpoints:
                    s, a = e.split("://")
                    etcd_addrs_raw.append(a)
                    if scheme == None:
                        scheme = s
                    else:
                        if scheme != s:
                            raise DataStoreError(
                                "Inconsistent protocols in %s.  Value "
                                "provided is '%s'" %
                                (ETCD_ENDPOINTS_ENV, etcd_endpoints)
                            )
                etcd_scheme = scheme
                addr_env = ETCD_ENDPOINTS_ENV
                scheme_env = ETCD_ENDPOINTS_ENV
            except ValueError:
                raise DataStoreError("Invalid %s. It must take the form"
                                     "'ENDPOINT[,ENDPOINT][,...]' where "
                                     "ENDPOINT:='http[s]://ADDRESS:PORT'. "
                                     "Value provided is '%s'" %
                                     (ETCD_ENDPOINTS_ENV, etcd_endpoints))
        else:
            # ETCD_ENDPOINTS not specified, fall back to ETCD_AUTHORITY and
            # ETCD_SCHEME instead.
            etcd_addrs_raw.append(etcd_authority)
            addr_env = ETCD_AUTHORITY_ENV
            scheme_env = ETCD_SCHEME_ENV

        etcd_addrs = []
        for addr in etcd_addrs_raw:
            if not validate_hostname_port(addr):
                raise DataStoreError(
                    "Invalid %s. Address must take the form "
                    "<address>:<port>. Value provided is '%s'" %
                    (addr_env, addr)
                )
            (host, port) = addr.split(":", 1)
            etcd_addrs.append((host, int(port)))

        key_pair = (etcd_cert, etcd_key) if (etcd_cert and etcd_key) else None

        if etcd_scheme == "https":
            # key and certificate must be both specified or both not specified
            if bool(etcd_key) != bool(etcd_cert):
                raise DataStoreError("Invalid %s, %s combination. Key and "
                                     "certificate must both be specified or "
                                     "both be blank. Values provided: %s=%s, "
                                     "%s=%s" % (ETCD_KEY_FILE_ENV,
                                                ETCD_CERT_FILE_ENV,
                                                ETCD_KEY_FILE_ENV, etcd_key,
                                                ETCD_CERT_FILE_ENV, etcd_cert))
            # Make sure etcd key and certificate are readable
            if etcd_key and etcd_cert and not (os.path.isfile(etcd_key) and
                                               os.access(etcd_key, os.R_OK) and
                                               os.path.isfile(etcd_cert) and
                                               os.access(etcd_cert, os.R_OK)):
                raise DataStoreError("Cannot read %s and/or %s. Both must "
                                     "be readable file paths. Values "
                                     "provided: %s=%s, %s=%s" %
                                     (ETCD_KEY_FILE_ENV,
                                      ETCD_CERT_FILE_ENV,
                                      ETCD_KEY_FILE_ENV, etcd_key,
                                      ETCD_CERT_FILE_ENV, etcd_cert))
            # Certificate Authority cert must be provided, check it's readable
            if not etcd_ca or not (os.path.isfile(etcd_ca) and
                                   os.access(etcd_ca, os.R_OK)):
                raise DataStoreError("Invalid %s. Certificate Authority "
                                     "cert is required and must be a "
                                     "readable file path. Value provided: "
                                     "%s" % (ETCD_CA_CERT_FILE_ENV, etcd_ca))
        elif etcd_scheme != "http":
            raise DataStoreError("Invalid %s. Value must be one of: \"\", "
                                 "\"http\", \"https\". Value provided: %s" %
                                 (scheme_env, etcd_scheme))

        # Set CA value to None if it is a None-value string
        etcd_ca = None if not etcd_ca else etcd_ca

        # python-etcd Client requires a different invocation when there's only
        # a single etcd host.
        if len(etcd_addrs) > 1:
            # Specify allow_reconnect when there are multiple endpoints, so
            # python-etcd will try connecting to all of them if one fails.
            self.etcd_client = etcd.Client(host=tuple(etcd_addrs),
                                           protocol=etcd_scheme,
                                           cert=key_pair,
                                           ca_cert=etcd_ca,
                                           allow_reconnect=True)
        else:
            self.etcd_client = etcd.Client(host=etcd_addrs[0][0],
                                           port=etcd_addrs[0][1],
                                           protocol=etcd_scheme,
                                           cert=key_pair,
                                           ca_cert=etcd_ca)

    @handle_errors
    def ensure_global_config(self):
        """
        Ensure the global config settings for Calico exist, creating them with
        defaults if they don't.
        :return: None.
        """
        # Configure Felix config.
        self._write_global_config(CONFIG_IF_PREF_PATH, IF_PREFIX)

        # Configure IPAM directory structures (to ensure confd is able to
        # watch appropriate directory trees).
        host = get_hostname()
        for version in (4, 6):
            affinity_path = IPAM_HOST_AFFINITY_PATH % {"host": host,
                                                       "version": version}
            pool_path = IP_POOLS_PATH % {"version": version}
            self._write_global_dir(affinity_path)
            self._write_global_dir(pool_path)

        # Configure BGP global (default) config if it doesn't exist.
        self._write_global_config(BGP_NODE_DEF_AS_PATH, str(DEFAULT_AS_NUM))
        self._write_global_config(BGP_NODE_MESH_PATH,
                                  json.dumps(DEFAULT_NODE_MESH))

        # Configure logging levels.
        self._write_global_config(LOG_SEVERITY_FILE_PATH,
                                  DEFAULT_LOG_SEVERITY_FILE)
        self._write_global_config(LOG_SEVERITY_SCREEN_PATH,
                                  DEFAULT_LOG_SEVERITY_SCREEN)
        self._write_global_config(LOG_FILE_PATH_PATH,
                                  DEFAULT_LOG_FILE_PATH)

        # IP in IP is enabled globally.
        self._write_global_config(IP_IN_IP_PATH, IP_IN_IP_DISABLED)

        # We are always ready.
        self.etcd_client.write(CALICO_V_PATH + "/Ready", "true")

    def _write_global_config(self, key, value):
        """
        Write global config into the datastore if it does not already exist.
        :param key: The configuration key.
        :param value: The configuration value.
        """
        try:
            self.etcd_client.read(key)
        except EtcdKeyNotFound:
            self.etcd_client.write(key, value)

    def _write_global_dir(self, key):
        """
        Write a global directory to the datastore if it does not already exist.
        :param key: The directory key.
        """
        try:
            self.etcd_client.write(key, None, dir=True)
        except EtcdNotFile:
            # Directory already exists.
            pass

    @handle_errors
    def create_host(self, hostname, ipv4, ipv6, as_num):
        """
        Create a new Calico host configuration in etcd.

        :param hostname: The name of the host to create.
        :param ipv4: The IPv4 address bound to the node.
        :param ipv6: The IPv6 address bound to the node.
        :param as_num: Optional AS Number to use for this host.  If not
        specified, the configured global or default global value is used.
        :return: nothing.
        """
        host_path = HOST_PATH % {"hostname": hostname}
        host_ipv4 = HOST_IPV4_PATH % {"hostname": hostname}
        bgp_ipv4 = BGP_HOST_IPV4_PATH % {"hostname": hostname}
        bgp_ipv6 = BGP_HOST_IPV6_PATH % {"hostname": hostname}
        bgp_as = BGP_HOST_AS_PATH % {"hostname": hostname}

        # Set up the host
        self.etcd_client.write(host_ipv4, ipv4)
        self.etcd_client.write(bgp_ipv4, ipv4)
        self.etcd_client.write(bgp_ipv6, ipv6)
        workload_dir = host_path + "workload"
        try:
            self.etcd_client.read(workload_dir)
        except EtcdKeyNotFound:
            # Didn't exist, create it now.
            self.etcd_client.write(workload_dir, None, dir=True)

        # Set or delete the node specific BGP AS number as required.  If the
        # value is missing from the etcd datastore, the BIRD templates will
        # inherit the configured global default value (and then the
        # hardcoded default value).
        if as_num is None:
            try:
                self.etcd_client.delete(bgp_as)
            except EtcdKeyNotFound:
                pass
        else:
            self.etcd_client.write(bgp_as, as_num)

        # Configure Felix to allow traffic from the containers to the host (if
        # not otherwise firewalled by the host administrator or profiles).
        # This is important for Mesos, where the containerized executor process
        # needs to exchange messages with the Mesos Slave process running on
        # the host.
        self.set_per_host_config(hostname, "DefaultEndpointToHostAction",
                                 "RETURN")

        # Flag that the host is created.
        self.set_per_host_config(hostname, "marker", "created")

        return

    @handle_errors
    def get_per_host_config(self, hostname, config_param):
        """
        Get a raw (string) per-host config parameter from etcd.
        :param hostname: The name of the host.
        :param config_param: The name of the config parameter (e.g.
               "LogSeverityFile").
        :return: string value or None if config wasn't present.
        """
        config_key = HOST_CONFIG_KEY_PATH % {
            "hostname": hostname,
            "config_param": config_param,
        }
        try:
            return self.etcd_client.read(config_key).value
        except EtcdKeyNotFound:
            return None

    @handle_errors
    def set_per_host_config(self, hostname, config_param, value):
        """
        Write a raw (string) per-host config parameter to etcd.
        :param hostname: The name of the host who's config should be updated.
        :param config_param: The name of the parameter (e.g.
               "LogSeverityFile").
        :param value: The raw string value to set, or None to delete the key.
        """
        config_key = HOST_CONFIG_KEY_PATH % {
            "hostname": hostname,
            "config_param": config_param,
        }
        if value is not None:
            self.etcd_client.write(config_key, value)
        else:
            try:
                self.etcd_client.delete(config_key)
            except EtcdKeyNotFound:
                pass

    @handle_errors
    def remove_per_host_config(self, hostname, config_param):
        """
        Remove a per-host config parameter.
        :param hostname: The name of the host who's config should be updated.
        :param config_param: The name of the parameter (e.g.
               "LogSeverityFile").
        """
        self.set_per_host_config(hostname, config_param, None)

    @handle_errors
    def remove_host(self, hostname):
        """
        Remove a Calico host.
        :param hostname: The name of the host to remove.
        :return: nothing.
        """
        # Remove the host BGP tree.
        bgp_host_path = BGP_HOST_PATH % {"hostname": hostname}
        try:
            self.etcd_client.delete(bgp_host_path, dir=True, recursive=True)
        except EtcdKeyNotFound:
            pass

        # Remove the host calico tree.
        host_path = HOST_PATH % {"hostname": hostname}
        try:
            self.etcd_client.delete(host_path, dir=True, recursive=True)
        except EtcdKeyNotFound:
            pass

    @handle_errors
    def get_hosts_data_dict(self):
        """
        Get list of hosts with data from the etcd datastore.
        :return: Dictionary of host dictionaries, indexed by hostname, with data
        for ipv4, ipv6, bgp peers and as_num
        """
        try:
            # Get all host data
            host_data = self.etcd_client.read(BGP_HOSTS_PATH, recursive=True)
        except EtcdKeyNotFound:
            # No BGP hosts currently configured in etcd
            return {}

        host_dict = {}
        for host_leaf in host_data.leaves:
            # Match expected host data values
            match = HOSTNAME_ANY_BGP_DATASTORE_RE.match(host_leaf.key)
            if match:
                # Get hostname and key name from match data
                hostname = match.group(1)
                data_name = match.group(2)
                if hostname not in host_dict.keys():
                    # Hostname has not been added to dict, init host data now
                    host_dict[hostname] = {"as_num":     "",
                                           "ip_addr_v4": "",
                                           "ip_addr_v6": "",
                                           "peer_v4":    [],
                                           "peer_v6":    []}
                if data_name in ["as_num", "ip_addr_v4", "ip_addr_v6"]:
                    host_dict[hostname][data_name] = host_leaf.value
                else:
                    # data_name is "peer_v[46]/<ip>", get "peer_v[46]
                    peer_key = data_name.split("/")[0]

                    # Save BGP peer dict {"ip": <ip>, "as_num": <as>} in data
                    leaf_dict = json.loads(host_leaf.value)
                    host_dict[hostname][peer_key].append(leaf_dict)

        return host_dict

    @handle_errors
    def get_hostnames_from_ips(self, ip_list):
        """
        Get the hostnames that are using the given IPs as their calico node IPs.
        :param ip_list: The list of IPs to get hostnames for.
        :return: A dictionary of {IP:hostname} the hosts that own the given IPs.
        """
        try:
            hosts = self.etcd_client.read(BGP_HOSTS_PATH, recursive=True)
            host_ips = hosts.leaves
        except EtcdKeyNotFound:
            # No BGP hosts currently configured in etcd, so no host owns the IP
            raise KeyError("No BGP host configurations found.")

        ip_host_dict = {}

        # Loop through key-value pairs to find IP addresses
        for host_ip in host_ips:
            # Check for the ipv4 or ipv6 address key values
            host_match = HOSTNAME_IP_DATASTORE_RE.match(host_ip.key)
            if host_match and host_ip.value in ip_list:
                # Pull the hostname from the datastore key string
                hostname = host_match.group(1)
                ip_host_dict[host_ip.value] = hostname

        return ip_host_dict

    @handle_errors
    def get_host_bgp_ips(self, hostname):
        """
        Check etcd for the configured IPv4 and IPv6 addresses for the specified
        host BGP binding. If it hasn't been configured yet, raise an
        EtcdKeyNotFound.

        :param hostname: The hostname.
        :return: A tuple containing the IPv4 and IPv6 address.
        """
        bgp_ipv4 = BGP_HOST_IPV4_PATH % {"hostname": hostname}
        bgp_ipv6 = BGP_HOST_IPV6_PATH % {"hostname": hostname}
        try:
            ipv4 = self.etcd_client.read(bgp_ipv4).value
            ipv6 = self.etcd_client.read(bgp_ipv6).value
        except EtcdKeyNotFound:
            raise KeyError("BIRD configuration for host %s not found." % hostname)
        else:
            return (ipv4, ipv6)

    @handle_errors
    def get_host_as(self, hostname):
        """
        Query the host AS number.

        :param hostname: The hostname.
        :return: The host AS number, or None if the host is inheriting the
        global default node AS number.
        """
        bgp_as = BGP_HOST_AS_PATH  % {"hostname": hostname}
        try:
            as_num = self.etcd_client.read(bgp_as).value
        except EtcdKeyNotFound:
            return None
        else:
            return as_num

    @handle_errors
    def get_ip_pools(self, version, ipam=None, include_disabled=True):
        """
        Get the configured IP pools.

        :param version: 4 for IPv4, 6 for IPv6
        :param ipam:  Filter on the ipam flag.  If None, all IP Pools are
        returned.  If False, only pools that are not used by Calico IPAM are
        returned.  If True, only pools that are used by Calico IPAM are
        returned.
        :param include_disabled:  Whether disabled pools should be in the list.
        :return: List of IPPool.
        """
        assert version in (4, 6)
        pool_path = IP_POOLS_PATH % {"version": str(version)}
        try:
            leaves = self.etcd_client.read(pool_path, recursive=True).leaves
        except EtcdKeyNotFound:
            # Path doesn't exist.
            pools = []
        else:
            # Convert the leaf values to IPPools.  We need to handle an empty
            # leaf value because when no pools are configured the recursive
            # read returns the parent directory.
            pools = [IPPool.from_json(leaf.value) for leaf in leaves
                                                  if leaf.value]

            # If required, filter out pools that are not used for Calico IPAM.
            if ipam is not None:
                pools = [pool for pool in pools
                              if ((pool.ipam == ipam) and
                                  (include_disabled or not pool.disabled))]

        return pools

    @handle_errors
    def get_pool(self, ip):
        """
        Returns the first pool which contains the given IP address

        :param ip: The IP address to search for
        :return: An IPPool object that contains the given IP address or
        None if none of the pools contain the IP address
        """
        pool = None
        pools = self.get_ip_pools(ip.version)
        for candidate_pool in pools:
            if ip in candidate_pool:
                pool = candidate_pool
                break

        return pool

    @handle_errors
    def get_ip_pool_config(self, version, cidr):
        """
        Get the configuration for the given pool.

        :param version: 4 for IPv4, 6 for IPv6
        :param pool: IPNetwork object representing the pool
        :return: An IPPool object.
        """
        assert version in (4, 6)
        assert isinstance(cidr, IPNetwork)

        # Normalize to CIDR format (i.e. 10.1.1.1/8 goes to 10.0.0.0/8)
        cidr = cidr.cidr

        key = IP_POOL_KEY % {"version": str(version),
                             "pool": str(cidr).replace("/", "-")}

        try:
            data = self.etcd_client.read(key).value
        except EtcdKeyNotFound:
            # Re-raise with a better error message.
            raise KeyError("%s is not a configured IP pool." % cidr)

        return IPPool.from_json(data)

    @handle_errors
    def set_ip_pool_config(self, version, pool):
        """
        Set the IP pool configuration.

        :param version: 4 for IPv4, 6 for IPv6
        :param pool: IPPool object to configure in the datastore.
        :return: None
        """
        assert version in (4, 6)
        assert isinstance(pool, IPPool)

        # Now write the pool configuration.
        key = IP_POOL_KEY % {"version": str(version),
                             "pool": str(pool.cidr).replace("/", "-")}
        self.etcd_client.write(key, pool.to_json())

    @handle_errors
    def add_ip_pool(self, version, pool):
        """
        Add the given pool to the list of IP allocation pools.  If the pool
        already exists, this method completes silently without modifying the
        list of pools, other than possibly updating the ipip config.

        :param version: 4 for IPv4, 6 for IPv6
        :param pool: IPPool object
        :return: None
        """
        assert version in (4, 6)
        assert isinstance(pool, IPPool)

        # If IP in IP is enabled on the pool, ensure that it is enabled
        # globally.
        if pool.ipip:
            # Attempt to read existing config and enable ipip if
            # etcd is empty or ipip is disabled.
            try:
                result = self.etcd_client.read(IP_IN_IP_PATH)
            except EtcdKeyError:
                result = None
            if not result or result.value != IP_IN_IP_ENABLED:
                self.etcd_client.write(IP_IN_IP_PATH, IP_IN_IP_ENABLED)

        # Now write the pool configuration.
        self.set_ip_pool_config(version, pool)

    @handle_errors
    def remove_ip_pool(self, version, cidr):
        """
        Delete the given CIDR range from the list of pools.  If the pool does
        not exist, raise a KeyError.

        :param version: 4 for IPv4, 6 for IPv6
        :param cidr: IPNetwork object representing the pool
        :return: None
        """
        assert version in (4, 6)
        assert isinstance(cidr, IPNetwork)

        # Normalize to CIDR format (i.e. 10.1.1.1/8 goes to 10.0.0.0/8)
        cidr = cidr.cidr

        key = IP_POOL_KEY % {"version": str(version),
                             "pool": str(cidr).replace("/", "-")}
        try:
            self.etcd_client.delete(key)
        except EtcdKeyNotFound:
            # Re-raise with a better error message.
            raise KeyError("%s is not a configured IP pool." % cidr)

    @handle_errors
    def get_bgp_peers(self, version, hostname=None):
        """
        Get the configured BGP Peers.

        :param version: 4 for IPv4, 6 for IPv6
        :param hostname: Optional hostname.  If supplied, this returns the
        node-specific BGP peers.  If None, this returns the globally configured
        BGP peers.
        :return: List of BGPPeer.
        """
        assert version in (4, 6)
        if hostname is None:
            bgp_peers_path = BGP_GLOBAL_PEERS_PATH % {"version": str(version)}
        else:
            bgp_peers_path = BGP_HOST_PEERS_PATH % {"hostname": hostname,
                                                    "version": str(version)}

        try:
            nodes = self.etcd_client.read(bgp_peers_path).children
        except EtcdKeyNotFound:
            # Path doesn't exist.
            return []

        # If there are no children etcd returns a single value with the parent
        # key and no value (so skip empty values).
        peers = [BGPPeer.from_json(node.value) for node in nodes if node.value]
        return peers

    @handle_errors
    def add_bgp_peer(self, version, bgp_peer, hostname=None):
        """
        Add a BGP Peer.

        If a peer exists with the peer IP address, this will update the peer .
        configuration.

        :param version: 4 for IPv4, 6 for IPv6
        :param bgp_peer: The BGPPeer to add or update.
        :param hostname: Optional hostname.  If supplied, this stores the BGP
         peer in the node specific configuration.  If None, this stores the BGP
         peer as a globally configured peer.
        :return: Nothing
        """
        assert version in (4, 6)
        if hostname is None:
            bgp_peer_path = BGP_GLOBAL_PEER_PATH % {"version": str(version),
                                                   "peer_ip": str(bgp_peer.ip)}
        else:
            bgp_peer_path = BGP_HOST_PEER_PATH % {"hostname": hostname,
                                                  "version": str(version),
                                                  "peer_ip": str(bgp_peer.ip)}
        self.etcd_client.write(bgp_peer_path, bgp_peer.to_json())

    @handle_errors
    def remove_bgp_peer(self, version, ip, hostname=None):
        """
        Delete a BGP Peer with the specified IP address.

        Raises KeyError if the Peer does not exist.

        :param version: 4 for IPv4, 6 for IPv6
        :param ip: The IP address of the BGP peer to delete. (an IPAddress)
        :param hostname: Optional hostname.  If supplied, this stores the BGP
         peer in the node specific configuration.  If None, this stores the BGP
         peer as a globally configured peer.
        :return: Nothing
        """
        assert version in (4, 6)
        assert isinstance(ip, IPAddress)
        if hostname is None:
            bgp_peer_path = BGP_GLOBAL_PEER_PATH % {"version": str(version),
                                             "peer_ip": str(ip)}
        else:
            bgp_peer_path = BGP_HOST_PEER_PATH % {"hostname": hostname,
                                                  "version": str(version),
                                                  "peer_ip": str(ip)}
        try:
            self.etcd_client.delete(bgp_peer_path)
        except EtcdKeyNotFound:
            # Re-raise with a better error message.
            raise KeyError("%s is not a configured peer." % ip)

    @handle_errors
    def profile_exists(self, name):
        """
        Check if a profile exists.

        :param name: The name of the profile.
        :return: True if the profile exists, false otherwise.
        """
        profile_path = PROFILE_PATH % {"profile_id": name}
        try:
            _ = self.etcd_client.read(profile_path)
        except EtcdKeyNotFound:
            return False
        else:
            return True

    @handle_errors
    def policy_exists(self, tier_name, policy_name):
        """
        Check if a policy exists.

        :param tier_name: The name of the tier in which to search
        for this policy.
        :param policy_name: The name of the policy to search for.
        :return: True if the profile exists, false otherwise.
        """
        profile_path = POLICY_PATH % {"tier_name": tier_name,
                                      "policy_name": policy_name}
        try:
            _ = self.etcd_client.read(profile_path)
        except EtcdKeyNotFound:
            return False
        else:
            return True

    def set_policy_tier_metadata(self, tier_name, metadata):
        """
        Creates the metadata for the given policy tier.  If
        a tier with this name already exists it will be overwritten. If
        no tier with this name exists it will be created.

        :param tier_name: Name of the tier to create.
        :param order: Order to apply to this tier.  Lower orders
        take precedence.
        :param metadata: Metadata to apply to this tier.
        :return: None
        """
        path = TIER_PATH % {"tier_name": tier_name}
        self.etcd_client.write(path + "/metadata", json.dumps(metadata))

    def get_policy_tier_metadata(self, tier_name):
        """
        Retrieves the metadata for the given policy tier if it exists.
        If no tier with the given name exists, a KeyError is raised.

        :param tier_name: Name of the tier for which to get metadata.
        :return: Dictionary of tier metadata.
        """
        path = TIER_PATH % {"tier_name": tier_name}
        try:
            result = self.etcd_client.read(path + "/metadata")
            metadata = json.loads(result.value)
        except EtcdKeyNotFound:
            raise KeyError("Tier '%s' does not exist" % tier_name)
        else:
            return metadata

    def delete_policy_tier(self, tier_name):
        """
        Deletes the policy tier with the given name and any
        policies within it.

        Raises KeyError if no tier exists with the given name.

        :param tier_name: Name of the tier to delete.
        :return: None
        """
        path = TIER_PATH % {"tier_name": tier_name}
        try:
            self.etcd_client.delete(path, recursive=True, dir=True)
        except EtcdKeyNotFound:
            raise KeyError("Tier '%s' does not exist" % tier_name)

    @handle_errors
    def create_policy(self, tier_name, policy_name, selector,
                      order=None, rules=None):
        """
        Creates a policy with a given group, name, selector, and rules,
        and stores it in the Calico data store.

        If no rules are specified, the created policy will allow to and from
        all sources.

        If no order is specified, an order of 100 will be assigned.

        :param tier_name: name of the tier in which to create this policy.
        :param policy_name: name of the policy to create.
        :return: Policy object.
        """
        policy_path = POLICY_PATH % {"tier_name": tier_name,
                                     "policy_name": policy_name}
        default_allow = Rule(action="allow")
        rules = rules or Rules(id=policy_name,
                               inbound_rules=[default_allow],
                               outbound_rules=[default_allow])
        order = order or 100

        # Create the Policy object.
        policy = Policy(tier_name, policy_name)
        policy.rules = rules
        policy.selector = selector
        policy.order = order

        # Write the profile to the data store.
        self.update_policy(policy)
        return policy

    @handle_errors
    def update_policy(self, policy):
        """
        Write the policy to the data store.  This creates the
        policy if it doesn't exist and is idempotent.
        :param policy: The Policy object to update.
        :return: None
        """
        policy_path = POLICY_PATH % {"tier_name": policy.tier_name,
                                     "policy_name": policy.policy_name}
        self.etcd_client.write(policy_path, policy.to_json())

    @handle_errors
    def get_policy(self, tier_name, policy_name):
        """
        Returns the policy with a given group and name.

        :param tier_name: name of the tier from which to get this policy.
        :param policy_name: name of the policy to retrieve.
        :return: nothing.
        """
        policy_path = POLICY_PATH % {"tier_name": tier_name,
                                     "policy_name": policy_name}
        try:
            result = self.etcd_client.read(policy_path)
            policy = Policy(tier_name, policy_name)
            policy.selector = result["selector"]
            policy.rules = result["rules"]
        except EtcdKeyNotFound:
            raise KeyError("%s/%s is not a configured policy." % \
                    (tier_name, policy_name))
        else:
            return policy

    @handle_errors
    def remove_policy(self, tier_name, policy_name):
        """
        Delete a policy with a given group / name and any subtrees.

        :param tier_name: name of the tier from which to delete this policy.
        :param policy_name: name of the policy to delete.
        :return: nothing.
        """
        profile_path = POLICY_PATH % {"tier_name": tier_name,
                                      "policy_name": policy_name}
        try:
            self.etcd_client.delete(profile_path, recursive=True, dir=True)
        except EtcdKeyNotFound:
            raise KeyError("%s/%s is not a configured policy."
                           % (tier_name, policy_name))

    @handle_errors
    def create_profile(self, name, rules=None, labels=None):
        """
        Create a policy profile.  By default, endpoints in a profile
        accept traffic only from other endpoints in that profile, but can send
        traffic anywhere.

        Note this will clobber any existing profile with this name.

        :param name: Unique string name for the profile.
        :param rules: Optional Rules to set on the profile. If not specified,
        default "allow all" Rules will be set.
        :type rules Rules
        :return: nothing.
        """
        profile_path = PROFILE_PATH % {"profile_id": name}
        self.etcd_client.write(profile_path + "tags", '["%s"]' % name)

        # Write any labels.
        labels = labels or {}
        self.etcd_client.write(profile_path + "labels", json.dumps(labels))

        # Accept inbound traffic from self, allow outbound traffic to anywhere.
        # Note: We do not need to add a default_deny to outbound packet traffic
        # since Felix implements a default drop at the end if no profile has
        # accepted. Dropping the packet will kill it before it can potentially
        # be accepted by another profile on the endpoint.
        accept_self = Rule(action="allow", src_tag=name)
        default_allow = Rule(action="allow")
        rules = rules or Rules(id=name,
                               inbound_rules=[accept_self],
                               outbound_rules=[default_allow])
        self.etcd_client.write(profile_path + "rules", rules.to_json())

    @handle_errors
    def remove_profile(self, name):
        """
        Delete a policy profile with a given name.

        :param name: Unique string name for the profile.
        :return: nothing.
        """

        profile_path = PROFILE_PATH % {"profile_id": name}
        try:
            self.etcd_client.delete(profile_path, recursive=True, dir=True)
        except EtcdKeyNotFound:
            raise KeyError("%s is not a configured profile." % name)

    @handle_errors
    def get_profile_names(self):
        """
        Get the all configured profiles.
        :return: a set of profile names
        """
        profiles = set()
        try:
            etcd_profiles = self.etcd_client.read(PROFILES_PATH).children
            for child in etcd_profiles:
                packed = child.key.split("/")
                if len(packed) > 5:
                    profiles.add(packed[5])
        except EtcdKeyNotFound:
            # Means the PROFILES_PATH was not set up.  So, profile does not
            # exist.
            pass
        return profiles

    @handle_errors
    def get_profile(self, name):
        """
        Get a Profile object representing the named profile from the data
        store.

        :param name: The name of the profile.
        :return: A Profile object.
        """
        profile_path = PROFILE_PATH % {"profile_id": name}
        try:
            _ = self.etcd_client.read(profile_path)
            profile = Profile(name)
        except EtcdKeyNotFound:
            raise KeyError("%s is not a configured profile." % name)

        tags_path = TAGS_PATH % {"profile_id": name}
        try:
            tags_result = self.etcd_client.read(tags_path)
            tags = json.loads(tags_result.value)
            profile.tags = set(tags)
        except EtcdKeyNotFound:
            pass

        rules_path = RULES_PATH % {"profile_id": name}
        try:
            rules_result = self.etcd_client.read(rules_path)
            rules = Rules.from_json(rules_result.value)
            profile.rules = rules
        except EtcdKeyNotFound:
            pass

        return profile

    @handle_errors
    def get_profile_members(self, profile_name):
        """
        Get the all of the endpoint members of a profile.

        :param profile_name: Unique string name of the profile.
        :return: a list of Endpoint objects.
        """
        return [endpoint for endpoint in self.get_endpoints()
                if profile_name in endpoint.profile_ids]

    @handle_errors
    def profile_update_tags(self, profile):
        """
        Write the tags set on the Profile to the data store.  This creates the
        profile if it doesn't exist and is idempotent.
        :param profile: The Profile object to update, with tags stored on it.
        :return: None
        """
        tags_path = TAGS_PATH % {"profile_id": profile.name}
        self.etcd_client.write(tags_path, json.dumps(list(profile.tags)))

    @handle_errors
    def profile_update_rules(self, profile):
        """
        Write the rules on the Profile to the data store.  This creates the
        profile if it doesn't exist and is idempotent.
        :param profile: The Profile object to update, with rules stored on it.
        :return: None
        """
        rules_path = RULES_PATH % {"profile_id": profile.name}
        self.etcd_client.write(rules_path, profile.rules.to_json())

    @handle_errors
    def append_profiles_to_endpoint(self, profile_names, **kwargs):
        """
        Append a list of profiles to the endpoint.  This assumes there is a
        single endpoint per workload.

        Raises ProfileAlreadyInEndpoint if any of the profiles are already
        configured in the endpoint profile list.

        :param hostname: The host the workload is on.
        :param profile_names: The profiles to append to the endpoint profile
        list.
        :param kwargs: See get_endpoint for additional keyword args.
        :return: None.
        """
        # Change the profiles on the endpoint.  Check that we are not adding a
        # duplicate entry, and perform an update to ensure atomicity.
        ep = self.get_endpoint(**kwargs)
        for profile_name in ep.profile_ids:
            if profile_name in profile_names:
                raise ProfileAlreadyInEndpoint(profile_name)
        ep.profile_ids += profile_names
        self.update_endpoint(ep)

    @handle_errors
    def set_profiles_on_endpoint(self, profile_names, **kwargs):
        """
        Set a list of profiles on the endpoint.  This assumes there is a single
        endpoint per workload.

        :param hostname: The host the workload is on.
        :param profile_names: The profiles to set for the endpoint profile
        list.
        :param kwargs: See get_endpoint for additional keyword args.
        :return: None.
        """
        # Set the profiles on the endpoint.
        ep = self.get_endpoint(**kwargs)
        ep.profile_ids = profile_names
        self.update_endpoint(ep)

    @handle_errors
    def remove_profiles_from_endpoint(self, profile_names, **kwargs):
        """
        Remove a profiles from the endpoint profile list.  This assumes there
        is a single endpoint per workload.

        Raises ProfileNotInEndpoint if any of the profiles are not configured
        in the endpoint profile list.

        Raises MultipleEndpointsMatch if the spe

        :param hostname: The name of the host the workload is on.
        :param profile_names: The profiles to remove from the endpoint profile
        list.
        :param kwargs: See get_endpoint for additional keyword args.
        :return: None.
        """
        # Change the profile on the endpoint.
        ep = self.get_endpoint(**kwargs)
        for profile_name in profile_names:
            try:
                ep.profile_ids.remove(profile_name)
            except ValueError:
                raise ProfileNotInEndpoint(profile_name)
        self.update_endpoint(ep)

    @handle_errors
    def get_endpoints(self, hostname=None, orchestrator_id=None,
                      workload_id=None, endpoint_id=None):
        """
        Optimized function to get endpoint(s).

        Constructs a etcd-path that it as specific as possible given the
        provided criteria, in order to return the smallest etcd tree as
        possible. After querying with the ep_path, it will then compare the
        returned endpoints to the provided criteria, and return all matches.

        :param endpoint_id: The ID of the endpoint
        :param hostname: The hostname that the endpoint lives on.
        :param workload_id: The workload that the endpoint belongs to.
        :param orchestrator_id: The workload that the endpoint belongs to.
        :return: A list of Endpoint Objects which match the criteria, or an
        empty list if none match
        """
        # First build the query string as specific as possible. Note, we want
        # the query to be as specific as possible, so we proceed any variables
        # with known constants e.g. we add '/workload' after the hostname
        # variable.
        if not hostname:
            ep_path = HOSTS_PATH
        elif not orchestrator_id:
            ep_path = HOST_PATH % {"hostname": hostname}
        elif not workload_id:
            ep_path = ORCHESTRATOR_PATH % {"hostname": hostname,
                                           "orchestrator_id": orchestrator_id}
        elif not endpoint_id:
            ep_path = WORKLOAD_PATH % {"hostname": hostname,
                                       "orchestrator_id": orchestrator_id,
                                       "workload_id": workload_id}
        else:
            ep_path = ENDPOINT_PATH % {"hostname": hostname,
                                       "orchestrator_id": orchestrator_id,
                                       "workload_id": workload_id,
                                       "endpoint_id": endpoint_id}
        try:
            # Search etcd
            leaves = self.etcd_client.read(ep_path, recursive=True).leaves
        except EtcdKeyNotFound:
            return []

        # Filter through result
        matches = []
        for leaf in leaves:
            endpoint = Endpoint.from_json(leaf.key, leaf.value)

            # If its an endpoint, compare it to search criteria
            if endpoint and endpoint.matches(hostname=hostname,
                                             orchestrator_id=orchestrator_id,
                                             workload_id=workload_id,
                                             endpoint_id=endpoint_id):
                matches.append(endpoint)
        return matches

    @handle_errors
    def get_endpoint(self, hostname=None, orchestrator_id=None,
                     workload_id=None, endpoint_id=None):
        """
        Calls through to get_endpoints to find an endpoint matching the
        passed-in criteria.
        Raises a MultipleEndpointsMatch exception if more than one endpoint
        matches.

        :param hostname: The hostname that the endpoint lives on.
        :param orchestrator_id: The workload that the endpoint belongs to.
        :param workload_id: The workload that the endpoint belongs to.
        :param endpoint_id: The ID of the endpoint
        :return: An Endpoint Object
        """
        eps = self.get_endpoints(hostname=hostname,
                                 orchestrator_id=orchestrator_id,
                                 workload_id=workload_id,
                                 endpoint_id=endpoint_id)
        if not eps:
            raise KeyError("No endpoint found matching specified criteria."
                           "hostname=%s"
                           "orchestrator_id=%s"
                           "workload_id=%s"
                           "endpoint_id=%s" % (hostname, orchestrator_id,
                                               workload_id, endpoint_id))
        elif len(eps) > 1:
            raise MultipleEndpointsMatch()
        else:
            return eps.pop()

    @handle_errors
    def set_endpoint(self, endpoint):
        """
        Write a single endpoint object to the datastore.

        :param endpoint: The Endpoint to add to the workload.
        """
        ep_path = ENDPOINT_PATH % {"hostname": endpoint.hostname,
                                   "orchestrator_id": endpoint.orchestrator_id,
                                   "workload_id": endpoint.workload_id,
                                   "endpoint_id": endpoint.endpoint_id}
        new_json = endpoint.to_json()
        self.etcd_client.write(ep_path, new_json)
        endpoint._original_json = new_json

    @handle_errors
    def update_endpoint(self, endpoint):
        """
        Update a single endpoint object to the datastore.  This assumes the
        endpoint was originally queried from the datastore and updated.
        Example usage:
            endpoint = datastore.get_endpoint(...)
            # modify new endpoint fields
            datastore.update_endpoint(endpoint)

        :param endpoint: The Endpoint to add to the workload.
        """
        ep_path = ENDPOINT_PATH % {"hostname": endpoint.hostname,
                                   "orchestrator_id": endpoint.orchestrator_id,
                                   "workload_id": endpoint.workload_id,
                                   "endpoint_id": endpoint.endpoint_id}
        new_json = endpoint.to_json()
        self.etcd_client.write(ep_path,
                               new_json,
                               prevValue=endpoint._original_json)
        endpoint._original_json = new_json

    @handle_errors
    def create_endpoint(self, hostname, orchestrator_id, workload_id,
                        ip_list, mac=None):
        """
        Create a single new endpoint object.

        Note, the endpoint will not be stored in ETCD until set_endpoint
        or update_endpoint is called.

        :param hostname: The hostname that the endpoint lives on.
        :param orchestrator_id: The workload that the endpoint belongs to.
        :param workload_id: The workload that the endpoint belongs to.
        :param ip_list: A list of ip addresses that the endpoint belongs to
        :param mac: The mac address that the endpoint belongs to
        :return: An Endpoint Object
        """
        ep = Endpoint(hostname=hostname,
                      orchestrator_id=orchestrator_id,
                      workload_id=workload_id,
                      endpoint_id=uuid.uuid1().hex,
                      state="active",
                      mac=mac)

        for ip in ip_list:
            network = IPNetwork(ip)
            if network.version == 4:
                ep.ipv4_nets.add(network)
            else:
                ep.ipv6_nets.add(network)

        return ep

    @handle_errors
    def remove_endpoint(self, endpoint):
        """
        Remove a single endpoint object from the datastore.

        :param endpoint: The Endpoint to remove.
        """
        ep_path = ENDPOINT_PATH % {"hostname": endpoint.hostname,
                                   "orchestrator_id": endpoint.orchestrator_id,
                                   "workload_id": endpoint.workload_id,
                                   "endpoint_id": endpoint.endpoint_id}
        self.etcd_client.delete(ep_path, dir=True, recursive=True)

    @handle_errors
    def remove_all_data(self):
        """
        Remove all data from the datastore.

        We don't care if Calico data can't be found.

        """
        try:
            self.etcd_client.delete("/calico", recursive=True, dir=True)
        except EtcdKeyNotFound:
            pass

    @handle_errors
    def remove_workload(self, hostname, orchestrator_id, workload_id):
        """
        Remove a workload from the datastore.
        :param hostname: The name of the host the workload is on.
        :param orchestrator_id: The orchestrator the workload belongs to.
        :param workload_id: The workload ID.
        :return: None.
        """
        workload_path = WORKLOAD_PATH % {"hostname": hostname,
                                         "orchestrator_id": orchestrator_id,
                                         "workload_id": workload_id}
        try:
            self.etcd_client.delete(workload_path, recursive=True, dir=True)
        except EtcdKeyNotFound:
            raise KeyError("%s is not a configured workload on host %s" %
                           (workload_id, hostname))

    @handle_errors
    def set_bgp_node_mesh(self, enable):
        """
        Set whether the BGP node mesh is enabled or not.

        :param enable: (Boolean) Whether the mesh is enabled or not.
        :return: None.
        """
        node_mesh = {"enabled": enable}
        self.etcd_client.write(BGP_NODE_MESH_PATH, json.dumps(node_mesh))

    @handle_errors
    def get_bgp_node_mesh(self):
        """
        Determine whether the BGP node mesh is enabled or not.

        :return: (Boolean) Whether the BGP node mesh is enabled.
        """
        # The default value is stored in etcd, however it is only initialised
        # during node instantiation.  Therefore, if the value is not present
        # return the default value.  The default should match the value
        # assigned in ensure_global_config().
        try:
            node_mesh = json.loads(
                               self.etcd_client.read(BGP_NODE_MESH_PATH).value)
        except EtcdKeyNotFound:
            node_mesh = DEFAULT_NODE_MESH

        return node_mesh["enabled"]

    @handle_errors
    def set_default_node_as(self, as_num):
        """
        Set the default node BGP AS Number
        """
        self.etcd_client.write(BGP_NODE_DEF_AS_PATH, str(as_num))

    @handle_errors
    def get_default_node_as(self):
        """
        Return the default node BGP AS Number.

        :return: The default node BGP AS Number as a string.
        """
        # The default value is stored in etcd, however it is only initialised
        # during node instantiation.  Therefore, if the value is not present
        # return the default value.  The default should match the value
        # assigned in ensure_global_config().
        try:
            as_num = self.etcd_client.read(BGP_NODE_DEF_AS_PATH).value
        except EtcdKeyNotFound:
            return str(DEFAULT_AS_NUM)
        else:
            return str(as_num)
