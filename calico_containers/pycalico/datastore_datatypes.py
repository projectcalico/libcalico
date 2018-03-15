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
"""
Module containing all of the datatypes written and read from the datastore.
"""
from collections import namedtuple
import copy
import json
import re
from pycalico import netns

from netaddr import IPAddress, IPNetwork

from pycalico.util import generate_cali_interface_name, validate_characters, \
    validate_ports, validate_icmp_type
from pycalico.block import BLOCK_PREFIXLEN
from pycalico.datastore_errors import InvalidBlockSizeError


IF_PREFIX = "cali"
"""
prefix that appears in all Calico interface names in the root namespace. e.g.
cali123456789ab.
"""


class Rules(namedtuple("Rules", ["inbound_rules", "outbound_rules"])):
    """
    A set of Calico rules describing inbound and outbound network traffic
    policy.
    """
    def to_dict(self):
        """
        Convert the Rules object to a dictionary.

        :return:  A dictionary representation of this object.
        """
        json_dict = self._asdict()
        rules = json_dict["inbound_rules"]
        json_dict["inbound_rules"] = [rule.to_json_dict() for rule in rules]
        rules = json_dict["outbound_rules"]
        json_dict["outbound_rules"] = [rule.to_json_dict() for rule in rules]
        return json_dict

    def to_json(self, indent=None):
        """
        Convert the Rules object to a JSON string.

        :param indent: Integer representing the level of indent from the
        returned json string. None = no indent, 0 = only newlines. Recommend
        using 1 for human-readable strings.
        :return:  A JSON string representation of this object.
        """
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str):
        """
        Create a Rules object from a JSON string.

        :param json_str: A JSON string representation of a Rules object.
        :return: A Rules object.
        """
        json_dict = json.loads(json_str)
        inbound_rules = []
        for rule in json_dict["inbound_rules"]:
            inbound_rules.append(Rule(**rule))
        outbound_rules = []
        for rule in json_dict["outbound_rules"]:
            outbound_rules.append(Rule(**rule))
        rules = cls(inbound_rules=inbound_rules,
                    outbound_rules=outbound_rules)
        return rules


class BGPPeer(object):
    """
    Class encapsulating a BGPPeer.
    """

    def __init__(self, ip, as_num):
        """
        Constructor.
        :param ip: The BGPPeer IP address (string or IPAddress)
        :param as_num: The AS Number (string or int).
        """
        self.ip = IPAddress(ip)

        # Store the AS number as a string.  This allows dotted notation of
        # AS numbers.
        self.as_num = str(as_num)

    def to_json(self):
        """
        Convert the BGPPeer to a JSON string.
        :return: A JSON string.
        """
        json_dict = {"ip": str(self.ip), "as_num": self.as_num}
        return json.dumps(json_dict)

    @classmethod
    def from_json(cls, json_str):
        """
        Convert the json string into a BGPPeer object.
        :param json_str: The JSON string representing a BGPPeer.
        :return: A BGPPeer object.
        """
        json_dict = json.loads(json_str)
        return cls(json_dict["ip"], json_dict["as_num"])

    def __eq__(self, other):
        if not isinstance(other, BGPPeer):
            return NotImplemented
        return (self.ip == other.ip and
                self.as_num == other.as_num)


class IPPool(object):
    """
    Class encapsulating an IPPool.
    """

    def __init__(self, cidr, ipip=False, masquerade=False, ipam=True, disabled=False):
        """
        Constructor.
        :param cidr: IPNetwork object (or CIDR string) representing the pool.
            NOTE: When used by Calico IPAM, an IPPool's cidr prefix must have a
            length equal to or smaller than an IPAM block, such as /24 if the
            IPAM block size is /26.
        :param ipip: Use IP-IP for this pool.
        :param masquerade: Enable masquerade (outgoing NAT) for this pool.
        :param ipam: Whether this IPPool is used by Calico IPAM.
        :param disabled: Whether this IPPool is disabled.  If disabled, the pool
        is not used by the IPAM client for new allocation blocks.
        """
        # Normalize the CIDR (e.g. 1.2.3.4/16 -> 1.2.0.0/16)
        self.cidr = IPNetwork(cidr).cidr
        self.ipam = bool(ipam)
        if self.ipam:
            if self.cidr.prefixlen > BLOCK_PREFIXLEN[self.cidr.version]:
                raise InvalidBlockSizeError("The CIDR block size for an "
                    "IPv%s pool when using Calico IPAM must have a prefix "
                    "length of %s or lower. Given: %s" %
                    (self.cidr.version,
                     BLOCK_PREFIXLEN[self.cidr.version],
                     self.cidr.prefixlen))
        self.ipip = bool(ipip)
        self.masquerade = bool(masquerade)
        self.disabled = bool(disabled)

    def to_json(self):
        """
        Convert the IPPool to a JSON string.
        :return: A JSON string.
        """
        json_dict = {"cidr" : str(self.cidr)}
        if self.ipip:
            json_dict["ipip"] = "tunl0"
        if self.masquerade:
            json_dict["masquerade"] = True
        # Only write "ipam" and "disabled" when they differ from their default
        # values.  This keeps the interface unchanged between versions when
        # these fields are not required.
        if not self.ipam:
            json_dict["ipam"] = False
        if self.disabled:
            json_dict["disabled"] = True
        return json.dumps(json_dict)

    @classmethod
    def from_json(cls, json_str):
        """
        Convert the json string into a IPPool object.
        :param json_str: The JSON string representing an IPPool.
        :return: An IPPool object.
        """
        # The fields "ipam" and "disabled" may not be present in older versions
        # of the data, so use default values if not present.
        json_dict = json.loads(json_str)
        return cls(json_dict["cidr"],
                   ipip=json_dict.get("ipip"),
                   masquerade=json_dict.get("masquerade"),
                   ipam=json_dict.get("ipam", True),
                   disabled=json_dict.get("disabled", False))

    def __eq__(self, other):
        if not isinstance(other, IPPool):
            return NotImplemented
        return (self.cidr == other.cidr and
                self.ipip == other.ipip and
                self.masquerade == other.masquerade and
                self.ipam == other.ipam and
                self.disabled == other.disabled)

    def __contains__(self, item):
        """
        Override __contains__ so that you can check if an IP address is in this
        pool.

        e.g. IPAddress("1.2.3.4) in IPPool("1.2.3.0/24") is True.
        """
        return item in self.cidr

    def __str__(self):
        """Return the CIDR of this pool."""
        return str(self.cidr)


class Endpoint(object):
    """
    Class encapsulating an Endpoint.
    This class keeps track of the original JSON representation of the
    endpoint to allow atomic updates to be performed.
    """
    # Endpoint path match regex
    ENDPOINT_KEY_MATCH = re.compile("/calico/v1/host/(?P<hostname>[^/]*)/"
                                "workload/(?P<orchestrator_id>[^/]*)/"
                                "(?P<workload_id>[^/]*)/"
                                "endpoint/(?P<endpoint_id>[^/]*)")

    def __init__(self, hostname, orchestrator_id, workload_id, endpoint_id,
                 state, mac, name=None):
        self.hostname = hostname
        self.orchestrator_id = orchestrator_id
        self.workload_id = workload_id
        self.endpoint_id = endpoint_id
        self.state = state
        self.mac = mac
        self.name = name or generate_cali_interface_name(IF_PREFIX,
                                                         endpoint_id)

        self.ipv4_nets = set()
        self.ipv6_nets = set()

        self.profile_ids = []
        self._original_json = None

        self.labels = {}

    def to_json(self):
        json_dict = {"state": self.state,
                     "name": self.name,
                     "mac": self.mac,
                     "profile_ids": self.profile_ids,
                     "labels": self.labels,
                     "ipv4_nets": sorted([str(net) for net in self.ipv4_nets]),
                     "ipv6_nets": sorted([str(net) for net in self.ipv6_nets])}
        return json.dumps(json_dict)

    @classmethod
    def from_json(cls, endpoint_key, json_str):
        """
        Create an Endpoint from the endpoint raw JSON and the endpoint key.

        :param endpoint_key: The endpoint key (the etcd path to the endpoint)
        :param json_str: The raw endpoint JSON data.
        :return: An Endpoint object, or None if the endpoint_key does not
        represent and Endpoint.
        """
        match = Endpoint.ENDPOINT_KEY_MATCH.match(endpoint_key)
        if not match:
            return None

        hostname = match.group("hostname")
        orchestrator_id = match.group("orchestrator_id")
        workload_id = match.group("workload_id")
        endpoint_id = match.group("endpoint_id")

        json_dict = json.loads(json_str)
        ep = cls(hostname, orchestrator_id, workload_id, endpoint_id,
                 json_dict["state"], json_dict["mac"], name=json_dict["name"])

        for net in json_dict["ipv4_nets"]:
            ep.ipv4_nets.add(IPNetwork(net))
        for net in json_dict["ipv6_nets"]:
            ep.ipv6_nets.add(IPNetwork(net))
        labels = json_dict.get("labels", {})
        ep.labels = labels

        # Version controlled fields
        profile_id = json_dict.get("profile_id", None)
        ep.profile_ids = [profile_id] if profile_id else \
                         json_dict.get("profile_ids", [])

        # Store the original JSON representation of this Endpoint.
        ep._original_json = json_str

        return ep

    def matches(self, hostname=None, orchestrator_id=None,
                workload_id=None, endpoint_id=None):
        """
        A less strict 'equals' function, which compares provided parameters to
        the current endpoint object.

        :param hostname: The hostname to compare to
        :param orchestrator_id: The orchestrator ID to compare to.
        :param workload_id: The workload ID to compare to
        :param endpoint_id: The endpoint ID to compare to

        :return: True if the provided parameters match the Endpoint's
        parameters, False if any of the provided parameters are different from
        the Endpoint's parameters.
        """
        if hostname and hostname != self.hostname:
            return False
        elif orchestrator_id and orchestrator_id != self.orchestrator_id:
            return False
        elif workload_id and workload_id != self.workload_id:
            return False
        elif endpoint_id and endpoint_id != self.endpoint_id:
            return False
        else:
            return True

    def provision_veth(self, namespace, veth_name_ns):
        """
        Create the veth, move into the container namespace, add the IP and
        set up the default routes.

        Note, the endpoint will not be updated in etcd. If desired, the user
        should update the endpoint mac with the mac address provided
        by the function and then call update_endpoint

        :param self: The endpoint object to provision the veth on
        :param namespace: The namespace to operate in
        :type namespace netns.Namespace
        :param veth_name_ns: The name of the interface in the namespace
        :return The mac address of the veth as a string
        """
        assert isinstance(namespace, netns.Namespace), \
            'Namespace object expected.'
        netns.create_veth(self.name, self.temp_interface_name)
        netns.move_veth_into_ns(namespace, self.temp_interface_name,
                                veth_name_ns)
        for ip_net in self.ipv4_nets | self.ipv6_nets:
            netns.add_ip_to_ns_veth(namespace, ip_net.ip, veth_name_ns)

        netns.add_ns_default_route(namespace, self.name, veth_name_ns)

        return netns.get_ns_veth_mac(namespace, veth_name_ns)

    def __eq__(self, other):
        if not isinstance(other, Endpoint):
            return NotImplemented
        return (self.endpoint_id == other.endpoint_id and
                self.state == other.state and
                self.mac == other.mac and
                self.profile_ids == other.profile_ids and
                self.ipv4_nets == other.ipv4_nets and
                self.name == other.name and
                self.ipv6_nets == other.ipv6_nets)

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def copy(self):
        return copy.deepcopy(self)

    @property
    def temp_interface_name(self):
        return generate_cali_interface_name("tmp", self.endpoint_id)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "Endpoint(%s)" % self.to_json()


class Profile(object):
    """A Calico policy profile."""

    def __init__(self, name):
        self.name = name
        self.tags = set()

        # Default to empty lists of rules.
        self.rules = Rules([], [])


class Policy(object):
    """A Calico policy."""
    def __init__(self, tier_name, policy_name):
        self.tier_name = tier_name
        self.policy_name = policy_name
        self.order = 0

        # Default to empty lists of rules.
        self.rules = Rules([], [])

        # Default to empty selector.
        self.selector = ""

    def to_json(self):
        """
        Returns a json string representing this Policy
        as stored in the data store.
        """
        data = {"order": self.order,
                "selector": self.selector}
        data.update(self.rules.to_dict())
        return json.dumps(data)


class Rule(dict):
    """
    A Calico inbound or outbound traffic rule.
    """

    ALLOWED_KEYS = ["protocol",
                    "src_tag",
                    "src_selector",
                    "src_ports",
                    "src_net",
                    "dst_tag",
                    "dst_selector",
                    "dst_ports",
                    "dst_net",
                    "icmp_type",
                    "icmp_code",
                    "action"]

    def __init__(self, **kwargs):
        super(Rule, self).__init__()
        for key, value in kwargs.iteritems():
            self[key] = value

    def __setitem__(self, key, value):
        if key not in Rule.ALLOWED_KEYS:
            raise KeyError("Key %s is not allowed on Rule." % key)

        # Convert any CIDR strings to netaddr before inserting them.
        if key in ("src_net", "dst_net"):
            value = IPNetwork(value)
        if key == "action" and value not in ("allow", "deny", "next-tier"):
            raise ValueError("'%s' is not allowed for key 'action'" % value)
        if (key == "protocol" and
            value not in ("tcp", "udp", "icmp", "icmpv6", None)):
            raise ValueError("'%s' is not allowed for key 'protocol'" % value)
        if key in ("src_tag", "dst_tag") and not validate_characters(value):
            raise ValueError("'%s' is not allowed for key '%s'" % (value, key))
        if key in ("src_ports", "dst_ports") and not validate_ports(value):
            raise ValueError("'%s' is not allowed for key '%s'" % (value, key))
        if key in ("icmp_type", "icmp_code") and not validate_icmp_type(value):
            raise ValueError("'%s' is not allowed for key '%s'" % (value, key))

        super(Rule, self).__setitem__(key, value)

    def to_json(self):
        """
        Convert the Rule object to a JSON string.

        :return:  A JSON string representation of this object.
        """
        return json.dumps(self.to_json_dict())

    def to_json_dict(self):
        """
        Convert the Rule object to a dict that can be directly converted to
        JSON.

        :return: A dict containing valid JSON types.
        """
        # Convert IPNetworks to strings
        json_dict = self.copy()
        if "dst_net" in json_dict:
            json_dict["dst_net"] = str(json_dict["dst_net"])
        if "src_net" in json_dict:
            json_dict["src_net"] = str(json_dict["src_net"])

        # Convert ports to integers.
        if "dst_ports" in json_dict:
            json_dict["dst_ports"] = [p for p in json_dict["dst_ports"]]
        if "src_ports" in json_dict:
            json_dict["src_ports"] = [p for p in json_dict["src_ports"]]

        return json_dict

    def pprint(self):
        """Human readable description."""
        out = [self["action"]]
        if "protocol" in self:
            out.append(self["protocol"])
        if "icmp_type" in self:
            out.extend(["type", str(self["icmp_type"])])
        if "icmp_code" in self:
            out.extend(["code", str(self["icmp_code"])])

        if "src_tag" in self or "src_ports" in self or "src_net" in self:
            out.append("from")
        if "src_ports" in self:
            ports = ",".join(str(p) for p in self["src_ports"])
            out.extend(["ports", ports])
        if "src_tag" in self:
            out.extend(["tag", self["src_tag"]])
        if "src_net" in self:
            out.extend(["cidr", str(self["src_net"])])

        if "dst_tag" in self or "dst_ports" in self or "dst_net" in self:
            out.append("to")
        if "dst_ports" in self:
            ports = ",".join(str(p) for p in self["dst_ports"])
            out.extend(["ports", ports])
        if "dst_tag" in self:
            out.extend(["tag", self["dst_tag"]])
        if "dst_net" in self:
            out.extend(["cidr", str(self["dst_net"])])

        return " ".join(out)


class IPAMConfig(object):
    """
    IPAM configuration.
    """
    AUTO_ALLOCATE_BLOCKS = "auto_allocate_blocks"
    STRICT_AFFINITY = "strict_affinity"

    def __init__(self, auto_allocate_blocks=True, strict_affinity=False):
        self.auto_allocate_blocks = auto_allocate_blocks
        """
        Whether Calico IPAM module is allowed to auto-allocate affine blocks
        when auto-assigning IP addresses.
        """

        self.strict_affinity = strict_affinity
        """
        Whether strict affinity should be observed for affine blocks.
        """

    def to_json(self):
        """
        Convert the IPAMConfig object to a JSON string.

        :return:  A JSON string representation of this object.
        """
        return json.dumps(self.to_json_dict())

    def to_json_dict(self):
        """
        Convert the Rule object to a dict that can be directly converted to
        JSON.

        :return: A dict containing valid JSON types.
        """
        return {
            IPAMConfig.AUTO_ALLOCATE_BLOCKS: self.auto_allocate_blocks,
            IPAMConfig.STRICT_AFFINITY: self.strict_affinity
        }

    @classmethod
    def from_json(cls, json_str):
        """
        Create an IPAMConfig from the raw JSON.
        :param json_str: A JSON string representation of an IPAMConfig
        object.
        :return: An IPAMConfig object.
        """
        json_dict = json.loads(json_str)
        return IPAMConfig(
            auto_allocate_blocks=json_dict[IPAMConfig.AUTO_ALLOCATE_BLOCKS],
            strict_affinity=json_dict[IPAMConfig.STRICT_AFFINITY]
        )

    def __eq__(self, other):
        if not isinstance(other, IPAMConfig):
            return NotImplemented
        return (self.auto_allocate_blocks == other.auto_allocate_blocks and
                self.strict_affinity == other.strict_affinity)

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "IPAMConfig(%s)" % self.to_json()
