package backend

import (
	"errors"
	"fmt"

	"regexp"

	"github.com/golang/glog"
	. "github.com/projectcalico/libcalico/lib/common"
)

var (
	matchHostEndpoint = regexp.MustCompile("^/calico/v1/host/([^/]+)/endpoint/([^/]+)$")
)

type HostEndpointKey struct {
	Hostname   string `json:"-" validate:"required,hostname"`
	EndpointID string `json:"-" validate:"required,hostname"`
}

func (key HostEndpointKey) asEtcdKey() (string, error) {
	if key.Hostname == "" || key.EndpointID == "" {
		return "", errors.New("insufficient identifiers")
	}
	e := fmt.Sprintf("/calico/v1/host/%s/endpoint/%s",
		key.Hostname, key.EndpointID)
	return e, nil
}

func (key HostEndpointKey) asEtcdDeleteKey() (string, error) {
	return key.asEtcdKey()
}

type HostEndpointListOptions struct {
	Hostname   string
	EndpointID string
}

func (options HostEndpointListOptions) asEtcdKeyRoot() string {
	k := "/calico/v1/host"
	if options.Hostname == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s/endpoint", options.Hostname)
	if options.EndpointID == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s", options.EndpointID)
	return k
}

func (options HostEndpointListOptions) keyFromEtcdResult(ekey string) KeyInterface {
	glog.V(2).Infof("Get HostEndpoint key from %s", ekey)
	r := matchHostEndpoint.FindAllStringSubmatch(ekey, -1)
	if len(r) != 1 {
		glog.V(2).Infof("Didn't match regex")
		return nil
	}
	hostname := r[0][1]
	endpointID := r[0][2]
	if options.Hostname != "" && hostname != options.Hostname {
		glog.V(2).Infof("Didn't match hostname %s != %s", options.Hostname, hostname)
		return nil
	}
	if options.EndpointID != "" && endpointID != options.EndpointID {
		glog.V(2).Infof("Didn't match endpointID %s != %s", options.EndpointID, endpointID)
		return nil
	}
	return HostEndpointKey{Hostname: hostname, EndpointID: endpointID}
}

type HostEndpoint struct {
	HostEndpointKey   `json:"-"`
	Name              string            `json:"name,omitempty" validate:"omitempty,interface"`
	ExpectedIPv4Addrs []IP              `json:"expected_ipv4_addrs,omitempty" validate:"omitempty,dive,ipv4"`
	ExpectedIPv6Addrs []IP              `json:"expected_ipv6_addrs,omitempty" validate:"omitempty,dive,ipv6"`
	Labels            map[string]string `json:"labels,omitempty" validate:"omitempty,labels"`
	ProfileIDs        []string          `json:"profile_ids,omitempty" validate:"omitempty,dive,name"`
}
