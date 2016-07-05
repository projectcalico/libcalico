package api

import (
	. "github.com/projectcalico/libcalico/lib/api/unversioned"
	. "github.com/projectcalico/libcalico/lib/common"
)

type HostEndpointMetadata struct {
	ObjectMetadata
	Hostname string            `json:"hostname,omitempty" valid:"omitempty,hostname"`
	Labels   map[string]string `json:"labels,omitempty" validate:"omitempty"`
}

type HostEndpointSpec struct {
	InterfaceName string   `json:"interfaceName,omitempty" validate:"omitempty,interface"`
	ExpectedIPs   []IP     `json:"expectedIPs,omitempty" validate:"omitempty,dive,ip"`
	Profiles      []string `json:"profiles,omitempty" validate:"omitempty,dive,name"`
}

type HostEndpoint struct {
	TypeMetadata
	Metadata HostEndpointMetadata `json:"metadata,omitempty"`
	Spec     HostEndpointSpec     `json:"spec,omitempty"`
}

func NewHostEndpoint() *HostEndpoint {
	return &HostEndpoint{TypeMetadata: TypeMetadata{Kind: "hostEndpoint", APIVersion: "v1"}}
}

type HostEndpointList struct {
	TypeMetadata
	Metadata ListMetadata   `json:"metadata,omitempty"`
	Items    []HostEndpoint `json:"items" validate:"dive"`
}

func NewHostEndpointList() *HostEndpointList {
	return &HostEndpointList{TypeMetadata: TypeMetadata{Kind: "hostEndpointList", APIVersion: "v1"}}
}
