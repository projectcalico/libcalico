package backend

import . "github.com/projectcalico/libcalico/lib/common"

type Rule struct {
	Action string `json:"action" validate:"backendaction"`

	Protocol    *Protocol `json:"protocol,omitempty" validate:"omitempty"`
	SrcTag      string    `json:"src_tag,omitempty" validate:"omitempty,tag"`
	SrcNet      *IPNet    `json:"src_net,omitempty" validate:"omitempty"`
	SrcSelector string    `json:"src_selector,omitempty" validate:"omitempty,selector"`
	SrcPorts    []int     `json:"src_ports,omitempty" validate:"omitempty,dive,gte=0,lte=65535"`
	DstTag      string    `json:"dst_tag,omitempty" validate:"omitempty,tag"`
	DstSelector string    `json:"dst_selector,omitempty" validate:"omitempty,selector"`
	DstNet      *IPNet    `json:"dst_net,omitempty" validate:"omitempty"`
	DstPorts    []int     `json:"dst_ports,omitempty" validate:"omitempty,dive,gte=0,lte=65535"`
	ICMPType    *int      `json:"icmp_type,omitempty" validate:"omitempty,gte=1,lte=255"`
	ICMPCode    *int      `json:"icmp_code,omitempty" validate:"omitempty,gte=1,lte=255"`

	NotProtocol    *Protocol `json:"!protocol,omitempty" validate:"omitempty"`
	NotSrcTag      string    `json:"!src_tag,omitempty" validate:"omitempty,tag"`
	NotSrcNet      *IPNet    `json:"!src_net,omitempty" validate:"omitempty"`
	NotSrcSelector string    `json:"!src_selector,omitempty" validate:"omitempty,selector"`
	NotSrcPorts    []int     `json:"!src_ports,omitempty" validate:"omitempty,dive,gte=0,lte=65535"`
	NotDstTag      string    `json:"!dst_tag,omitempty" validate:"omitempty"`
	NotDstSelector string    `json:"!dst_selector,omitempty" validate:"omitempty,selector"`
	NotDstNet      *IPNet    `json:"!dst_net,omitempty" validate:"omitempty"`
	NotDstPorts    []int     `json:"!dst_ports,omitempty" validate:"omitempty,dive,gte=0,lte=65535"`
	NotICMPType    *int      `json:"!icmp_type,omitempty" validate:"omitempty,gte=1,lte=255"`
	NotICMPCode    *int      `json:"!icmp_code,omitempty" validate:"omitempty,gte=1,lte=255"`
}
