package api

import (
	"reflect"

	. "github.com/projectcalico/libcalico/lib/common"
	"gopkg.in/go-playground/validator.v8"
)

type Rule struct {
	Action string `json:"action" validate:"action"`

	Protocol *Protocol `json:"protocol,omitempty" validate:"omitempty"`
	ICMPType *int      `json:"icmpType,omitempty" validate:"omitempty,gte=0,lte=255"`
	ICMPCode *int      `json:"icmpCode,omitempty" validate:"omitempty,gte=0,lte=255"`

	NotProtocol *Protocol `json:"!protocol,omitempty" validate:"omitempty"`
	NotICMPType *int      `json:"!icmpType,omitempty" validate:"omitempty,gte=0,lte=255"`
	NotICMPCode *int      `json:"!icmpCode,omitempty" validate:"omitempty,gte=0,lte=255"`

	Source      EntityRule `json:"source,omitempty" validate:"omitempty"`
	Destination EntityRule `json:"destination,omitempty" validate:"omitempty"`
}

type EntityRule struct {
	Tag      string `json:"tag,omitempty" validate:"omitempty,tag"`
	Net      *IPNet `json:"net,omitempty" validate:"omitempty"`
	Selector string `json:"selector,omitempty" validate:"omitempty,selector"`
	Ports    []int  `json:"ports,omitempty" validate:"omitempty,dive,gte=0,lte=65535"`

	NotTag      string `json:"!tag,omitempty" validate:"omitempty,tag"`
	NotNet      *IPNet `json:"!net,omitempty" validate:"omitempty"`
	NotSelector string `json:"!selector,omitempty" validate:"omitempty,selector"`
	NotPorts    []int  `json:"!ports,omitempty" validate:"omitempty,dive,gte=0,lte=65535"`
}

// Register v1 structure validators to validate cross-field dependencies in any of the
// required structures.
func init() {
	RegisterStructValidator(validateRule, Rule{})
}

func validateRule(v *validator.Validate, structLevel *validator.StructLevel) {
	rule := structLevel.CurrentStruct.Interface().(Rule)
	if rule.ICMPCode != nil && rule.ICMPType == nil {
		structLevel.ReportError(reflect.ValueOf(rule.ICMPCode), "ICMPCode", "icmpCode", "icmpCodeWithoutType")
	}

	// TODO other cross-struct validation
}
