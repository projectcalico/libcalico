package api

import (
	"reflect"

	. "github.com/projectcalico/libcalico/lib/api/unversioned"
	. "github.com/projectcalico/libcalico/lib/common"
	"gopkg.in/go-playground/validator.v8"
)

type TierMetadata ObjectMetadata

type TierSpec struct {
	Order *float32 `json:"order,omitempty"`
}

type Tier struct {
	TypeMetadata
	Metadata TierMetadata `json:"metadata,omitempty"`
	Spec     TierSpec     `json:"spec,omitempty"`
}

func NewTier() *Tier {
	return &Tier{TypeMetadata: TypeMetadata{Kind: "tier", APIVersion: "v1"}}
}

type TierList struct {
	TypeMetadata
	Metadata ListMetadata `json:"metadata,omitempty"`
	Items    []Tier       `json:"items" validate:"dive"`
}

func NewTierList() *TierList {
	return &TierList{TypeMetadata: TypeMetadata{Kind: "tierList", APIVersion: "v1"}}
}

// Register v1 structure validators to validate cross-field dependencies in any of the
// required structures.
func init() {
	RegisterStructValidator(validateTier, Tier{})
}

func validateTier(v *validator.Validate, structLevel *validator.StructLevel) {
	tier := structLevel.CurrentStruct.Interface().(Tier)
	if tier.Metadata.Name == DefaultTierName {
		structLevel.ReportError(reflect.ValueOf(tier.Metadata.Name), "Name", "name", "tierNameReserved")
	}
}
