package backend

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/golang/glog"
	"github.com/projectcalico/libcalico/lib/common"
)

var (
	matchPolicy = regexp.MustCompile("^/calico/v1/policy/tier/([^/]+)/policy/([^/]+)$")
)

type PolicyKey struct {
	Name string `json:"-" validate:"required,name"`
	Tier string `json:"-" validate:"required,name"`
}

func (key PolicyKey) asEtcdKey() (string, error) {
	if key.Name == "" || key.Tier == "" {
		return "", errors.New("insufficient identifiers")
	}
	e := fmt.Sprintf("/calico/v1/policy/tier/%s/policy/%s",
		key.Tier, key.Name)
	return e, nil
}

func (key PolicyKey) asEtcdDeleteKey() (string, error) {
	return key.asEtcdKey()
}

type PolicyListOptions struct {
	Name string
	Tier string
}

func (options PolicyListOptions) asEtcdKeyRoot() string {
	k := "/calico/v1/policy/tier"
	k = k + fmt.Sprintf("/%s/policy", common.TierOrDefault(options.Tier))
	if options.Name == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s", options.Name)
	return k
}

func (options PolicyListOptions) keyFromEtcdResult(ekey string) KeyInterface {
	glog.V(2).Infof("Get Policy key from %s", ekey)
	r := matchPolicy.FindAllStringSubmatch(ekey, -1)
	if len(r) != 1 {
		glog.V(2).Infof("Didn't match regex")
		return nil
	}
	tier := common.TierOrBlank(r[0][1])
	name := r[0][2]
	if options.Tier != "" && tier != options.Tier {
		glog.V(2).Infof("Didn't match tier %s != %s", options.Tier, tier)
		return nil
	}
	if options.Name != "" && name != options.Name {
		glog.V(2).Infof("Didn't match name %s != %s", options.Name, name)
		return nil
	}
	return PolicyKey{Tier: tier, Name: name}
}

type Policy struct {
	PolicyKey     `json:"-"`
	Order         *float32 `json:"order,omitempty"`
	InboundRules  []Rule   `json:"inbound_rules,omitempty" validate:"omitempty,dive"`
	OutboundRules []Rule   `json:"outbound_rules,omitempty" validate:"omitempty,dive"`
	Selector      string   `json:"selector" validate:"selector"`
}
