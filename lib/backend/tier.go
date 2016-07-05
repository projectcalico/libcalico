package backend

import (
	"fmt"
	"regexp"

	"github.com/golang/glog"
	"github.com/projectcalico/libcalico/lib/common"
)

var (
	matchTier = regexp.MustCompile("^/calico/v1/policy/tier/([^/]+)/metadata$")
)

type TierKey struct {
	Name string `json:"-" validate:"required,name"`
}

func (key TierKey) asEtcdKey() (string, error) {
	k, err := key.asEtcdDeleteKey()
	return k + "/metadata", err
}

func (key TierKey) asEtcdDeleteKey() (string, error) {
	if key.Name == "" {
		return "", common.ErrorInsufficientIdentifiers{}
	}
	e := fmt.Sprintf("/calico/v1/policy/tier/%s", key.Name)
	return e, nil
}

type TierListOptions struct {
	Name string
}

func (options TierListOptions) asEtcdKeyRoot() string {
	k := "/calico/v1/policy/tier"
	if options.Name == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s/metadata", options.Name)
	return k
}

func (options TierListOptions) keyFromEtcdResult(ekey string) KeyInterface {
	glog.V(2).Infof("Get Tier key from %s", ekey)
	r := matchTier.FindAllStringSubmatch(ekey, -1)
	if len(r) != 1 {
		glog.V(2).Infof("Didn't match regex")
		return nil
	}
	name := r[0][1]
	if options.Name != "" && name != options.Name {
		glog.V(2).Infof("Didn't match name %s != %s", options.Name, name)
		return nil
	}
	return TierKey{Name: name}
}

type Tier struct {
	TierKey `json:"-"`
	Order   *float32 `json:"order,omitempty"`
}
