package libcalico

import (
	"encoding/json"
	"github.com/coreos/etcd/client"
	"fmt"
	"golang.org/x/net/context"
)

type ProfileKey struct {
	ProfileID string
}

type ProfileRulesKey ProfileKey

func (key ProfileRulesKey) asEtcdKey() string {
	return fmt.Sprintf("/calico/v1/policy/profile/%s/rules",
		key.ProfileID)
}

type ProfileTagsKey ProfileKey

func (key ProfileTagsKey) asEtcdKey() string {
	return fmt.Sprintf("/calico/v1/policy/profile/%s/tags",
		key.ProfileID)
}

type ProfileLabelsKey ProfileKey

func (key ProfileLabelsKey) asEtcdKey() string {
	return fmt.Sprintf("/calico/v1/policy/profile/%s/labels",
		key.ProfileID)
}

type Rules struct {
	Inbound  []Rule `json:"inbound_rules"`
	Outbound []Rule `json:"outbound_rules"`
}

type Rule struct {
	Action string `json:"action"`
	SrcTag string `json:"src_tag,omitempty"`
}

type Profile struct {
	ProfileKey `json:"-"`
	Tags  []string `json:"tags"`
	Rules Rules `json:"rules"`
}

func ProfileExists(id string, etcd client.KeysAPI) (bool, error) {
	_, err := etcd.Get(context.Background(), "/calico/v1/policy/profile/" + id, &client.GetOptions{})
	if err != nil {
		if client.IsKeyNotFound(err) {
			return false, nil
		} else {
			return true, nil
		}
	}
	return false, err
}

func (p *Profile) Write(etcd client.KeysAPI) error {
	tagsKey := fmt.Sprintf("/calico/v1/policy/profile/%s/tags", p.ProfileID)
	rulesKey := fmt.Sprintf("/calico/v1/policy/profile/%s/rules", p.ProfileID)
	tagBytes, _ := json.Marshal(p.Tags)
	ruleBytes, _ := json.Marshal(p.Rules)

	if _, err := etcd.Set(context.Background(), tagsKey, string(tagBytes), &client.SetOptions{}); err != nil {
		return err
	}

	if _, err := etcd.Set(context.Background(), rulesKey, string(ruleBytes), &client.SetOptions{}); err != nil {
		return err
	}
	return nil
}
