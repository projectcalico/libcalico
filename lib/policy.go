// Copyright (c) 2016 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package libcalico

import (
	"fmt"
	"encoding/json"
)

type TierMetadataKey struct {
	TierID string
}

func (key TierMetadataKey) asEtcdKey() string {
	return fmt.Sprintf("/calico/v1/policy/tier/%s/metadata",
		key.TierID)
}

type TierMetadata struct {
	TierMetadataKey `json:"-"`
	Order float64 `json:"order"`
}

type PolicyKey struct {
	TierID   string
	PolicyID string
}

func (key PolicyKey) asEtcdKey() string {
	return fmt.Sprintf("/calico/v1/policy/tier/%s/metadata/%s",
		key.TierID, key.PolicyID)
}

type Policy struct {
	PolicyKey
	Selector string  `json:"selector"`
	Order    float64 `json:"order"`
	Inbound  []Rule  `json:"inbound_rules"`
	Outbound []Rule  `json:"outbound_rules"`
}

func ParseTierMetadata(key *TierMetadataKey, rawData []byte) (tierMetadata *TierMetadata, err error) {
	tierMetadata = &TierMetadata{TierMetadataKey: *key}
	err = json.Unmarshal([]byte(rawData), tierMetadata)
	if err != nil {
		tierMetadata = nil
	}
	return
}

func ParsePolicy(key *PolicyKey, rawData []byte) (policy *Policy, err error) {
	policy = &Policy{PolicyKey: *key}
	err = json.Unmarshal([]byte(rawData), policy)
	if err != nil {
		policy = nil
	}
	return
}
