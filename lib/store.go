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
	"regexp"
	"fmt"
)

var (
	tierDataRegex      = regexp.MustCompile(`^/calico/v1/policy/tier/([^/]+)/metadata`)
	policyRegex        = regexp.MustCompile(`^/calico/v1/policy/tier/([^/]+)/policy/([^/]+)`)
	profileRulesRegex  = regexp.MustCompile(`^/calico/v1/policy/profile/([^/]+)/rules`)
	profileTagsRegex   = regexp.MustCompile(`^/calico/v1/policy/profile/([^/]+)/tags`)
	profileLabelsRegex = regexp.MustCompile(`^/calico/v1/policy/profile/([^/]+)/labels`)
	hostIpRegex        = regexp.MustCompile(`^/calico/v1/host/([^/]+)/bird_ip`)
	endpointRegex      = regexp.MustCompile(`^/calico/v1/host/([^/]+)/workload/([^/]+)/([^/]+)/endpoint/([^/]+)`)
)

// TODO find a place to put this
type HostIPKey struct {
	Hostname string
}

func (key HostIPKey) asEtcdKey() string {
	return fmt.Sprintf("/calico/v1/host/%s/bird_ip",
		key.Hostname)
}

type storeKey interface {
	asEtcdKey() string
}

// ParseKey parses a datastore key into one of the <Type>Key structs.
// Returns nil if the string doesn't match one of our objects.
func ParseKey(key string) storeKey {
	if m := endpointRegex.FindStringSubmatch(key); m != nil {
		return EndpointKey{
			Hostname:       m[1],
			OrchestratorID: m[2],
			WorkloadID:     m[3],
			EndpointID:     m[4],
		}
	} else if m := policyRegex.FindStringSubmatch(key); m != nil {
		return PolicyKey{
			TierID:   m[1],
			PolicyID: m[2],
		}
	} else if m := profileRulesRegex.FindStringSubmatch(key); m != nil {
		return ProfileRulesKey{ProfileID: m[1]}
	} else if m := profileTagsRegex.FindStringSubmatch(key); m != nil {
		return ProfileTagsKey{ProfileID: m[1]}
	} else if m := profileLabelsRegex.FindStringSubmatch(key); m != nil {
		return ProfileLabelsKey{ProfileID: m[1]}
	} else if m := tierDataRegex.FindStringSubmatch(key); m != nil {
		return TierMetadataKey{TierID: m[1]}
	} else if m := hostIpRegex.FindStringSubmatch(key); m != nil {
		return HostIPKey{Hostname: m[1]}
	}
	// Not a key we know about.
	return nil
}

