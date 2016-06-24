package libcalico

import (
	"encoding/json"
	"fmt"
	"github.com/coreos/etcd/client"
	"github.com/satori/go.uuid"
	"golang.org/x/net/context"
	"log"
	"regexp"
)

var re = regexp.MustCompile(`/calico/v1/host/[^/]*?/workload/[^/]*/([^/]*)/endpoint/[^/]*`)

type EndpointKey struct {
	Hostname       string `json:"-"`
	OrchestratorID string `json:"-"`
	WorkloadID     string `json:"-"`
	EndpointID     string `json:"-"`
}

func (key EndpointKey) asEtcdKey() string {
	return fmt.Sprintf("/calico/v1/host/%s/workload/%s/%s/endpoint/%s",
		key.Hostname, key.OrchestratorID, key.WorkloadID, key.EndpointID)
}

type Endpoint struct {
	EndpointKey `json:"-"`
	State       string            `json:"state"`
	Name        string            `json:"name"`
	Mac         string            `json:"mac"`
	ProfileID   []string          `json:"profile_ids"`
	IPv4Nets    []string          `json:"ipv4_nets"`
	IPv6Nets    []string          `json:"ipv6_nets"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type HostEndpointKey struct {
	Hostname       string `json:"-"`
	EndpointID     string `json:"-"`
}

func (key HostEndpointKey) asEtcdKey() string {
	return fmt.Sprintf("/calico/v1/host/%s/endpoint/%s",
		key.Hostname, key.EndpointID)
}

type HostEndpoint struct {
	HostEndpointKey `json:"-"`
	Name        string            `json:"name,omitempty"`
	ProfileIDs   []string          `json:"profile_ids"`
	ExpectedIPv4Addrs    []string          `json:"expected_ipv4_addrs"`
	ExpectedIPv6Addrs    []string          `json:"expected_ipv4_addrs"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type LabelOnlyEndpoint struct {
	Labels map[string]string `json:"labels"`
	Key    string            `json:"-"`
	Json   string            `json:"-"`
}

type EndpointUpdate struct {
	LabelOnlyEndpoint
	Remove     bool
	WorkloadID string
	Index      uint64
}

type EndpointSync struct {
	Endpoints map[string]LabelOnlyEndpoint
	Index     uint64
}

func GetEndpoints(endpoints_chan chan EndpointSync, etcd client.KeysAPI) error {
	endpoints := make(map[string]LabelOnlyEndpoint)
	resp, err := etcd.Get(context.Background(), "/calico/v1/host/", &client.GetOptions{Recursive: true})
	if err != nil {
		if !client.IsKeyNotFound(err) {
			return err
		}
	} else {
		for _, node := range resp.Node.Nodes {
			processNode(node, endpoints)
		}
	}

	endpoints_chan <- EndpointSync{endpoints, resp.Index}
	return nil
}

func ParseEndpoint(key *EndpointKey, rawData []byte) (endpoint *Endpoint, err error) {
	endpoint = &Endpoint{EndpointKey: *key}
	err = json.Unmarshal([]byte(rawData), endpoint)
	if err != nil {
		endpoint = nil
	}
	return
}

func ParseHostEndpoint(key *HostEndpointKey, rawData []byte) (hostEndpoint *HostEndpoint, err error) {
	hostEndpoint = &HostEndpoint{HostEndpointKey: *key}
	err = json.Unmarshal([]byte(rawData), hostEndpoint)
	if err != nil {
		hostEndpoint = nil
	}
	return
}

func WatchEndpoints(ch chan EndpointUpdate, AfterIndex uint64, etcd client.KeysAPI) error {
	path := "/calico/v1/host/"
	watcher := etcd.Watcher(path, &client.WatcherOptions{Recursive: true, AfterIndex: AfterIndex})
	log.Println("Watching", path)
	for {
		resp, err := watcher.Next(context.Background())
		if err != nil {
			log.Fatal("Etcdwatch failed: ", err)
		} else {
			update := EndpointUpdate{}
			log.Println(resp.PrevNode)
			if resp.Action == "set" && resp.PrevNode == nil {
				update.Index = resp.Index
				endpoints := make(map[string]LabelOnlyEndpoint)
				processNode(resp.Node, endpoints)
				if len(endpoints) == 1 {
					for k, v := range endpoints {
						update.LabelOnlyEndpoint = v
						update.WorkloadID = k
					}

				} else if len(endpoints) > 1 {
					log.Panic("Should never happen")
				}
			} else if resp.Action == "delete" {
				update.Remove = true
			} else {
				log.Println("Ignoring etcd update with action for ", resp.Node.Key)
				continue
			}

			ch <- update
		}

	}
	log.Panic("Exited infinite loop!")
	return nil
}

func SetLabelOnlyEndpoint(endpoint LabelOnlyEndpoint, etcd client.KeysAPI) error {
	// Unmarshal the JSON in the endpoint, update the labels then remarshal it in order to store it in etcd.

	log.Println("Setting etcddata for ", endpoint.Key)

	var dat map[string]interface{}
	if err := json.Unmarshal([]byte(endpoint.Json), &dat); err != nil {
		return err
	}

	dat["labels"] = endpoint.Labels
	bytes, err := json.Marshal(dat)
	endpoint.Json = string(bytes)

	// TODO - CAS
	if _, err = etcd.Set(context.Background(), endpoint.Key, endpoint.Json, &client.SetOptions{}); err != nil {
		return err
	}
	return nil
}

func (e *Endpoint) Write(etcd client.KeysAPI) error {
	if e.EndpointID == "" {
		u1 := uuid.NewV1()
		e.EndpointID = fmt.Sprintf("%x", u1)
	}
	key := fmt.Sprintf("/calico/v1/host/%s/workload/%s/%s/endpoint/%s",
		e.Hostname, e.OrchestratorID, e.WorkloadID, e.EndpointID)
	bytes, err := json.Marshal(e)
	if err != nil {
		return err
	}
	json := string(bytes)

	if _, err := etcd.Set(context.Background(), key, json, &client.SetOptions{}); err != nil {
		return err
	}
	return nil
}

func GetEndpoint(etcd client.KeysAPI, w Workload) (bool, *Endpoint, error) {
	key := fmt.Sprintf("/calico/v1/host/%s/workload/%s/%s/endpoint/", w.Hostname, w.OrchestratorID, w.WorkloadID)
	resp, err := etcd.Get(context.Background(), key, &client.GetOptions{Recursive: true})
	if err != nil {
		if client.IsKeyNotFound(err) {
			return false, &Endpoint{}, nil
		} else {
			return false, &Endpoint{}, err
		}

	} else {
		for _, node := range resp.Node.Nodes {
			if !node.Dir {
				key := ParseKey(node.Key).(EndpointKey)
				endpoint, err := ParseEndpoint(&key, []byte(node.Value))
				if err != nil {
					return false, nil, err
				}
				return true, endpoint, nil
			}
		}
	}

	return false, &Endpoint{}, nil
}

func processNode(n *client.Node, endpoints map[string]LabelOnlyEndpoint) {
	if !n.Dir {
		matches := re.FindStringSubmatch(n.Key)
		if len(matches) == 2 {
			endpoint := LabelOnlyEndpoint{Key: n.Key, Json: n.Value}
			err := json.Unmarshal([]byte(n.Value), &endpoint)
			if err != nil {
				log.Fatal(err)
			}

			endpoints[matches[1]] = endpoint

		}
	}
	for _, node := range n.Nodes {
		processNode(node, endpoints)
	}
}
