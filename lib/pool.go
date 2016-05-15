package libcalico

import (
	"log"
	"fmt"
	"encoding/json"
	"github.com/coreos/etcd/client"
	"golang.org/x/net/context"
)

type Pool struct {
	Cidr string `json:"cidr"`
	Masquerade bool `json:"masquerade"`
	Ipip string `json:"ipip"`
	Version string `json:"-"`
}

func GetPools(etcd client.KeysAPI, version string) (pools []Pool) {
	// Fetch pool config
	resp, err := etcd.Get(context.Background(), fmt.Sprintf("/calico/v1/ipam/v%s/pool", version), &client.GetOptions{Recursive:true})
	if err != nil {
		if ! client.IsKeyNotFound(err) {
			log.Fatal(err)
		}
	} else {
		for _, node := range resp.Node.Nodes {
			pool := Pool{}

			err = json.Unmarshal([]byte(node.Value), &pool)
			if err != nil {
				log.Fatal(err)
			}
			pools = append(pools,pool)
		}}
	return
}