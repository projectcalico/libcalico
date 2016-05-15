package libcalico

import (
	"github.com/coreos/etcd/client"
	"strings"
)

func GetKeysAPI(etcdAuthority, etcdEndpoint string) (client.KeysAPI, error) {
	etcdLocation := []string{"http://127.0.0.1:2379"}
	if etcdAuthority != "" {
		etcdLocation = []string{"http://" + etcdAuthority}
	}
	if etcdEndpoint != "" {
		etcdLocation = strings.Split(etcdEndpoint, ",")
	}

	// Create etcd client
	cfg := client.Config{
		Endpoints: etcdLocation,
		Transport: client.DefaultTransport}
	c, err := client.New(cfg)
	if err != nil {
		return nil, err
	}
	return client.NewKeysAPI(c), nil
}