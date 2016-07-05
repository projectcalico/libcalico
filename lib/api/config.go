package api

// Client configuration required to instantiate a Calico client interface.
type ClientConfig struct {
	EtcdAuthority string `json:"etcdAuthority" envconfig:"ETCD_AUTHORITY" default:"127.0.0.1:2379"`
	EtcdEndpoints string `json:"etcdEndpoints" envconfig:"ETCD_ENDPOINTS"`
	EtcdUsername  string `json:"etcdUsername" envconfig:"ETCD_USERNAME"`
	EtcdPassword  string `json:"etcdPassword" envconfig:"ETCD_PASSWORD"`
}
