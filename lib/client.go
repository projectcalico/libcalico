package libcalico

import (
	"errors"
	"strings"

	"io/ioutil"

	"github.com/coreos/etcd/client"
	"github.com/ghodss/yaml"
	"github.com/kelseyhightower/envconfig"
)

// TODO rework.  Client should hide the fact that its etcd - so really need a new client
// struct with methods attached to it.

type ClientConfig struct {
	Authority string `json:"etcdAuthority" envconfig:"ETCD_AUTHORITY" default:"127.0.0.1:2379"`
	Endpoints string `json:"etcdEndpoints" envconfig:"ETCD_ENDPOINTS"`
	Username  string `json:"etcdUsername" envconfig:"ETCD_USERNAME"`
	Password  string `json:"etcdPassword" envconfig:"ETCD_PASSWORD"`
}

func (cc *ClientConfig) GetKeysAPI() (client.KeysAPI, error) {
	etcdLocation := []string{}

	// Determine the location from the authority or the endpoints.  The endpoints
	// takes precedence if both are specified.
	if cc.Authority != "" {
		etcdLocation = []string{"http://" + cc.Authority}
	}
	if cc.Endpoints != "" {
		etcdLocation = strings.Split(cc.Endpoints, ",")
	}

	if len(etcdLocation) == 0 {
		return nil, errors.New("no etcd authority or endpoints specified")
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

// Load the client config from the specified file (if it exists), falling back
// to environment variables for non-specified fields.
func LoadClientConfig(f string) (*ClientConfig, error) {
	var c ClientConfig

	err := envconfig.Process("calico", &c)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(f)
	if err == nil {
		err := yaml.Unmarshal(b, &c)
		if err != nil {
			return nil, err
		}
	}

	return &c, nil
}

// Get the etcd keys API.  The access details will be searched for in the following
// order:
// -  The specified file (if it exists)
// -  The environment variables
// -  System default values
func GetKeysAPI(f string) (client.KeysAPI, error) {
	cc, err := LoadClientConfig(f)
	if err != nil {
		return nil, err
	}
	return cc.GetKeysAPI()
}
