package backend

import (
	"errors"
	"strings"

	etcd "github.com/coreos/etcd/client"
	"github.com/golang/glog"
	"github.com/projectcalico/libcalico/lib/api"
	"github.com/projectcalico/libcalico/lib/common"
	"golang.org/x/net/context"
)

var (
	etcdSetOpts    = etcd.SetOptions{PrevExist: etcd.PrevIgnore}
	etcdDeleteOpts = etcd.DeleteOptions{Recursive: true}
	etcdGetOpts    = etcd.GetOptions{}
	etcdListOpts   = etcd.GetOptions{Recursive: true, Sort: true}
)

// Interface used to calculate a datastore key.
type KeyInterface interface {
	asEtcdKey() (string, error)
	asEtcdDeleteKey() (string, error)
}

// Interface used to perform datastore lookups.
type ListInterface interface {
	asEtcdKeyRoot() string
	keyFromEtcdResult(key string) KeyInterface
}

// Encapsulated datastore key interface with value.
type KeyValue struct {
	Key   KeyInterface
	Value []byte
}

// Backend client data
type Client struct {
	// Calico client config
	config *api.ClientConfig

	// ---- Internal package data ----
	connected   bool
	etcdClient  etcd.Client
	etcdKeysAPI etcd.KeysAPI
}

// NewClient creates a new backend datastore client.
func NewClient(config *api.ClientConfig) (*Client, error) {
	c := Client{config: config}
	return &c, c.connectEtcd()
}

// Connect the client to the etcd datastore specified in the config.
func (c *Client) connectEtcd() error {
	if c.connected {
		panic("Client is already connected")
	}

	// Determine the location from the authority or the endpoints.  The endpoints
	// takes precedence if both are specified.
	etcdLocation := []string{}
	if c.config.EtcdAuthority != "" {
		etcdLocation = []string{"http://" + c.config.EtcdAuthority}
	}
	if c.config.EtcdEndpoints != "" {
		etcdLocation = strings.Split(c.config.EtcdEndpoints, ",")
	}

	if len(etcdLocation) == 0 {
		return errors.New("no etcd authority or endpoints specified")
	}

	// Create the etcd client
	cfg := etcd.Config{
		Endpoints: etcdLocation,
		Transport: etcd.DefaultTransport}

	// Plumb through the username and password if both are configured.
	if c.config.EtcdUsername != "" && c.config.EtcdPassword != "" {
		cfg.Username = c.config.EtcdUsername
		cfg.Password = c.config.EtcdPassword
	}

	client, err := etcd.New(cfg)
	if err != nil {
		return err
	}
	keys := etcd.NewKeysAPI(client)
	c.etcdClient = client
	c.etcdKeysAPI = keys
	c.connected = true
	return nil
}

// Create an entry in the datastore.  This errors if the entry already exists.
func (c *Client) Create(d KeyValue) error {
	key, _ := d.Key.asEtcdKey()
	glog.V(2).Infof("Create Key: %s\n", key)
	glog.V(2).Infof("Value: %s\n", d.Value)
	_, err := c.etcdKeysAPI.Create(context.Background(), key, string(d.Value))
	return convertError(err, key)
}

// Update an existing entry in the datastore.  This errors if the entry does
// not exist.
func (c *Client) Update(d KeyValue) error {
	key, _ := d.Key.asEtcdKey()
	glog.V(2).Infof("Update Key: %s\n", key)
	glog.V(2).Infof("Value: %s\n", d.Value)
	_, err := c.etcdKeysAPI.Update(context.Background(), key, string(d.Value))
	return convertError(err, key)
}

// Set an existing entry in the datastore.  This ignores whether an entry already
// exists.
func (c *Client) Set(d KeyValue) error {
	key, _ := d.Key.asEtcdKey()
	glog.V(2).Infof("Set Key: %s\n", key)
	glog.V(2).Infof("Value: %s\n", d.Value)
	_, err := c.etcdKeysAPI.Set(context.Background(), key, string(d.Value), &etcdSetOpts)
	return convertError(err, key)
}

// Delete an entry in the datastore.  This errors if the entry does not exists.
func (c *Client) Delete(k KeyInterface) error {
	key, _ := k.asEtcdDeleteKey()
	glog.V(2).Infof("Delete Key: %s\n", key)
	_, err := c.etcdKeysAPI.Delete(context.Background(), key, &etcdDeleteOpts)
	return convertError(err, key)
}

// Get an entry from the datastore.  This errors if the entry does not exist.
func (c *Client) Get(k KeyInterface) (KeyValue, error) {
	key, _ := k.asEtcdKey()
	glog.V(2).Infof("Get Key: %s\n", key)
	if results, err := c.etcdKeysAPI.Get(context.Background(), key, &etcdGetOpts); err != nil {
		return KeyValue{}, convertError(err, key)
	} else {
		return KeyValue{Key: k, Value: []byte(results.Node.Value)}, nil
	}
}

// List entries in the datastore.  This may return an empty list of there are
// no entries matching the request in the ListInterface.
func (c *Client) List(l ListInterface) ([]KeyValue, error) {
	// To list entries, we enumerate from the common root based on the supplied
	// IDs, and then filter the results.
	key := l.asEtcdKeyRoot()
	glog.V(2).Infof("List Key: %s\n", key)
	if results, err := c.etcdKeysAPI.Get(context.Background(), key, &etcdListOpts); err != nil {
		return nil, err
	} else {
		return filterListNode(results.Node, l), nil
	}
}

// Process a node returned from a list to filter results based on the List type and to
// compile and return the required results.
func filterListNode(n *etcd.Node, l ListInterface) []KeyValue {
	kvs := []KeyValue{}
	if n.Dir {
		for _, node := range n.Nodes {
			kvs = append(kvs, filterListNode(node, l)...)
		}
	} else if k := l.keyFromEtcdResult(n.Key); k != nil {
		kvs = append(kvs, KeyValue{Key: k, Value: []byte(n.Value)})
	}
	glog.V(2).Infof("Returning: %v", kvs)
	return kvs
}

func convertError(err error, key string) error {
	if err == nil {
		glog.V(2).Info("Comand completed without error")
		return nil
	}

	switch err.(type) {
	case etcd.Error:
		switch err.(etcd.Error).Code {
		case etcd.ErrorCodeNodeExist:
			glog.V(2).Info("Node exists error")
			return common.ErrorResourceAlreadyExists{Err: err, Name: key}
		case etcd.ErrorCodeKeyNotFound:
			glog.V(2).Info("Key not found error")
			return common.ErrorResourceDoesNotExist{Err: err, Name: key}
		case etcd.ErrorCodeUnauthorized:
			glog.V(2).Info("Unauthorized error")
			return common.ErrorConnectionUnauthorized{Err: err}
		default:
			glog.V(2).Infof("Generic etcd error error: %v", err)
			return common.ErrorDatastoreError{Err: err}
		}
	default:
		glog.V(2).Infof("Unhandled error: %v", err)
		return common.ErrorDatastoreError{Err: err}
	}
}
