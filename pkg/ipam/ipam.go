package ipam

import (
	"errors"
	"fmt"
	"github.com/coreos/etcd/client"
	"golang.org/x/net/context"
	"log"
	"math"
	"net"
	"strings"
	"time"
)

const (
	RETRIES           = 100
	KEY_ERROR_RETRIES = 3

	// IPAM paths
	IPAM_V_PATH             = "/calico/ipam/v2/"
	IPAM_CONFIG_PATH        = IPAM_V_PATH + "config"
	IPAM_HOSTS_PATH         = IPAM_V_PATH + "host"
	IPAM_HOST_PATH          = IPAM_HOSTS_PATH + "/%s"
	IPAM_HOST_AFFINITY_PATH = IPAM_HOST_PATH + "/ipv%d/block/"
	IPAM_BLOCK_PATH         = IPAM_V_PATH + "assignment/ipv%d/block/"
	IPAM_HANDLE_PATH        = IPAM_V_PATH + "handle/"
)

type IPAMConfig struct {
	StrictAffinity bool
}

type BlockReaderWriter struct {
	etcd client.KeysAPI
}

func (rw BlockReaderWriter) ClaimNewAffineBlock(host string, version int, pool *net.IPNet, config IPAMConfig) (*net.IPNet, error) {
	// TODO: Validate the given pool to ensure it exists, default to all pools.
	pools := []net.IPNet{*pool}

	// Iterate through pools to find a new block.
	log.Println("Claiming a new affine block for host", host)
	for _, pool := range pools {
		for _, subnet := range Subnets(pool, BLOCK_PREFIX_LEN_4) {
			// Check if a block already exists for this subnet.
			etcdPath := blockDatastorePath(subnet)
			_, err := rw.etcd.Get(context.Background(), etcdPath, nil)
			if client.IsKeyNotFound(err) {
				// The block does not yet exist in etcd.  Try to grab it.
				log.Println("Found free block:", subnet)
				rw.claimBlockAffinity(subnet, host, config)
				return &subnet, nil
			} else if err != nil {
				log.Println("Error checking block:", err)
				return nil, err
			}
		}
	}
	return nil, errors.New("No free blocks")
}

func (rw BlockReaderWriter) claimBlockAffinity(subnet net.IPNet, host string, config IPAMConfig) {
	// Claim the block in etcd.
	log.Printf("Host %s claiming block affinity for %s", host, subnet)
	affinityPath := blockHostAffinityPath(subnet, host)
	rw.etcd.Set(context.Background(), affinityPath, "", nil)

	// Create the new block.
	block := NewBlock(subnet)
	block.HostAffinity = host
	block.StrictAffinity = config.StrictAffinity

	// Compare and swap the new block.
	err := rw.compareAndSwapBlock(block)
	if err != nil {
		log.Println("Error claiming block affinity:", err)
	}
}

func (rw BlockReaderWriter) compareAndSwapBlock(block AllocationBlock) error {
	// If the block has a store result, compare and swap agianst that.
	if block.DbResult != "" {
		log.Println("CAS update block:", block)
	} else {
		log.Println("CAS write new block:", block)
		etcdPath := blockDatastorePath(block.Cidr)
		opts := client.SetOptions{PrevExist: client.PrevNoExist}
		rw.etcd.Set(context.Background(), etcdPath, "", &opts)
	}

	//        # If the block has a db_result, CAS against that.
	//        if block.db_result is not None:
	//            _log.debug("CAS Update block %s", block)
	//            try:
	//                self.etcd_client.update(block.update_result())
	//            except EtcdCompareFailed:
	//                raise CASError(str(block.cidr))
	//        else:
	//            _log.debug("CAS Write new block %s", block)
	//            key = _block_datastore_key(block.cidr)
	//            value = block.to_json()
	//            try:
	//                self.etcd_client.write(key, value, prevExist=False)
	//            except EtcdAlreadyExist:
	//                raise CASError(str(block.cidr))
	//
	return nil
}

func Subnets(network net.IPNet, prefixLength int) []net.IPNet {
	subnets := []net.IPNet{}
	ip := network.IP
	size := int64(math.Exp2(float64(32 - prefixLength)))
	mask := net.CIDRMask(prefixLength, 32) // TODO: Support IPv6
	for network.Contains(ip) {
		subnets = append(subnets, net.IPNet{ip, mask})
		ip = IncrementIp(ip, size)
	}
	log.Printf("%s has %d subnets of size %d", network, len(subnets), size)
	return subnets
}

func (rw BlockReaderWriter) ReadBlock(blockCidr net.IPNet) (*AllocationBlock, error) {
	// TODO: Set Get options properly (quorum, etc)
	etcdPath := blockDatastorePath(blockCidr)
	resp, err := rw.etcd.Get(context.Background(), etcdPath, nil)
	if err != nil {
		log.Println("Error reading IPAM block:", err)
		return nil, err
	}
	log.Println("Response:", resp)
	block := NewBlock(blockCidr)
	return &block, nil
}

func blockDatastorePath(blockCidr net.IPNet) string {
	// TODO: Support v6
	path := fmt.Sprintf(IPAM_BLOCK_PATH, 4)
	return path + strings.Replace(blockCidr.String(), "/", "-", 1)
}

func blockHostAffinityPath(blockCidr net.IPNet, host string) string {
	// TODO: Support v6
	path := fmt.Sprintf(IPAM_HOST_AFFINITY_PATH, host, 4)
	return path + strings.Replace(blockCidr.String(), "/", "-", 1)
}

type IPAMClient struct {
	BlockWriter BlockReaderWriter
}

func NewIPAMClient() (*IPAMClient, error) {
	// Create the interface into etcd for blocks.
	log.Println("Creating new IPAM client")
	config := client.Config{
		Endpoints:               []string{"http://localhost:2379"},
		Transport:               client.DefaultTransport,
		HeaderTimeoutPerRequest: time.Second,
	}
	c, err := client.New(config)
	if err != nil {
		log.Println("Failed to configure etcd client")
		return nil, err
	}
	api := client.NewKeysAPI(c)
	blockWriter := BlockReaderWriter{etcd: api}

	return &IPAMClient{BlockWriter: blockWriter}, nil
}
