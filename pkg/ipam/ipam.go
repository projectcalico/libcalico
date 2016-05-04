package ipam

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/etcd/client"
	"golang.org/x/net/context"
	"log"
	"math"
	"net"
	"os"
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

func (c IPAMClient) AutoAssign(
	num4 int64, num6 int64, handleId string, attributes map[string]string,
	host *string, v4pool *net.IPNet, v6pool *net.IPNet) ([]net.IP, []net.IP, error) {

	// Determine the hostname to use - prefer the provided hostname if
	// non-nil, otherwise use the hostname reported by os.
	log.Printf("Auto-assign %d ipv4, %d ipv6 addrs", num4, num6)
	var hostname string
	var err error
	if host != nil {
		hostname = *host
	} else {
		hostname, err = os.Hostname()
		if err != nil {
			log.Fatal("Failed to acquire hostname")
		}
	}
	log.Printf("Assigning for host: %s", hostname)

	// Assign addresses.
	v4list, _ := c.autoAssignV4(num4, handleId, attributes, v4pool, hostname)
	//	v6list := rw.autoAssignV6()
	v6list := []net.IP{}

	return v4list, v6list, nil
}

func (c IPAMClient) autoAssignV4(
	num int64, handleId string, attrs map[string]string, pool *net.IPNet, host string) ([]net.IP, error) {

	// Start by trying to assign from one of the host-affine blocks.  We
	// always do strict checking at this stage, so it doesn't matter whether
	// globally we have strict_affinity or not.
	log.Printf("Looking for addresses in current affine blocks for host %s", host)
	affBlocks, _ := c.BlockReaderWriter.GetAffineBlocks(host, 4, pool)
	log.Printf("Found %d affine IPv4 blocks", len(affBlocks))
	ips := []net.IP{}
	for int64(len(ips)) < num {
		if len(affBlocks) == 0 {
			log.Println("Ran out of affine blocks for host", host)
			break
		}
		cidr := affBlocks[0]
		affBlocks = affBlocks[1:]
		ips, _ = c.assignFromExistingBlock(cidr, num, handleId, attrs, host, nil)
		log.Println("Block provided addresses:", ips)
	}

	if int64(len(ips)) == num {
		log.Println("Found enough IP addresses")
		return ips, nil
	}

	// If there are still addresses to allocate, then we've run out of
	// blocks with affinity.  Before we can assign new blocks or assign in
	// non-affine blocks, we need to check that our IPAM configuration
	// allows that. TODO - check config, support v6.
	config := IPAMConfig{StrictAffinity: false}
	_, p, _ := net.ParseCIDR("192.168.0.0/24")
	c.BlockReaderWriter.ClaimNewAffineBlock(host, 4, p, config)

	return ips, nil
}

func (c IPAMClient) assignFromExistingBlock(
	blockCidr net.IPNet, num int64, handle string, attrs map[string]string, host string, affCheck *bool) ([]net.IP, error) {
	// Limit number of retries.
	var ips []net.IP
	for i := 0; i < RETRIES; i++ {
		log.Printf("Auto-assign from %s - retry %d", blockCidr, i)
		b, err := c.BlockReaderWriter.ReadBlock(blockCidr)
		if err != nil {
			return nil, err
		}
		log.Println("Got block:", b)
		ips, err = b.AutoAssign(num, handle, host, attrs, true)
		if err != nil {
			log.Println("Error in auto assign:", err)
			return nil, err
		}
		if len(ips) == 0 {
			log.Printf("Block %s is full", blockCidr)
			return []net.IP{}, nil
		}

		// TODO: Increment handle?

		// Update the block using CAS.
		err = c.BlockReaderWriter.CompareAndSwapBlock(*b)
		if err != nil {
			// TODO: Decrement handle?
			log.Println("Error updating block - try again")
			continue
		}
		break
	}
	return ips, nil
}

func (rw BlockReaderWriter) GetAffineBlocks(host string, ipVersion int, pool *net.IPNet) ([]net.IPNet, error) {
	key := fmt.Sprintf(IPAM_HOST_AFFINITY_PATH, host, ipVersion)
	opts := client.GetOptions{Quorum: true, Recursive: true}
	res, err := rw.etcd.Get(context.Background(), key, &opts)
	if err != nil {
		log.Println("Error reading blocks from etcd", err)
		return nil, err
	}
	log.Println("Read blocks from etcd:", res)

	ids := []net.IPNet{}
	if res.Node != nil {
		for _, n := range res.Node.Nodes {
			if !n.Dir {
				// Extract the block identifier (subnet) which is encoded
				// into the etcd key.  We need to replace "-" with "/" to
				// turn it back into a cidr.
				log.Printf("Found block on host %s: %s", host, n.Key)
				ss := strings.Split(n.Key, "/")
				_, id, _ := net.ParseCIDR(strings.Replace(ss[len(ss)-1], "-", "/", 1))
				ids = append(ids, *id)
			}
		}
	}
	return ids, nil
}

func (rw BlockReaderWriter) ClaimNewAffineBlock(
	host string, version int, pool *net.IPNet, config IPAMConfig) (*net.IPNet, error) {

	// TODO: Validate the given pool to ensure it exists, default to all pools.
	pools := []net.IPNet{*pool}

	// Iterate through pools to find a new block.
	log.Println("Claiming a new affine block for host", host)
	for _, pool := range pools {
		for _, subnet := range Subnets(pool, BLOCK_PREFIX_LEN_4) {
			// Check if a block already exists for this subnet.
			key := blockDatastorePath(subnet)
			_, err := rw.etcd.Get(context.Background(), key, nil)
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
	err := rw.CompareAndSwapBlock(block)
	if err != nil {
		log.Println("Error claiming block affinity:", err)
	}
}

func (rw BlockReaderWriter) CompareAndSwapBlock(b AllocationBlock) error {
	// If the block has a store result, compare and swap agianst that.
	var opts client.SetOptions
	key := blockDatastorePath(b.Cidr)

	// Determine correct Set options.
	if b.DbResult != "" {
		log.Println("CAS update block:", b.Cidr)
		opts = client.SetOptions{PrevExist: client.PrevExist, PrevValue: b.DbResult}
	} else {
		log.Println("CAS write new block:", b.Cidr)
		opts = client.SetOptions{PrevExist: client.PrevNoExist}
	}

	j, err := json.Marshal(b)
	if err != nil {
		log.Println("Error converting block to json:", err)
		return err
	}
	_, err = rw.etcd.Set(context.Background(), key, string(j), &opts)
	if err != nil {
		log.Println("CAS error writing block:", err)
		return err
	}

	return nil
}

func Subnets(network net.IPNet, prefixLength int) []net.IPNet {
	nets := []net.IPNet{}
	ip := network.IP
	size := int64(math.Exp2(float64(32 - prefixLength)))
	mask := net.CIDRMask(prefixLength, 32) // TODO: Support IPv6
	for network.Contains(ip) {
		nets = append(nets, net.IPNet{ip, mask})
		ip = IncrementIP(ip, size)
	}
	log.Printf("%s has %d subnets of size %d", network, len(nets), size)
	return nets
}

func (rw BlockReaderWriter) ReadBlock(blockCidr net.IPNet) (*AllocationBlock, error) {
	key := blockDatastorePath(blockCidr)
	opts := client.GetOptions{Quorum: true}
	resp, err := rw.etcd.Get(context.Background(), key, &opts)
	if err != nil {
		log.Println("Error reading IPAM block:", err)
		return nil, err
	}
	log.Println("Response from etcd:", resp)
	b := NewBlock(blockCidr)
	json.Unmarshal([]byte(resp.Node.Value), &b)
	b.DbResult = resp.Node.Value
	return &b, nil
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
	BlockReaderWriter BlockReaderWriter
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
	b := BlockReaderWriter{etcd: api}

	return &IPAMClient{BlockReaderWriter: b}, nil
}
