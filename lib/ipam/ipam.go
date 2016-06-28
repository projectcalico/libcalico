package ipam

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/etcd/client"
	"golang.org/x/net/context"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

const (
	// Number of retries when we have an error writing data
	// to etcd.
	etcdRetries   = 100
	keyErrRetries = 3

	// IPAM paths
	ipamVersionPath      = "/calico/ipam/v2/"
	ipamConfigPath       = ipamVersionPath + "config"
	ipamHostsPath        = ipamVersionPath + "host"
	ipamHostPath         = ipamHostsPath + "/%s"
	ipamHostAffinityPath = ipamHostPath + "/ipv%d/block/"
	ipamBlockPath        = ipamVersionPath + "assignment/ipv%d/block/"
	ipamHandlePath       = ipamVersionPath + "handle/"
)

// IPAMConfig contains global configuration options for Calico IPAM.
type IPAMConfig struct {
	// When StrictAffinity is true, addresses from a given block can only be
	// assigned by hosts with the blocks affinity.  If false, then AutoAllocateBlocks
	// must be true.
	StrictAffinity bool

	// When AutoAllocateBlocks is true, the IPAM client will automatically
	// allocate blocks as needed to assign addresses.  If false, then
	// StrictAffinity must be true.
	AutoAllocateBlocks bool
}

// AutoAssignArgs defines the set of arguments for assigning one or more
// IP addresses.
type AutoAssignArgs struct {
	// The number of IPv4 addresses to automatically assign.
	Num4 int

	// The number of IPv6 addresses to automatically assign.
	Num6 int

	// If specified, a handle which can be used to retrieve / release
	// the allocated IP addresses in the future.
	HandleID *string

	// A key/value mapping of metadata to store with the allocations.
	Attrs map[string]string

	// If specified, the hostname of the host on which IP addresses
	// will be allocated.  If not specified, this will default
	// to the value provided by os.Hostname.
	Hostname *string

	// If specified, the previously configured IPv4 pool from which
	// to assign IPv4 addresses.  If not specified, this defaults to all IPv4 pools.
	IPv4Pool *net.IPNet

	// If specified, the previously configured IPv6 pool from which
	// to assign IPv6 addresses.  If not specified, this defaults to all IPv6 pools.
	IPv6Pool *net.IPNet
}

// AutoAssign automatically assigns one or more IP addresses as specified by the
// provided AutoAssignArgs.  AutoAssign returns the list of the assigned IPv4 addresses,
// and the list of the assigned IPv6 addresses.
func (c IPAMClient) AutoAssign(args AutoAssignArgs) ([]net.IP, []net.IP, error) {
	// Determine the hostname to use - prefer the provided hostname if
	// non-nil, otherwise use the hostname reported by os.
	log.Printf("Auto-assign args: %+v", args)
	log.Printf("Auto-assign %d ipv4, %d ipv6 addrs", args.Num4, args.Num6)
	hostname := decideHostname(args.Hostname)
	log.Printf("Assigning for host: %s", hostname)

	// Assign addresses.
	var err error
	var v4list, v6list []net.IP
	v4list, err = c.autoAssign(args.Num4, args.HandleID, args.Attrs, args.IPv4Pool, ipv4, hostname)
	if err != nil {
		log.Printf("Error assigning IPV4 addresses: %s", err)
	} else {
		// If no err assigning V4, try to assign any V6.
		v6list, err = c.autoAssign(args.Num6, args.HandleID, args.Attrs, args.IPv6Pool, ipv6, hostname)
	}

	return v4list, v6list, err
}

func (c IPAMClient) autoAssign(num int, handleID *string, attrs map[string]string, pool *net.IPNet, version ipVersion, host string) ([]net.IP, error) {

	// Start by trying to assign from one of the host-affine blocks.  We
	// always do strict checking at this stage, so it doesn't matter whether
	// globally we have strict_affinity or not.
	log.Printf("Looking for addresses in current affine blocks for host %s", host)
	affBlocks, err := c.blockReaderWriter.getAffineBlocks(host, version, pool)
	if err != nil {
		return nil, err
	}
	log.Printf("Found %d affine IPv%d blocks", len(affBlocks), version.Number)
	ips := []net.IP{}
	for len(ips) < num {
		if len(affBlocks) == 0 {
			log.Println("Ran out of affine blocks for host", host)
			break
		}
		cidr := affBlocks[0]
		affBlocks = affBlocks[1:]
		ips, _ = c.assignFromExistingBlock(cidr, num, handleID, attrs, host, nil)
		log.Println("Block provided addresses:", ips)
	}

	// If there are still addresses to allocate, then we've run out of
	// blocks with affinity.  Before we can assign new blocks or assign in
	// non-affine blocks, we need to check that our IPAM configuration
	// allows that.
	config, err := c.GetIPAMConfig()
	if err != nil {
		return nil, err
	}
	if config.AutoAllocateBlocks == true {
		rem := num - len(ips)
		log.Printf("Need to allocate %d more addresses", rem)
		retries := etcdRetries
		for rem > 0 {
			// Claim a new block.
			b, err := c.blockReaderWriter.claimNewAffineBlock(host, version, pool, *config)
			if err != nil {
				log.Println("Error claiming new block:", err)
				retries = retries - 1
				if retries == 0 {
					log.Println("Max retries hit")
					return nil, errors.New("Max retries hit")
				}
			} else {
				// Claim successful.  Assign addresses from the new block.
				log.Println("Claimed new block - assigning addresses")
				newIPs, err := c.assignFromExistingBlock(*b, rem, handleID, attrs, host, &config.StrictAffinity)
				if err != nil {
					log.Println("Error assigning IPs:", err)
					break
				}
				ips = append(ips, newIPs...)
				rem = num - len(ips)
			}
		}
	}

	// If there are still addresses to allocate, we've now tried all blocks
	// with some affinity to us, and tried (and failed) to allocate new
	// ones.  If we do not require strict host affinity, our last option is
	// a random hunt through any blocks we haven't yet tried.
	//
	// Note that this processing simply takes all of the IP pools and breaks
	// them up into block-sized CIDRs, then shuffles and searches through each
	// CIDR.  This algorithm does not work if we disallow auto-allocation of
	// blocks because the allocated blocks may be sparsely populated in the
	// pools resulting in a very slow search for free addresses.
	//
	// If we need to support non-strict affinity and no auto-allocation of
	// blocks, then we should query the actual allocation blocks and assign
	// from those.
	if config.StrictAffinity != true {
		log.Println("Attempting to assign from non-affine block")
		// TODO: this
	}

	return ips, nil
}

// AssignIPArgs defines the set of arguments for assigning a specific IP address.
type AssignIPArgs struct {
	// The IP address to assign.
	IP net.IP

	// If specified, a handle which can be used to retrieve / release
	// the allocated IP addresses in the future.
	HandleID *string

	// A key/value mapping of metadata to store with the allocations.
	Attrs map[string]string

	// If specified, the hostname of the host on which IP addresses
	// will be allocated.  If not specified, this will default
	// to the value provided by os.Hostname.
	Hostname *string
}

// AssignIP assigns the provided IP address to the provided host.  The IP address
// must fall within a configured pool.  AssignIP will claim block affinity as needed
// in order to satisfy the assignment.  An error will be returned if the IP address
// is already assigned, or if StrictAffinity is enabled and the address is within
// a block that does not have affinity for the given host.
func (c IPAMClient) AssignIP(args AssignIPArgs) error {
	hostname := decideHostname(args.Hostname)
	log.Printf("Assigning IP %s to host: %s", args.IP, hostname)

	blockCidr := getBlockCIDRForAddress(args.IP)
	for i := 0; i < etcdRetries; i++ {
		block, err := c.blockReaderWriter.readBlock(blockCidr)
		if err != nil {
			if _, ok := err.(NoSuchBlockError); ok {
				// Block doesn't exist, we need to create it.
				// TODO: Validate the given IP address is in a configured pool.
				log.Printf("Block for IP %s does not yet exist, creating", args.IP)
				cfg := IPAMConfig{StrictAffinity: false, AutoAllocateBlocks: true}
				version := getIPVersion(args.IP)
				newBlockCidr, err := c.blockReaderWriter.claimNewAffineBlock(hostname, version, nil, cfg)
				if err != nil {
					if _, ok := err.(*AffinityClaimedError); ok {
						log.Printf("Someone else claimed block %s before us", blockCidr)
						continue
					} else {
						return err
					}
				}
				log.Printf("Claimed new block: %s", newBlockCidr)
				continue
			} else {
				// Unexpected error
				return err
			}
		}
		log.Printf("IP %s is in block %s", args.IP, block.Cidr)
		err = block.assign(args.IP, args.HandleID, args.Attrs, hostname)
		if err != nil {
			log.Printf("Failed to assign address %s: %s", args.IP, err)
			return err
		}

		// Increment handle.
		if args.HandleID != nil {
			c.incrementHandle(*args.HandleID, blockCidr, 1)
		}

		// Update the block.
		err = c.blockReaderWriter.compareAndSwapBlock(*block)
		if err != nil {
			log.Println("CAS failed on block %s", block.Cidr)
			if args.HandleID != nil {
				c.decrementHandle(*args.HandleID, blockCidr, 1)
			}
			return err
		}
		return nil
	}
	return errors.New("Max retries hit")
}

// ReleaseIPs releases any of the given IP addresses that are currently assigned,
// so that they are available to be used in another assignment.
func (c IPAMClient) ReleaseIPs(ips []net.IP) ([]net.IP, error) {
	log.Println("Releasing IP addresses:", ips)
	unallocated := []net.IP{}
	for _, ip := range ips {
		blockCidr := getBlockCIDRForAddress(ip)
		// TODO: Group IP addresses per-block to minimize writes to etcd.
		unalloc, err := c.releaseIPsFromBlock([]net.IP{ip}, blockCidr)
		if err != nil {
			log.Println("Error releasing IPs:", err)
			return nil, err
		}
		unallocated = append(unallocated, unalloc...)
	}
	return unallocated, nil
}

func (c IPAMClient) releaseIPsFromBlock(ips []net.IP, blockCidr net.IPNet) ([]net.IP, error) {
	for i := 0; i < etcdRetries; i++ {
		b, err := c.blockReaderWriter.readBlock(blockCidr)
		if err != nil {
			if _, ok := err.(NoSuchBlockError); ok {
				// The block does not exist - all addresses must be unassigned.
				return ips, nil
			} else {
				// Unexpected error reading block.
				return nil, err
			}
		}

		// Block exists - release the IPs from it.
		unallocated, handles, err2 := b.release(ips)
		if err2 != nil {
			return nil, err2
		}
		if len(ips) == len(unallocated) {
			// All the given IP addresses are already unallocated.
			// Just return.
			return unallocated, nil
		}

		// If the block is empty and has no affinity, we can delete it.
		// Otherwise, update the block using CAS.
		var casError error
		if b.empty() && b.HostAffinity == nil {
			log.Println("Deleting non-affine block")
			casError = c.blockReaderWriter.deleteBlock(*b)
		} else {
			log.Println("Updating assignments in block")
			casError = c.blockReaderWriter.compareAndSwapBlock(*b)
		}

		if casError != nil {
			log.Printf("Error updating block - retry #%d", i)
			continue
		}

		// Success - decrement handles.
		log.Println("Decrementing handles:", handles)
		for handleID, amount := range handles {
			c.decrementHandle(handleID, blockCidr, amount)
		}
		return unallocated, nil
	}
	return nil, errors.New("Max retries hit")
}

func (c IPAMClient) assignFromExistingBlock(
	blockCidr net.IPNet, num int, handleID *string, attrs map[string]string, host string, affCheck *bool) ([]net.IP, error) {
	// Limit number of retries.
	var ips []net.IP
	for i := 0; i < etcdRetries; i++ {
		log.Printf("Auto-assign from %s - retry %d", blockCidr, i)
		b, err := c.blockReaderWriter.readBlock(blockCidr)
		if err != nil {
			return nil, err
		}
		log.Println("Got block:", b)
		ips, err = b.autoAssign(num, handleID, host, attrs, true)
		if err != nil {
			log.Println("Error in auto assign:", err)
			return nil, err
		}
		if len(ips) == 0 {
			log.Printf("Block %s is full", blockCidr)
			return []net.IP{}, nil
		}

		// Increment handle count.
		if handleID != nil {
			c.incrementHandle(*handleID, blockCidr, num)
		}

		// Update the block using CAS.
		err = c.blockReaderWriter.compareAndSwapBlock(*b)
		if err != nil {
			log.Println("Error updating block - try again")
			if handleID != nil {
				c.decrementHandle(*handleID, blockCidr, num)
			}
			continue
		}
		break
	}
	return ips, nil
}

// ClaimAffinity claims affinity to the given host for all blocks
// within the given CIDR.  The given CIDR must fall within a configured
// pool.
// TODO: Return indicators of claimed vs already claimed by another host.
func (c IPAMClient) ClaimAffinity(cidr net.IPNet, host *string) error {
	// Validate that the given CIDR is at least as big as a block.
	if !largerThanBlock(cidr) {
		estr := fmt.Sprintf("The requested CIDR (%s) is smaller than the minimum block size.", cidr.String())
		return InvalidBlockSizeError(estr)
	}

	// Determine the hostname to use.
	hostname := decideHostname(host)

	// TODO: Verify the requested CIDR falls within a configured pool.

	// Get IPAM config.
	cfg, err := c.GetIPAMConfig()
	if err != nil {
		return err
	}

	// Claim all blocks within the given cidr.
	for _, blockCidr := range blocks(cidr) {
		err := c.blockReaderWriter.claimBlockAffinity(blockCidr, hostname, *cfg)
		if err != nil {
			// TODO: Check error type to determine:
			// 1) claimed by another host.
			return err
		}
		log.Println("Claimed: ", blockCidr)
	}
	return nil

}

// ReleaseAffinity releases affinity for all blocks within the given CIDR
// on the given host.  If host is not specified, then the value returned by os.Hostname
// will be used.
func (c IPAMClient) ReleaseAffinity(cidr net.IPNet, host *string) error {
	// Validate that the given CIDR is at least as big as a block.
	if !largerThanBlock(cidr) {
		return InvalidBlockSizeError("The requested CIDR is smaller than the minimum block size.")
	}

	// Determine the hostname to use.
	hostname := decideHostname(host)

	// Release all blocks within the given cidr.
	for _, blockCidr := range blocks(cidr) {
		err := c.blockReaderWriter.releaseBlockAffinity(hostname, blockCidr)
		if err != nil {
			// TODO: Check error type to determine:
			// 1) claimed by another host.
			// 2) not claimed.
			return err
		}
	}
	return nil
}

// ReleaseHostAffinities releases affinity for all blocks that are affine
// to the given host.  If host is not specified, the value returned by os.Hostname
// will be used.
func (c IPAMClient) ReleaseHostAffinities(host *string) error {
	hostname := decideHostname(host)

	versions := []ipVersion{ipv4, ipv6}
	for _, version := range versions {
		blockCidrs, err := c.blockReaderWriter.getAffineBlocks(hostname, version, nil)
		if err != nil {
			return err
		}

		for _, blockCidr := range blockCidrs {
			err := c.ReleaseAffinity(blockCidr, &hostname)
			if err != nil {
				if _, ok := err.(AffinityClaimedError); ok {
					// Claimed by a different host.
				} else {
					return err
				}
			}
		}
	}
	return nil
}

// ReleasePoolAffinities releases affinity for all blocks within
// the specified pool across all hosts.
func (c IPAMClient) ReleasePoolAffinities(pool net.IPNet) error {
	for i := 0; i < keyErrRetries; i++ {
		retry := false
		pairs, err := c.hostBlockPairs(pool)
		if err != nil {
			return err
		}

		if len(pairs) == 0 {
			log.Println("No blocks have affinity")
			return nil
		}

		for blockString, host := range pairs {
			_, blockCidr, _ := net.ParseCIDR(blockString)
			err = c.blockReaderWriter.releaseBlockAffinity(host, *blockCidr)
			if err != nil {
				log.Printf("Error: %s", err)
				if _, ok := err.(AffinityClaimedError); ok {
					retry = true
				} else if _, ok := err.(NoSuchBlockError); ok {
					continue
				} else {
					return err
				}
			}

		}

		if !retry {
			return nil
		}
	}
	return errors.New("Max retries hit")
}

// RemoveIPAMHost releases affinity for all blocks on the given host,
// and removes all host-specific IPAM data from the datastore.
// RemoveIPAMHost does not release any IP addresses claimed on the given host.
func (c IPAMClient) RemoveIPAMHost(host *string) error {
	// Determine the hostname to use.
	hostname := decideHostname(host)

	// Release host affinities.
	c.ReleaseHostAffinities(&hostname)

	// Remove the host ipam tree.
	key := fmt.Sprintf(ipamHostPath, hostname)
	opts := client.DeleteOptions{Recursive: true}
	_, err := c.blockReaderWriter.etcd.Delete(context.Background(), key, &opts)
	if err != nil {
		if eerr, ok := err.(client.Error); ok && eerr.Code == client.ErrorCodeNodeExist {
			// Already deleted.  Carry on.

		} else {
			return err
		}
	}
	return nil
}

func (c IPAMClient) hostBlockPairs(pool net.IPNet) (map[string]string, error) {
	pairs := map[string]string{}

	opts := client.GetOptions{Quorum: true, Recursive: true}
	res, err := c.blockReaderWriter.etcd.Get(context.Background(), ipamHostsPath, &opts)
	if err != nil {
		return nil, err
	}

	if res.Node != nil {
		for _, n := range leaves(*res.Node) {
			if !n.Dir {
				// Extract the block identifier (subnet) which is encoded
				// into the etcd key.  We need to replace "-" with "/" to
				// turn it back into a cidr.  Also pull out the hostname.
				ss := strings.Split(n.Key, "/")
				ipString := strings.Replace(ss[len(ss)-1], "-", "/", 1)
				pairs[ipString] = ss[5]
			}
		}
	}
	return pairs, nil
}

func leaves(root client.Node) []client.Node {
	l := []client.Node{}
	for _, n := range root.Nodes {
		if !n.Dir {
			l = append(l, *n)
		} else {
			l = append(l, leaves(*n)...)
		}
	}
	return l
}

// IpsByHandle returns a list of all IP addresses that have been
// assigned using the provided handle.
func (c IPAMClient) IpsByHandle(handleID string) ([]net.IP, error) {
	handle, err := c.readHandle(handleID)
	if err != nil {
		return nil, err
	}

	assignments := []net.IP{}
	for k, _ := range handle.Block {
		_, blockCidr, _ := net.ParseCIDR(k)
		b, err := c.blockReaderWriter.readBlock(*blockCidr)
		if err != nil {
			log.Printf("Couldn't read block %s referenced by handle %s", blockCidr, handleID)
			continue
		}
		assignments = append(assignments, b.ipsByHandle(handleID)...)
	}
	return assignments, nil
}

// ReleaseByHandle releases all IP addresses that have been assigned
// using the provided handle.
func (c IPAMClient) ReleaseByHandle(handleID string) error {
	log.Printf("Releasing all IPs with handle '%s'", handleID)
	handle, err := c.readHandle(handleID)
	if err != nil {
		return err
	}

	for blockStr, _ := range handle.Block {
		_, blockCidr, _ := net.ParseCIDR(blockStr)
		err = c.releaseByHandle(handleID, *blockCidr)
	}
	return nil
}

func (c IPAMClient) releaseByHandle(handleID string, blockCidr net.IPNet) error {
	for i := 0; i < etcdRetries; i++ {
		block, err := c.blockReaderWriter.readBlock(blockCidr)
		if err != nil {
			if _, ok := err.(NoSuchBlockError); ok {
				// Block doesn't exist, so all addresses are already
				// unallocated.  This can happen when a handle is
				// overestimating the number of assigned addresses.
				return nil
			} else {
				return err
			}
		}
		num := block.releaseByHandle(handleID)
		if num == 0 {
			// Block has no addresses with this handle, so
			// all addresses are already unallocated.
			return nil
		}

		if block.empty() && block.HostAffinity == nil {
			err = c.blockReaderWriter.deleteBlock(*block)
			if err != nil {
				if eerr, ok := err.(client.Error); ok && eerr.Code == client.ErrorCodeNodeExist {
					// Already deleted - carry on.
				} else {
					return err
				}
			}
		} else {
			err = c.blockReaderWriter.compareAndSwapBlock(*block)
			if err != nil {
				// Failed to update - retry.
				log.Printf("CAS error for block, retry #%d: %s", i, err)
				continue
			}
		}

		c.decrementHandle(handleID, blockCidr, num)
		return nil
	}
	return errors.New("Hit max retries")
}

func (c IPAMClient) readHandle(handleID string) (*allocationHandle, error) {
	key := ipamHandlePath + handleID
	opts := client.GetOptions{Quorum: true}
	resp, err := c.blockReaderWriter.etcd.Get(context.Background(), key, &opts)
	if err != nil {
		log.Println("Error reading IPAM handle:", err)
		return nil, err
	}
	h := allocationHandle{}
	json.Unmarshal([]byte(resp.Node.Value), &h)
	h.DbResult = resp.Node.Value
	return &h, nil
}

func (c IPAMClient) incrementHandle(handleID string, blockCidr net.IPNet, num int) error {
	for i := 0; i < etcdRetries; i++ {
		handle, err := c.readHandle(handleID)
		if err != nil {
			if client.IsKeyNotFound(err) {
				// Handle doesn't exist - create it.
				log.Println("Creating new handle:", handleID)
				handle = &allocationHandle{
					HandleID: handleID,
					Block:    map[string]int{},
				}
			} else {
				// Unexpected error reading handle.
				return err
			}
		}

		// Increment the handle for this block.
		handle.incrementBlock(blockCidr, num)
		err = c.compareAndSwapHandle(*handle)
		if err != nil {
			continue
		}
		return nil
	}
	return errors.New("Max retries hit")

}

func (c IPAMClient) decrementHandle(handleID string, blockCidr net.IPNet, num int) error {
	for i := 0; i < etcdRetries; i++ {
		handle, err := c.readHandle(handleID)
		if err != nil {
			log.Fatal("Can't decrement block because it doesn't exist")
		}

		_, err = handle.decrementBlock(blockCidr, num)
		if err != nil {
			log.Fatal("Can't decrement block - too few allocated")
		}

		err = c.compareAndSwapHandle(*handle)
		if err != nil {
			continue
		}
		log.Printf("Decremented handle '%s' by %d", handleID, num)
		return nil
	}
	return errors.New("Max retries hit")
}

func (c IPAMClient) compareAndSwapHandle(h allocationHandle) error {
	// If the block has a store result, compare and swap agianst that.
	var opts client.SetOptions
	key := ipamHandlePath + h.HandleID

	// Determine correct Set options.
	if h.DbResult != "" {
		if h.empty() {
			// The handle is empty - delete it instead of an update.
			log.Println("CAS delete handle:", h.HandleID)
			deleteOpts := client.DeleteOptions{PrevValue: h.DbResult}
			_, err := c.blockReaderWriter.etcd.Delete(context.Background(),
				key, &deleteOpts)
			return err
		}
		log.Println("CAS update handle:", h.HandleID)
		opts = client.SetOptions{PrevExist: client.PrevExist, PrevValue: h.DbResult}
	} else {
		log.Println("CAS write new handle:", h.HandleID)
		opts = client.SetOptions{PrevExist: client.PrevNoExist}
	}

	j, err := json.Marshal(h)
	if err != nil {
		log.Println("Error converting handle to json:", err)
		return err
	}
	_, err = c.blockReaderWriter.etcd.Set(context.Background(), key, string(j), &opts)
	if err != nil {
		log.Println("CAS error writing json:", err)
		return err
	}

	return nil
}

// GetAssignmentAttributes returns the attributes stored with the given IP address
// upon assignment.
func (c IPAMClient) GetAssignmentAttributes(addr net.IP) (map[string]string, error) {
	blockCidr := getBlockCIDRForAddress(addr)
	block, err := c.blockReaderWriter.readBlock(blockCidr)
	if err != nil {
		log.Printf("Error reading block %s: %s", blockCidr, err)
		return nil, errors.New(fmt.Sprintf("%s is not assigned", addr))
	}
	return block.attributesForIP(addr)
}

func (rw blockReaderWriter) getAffineBlocks(host string, ver ipVersion, pool *net.IPNet) ([]net.IPNet, error) {
	key := fmt.Sprintf(ipamHostAffinityPath, host, ver.Number)
	opts := client.GetOptions{Quorum: true, Recursive: true}
	res, err := rw.etcd.Get(context.Background(), key, &opts)
	if err != nil {
		log.Println("Error reading blocks from etcd", err)
		return nil, err
	}

	ids := []net.IPNet{}
	if res.Node != nil {
		for _, n := range res.Node.Nodes {
			if !n.Dir {
				// Extract the block identifier (subnet) which is encoded
				// into the etcd key.  We need to replace "-" with "/" to
				// turn it back into a cidr.
				ss := strings.Split(n.Key, "/")
				_, id, _ := net.ParseCIDR(strings.Replace(ss[len(ss)-1], "-", "/", 1))
				ids = append(ids, *id)
			}
		}
	}
	return ids, nil
}

func (rw blockReaderWriter) claimNewAffineBlock(
	host string, version ipVersion, pool *net.IPNet, config IPAMConfig) (*net.IPNet, error) {

	// If pool is not nil, use the given pool.  Otherwise, default to
	// all configured pools.
	var pools []net.IPNet
	if pool != nil {
		// TODO: Validate the given pool is actually configured.
		pools = []net.IPNet{*pool}
	} else {
		// TODO: Default to all configured pools.
		_, p, _ := net.ParseCIDR("192.168.0.0/16")
		pools = []net.IPNet{*p}
	}

	// Iterate through pools to find a new block.
	log.Println("Claiming a new affine block for host", host)
	for _, pool := range pools {
		for _, subnet := range blocks(pool) {
			// Check if a block already exists for this subnet.
			key := blockDatastorePath(subnet)
			_, err := rw.etcd.Get(context.Background(), key, nil)
			if client.IsKeyNotFound(err) {
				// The block does not yet exist in etcd.  Try to grab it.
				log.Println("Found free block:", subnet)
				err = rw.claimBlockAffinity(subnet, host, config)
				return &subnet, err
			} else if err != nil {
				log.Println("Error checking block:", err)
				return nil, err
			}
		}
	}
	return nil, NoFreeBlocksError("No Free Blocks")
}

func (rw blockReaderWriter) claimBlockAffinity(subnet net.IPNet, host string, config IPAMConfig) error {
	// Claim the block in etcd.
	log.Printf("Host %s claiming block affinity for %s", host, subnet)
	affinityPath := blockHostAffinityPath(subnet, host)
	rw.etcd.Set(context.Background(), affinityPath, "", nil)

	// Create the new block.
	block := NewBlock(subnet)
	block.HostAffinity = &host
	block.StrictAffinity = config.StrictAffinity

	// Compare and swap the new block.
	err := rw.compareAndSwapBlock(block)
	if err != nil {
		if _, ok := err.(CASError); ok {
			// Block already exists, check affinity.
			log.Println("Error claiming block affinity:", err)
			b, err := rw.readBlock(subnet)
			if err != nil {
				log.Println("Error reading block:", err)
				return err
			}
			if b.HostAffinity != nil && *b.HostAffinity == host {
				// Block has affinity to this host, meaning another
				// process on this host claimed it.
				log.Printf("Block %s already claimed by us.  Success", subnet)
				return nil
			}

			// Some other host beat us to this block.  Cleanup and return error.
			rw.etcd.Delete(context.Background(), affinityPath, &client.DeleteOptions{})
			return &AffinityClaimedError{Block: *b}
		} else {
			return err
		}
	}
	return nil
}

func (rw blockReaderWriter) releaseBlockAffinity(host string, blockCidr net.IPNet) error {
	for i := 0; i < etcdRetries; i++ {
		// Read the block from etcd.
		b, err := rw.readBlock(blockCidr)
		if err != nil {
			return err
		}

		// Check that the block affinity matches the given affinity.
		if b.HostAffinity != nil && *b.HostAffinity != host {
			return AffinityClaimedError{Block: *b}
		}

		if b.empty() {
			// If the block is empty, we can delete it.
			err := rw.deleteBlock(*b)
			if err != nil {
				if eerr, ok := err.(client.Error); ok && eerr.Code == client.ErrorCodeNodeExist {
					// Block already deleted.  Carry on.

				} else {
					log.Printf("Error deleting block: %s", err)
					return err
				}
			}
		} else {
			// Otherwise, we need to remove affinity from it.
			// This prevents the host from automatically assigning
			// from this block unless we're allowed to overflow into
			// non-affine blocks.
			b.HostAffinity = nil
			err = rw.compareAndSwapBlock(*b)
			if err != nil {
				if _, ok := err.(CASError); ok {
					// CASError - continue.
					continue
				} else {
					return err
				}
			}
		}

		// We've removed / updated the block, so update the host config
		// to remove the CIDR.
		key := blockHostAffinityPath(b.Cidr, host)
		_, err = rw.etcd.Delete(context.Background(), key, nil)
		if err != nil {
			if eerr, ok := err.(client.Error); ok && eerr.Code == client.ErrorCodeNodeExist {
				// Already deleted.  Carry on.

			} else {
				return err
			}
		}
		return nil

	}
	return errors.New("Max retries hit")
}

func (rw blockReaderWriter) compareAndSwapBlock(b allocationBlock) error {
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
		if eerr, ok := err.(client.Error); ok && eerr.Code == client.ErrorCodeNodeExist {
			log.Println("CAS error writing block:", err)
			return CASError(fmt.Sprintf("Failed to write block %s", b.Cidr))
		} else {
			return err
		}
	}

	return nil
}

func (rw blockReaderWriter) deleteBlock(b allocationBlock) error {
	opts := client.DeleteOptions{PrevValue: b.DbResult}
	key := blockDatastorePath(b.Cidr)
	_, err := rw.etcd.Delete(context.Background(), key, &opts)
	return err
}

func (rw blockReaderWriter) readBlock(blockCidr net.IPNet) (*allocationBlock, error) {
	key := blockDatastorePath(blockCidr)
	opts := client.GetOptions{Quorum: true}
	resp, err := rw.etcd.Get(context.Background(), key, &opts)
	if err != nil {
		log.Println("Error reading IPAM block:", err)
		if client.IsKeyNotFound(err) {
			return nil, NoSuchBlockError{Cidr: blockCidr}
		}
		return nil, err
	}
	b := NewBlock(blockCidr)
	json.Unmarshal([]byte(resp.Node.Value), &b)
	b.DbResult = resp.Node.Value
	return &b, nil
}

func (rw blockReaderWriter) readAllBlocks() ([]allocationBlock, []allocationBlock, error) {
	blocks := map[int][]allocationBlock{
		ipv4.Number: []allocationBlock{},
		ipv6.Number: []allocationBlock{},
	}

	opts := client.GetOptions{Quorum: true}
	for _, version := range []ipVersion{ipv4, ipv6} {
		key := fmt.Sprintf(ipamBlockPath, version.Number)
		resp, err := rw.etcd.Get(context.Background(), key, &opts)
		if err != nil {
			log.Println("Error reading IPAM blocks:", err)
			return nil, nil, err
		}

		for _, node := range resp.Node.Nodes {
			if node.Value != "" {
				b := allocationBlock{}
				json.Unmarshal([]byte(resp.Node.Value), &b)
				b.DbResult = node.Value
				blocks[version.Number] = append(blocks[version.Number], b)
			}
		}
	}
	return blocks[ipv4.Number], blocks[ipv6.Number], nil
}

// GetIPAMConfig returns the global IPAM configuration.  If no IPAM configuration
// has been set, returns a default configuration with StrictAffinity disabled
// and AutoAllocateBlocks enabled.
func (c IPAMClient) GetIPAMConfig() (*IPAMConfig, error) {
	opts := client.GetOptions{Quorum: true}
	resp, err := c.blockReaderWriter.etcd.Get(context.Background(), ipamConfigPath, &opts)
	if err != nil {
		if client.IsKeyNotFound(err) {
			cfg := IPAMConfig{
				StrictAffinity:     false,
				AutoAllocateBlocks: true,
			}
			return &cfg, nil
		} else {
			log.Println("Error reading IPAM config:", err)
			return nil, err
		}
	}
	cfg := IPAMConfig{}
	json.Unmarshal([]byte(resp.Node.Value), &cfg)
	return &cfg, nil
}

// SetIPAMConfig sets global IPAM configuration.  This can only
// be done when there are no allocated blocks and IP addresses.
func (c IPAMClient) SetIPAMConfig(cfg IPAMConfig) error {
	current, err := c.GetIPAMConfig()
	if err != nil {
		return err
	}

	if *current == cfg {
		return nil
	}

	if cfg.StrictAffinity && !cfg.AutoAllocateBlocks {
		return errors.New("Cannot disable 'StrictAffinity' and 'AutoAllocateBlocks' at the same time")
	}

	v4Blocks, v6Blocks, err := c.blockReaderWriter.readAllBlocks()
	if len(v4Blocks) != 0 && len(v6Blocks) != 0 {
		log.Printf("V4: %s, V6: %s", v4Blocks, v6Blocks)
		return errors.New("Cannot change IPAM config while allocations exist")
	}

	// Write to etcd.
	j, err := json.Marshal(c)
	if err != nil {
		log.Println("Error converting IPAM config to json:", err)
		return err
	}
	_, err = c.blockReaderWriter.etcd.Set(context.Background(), ipamConfigPath, string(j), nil)
	return nil
}

// IPAMClient is a client which can be used to configure global IPAM configuration,
// IP allocations, and affinities.
type IPAMClient struct {
	blockReaderWriter blockReaderWriter
}

// TODO: Reorganize where this lives.
type blockReaderWriter struct {
	etcd client.KeysAPI
}

// Creates a new IPAMClient.
func NewIPAMClient() (*IPAMClient, error) {
	// Create the interface into etcd for blocks.
	log.Println("Creating new IPAM client")
	config := client.Config{
		// TODO: Make this configurable.
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
	b := blockReaderWriter{etcd: api}

	return &IPAMClient{blockReaderWriter: b}, nil
}

// Return the list of block CIDRs which fall within
// the given pool.
func blocks(pool net.IPNet) []net.IPNet {
	// Determine the IP type to use.
	ipVersion := getIPVersion(pool.IP)
	nets := []net.IPNet{}
	ip := pool.IP
	for pool.Contains(ip) {
		nets = append(nets, net.IPNet{ip, ipVersion.BlockPrefixMask})
		ip = incrementIP(ip, BLOCK_SIZE)
	}
	return nets
}

func blockDatastorePath(blockCidr net.IPNet) string {
	version := getIPVersion(blockCidr.IP)
	path := fmt.Sprintf(ipamBlockPath, version.Number)
	return path + strings.Replace(blockCidr.String(), "/", "-", 1)
}

func blockHostAffinityPath(blockCidr net.IPNet, host string) string {
	version := getIPVersion(blockCidr.IP)
	path := fmt.Sprintf(ipamHostAffinityPath, host, version.Number)
	return path + strings.Replace(blockCidr.String(), "/", "-", 1)
}

func decideHostname(host *string) string {
	// Determine the hostname to use - prefer the provided hostname if
	// non-nil, otherwise use the hostname reported by os.
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
	return hostname
}

// AffinityClaimedError indicates that a given block has already
// been claimed by another host.
type AffinityClaimedError struct {
	Block allocationBlock
}

func (e AffinityClaimedError) Error() string {
	return fmt.Sprintf("Block %s already claimed by %s", e.Block.Cidr, e.Block.HostAffinity)
}

// CASError incidates an error performing a compare-and-swap atomic update.
type CASError string

func (e CASError) Error() string {
	return string(e)
}

// NoFreeBlocksError indicates that the user tried to claim a block
// but there are none available.
type NoFreeBlocksError string

func (e NoFreeBlocksError) Error() string {
	return string(e)
}

// IPAMConfigConflictError indicates an attempt to change IPAM configuration
// that conflicts with existing allocations.
type IPAMConfigConflictError string

func (e IPAMConfigConflictError) Error() string {
	return string(e)
}

// NoSuchBlock error indicates that the requested block does not exist.
type NoSuchBlockError struct {
	Cidr net.IPNet
}

func (e NoSuchBlockError) Error() string {
	return fmt.Sprintf("No such block: %s", e.Cidr)
}

// InvalidBlockSizeError indicates that the requested block size does not match
// the expected block size.
type InvalidBlockSizeError string

func (e InvalidBlockSizeError) Error() string {
	return string(e)
}
