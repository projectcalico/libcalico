package ipam

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"reflect"
)

const (
	BLOCK_SIZE_BITS = 6
	BLOCK_SIZE      = 64 // 2**BLOCK_SIZE_BITS
	CIDR            = "cidr"
	AFFINITY        = "affinity"
	HOST_AFFINITY_T = "host:%s"
	ALLOCATIONS     = "allocations"
	UNALLOCATED     = "unallocated"
	STRICT_AFFINITY = "strict_affinity"
	ATTRIBUTES      = "attributes"
	ATTR_HANDLE_ID  = "handle_id"
	ATTR_SECONDARY  = "secondary"
)

type AllocationBlock struct {
	Cidr           net.IP                `json:"-"`
	DbResult       string                `json:"-"`
	HostAffinity   string                `json:"hostAffinity"`
	StrictAffinity bool                  `json:"strictAffinity"`
	Allocations    []*int64              `json:"allocations"`
	Unallocated    []int64               `json:"unallocated"`
	Attributes     []AllocationAttribute `json:"attributes"`
}

type AllocationAttribute struct {
	AttrPrimary   string
	AttrSecondary map[string]string
}

func NewBlock(cidr net.IP) AllocationBlock {
	block := AllocationBlock{}
	block.Allocations = make([]*int64, BLOCK_SIZE)
	block.Unallocated = make([]int64, BLOCK_SIZE)
	block.HostAffinity = ""
	block.StrictAffinity = false
	block.Cidr = cidr

	// Initialize unallocated ordinals.
	for i := 0; i < BLOCK_SIZE; i++ {
		block.Unallocated[i] = int64(i)
	}

	return block
}

func IpToInt(ip net.IP) int64 {
	return int64(binary.BigEndian.Uint32(ip.To4()))
}

func IntToIp(ipInt int64) net.IP {
	ipByte := make([]byte, 4)
	binary.BigEndian.PutUint32(ipByte, uint32(ipInt))
	ip := net.IP(ipByte)
	return ip
}

func IncrementIp(ip net.IP, increment int64) net.IP {
	return IntToIp(IpToInt(ip) + increment)
}

func IpToOrdinal(ip net.IP, block AllocationBlock) int64 {
	ip_int := IpToInt(ip)
	base_int := IpToInt(block.Cidr)
	return ip_int - base_int
}

func OrdinalToIp(ordinal int64, block AllocationBlock) net.IP {
	return IntToIp(IpToInt(block.Cidr) + ordinal)
}

func (block *AllocationBlock) AutoAssign(num int64, handleId string, host string,
	attributes map[string]string, affinity_check bool) ([]net.IP, error) {
	// Determine if we need to check for affinity.
	checkAffinity := block.StrictAffinity || affinity_check
	if checkAffinity && host != block.HostAffinity {
		// Affinity check is enabled but the host does not match - error.
		return nil, errors.New("Block host affinity does not match")
	}

	// Walk the allocations until we find enough addresses.
	ordinals := []int64{}
	for len(block.Unallocated) > 0 && int64(len(ordinals)) < num {
		ordinals = append(ordinals, block.Unallocated[0])
		block.Unallocated = block.Unallocated[1:]
	}

	// Create slice of IPs and perform the allocations.
	ips := []net.IP{}
	for _, o := range ordinals {
		attrIndex := block.FindOrAddAttribute(handleId, attributes)
		block.Allocations[o] = &attrIndex
		ips = append(ips, IncrementIp(block.Cidr, o))
	}
	return ips, nil
}

func (block *AllocationBlock) Assign(address net.IP, handleId string, attributes map[string]string, host string) error {
	if block.StrictAffinity && host != block.HostAffinity {
		// Affinity check is enabled but the host does not match - error.
		return errors.New("Block host affinity does not match")
	}

	// Convert to an ordinal.
	ordinal := IpToOrdinal(address, *block)
	if (ordinal < 0) || (ordinal > BLOCK_SIZE) {
		return errors.New("IP address not in block")
	}

	// Check if already allocated.
	if block.Allocations[ordinal] != nil {
		return errors.New("Address already assigned in block")
	}

	// Set up attributes.
	attrIndex := block.FindOrAddAttribute(handleId, attributes)
	block.Allocations[ordinal] = &attrIndex

	// Remove from unallocated.
	for i, unallocated := range block.Unallocated {
		if unallocated == ordinal {
			block.Unallocated = append(block.Unallocated[:i], block.Unallocated[i+1:]...)
			break
		}
	}
	return nil
}

func (block AllocationBlock) NumFreeAddresses() int64 {
	return int64(len(block.Unallocated))
}

func (block AllocationBlock) Empty() bool {
	return block.NumFreeAddresses() == BLOCK_SIZE
}

func (block *AllocationBlock) Release(addresses []net.IP) ([]net.IP, map[string]int64, error) {
	// Store return values.
	unallocated := []net.IP{}
	count_by_handle := map[string]int64{}

	// Used internally.
	var ordinals []int64

	// Determine the ordinals that need to be released and the
	// attributes that need to be cleaned up.
	for _, ip := range addresses {
		// Convert to an ordinal.
		ordinal := IpToOrdinal(ip, *block)
		if (ordinal < 0) || (ordinal > BLOCK_SIZE) {
			return nil, nil, errors.New("IP address not in block")
		}

		// Check if allocated.
		attrIdx := block.Allocations[ordinal]
		if attrIdx == nil {
			log.Println("Asked to release address that was not allocated")
			unallocated = append(unallocated, ip)
		}
		ordinals = append(ordinals, ordinal)

		// TODO: Handle cleaning up of attributes.
	}

	// Release requested addresses.
	for _, ordinal := range ordinals {
		block.Allocations[ordinal] = nil
		block.Unallocated = append(block.Unallocated, ordinal)
	}
	return unallocated, count_by_handle, nil
}

func (block AllocationBlock) attributeIndexesByHandle(handleId string) []int64 {
	indexes := []int64{}
	for i, attr := range block.Attributes {
		if attr.AttrPrimary == handleId {
			indexes = append(indexes, int64(i))
		}
	}
	return indexes
}

func (block *AllocationBlock) ReleaseByHandle(handleId string) int64 {
	attrIndexes := block.attributeIndexesByHandle(handleId)
	log.Println("Attribute indexes to release:", attrIndexes)
	if len(attrIndexes) == 0 {
		// Nothing to release.
		log.Println("No addresses assigned to handle", handleId)
		return 0
	}

	// There are addresses to release.
	ordinals := []int64{}
	var o int64
	for o = 0; o < BLOCK_SIZE; o++ {
		// Only check allocated ordinals.
		if block.Allocations[o] != nil && IntInSlice(*block.Allocations[o], attrIndexes) {
			// Release this ordinal.
			ordinals = append(ordinals, o)
		}
	}

	// TODO: Clean and reorder attributes.

	// Release the addresses.
	for _, o := range ordinals {
		block.Allocations[o] = nil
		block.Unallocated = append(block.Unallocated, o)
	}
	return int64(len(ordinals))
}

func (block AllocationBlock) IpsByHandle(handleId string) []net.IP {
	ips := []net.IP{}
	attrIndexes := block.attributeIndexesByHandle(handleId)
	var o int64
	for o = 0; o < BLOCK_SIZE; o++ {
		if IntInSlice(*block.Allocations[o], attrIndexes) {
			ip := OrdinalToIp(o, block)
			ips = append(ips, ip)
		}
	}
	return ips
}

func (block AllocationBlock) AttributesForIp(ip net.IP) (*AllocationAttribute, error) {
	// Convert to an ordinal.
	ordinal := IpToOrdinal(ip, block)
	if (ordinal < 0) || (ordinal > BLOCK_SIZE) {
		return nil, errors.New("IP address not in block")
	}

	// Check if allocated.
	attrIndex := block.Allocations[ordinal]
	if attrIndex == nil {
		return nil, errors.New("IP address is not assigned in block")
	}
	return &block.Attributes[*attrIndex], nil
}

func (block *AllocationBlock) FindOrAddAttribute(handleId string, attributes map[string]string) int64 {
	attr := AllocationAttribute{handleId, attributes}
	for idx, existing := range block.Attributes {
		if reflect.DeepEqual(attr, existing) {
			log.Println("Attribute already exists")
			return int64(idx)
		}
	}

	// Does not exist - add it.
	log.Println("New attribute", attr)
	attrIndex := len(block.Attributes)
	block.Attributes = append(block.Attributes, attr)
	return int64(attrIndex)
}

func IntInSlice(searchInt int64, slice []int64) bool {
	for _, v := range slice {
		if v == searchInt {
			return true
		}
	}
	return false
}
