package ipam

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"reflect"
)

const (
	BLOCK_PREFIX_LEN_4 = 26
	BLOCK_SIZE_BITS    = 6
	BLOCK_SIZE         = 64 // 2**BLOCK_SIZE_BITS
	CIDR               = "cidr"
	AFFINITY           = "affinity"
	HOST_AFFINITY_T    = "host:%s"
	ALLOCATIONS        = "allocations"
	UNALLOCATED        = "unallocated"
	STRICT_AFFINITY    = "strict_affinity"
	ATTRIBUTES         = "attributes"
	ATTR_HANDLE_ID     = "handle_id"
	ATTR_SECONDARY     = "secondary"
)

type AllocationBlock struct {
	Cidr           net.IPNet             `json:"-"`
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

func NewBlock(cidr net.IPNet) AllocationBlock {
	b := AllocationBlock{}
	b.Allocations = make([]*int64, BLOCK_SIZE)
	b.Unallocated = make([]int64, BLOCK_SIZE)
	b.HostAffinity = ""
	b.StrictAffinity = false
	b.Cidr = cidr

	// Initialize unallocated ordinals.
	for i := 0; i < BLOCK_SIZE; i++ {
		b.Unallocated[i] = int64(i)
	}

	return b
}

func IPToInt(ip net.IP) int64 {
	return int64(binary.BigEndian.Uint32(ip.To4()))
}

func IntToIP(ipInt int64) net.IP {
	ipByte := make([]byte, 4)
	binary.BigEndian.PutUint32(ipByte, uint32(ipInt))
	ip := net.IP(ipByte)
	return ip
}

func IncrementIP(ip net.IP, increment int64) net.IP {
	return IntToIP(IPToInt(ip) + increment)
}

func IPToOrdinal(ip net.IP, b AllocationBlock) int64 {
	ip_int := IPToInt(ip)
	base_int := IPToInt(b.Cidr.IP)
	return ip_int - base_int
}

func OrdinalToIP(ord int64, b AllocationBlock) net.IP {
	return IntToIP(IPToInt(b.Cidr.IP) + ord)
}

func (b *AllocationBlock) AutoAssign(
	num int64, handleId string, host string, attrs map[string]string, affinityCheck bool) ([]net.IP, error) {

	// Determine if we need to check for affinity.
	checkAffinity := b.StrictAffinity || affinityCheck
	if checkAffinity && host != b.HostAffinity {
		// Affinity check is enabled but the host does not match - error.
		s := fmt.Sprintf("Block affinity (%s) does not match provided (%s)", b.HostAffinity, host)
		return nil, errors.New(s)
	}

	// Walk the allocations until we find enough addresses.
	ordinals := []int64{}
	for len(b.Unallocated) > 0 && int64(len(ordinals)) < num {
		ordinals = append(ordinals, b.Unallocated[0])
		b.Unallocated = b.Unallocated[1:]
	}

	// Create slice of IPs and perform the allocations.
	ips := []net.IP{}
	for _, o := range ordinals {
		attrIndex := b.FindOrAddAttribute(handleId, attrs)
		b.Allocations[o] = &attrIndex
		ips = append(ips, IncrementIP(b.Cidr.IP, o))
	}
	return ips, nil
}

func (b *AllocationBlock) Assign(address net.IP, handleId string, attrs map[string]string, host string) error {
	if b.StrictAffinity && host != b.HostAffinity {
		// Affinity check is enabled but the host does not match - error.
		return errors.New("Block host affinity does not match")
	}

	// Convert to an ordinal.
	ordinal := IPToOrdinal(address, *b)
	if (ordinal < 0) || (ordinal > BLOCK_SIZE) {
		return errors.New("IP address not in block")
	}

	// Check if already allocated.
	if b.Allocations[ordinal] != nil {
		return errors.New("Address already assigned in block")
	}

	// Set up attributes.
	attrIndex := b.FindOrAddAttribute(handleId, attrs)
	b.Allocations[ordinal] = &attrIndex

	// Remove from unallocated.
	for i, unallocated := range b.Unallocated {
		if unallocated == ordinal {
			b.Unallocated = append(b.Unallocated[:i], b.Unallocated[i+1:]...)
			break
		}
	}
	return nil
}

func (b AllocationBlock) NumFreeAddresses() int64 {
	return int64(len(b.Unallocated))
}

func (b AllocationBlock) Empty() bool {
	return b.NumFreeAddresses() == BLOCK_SIZE
}

func (b *AllocationBlock) Release(addresses []net.IP) ([]net.IP, map[string]int64, error) {
	// Store return values.
	unallocated := []net.IP{}
	count_by_handle := map[string]int64{}

	// Used internally.
	var ordinals []int64

	// Determine the ordinals that need to be released and the
	// attributes that need to be cleaned up.
	for _, ip := range addresses {
		// Convert to an ordinal.
		ordinal := IPToOrdinal(ip, *b)
		if (ordinal < 0) || (ordinal > BLOCK_SIZE) {
			return nil, nil, errors.New("IP address not in block")
		}

		// Check if allocated.
		attrIdx := b.Allocations[ordinal]
		if attrIdx == nil {
			log.Println("Asked to release address that was not allocated")
			unallocated = append(unallocated, ip)
		}
		ordinals = append(ordinals, ordinal)

		// TODO: Handle cleaning up of attributes.
	}

	// Release requested addresses.
	for _, ordinal := range ordinals {
		b.Allocations[ordinal] = nil
		b.Unallocated = append(b.Unallocated, ordinal)
	}
	return unallocated, count_by_handle, nil
}

func (b AllocationBlock) attributeIndexesByHandle(handleId string) []int64 {
	indexes := []int64{}
	for i, attr := range b.Attributes {
		if attr.AttrPrimary == handleId {
			indexes = append(indexes, int64(i))
		}
	}
	return indexes
}

func (b *AllocationBlock) ReleaseByHandle(handleId string) int64 {
	attrIndexes := b.attributeIndexesByHandle(handleId)
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
		if b.Allocations[o] != nil && IntInSlice(*b.Allocations[o], attrIndexes) {
			// Release this ordinal.
			ordinals = append(ordinals, o)
		}
	}

	// TODO: Clean and reorder attributes.

	// Release the addresses.
	for _, o := range ordinals {
		b.Allocations[o] = nil
		b.Unallocated = append(b.Unallocated, o)
	}
	return int64(len(ordinals))
}

func (b AllocationBlock) IPsByHandle(handleId string) []net.IP {
	ips := []net.IP{}
	attrIndexes := b.attributeIndexesByHandle(handleId)
	var o int64
	for o = 0; o < BLOCK_SIZE; o++ {
		if IntInSlice(*b.Allocations[o], attrIndexes) {
			ip := OrdinalToIP(o, b)
			ips = append(ips, ip)
		}
	}
	return ips
}

func (b AllocationBlock) AttributesForIP(ip net.IP) (*AllocationAttribute, error) {
	// Convert to an ordinal.
	ordinal := IPToOrdinal(ip, b)
	if (ordinal < 0) || (ordinal > BLOCK_SIZE) {
		return nil, errors.New("IP address not in block")
	}

	// Check if allocated.
	attrIndex := b.Allocations[ordinal]
	if attrIndex == nil {
		return nil, errors.New("IP address is not assigned in block")
	}
	return &b.Attributes[*attrIndex], nil
}

func (b *AllocationBlock) FindOrAddAttribute(handleId string, attrs map[string]string) int64 {
	attr := AllocationAttribute{handleId, attrs}
	for idx, existing := range b.Attributes {
		if reflect.DeepEqual(attr, existing) {
			log.Println("Attribute already exists")
			return int64(idx)
		}
	}

	// Does not exist - add it.
	log.Println("New attribute", attr)
	attrIndex := len(b.Attributes)
	b.Attributes = append(b.Attributes, attr)
	return int64(attrIndex)
}

func GetBlockCIDRForAddress(addr net.IP) net.IPNet {
	// TODO: Support v6
	mask := net.CIDRMask(26, 32)
	masked := addr.Mask(mask)
	return net.IPNet{IP: masked, Mask: mask}
}

func IntInSlice(searchInt int64, slice []int64) bool {
	for _, v := range slice {
		if v == searchInt {
			return true
		}
	}
	return false
}
