package ipam

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"reflect"
)

const (
	BLOCK_SIZE = 64
)

type IPVersion struct {
	Number            int
	TotalBits         int
	BlockPrefixLength int
	BlockPrefixMask   net.IPMask
}

var IPv4 IPVersion = IPVersion{
	Number:            4,
	TotalBits:         32,
	BlockPrefixLength: 26,
	BlockPrefixMask:   net.CIDRMask(26, 32),
}

var IPv6 IPVersion = IPVersion{
	Number:            6,
	TotalBits:         128,
	BlockPrefixLength: 122,
	BlockPrefixMask:   net.CIDRMask(122, 128),
}

type AllocationBlock struct {
	Cidr           net.IPNet             `json:"-"`
	DbResult       string                `json:"-"`
	HostAffinity   *string               `json:"hostAffinity"`
	StrictAffinity bool                  `json:"strictAffinity"`
	Allocations    []*int                `json:"allocations"`
	Unallocated    []int                 `json:"unallocated"`
	Attributes     []AllocationAttribute `json:"attributes"`
}

type AllocationAttribute struct {
	AttrPrimary   *string           `json:"handle_id"`
	AttrSecondary map[string]string `json:"secondary"`
}

func NewBlock(cidr net.IPNet) AllocationBlock {
	b := AllocationBlock{}
	b.Allocations = make([]*int, BLOCK_SIZE)
	b.Unallocated = make([]int, BLOCK_SIZE)
	b.StrictAffinity = false
	b.Cidr = cidr

	// Initialize unallocated ordinals.
	for i := 0; i < BLOCK_SIZE; i++ {
		b.Unallocated[i] = i
	}

	return b
}

func (b *AllocationBlock) AutoAssign(
	num int, handleID *string, host string, attrs map[string]string, affinityCheck bool) ([]net.IP, error) {

	// Determine if we need to check for affinity.
	checkAffinity := b.StrictAffinity || affinityCheck
	if checkAffinity && b.HostAffinity != nil && host != *b.HostAffinity {
		// Affinity check is enabled but the host does not match - error.
		s := fmt.Sprintf("Block affinity (%s) does not match provided (%s)", b.HostAffinity, host)
		return nil, errors.New(s)
	}

	// Walk the allocations until we find enough addresses.
	ordinals := []int{}
	for len(b.Unallocated) > 0 && len(ordinals) < num {
		ordinals = append(ordinals, b.Unallocated[0])
		b.Unallocated = b.Unallocated[1:]
	}

	// Create slice of IPs and perform the allocations.
	ips := []net.IP{}
	for _, o := range ordinals {
		attrIndex := b.FindOrAddAttribute(handleID, attrs)
		b.Allocations[o] = &attrIndex
		ips = append(ips, IncrementIP(b.Cidr.IP, o))
	}
	return ips, nil
}

func (b *AllocationBlock) Assign(address net.IP, handleID *string, attrs map[string]string, host string) error {
	if b.StrictAffinity && b.HostAffinity != nil && host != *b.HostAffinity {
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
	attrIndex := b.FindOrAddAttribute(handleID, attrs)
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

func (b AllocationBlock) NumFreeAddresses() int {
	return len(b.Unallocated)
}

func (b AllocationBlock) Empty() bool {
	return b.NumFreeAddresses() == BLOCK_SIZE
}

func (b *AllocationBlock) Release(addresses []net.IP) ([]net.IP, map[string]int, error) {
	// Store return values.
	unallocated := []net.IP{}
	countByHandle := map[string]int{}

	// Used internally.
	var ordinals []int
	delRefCounts := map[int]int{}
	attrsToDelete := []int{}

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
			continue
		}
		ordinals = append(ordinals, ordinal)

		// Increment referece counting for attributes.
		cnt := 1
		if cur, exists := delRefCounts[*attrIdx]; exists {
			cnt = cur + 1
		}
		delRefCounts[*attrIdx] = cnt

		// Increment count of addresses by handle if a handle
		// exists.
		handleID := b.Attributes[*attrIdx].AttrPrimary
		if handleID != nil {
			handleCount := 0
			if count, ok := countByHandle[*handleID]; !ok {
				handleCount = count
			}
			handleCount += 1
			countByHandle[*handleID] = handleCount
		}
	}

	// Handle cleaning up of attributes.  We do this by
	// reference counting.  If we're deleting the last reference to
	// a given attribute, then it needs to be cleaned up.
	refCounts := b.attributeRefCounts()
	for idx, refs := range delRefCounts {
		if refCounts[idx] == refs {
			attrsToDelete = append(attrsToDelete, idx)
		}
	}
	if len(attrsToDelete) != 0 {
		log.Printf("Deleting attributes: %s", attrsToDelete)
		b.deleteAttributes(attrsToDelete, ordinals)
	}

	// Release requested addresses.
	for _, ordinal := range ordinals {
		b.Allocations[ordinal] = nil
		b.Unallocated = append(b.Unallocated, ordinal)
	}
	return unallocated, countByHandle, nil
}

func (b *AllocationBlock) deleteAttributes(delIndexes, ordinals []int) {
	newIndexes := make([]*int, len(b.Attributes))
	newAttrs := []AllocationAttribute{}
	y := 0 // Next free slot in the new attributes list.
	for x := range b.Attributes {
		if !IntInSlice(x, delIndexes) {
			log.Printf("%d in %s", x, delIndexes)
			// Attribute at x is not being deleted.  Build a mapping
			// of old attribute index (x) to new attribute index (y).
			newIndex := y
			newIndexes[x] = &newIndex
			y += 1
			newAttrs = append(newAttrs, b.Attributes[x])
		}
	}
	b.Attributes = newAttrs

	// Update attribute indexes for all allocations in this block.
	for i := 0; i < BLOCK_SIZE; i++ {
		if b.Allocations[i] != nil {
			// Get the new index that corresponds to the old index
			// and update the allocation.
			newIndex := newIndexes[*b.Allocations[i]]
			b.Allocations[i] = newIndex
		}
	}
}

func (b AllocationBlock) attributeRefCounts() map[int]int {
	refCounts := map[int]int{}
	for _, a := range b.Allocations {
		if a == nil {
			continue
		}

		if count, ok := refCounts[*a]; !ok {
			// No entry for given attribute index.
			refCounts[*a] = 1
		} else {
			refCounts[*a] = count + 1
		}
	}
	return refCounts
}

func (b AllocationBlock) attributeIndexesByHandle(handleID string) []int {
	indexes := []int{}
	for i, attr := range b.Attributes {
		if attr.AttrPrimary != nil && *attr.AttrPrimary == handleID {
			indexes = append(indexes, i)
		}
	}
	return indexes
}

func (b *AllocationBlock) ReleaseByHandle(handleID string) int {
	attrIndexes := b.attributeIndexesByHandle(handleID)
	log.Println("Attribute indexes to release:", attrIndexes)
	if len(attrIndexes) == 0 {
		// Nothing to release.
		log.Println("No addresses assigned to handle", handleID)
		return 0
	}

	// There are addresses to release.
	ordinals := []int{}
	var o int
	for o = 0; o < BLOCK_SIZE; o++ {
		// Only check allocated ordinals.
		if b.Allocations[o] != nil && IntInSlice(*b.Allocations[o], attrIndexes) {
			// Release this ordinal.
			ordinals = append(ordinals, o)
		}
	}

	// Clean and reorder attributes.
	b.deleteAttributes(attrIndexes, ordinals)

	// Release the addresses.
	for _, o := range ordinals {
		b.Allocations[o] = nil
		b.Unallocated = append(b.Unallocated, o)
	}
	return len(ordinals)
}

func (b AllocationBlock) IPsByHandle(handleID string) []net.IP {
	ips := []net.IP{}
	attrIndexes := b.attributeIndexesByHandle(handleID)
	var o int
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

func (b *AllocationBlock) FindOrAddAttribute(handleID *string, attrs map[string]string) int {
	attr := AllocationAttribute{handleID, attrs}
	for idx, existing := range b.Attributes {
		if reflect.DeepEqual(attr, existing) {
			log.Println("Attribute already exists")
			return idx
		}
	}

	// Does not exist - add it.
	log.Println("New attribute", attr)
	attrIndex := len(b.Attributes)
	b.Attributes = append(b.Attributes, attr)
	return attrIndex
}

func GetBlockCIDRForAddress(addr net.IP) net.IPNet {
	var mask net.IPMask
	if addr.To4() == nil {
		// This is an IPv6 address.
		mask = IPv6.BlockPrefixMask
	} else {
		// This is an IPv4 address.
		mask = IPv4.BlockPrefixMask
	}
	masked := addr.Mask(mask)
	return net.IPNet{IP: masked, Mask: mask}
}

func GetIPVersion(ip net.IP) IPVersion {
	if ip.To4() == nil {
		return IPv6
	}
	return IPv4
}

func LargerThanBlock(blockCidr net.IPNet) bool {
	ones, bits := blockCidr.Mask.Size()
	prefixLength := bits - ones
	ipVersion := GetIPVersion(blockCidr.IP)
	return prefixLength < ipVersion.BlockPrefixLength
}

func IntInSlice(searchInt int, slice []int) bool {
	for _, v := range slice {
		if v == searchInt {
			return true
		}
	}
	return false
}

func IPToInt(ip net.IP) *big.Int {
	if ip.To4() != nil {
		return big.NewInt(0).SetBytes(ip.To4())
	} else {
		return big.NewInt(0).SetBytes(ip.To16())
	}
}

func IntToIP(ipInt *big.Int) net.IP {
	ip := net.IP(ipInt.Bytes())
	return ip
}

func IncrementIP(ip net.IP, increment int) net.IP {
	sum := big.NewInt(0).Add(IPToInt(ip), big.NewInt(int64(increment)))
	return IntToIP(sum)
}

func IPToOrdinal(ip net.IP, b AllocationBlock) int {
	ip_int := IPToInt(ip)
	base_int := IPToInt(b.Cidr.IP)
	ord := big.NewInt(0).Sub(ip_int, base_int).Int64()
	if ord < 0 || ord >= BLOCK_SIZE {
		// IP address not in the given block.
		log.Fatalf("IP %s not in block %s", ip, b.Cidr)
	}
	return int(ord)
}

func OrdinalToIP(ord int, b AllocationBlock) net.IP {
	sum := big.NewInt(0).Add(IPToInt(b.Cidr.IP), big.NewInt(int64(ord)))
	return IntToIP(sum)
}
