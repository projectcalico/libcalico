package ipam

import (
	"fmt"
	"net"
)

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
