package main

import (
	"fmt"
	"github.com/projectcalico/libcalico/lib/ipam"
	"net"
)

func main() {
	c, err := ipam.NewIPAMClient()
	if err != nil {
		fmt.Printf("Error creating client: %s\n", err)
		return
	}

	// Release all affinities with pool.
	_, pool, _ := net.ParseCIDR("192.168.0.0/16")
	fmt.Println("Claiming Pool:", pool)
	err = c.ClaimAffinity(*pool, nil)
	if err != nil {
		fmt.Printf("Error: %s\n\n", err)
		return
	}

	//fmt.Println("Releasing Pool")
	//err = c.ReleasePoolAffinities(*pool)
	err = c.RemoveIPAMHost(nil)
	if err != nil {
		fmt.Printf("Error: %s\n\n", err)
		return
	}

	// Set up config.
	//err = cfg(c)
	//if err != nil {
	//	fmt.Printf("Error: %s\n\n", err)
	//	return
	//}

	//// Perform AutoAssign test.
	////err = auto(c)
	//if err != nil {
	//	fmt.Printf("Error: %s\n\n", err)
	//	return
	//}

	//// Cleanup.
	////err = c.ReleaseByHandle("handleID")
	//if err != nil {
	//	fmt.Printf("Error: %s\n\n", err)
	//}

	//// Peform assignment test.
	//err = assn(c)
	//if err != nil {
	//	fmt.Printf("Error: %s\n\n", err)
	//	return
	//}

}

func cfg(c *ipam.IPAMClient) error {
	cfg, err := c.GetIPAMConfig()
	fmt.Printf("First IPAM Config: %+v\n", cfg)
	if err != nil {
		return err
	}

	cfg.AutoAllocateBlocks = false
	cfg.StrictAffinity = false

	fmt.Printf("Setting to: %+v\n", cfg)
	err = c.SetIPAMConfig(*cfg)
	if err != nil {
		return err
	}

	cfg, err = c.GetIPAMConfig()
	if err != nil {
		return err
	}

	fmt.Printf("Re-read: %+v\n", cfg)
	return nil
}

func assn(c *ipam.IPAMClient) error {
	// Arguments.
	args := ipam.AssignIPArgs{IP: net.ParseIP("192.168.0.2")}

	// Assign.
	c.AssignIP(args)

	// Release.
	c.ReleaseIPs([]net.IP{args.IP})
	//attrs := map[string]string{"attr1": "value", "attr2": "value2"}
	//unall, err := c.ReleaseIPs([]net.IP{net.ParseIP("192.168.0.2")})
	//c.ReleaseIPs([]net.IP{net.ParseIP("192.168.0.6")})
	//back, err := c.GetAssignmentAttributes(net.ParseIP("192.168.0.2"))
	//c.ReleaseByHandle("handleID")
	//fmt.Printf("Unallocated: %s, Error? %s\n", unall, err)
	//fmt.Println(back, err)
	//return err
	return nil
}

func auto(c *ipam.IPAMClient) error {
	handleId := "handleID"
	args := ipam.AutoAssignArgs{Num4: 1, HandleID: &handleId}
	v4, v6, err2 := c.AutoAssign(args)
	if err2 != nil {
		fmt.Printf("Error assigning addresses: %s\n", err2)
		return err2
	}
	fmt.Printf("Assigned addresses: %s ... %s\n", v4, v6)
	return nil
}
