package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jondot/arper"
)

var timeout = flag.Uint("timeout", 10, "Timeout in seconds")
var verbose = flag.Bool("verbose", false, "Verbose logging")

func main() {
	flag.Parse()

	arp, err := arper.New()
	if err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
	arp.Verbose = *verbose

	devices, err := arp.Scan(time.Second * time.Duration(*timeout))
	if err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}

	for _, device := range devices {
		fmt.Printf("%s\t%s\t%s\n", device.IP, device.MAC, device.Vendor)
	}
}
