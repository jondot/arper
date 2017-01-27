// Package arper - An ARP scanner library
//
// Some of this code inspired by:
// https://github.com/google/gopacket/tree/master/examples/arpscan
package arper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	ouidb "github.com/dutchcoders/go-ouitools"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var arperDb = "/tmp/arper-oui.db"

// DeviceInfo TBD
type DeviceInfo struct {
	IP     string
	MAC    string
	Vendor string
}

// Arper TBD
type Arper struct {
	Verbose bool
	OuiDB   *ouidb.OuiDb
}

// New TBD
func New() (*Arper, error) {
	if _, err := os.Stat(arperDb); os.IsNotExist(err) {
		data, err := Asset("data/oui.txt")
		if err != nil {
			return nil, err
		}
		ioutil.WriteFile(arperDb, data, os.ModePerm)
	}

	db := ouidb.New(arperDb)
	if db == nil {
		return nil, errors.New("Oui database cannot be initialized")
	}
	return &Arper{
		OuiDB: db,
	}, nil
}

// Scan TBD
func (a *Arper) Scan(timeout time.Duration) ([]DeviceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	ipstream := make(chan DeviceInfo)
	devices := []DeviceInfo{}
	go func() {
		for device := range ipstream {
			devices = append(devices, device)
		}
	}()
	defer close(ipstream)

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		go func(iface net.Interface) {
			defer wg.Done()
			if err := a.scanInterface(&iface, ipstream, timeout); err != nil {
				if a.Verbose {
					log.Printf("interface %v: %v", iface.Name, err)
				}
			}
		}(iface)
	}
	wg.Wait()

	return devices, nil
}

func (a *Arper) scanInterface(iface *net.Interface, ipstream chan DeviceInfo, timeout time.Duration) error {
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	if addr == nil {
		return errors.New("no good IP network found")
	} else if addr.IP[0] == 127 {
		return errors.New("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("mask means network is too large")
	}
	if a.Verbose {
		log.Printf("Using network range %v for interface %v", addr, iface.Name)
	}

	handle, err := pcap.OpenLive(iface.Name, 65536, true, timeout)
	if err != nil {
		return err
	}
	defer handle.Close()

	stop := make(chan struct{})
	go a.readARP(handle, iface, ipstream, stop)
	defer close(stop)
	if err := a.writeARP(handle, iface, addr); err != nil {
		if a.Verbose {
			log.Printf("error writing packets on %v: %v", iface.Name, err)
		}
		return err
	}
	time.Sleep(timeout)
	return nil
}

func (a *Arper) readARP(handle *pcap.Handle, iface *net.Interface, ipstream chan DeviceInfo, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
				continue
			}
			if a.Verbose {
				log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
			}
			mac := net.HardwareAddr(arp.SourceHwAddress)
			block := a.OuiDB.Lookup(ouidb.HardwareAddr(mac))
			desc := ""
			if block != nil {
				desc = block.Organization
			}

			ipstream <- DeviceInfo{
				IP:     fmt.Sprintf("%v", net.IP(arp.SourceProtAddress)),
				MAC:    fmt.Sprintf("%v", mac),
				Vendor: desc,
			}
		}
	}
}

func (a *Arper) writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	for _, ip := range a.ips(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func (a *Arper) ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	num &= mask
	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, net.IP(buf[:]))
		mask++
		num++
	}
	return
}
