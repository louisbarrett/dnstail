package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	flagDevice         = flag.String("i", "eth0", "select network device")
	flagList           = flag.Bool("l", false, "list network device devices")
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = 1 * time.Second
	handle       *pcap.Handle
)

func listDevices() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	fmt.Println("\n")
	for _, device := range devices {
		fmt.Println(device.Name)
	}
}

func capturePackets() {
	// Open device
	device := *flagDevice
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}

	var filter string = "udp and port 53"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Network poackets

		NetworkLayer := packet.Layer(layers.LayerTypeIPv4)
		NetworkPacket, _ := NetworkLayer.(*layers.IPv4)
		// Process DNS packet here
		packetTime := packet.Metadata().Timestamp
		DNSLayer := packet.Layer(layers.LayerTypeDNS)
		DNSPacket := DNSLayer.(*layers.DNS)
		if DNSPacket.ANCount == 0 {
			Request := DNSPacket.Questions[0]
			fmt.Println(packetTime.String(),
				NetworkPacket.SrcIP.String(),
				string(Request.Name),
				Request.Type.String(),
			)
		}

		// // Process generic packet flow\
		// sourceIP := packet.NetworkLayer().NetworkFlow().Src().String()
		// destIP := packet.NetworkLayer().NetworkFlow().Dst().String()
		// sourcePort := packet.TransportLayer().TransportFlow().Src().String()
		// destPort := packet.TransportLayer().TransportFlow().Dst().String()

		// fmt.Println(packetTime.String(), sourceIP, sourcePort, destIP, destPort)

	}
}
func main() {
	flag.Parse()
	if *flagList {
		listDevices()
		return
	}

	capturePackets()
}
