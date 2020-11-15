// +build linux

package wgrpcd

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snapshotLen int32 = 1024
)

// CollectFlowLogs takes packets from a WireTap's target Wireguard interface and sends some packet attributes to its SubscriptionBroker for further processing.
func CollectFlowLogs(w *WiretapConfig) error {
	handle, err := pcap.OpenLive(w.DeviceName, snapshotLen, false, 30*time.Second)
	if err != nil {
		return err
	}
	defer handle.Close()

	var ethLayer layers.Ethernet
	var ipLayer layers.IPv4
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipLayer,
	)

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		foundLayerTypes := []gopacket.LayerType{}
		packetData := packet.Data()
		err := parser.DecodeLayers(packetData, &foundLayerTypes)
		if err != nil {
			w.Log("Error decoding packet: %v", err)
			continue
		}

		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeIPv4 {
				packet := &Packet{
					SrcIP: ipLayer.SrcIP,
					DstIP: ipLayer.DstIP,
				}
				w.Log("%s -> %s", packet.SrcIP, packet.DstIP)
				w.Broker.Send(packet)
			}
		}
	}

	return nil
}
