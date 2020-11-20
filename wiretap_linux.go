// +build linux

package wgrpcd

import (
	"context"
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
				networkFlow := ipLayer.NetworkFlow()
				flow := &Flow{
					Src:      networkFlow.Src().String(),
					Dst:      networkFlow.Dst().String(),
					Protocol: ipLayer.Protocol.String(),
				}
				w.Log("%s -> %s", flow.Src, flow.Dst)
				w.Broker.Send(w.DeviceName, flow)
			}
		}
	}

	return nil
}

type subscriptionBroker struct {
}

// Send takes a flow from the Wireguard interface and passes it to a subscriber if one exists.
func (b *subscriptionBroker) Send(deviceName string, flow *Flow) error {
	return nil
}

// Receive allows a gRPC handler to stream flow logs to a client.
func (b *subscriptionBroker) Receive(ctx context.Context, deviceName string, flows chan<- *Flow) error {
	return nil
}
