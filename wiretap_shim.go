package wgrpcd

import (
	"context"
	"log"
)

// Flow is an IP packet with the source and destination parsed out for flow logs.
// It is meant to be similar to those provided by AWS and Azure at the VPC level for individual clients.
type Flow struct {
	Src      string
	Dst      string
	Protocol string
}

// WiretapConfig contains all necessary information to configure a Wiretap.
type WiretapConfig struct {
	Logger     *log.Logger
	DeviceName string
	Broker     SubscriptionBroker
}

// Log prints a message with the attached logger if it's not nil.
func (w *WiretapConfig) Log(format string, args ...interface{}) {
	if w.Logger != nil {
		w.Logger.Printf(format, args...)
	}
}

// Wiretap exposes flow logs from a running Wireguard interface on Linux and a no-op on other OSs.
type Wiretap func(*WiretapConfig) error

// SubscriptionBroker is a shim that relays packets for a given host to an active listener through a datastore.
// It is meant to abstract gopacket away from the rest of the program so it can still build on Linux and allow multiple datastores to be used as a broker.
type SubscriptionBroker interface {
	// Send takes a flow from the Wireguard interface and passes it to a subscriber if one exists.
	Send(deviceName string, flow *Flow) error

	// Receive is meant to allow a listener to pull down flow logs for an IP address.
	Receive(ctx context.Context, deviceName string, flows chan<- *Flow) error
}

// NewSubscriptionBroker returns a broker to relay flow logs from gopacket to a caller.
// It will return a no-op broker on non-linux OSs.
func NewSubscriptionBroker() (SubscriptionBroker, error) {
	return &subscriptionBroker{}, nil
}
