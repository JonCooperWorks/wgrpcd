// +build !linux

package wgrpcd

import "context"

// These are no-op implementations for non-Linux OSs.

// CollectFlowLogs is a no-op on every OS except Linux.
func CollectFlowLogs(config *WiretapConfig) error {
	panic("this should never be called")
}

type subscriptionBroker struct {
}

func (b *subscriptionBroker) Send(deviceName string, flow *Flow) error {
	panic("this should never be called")
}

func (b *subscriptionBroker) Receive(ctx context.Context, deviceName string, flows chan<- *Flow) error {
	panic("receive should never be called")
}
