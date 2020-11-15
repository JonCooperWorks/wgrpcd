// +build !linux

package wgrpcd

import "runtime"

// These are no-op implementations for non-Linux OSs.

// CollectFlowLogs is a no-op on every OS except Linux.
func CollectFlowLogs(config *WiretapConfig) error {
	if runtime.GOOS == "linux" {
		panic("no-op CollectFlowLogs shouldn't be called on Linux")
	}
	return nil
}
