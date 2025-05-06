//go:build !linux

package router_test

import (
	"testing"

	"github.com/apoxy-dev/apoxy-cli/pkg/utils/vm"
)

// A stub for non-linux operating systems, when the test is compiled for the VM
// it will use the linux version of this test.
func TestNetlinkRouter(t *testing.T) {
	// Run the test in a linux VM.
	vm.RunTestInVM(t)
}
