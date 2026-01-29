//go:build !linux

package tun

import (
	"fmt"
)

// Device: TUN stub (non-Linux).
type Device struct{}

// NewDevice err on non-Linux (TUN Linux-only).
func NewDevice(name string) (*Device, error) {
	return nil, fmt.Errorf("tun only supported on Linux")
}

// Read stub.
func (d *Device) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("tun only supported on Linux")
}

// Write stub.
func (d *Device) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("tun only supported on Linux")
}

// Close stub.
func (d *Device) Close() error {
	return nil
}

// Name stub.
func (d *Device) Name() string {
	return ""
}
