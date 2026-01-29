//go:build linux

package tun

import (
	"fmt"

	"github.com/songgao/water"
)

// Device: TUN iface (Linux, CAP_NET_ADMIN or root).
type Device struct {
	ifce *water.Interface
}

// NewDevice creates TUN; name empty = OS picks tun0, tun1, ...
func NewDevice(name string) (*Device, error) {
	config := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: name,
		},
	}
	ifce, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("tun: %w", err)
	}
	return &Device{ifce: ifce}, nil
}

// Read reads one IP pkt into p.
func (d *Device) Read(p []byte) (n int, err error) {
	return d.ifce.Read(p)
}

// Write writes one IP pkt.
func (d *Device) Write(p []byte) (n int, err error) {
	return d.ifce.Write(p)
}

// Close closes TUN.
func (d *Device) Close() error {
	return d.ifce.Close()
}

// Name returns iface name (e.g. tun0).
func (d *Device) Name() string {
	return d.ifce.Name()
}
