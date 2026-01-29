package overlay

import (
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	"dev.c0redev.0cdn/internal/client"
	"dev.c0redev.0cdn/internal/tun"
)

const overlayPrefix = "ip\t"

// Run overlay loop: TUN read -> Data "ip\t"+pkt to exit; exit read -> decap -> TUN. exitAddr = default gw; CAP_NET_ADMIN on Linux.
func Run(dev *tun.Device, exitAddr string) error {
	tc, err := client.DialExit(exitAddr)
	if err != nil {
		return err
	}
	defer tc.Close()
	// DialExit already did Handshake (PQ if set, Ping, Auth if set)
	var wg sync.WaitGroup
	wg.Add(2)
	// TUN -> tunnel
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Println("overlay tun read:", err)
				}
				return
			}
			payload := make([]byte, len(overlayPrefix)+n)
			copy(payload, overlayPrefix)
			copy(payload[len(overlayPrefix):], buf[:n])
			if err := tc.WriteData(payload); err != nil {
				log.Println("overlay write:", err)
				return
			}
		}
	}()
	// tunnel -> TUN
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		for {
			payload, err := tc.ReadData(buf)
			if err != nil {
				if err != io.EOF {
					log.Println("overlay read:", err)
				}
				return
			}
			if len(payload) > len(overlayPrefix) && string(payload[:len(overlayPrefix)]) == overlayPrefix {
				pkt := payload[len(overlayPrefix):]
				if _, err := dev.Write(pkt); err != nil {
					log.Println("overlay tun write:", err)
					return
				}
			}
		}
	}()
	wg.Wait()
	return nil
}

// Up brings TUN up, assigns cidr (e.g. 10.200.0.2/24); ip addr add, ip link set up.
func Up(ifName, cidr string) error {
	if cidr == "" {
		cidr = "10.200.0.2/24"
	}
	cmd := exec.Command("ip", "addr", "add", cidr, "dev", ifName)
	if out, err := cmd.CombinedOutput(); err != nil && !strings.Contains(string(out), "File exists") {
		return err
	}
	cmd = exec.Command("ip", "link", "set", "dev", ifName, "up")
	return cmd.Run()
}

// DefaultGW adds default route via gw (overlay IP); opt, user can add manually.
func DefaultGW(ifName, gw string) error {
	if gw == "" {
		return nil
	}
	cmd := exec.Command("ip", "route", "add", "default", "via", gw, "dev", ifName)
	return cmd.Run()
}

// ResolveExit returns exit addr (0CDN_EXIT_NODE_ID, 0CDN_TUN_GW_ADDR, or routes); dhtBootstrap when server unreachable.
func ResolveExit(serverURL, token string, lookupCache *client.LookupCache, dhtBootstrap []string) (string, error) {
	if a := os.Getenv("0CDN_TUN_GW_ADDR"); a != "" {
		return a, nil
	}
	if nodeID := os.Getenv("0CDN_EXIT_NODE_ID"); nodeID != "" {
		a, err := client.LookupNodeWithDHT(serverURL, token, nodeID, lookupCache, dhtBootstrap)
		if err == nil && a != "" {
			return a, nil
		}
	}
	exits, err := client.FetchRoutes(serverURL, token, "", "")
	if err != nil {
		return "", err
	}
	if len(exits) == 0 {
		return "", nil
	}
	a := client.PickExit(exits, true)
	if a == "" {
		a = exits[0].Addr
	}
	return a, nil
}

