// Package dns: DNS server for .0cdn; mysite.0cdn -> A/AAAA (edge IPs from store).
package dns

import (
	"context"
	"net"
	"strings"
	"sync"

	"dev.c0redev.0cdn/internal/store"
)

// Resolver returns IPs for site name; empty = not found.
type Resolver func(ctx context.Context, name string) ([]string, error)

// Server: UDP DNS for .0cdn.
type Server struct {
	DB       *store.DB
	Listen   string
	listener *net.UDPConn
	mu       sync.Mutex
}

// New returns DNS server (DB sites + nodes).
func New(db *store.DB, listen string) *Server {
	return &Server{DB: db, Listen: listen}
}

// Run starts DNS server (blocking).
func (s *Server) Run(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.Listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = conn
	s.mu.Unlock()
	defer conn.Close()
	buf := make([]byte, 512)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		go s.handlePacket(conn, buf[:n], remote)
	}
}

// handlePacket parse query, resolve .0cdn, write response.
func (s *Server) handlePacket(conn *net.UDPConn, req []byte, remote *net.UDPAddr) {
	if len(req) < 12 {
		return
	}
	// minimal DNS: id (2), flags (2), qdcount (2), ancount (2), nscount (2), arcount (2)
	id := uint16(req[0])<<8 | uint16(req[1])
	// simple response: same id, flags = 0x8180 (response, auth), qdcount=1, ancount=0 or 1
	resp := make([]byte, 0, 512)
	resp = append(resp, byte(id>>8), byte(id))
	resp = append(resp, 0x81, 0x80)
	resp = append(resp, 0, 1, 0, 0, 0, 0, 0, 0)
	// copy question section (name + type + class)
	name, off, ok := parseName(req, 12)
	if !ok || off+4 > len(req) {
		conn.WriteToUDP(req[:12], remote)
		return
	}
	qtype := uint16(req[off])<<8 | uint16(req[off+1])
	_ = uint16(req[off+2])<<8 | uint16(req[off+3])
	resp = append(resp, req[12:off+4]...)
	if qtype != 1 && qtype != 28 {
		conn.WriteToUDP(resp, remote)
		return
	}
	// resolve name
	nameLower := strings.ToLower(name)
	if !strings.HasSuffix(nameLower, ".0cdn.") && nameLower != "0cdn." {
		conn.WriteToUDP(resp, remote)
		return
	}
	// lookup site: mysite.0cdn -> mysite
	trimmed := strings.TrimSuffix(nameLower, ".0cdn.")
	if trimmed == "" {
		conn.WriteToUDP(resp, remote)
		return
	}
	site, err := s.DB.SiteByName(trimmed + ".0cdn")
	if err != nil || site == nil {
		conn.WriteToUDP(resp, remote)
		return
	}
	// get edge IPs from nodes (any node for now; later bind site to preferred nodes)
	nodes, err := s.DB.ListNodes(nil)
	if err != nil || len(nodes) == 0 {
		conn.WriteToUDP(resp, remote)
		return
	}
	var ips []string
	for _, n := range nodes {
		host, _, _ := net.SplitHostPort(n.Addr)
		if host != "" {
			ips = append(ips, host)
		} else {
			ips = append(ips, n.Addr)
		}
	}
	if len(ips) == 0 {
		conn.WriteToUDP(resp, remote)
		return
	}
	// add answer(s). name in response is pointer to question name (offset 12)
	namePtr := []byte{0xc0, 12}
	var ancount int
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			if qtype == 1 {
				resp = append(resp, namePtr...)
				resp = append(resp, 0, 1, 0, 1)
				resp = append(resp, 0, 0, 0, 60)
				resp = append(resp, 0, 4)
				resp = append(resp, ip.To4()...)
				ancount++
			}
		} else {
			if qtype == 28 {
				resp = append(resp, namePtr...)
				resp = append(resp, 0, 28, 0, 1)
				resp = append(resp, 0, 0, 0, 60)
				resp = append(resp, 0, 16)
				resp = append(resp, ip...)
				ancount++
			}
		}
	}
	resp[6] = byte(ancount >> 8)
	resp[7] = byte(ancount)
	conn.WriteToUDP(resp, remote)
}

func parseName(b []byte, off int) (string, int, bool) {
	var labels []string
	for off < len(b) {
		if b[off] == 0 {
			return strings.Join(labels, ".") + ".", off + 1, true
		}
		if b[off]&0xc0 == 0xc0 {
			// pointer
			ptr := int(b[off]&0x3f)<<8 | int(b[off+1])
			if ptr >= off {
				return "", 0, false
			}
			s, _, ok := parseName(b, ptr)
			return s, off + 2, ok
		}
		ln := int(b[off])
		off++
		if off+ln > len(b) {
			return "", 0, false
		}
		labels = append(labels, string(b[off:off+ln]))
		off += ln
	}
	return "", 0, false
}

