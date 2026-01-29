package dht

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	cmdGet = "get"
	cmdPut = "put"
)

// Node: node_id -> addr (opt overlay_ip) for DHT.
type Node struct {
	NodeID    string
	Addr      string
	OverlayIP string
}

// Server: DHT node, in-memory, TCP get/put; fallback when control server blocked.
type Server struct {
	mu     sync.RWMutex
	nodes  map[string]Node
	listen string
	ln     net.Listener
}

// NewServer creates DHT server (in-memory).
func NewServer() *Server {
	return &Server{nodes: make(map[string]Node)}
}

// Put stores node_id -> addr (overlay_ip opt).
func (s *Server) Put(nodeID, addr, overlayIP string) {
	if nodeID == "" || addr == "" {
		return
	}
	s.mu.Lock()
	s.nodes[nodeID] = Node{NodeID: nodeID, Addr: addr, OverlayIP: overlayIP}
	s.mu.Unlock()
}

// Get returns addr, overlay_ip for node_id.
func (s *Server) Get(nodeID string) (addr, overlayIP string) {
	s.mu.RLock()
	n, ok := s.nodes[nodeID]
	s.mu.RUnlock()
	if !ok {
		return "", ""
	}
	return n.Addr, n.OverlayIP
}

// ListenAndServe TCP on addr. get\nnode_id\n -> addr\noverlay_ip\n or not_found\n; put\n... -> ok\n.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.listen = addr
	s.mu.Unlock()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	cmd := strings.TrimSpace(strings.ToLower(line))
	switch cmd {
	case cmdGet:
		line2, _ := br.ReadString('\n')
		nodeID := strings.TrimSpace(line2)
		addr, overlayIP := s.Get(nodeID)
		if addr == "" {
			conn.Write([]byte("not_found\n"))
		} else {
			conn.Write([]byte(addr + "\n" + overlayIP + "\n"))
		}
	case cmdPut:
		lines := make([]string, 0, 4)
		for i := 0; i < 4; i++ {
			l, err := br.ReadString('\n')
			if err != nil {
				return
			}
			lines = append(lines, strings.TrimSpace(l))
		}
		if len(lines) >= 3 {
			s.Put(lines[1], lines[2], lines[3])
		}
		conn.Write([]byte("ok\n"))
	}
}

// Lookup asks bootstrap for node_id; returns addr or ""; one try per peer.
func Lookup(nodeID string, bootstrapPeers []string, timeout time.Duration) (addr string) {
	if nodeID == "" || timeout <= 0 {
		timeout = 5 * time.Second
	}
	for _, peer := range bootstrapPeers {
		peer = strings.TrimSpace(peer)
		if peer == "" {
			continue
		}
		a := lookupOne(nodeID, peer, timeout)
		if a != "" {
			return a
		}
	}
	return ""
}

func lookupOne(nodeID, peer string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", peer, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte("get\n" + nodeID + "\n"))
	if err != nil {
		return ""
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return ""
	}
	line = strings.TrimSpace(line)
	if line == "not_found" {
		return ""
	}
	return line
}

// Announce put to bootstrap peers (node_id -> addr).
func Announce(nodeID, addr, overlayIP string, bootstrapPeers []string, timeout time.Duration) {
	if nodeID == "" || addr == "" {
		return
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	for _, peer := range bootstrapPeers {
		peer = strings.TrimSpace(peer)
		if peer == "" || peer == addr {
			continue
		}
		announceOne(nodeID, addr, overlayIP, peer, timeout)
	}
}

func announceOne(nodeID, addr, overlayIP, peer string, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", peer, timeout)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte(fmt.Sprintf("put\n%s\n%s\n%s\n", nodeID, addr, overlayIP)))
}
