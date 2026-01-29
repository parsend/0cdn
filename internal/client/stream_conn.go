package client

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// StreamConn wraps tunnel (TCP to exit); first Data = "connect host:port", then relay.
type StreamConn struct {
	tunnel   *TunnelClient
	streamID uint32
	readBuf  []byte
	readMu   sync.Mutex
	readCond *sync.Cond
	closed   bool
	closeMu  sync.Mutex
}

// DialExitStream connects to exit, sends connect target, returns net.Conn (target = host:port).
func DialExitStream(exitAddr, target string) (net.Conn, error) {
	tc, err := DialExit(exitAddr)
	if err != nil {
		return nil, err
	}
	return dialExitStreamFromTunnel(tc, target)
}

// DialExitStreamFromConn uses existing conn (e.g. ICE) as tunnel; handshake, connect frame, net.Conn.
func DialExitStreamFromConn(conn net.Conn, target string) (net.Conn, error) {
	tc := NewTunnelClientFromConn(conn)
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return nil, err
	}
	return dialExitStreamFromTunnel(tc, target)
}

func dialExitStreamFromTunnel(tc *TunnelClient, target string) (net.Conn, error) {
	payload := []byte("connect\t" + target)
	if err := tc.WriteData(payload); err != nil {
		tc.Close()
		return nil, err
	}
	sc := &StreamConn{tunnel: tc, streamID: 1}
	sc.readCond = sync.NewCond(&sc.readMu)
	go sc.readLoop()
	return &streamConnWrapper{StreamConn: sc}, nil
}

// streamConnWrapper adds SetDeadline for net.Conn.
type streamConnWrapper struct {
	*StreamConn
}

func (w *streamConnWrapper) SetDeadline(t time.Time) error      { return nil }
func (w *streamConnWrapper) SetReadDeadline(t time.Time) error  { return nil }
func (w *streamConnWrapper) SetWriteDeadline(t time.Time) error { return nil }

func (s *StreamConn) readLoop() {
	buf := make([]byte, 32*1024)
	for {
		payload, err := s.tunnel.ReadData(buf)
		if err != nil {
			s.closeLocked()
			return
		}
		s.readMu.Lock()
		if s.closed {
			s.readMu.Unlock()
			return
		}
		s.readBuf = append(s.readBuf, payload...)
		s.readCond.Signal()
		s.readMu.Unlock()
	}
}

func (s *StreamConn) closeLocked() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if !s.closed {
		s.closed = true
		s.tunnel.Close()
		s.readCond.Signal()
	}
}

// Read reads from tunnel.
func (s *StreamConn) Read(b []byte) (n int, err error) {
	s.readMu.Lock()
	for len(s.readBuf) == 0 && !s.closed {
		s.readCond.Wait()
	}
	if s.closed {
		s.readMu.Unlock()
		return 0, io.EOF
	}
	n = copy(b, s.readBuf)
	s.readBuf = s.readBuf[n:]
	s.readMu.Unlock()
	return n, nil
}

// Write sends Data frame.
func (s *StreamConn) Write(b []byte) (n int, err error) {
	s.closeMu.Lock()
	closed := s.closed
	s.closeMu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if err := s.tunnel.WriteData(b); err != nil {
		s.closeLocked()
		return 0, err
	}
	return len(b), nil
}

// Close closes tunnel.
func (s *StreamConn) Close() error {
	s.closeLocked()
	return nil
}

// LocalAddr, RemoteAddr for net.Conn (opt).
func (s *StreamConn) LocalAddr() net.Addr  { return &addr{"tunnel", "0"} }
func (s *StreamConn) RemoteAddr() net.Addr { return &addr{"tunnel", "0"} }

type addr struct{ network, addr string }

func (a *addr) Network() string { return a.network }
func (a *addr) String() string  { return a.addr }

// ParseConnect parses "connect\thost:port" and returns host, port. Used by agent.
func ParseConnect(payload []byte) (host string, port int, err error) {
	if !bytes.HasPrefix(payload, []byte("connect\t")) {
		return "", 0, fmt.Errorf("not a connect frame")
	}
	s := string(payload[len("connect\t"):])
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// IsConnect true if payload is connect frame.
func IsConnect(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte("connect\t"))
}

// ConnectTarget returns host:port from connect payload.
func ConnectTarget(payload []byte) string {
	s := string(payload)
	if !strings.HasPrefix(s, "connect\t") {
		return ""
	}
	return s[len("connect\t"):]
}
