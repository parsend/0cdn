package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"dev.c0redev.0cdn/internal/crypto"
	"dev.c0redev.0cdn/internal/proto"
	"dev.c0redev.0cdn/internal/transport"
)

// ExitEntry: one exit from routes API.
type ExitEntry struct {
	NodeID    string `json:"node_id"`
	Addr      string `json:"addr"`
	OverlayIP string `json:"overlay_ip,omitempty"`
	Priority  int32  `json:"priority"`
	Country   string `json:"country"`
	City      string `json:"city"`
	IsP2P     bool   `json:"is_p2p"`
}

// LookupResult holds full lookup response (addr + optional ICE for P2P).
type LookupResult struct {
	Addr          string
	OverlayIP     string
	IceUfrag      string
	IcePwd        string
	IceCandidates string
}

// LookupNode returns addr for node_id (own first, then P2P); dial-by-ID.
func LookupNode(serverURL, token, nodeID string) (addr string, err error) {
	r, err := LookupNodeFull(serverURL, token, nodeID)
	if err != nil || r == nil {
		return "", err
	}
	return r.Addr, nil
}

// LookupNodeFull returns full lookup + ICE when avail (P2P).
func LookupNodeFull(serverURL, token, nodeID string) (*LookupResult, error) {
	serverURL = NormalizeServerURL(serverURL)
	if serverURL == "" || token == "" || nodeID == "" {
		return nil, fmt.Errorf("server URL, token and node_id required")
	}
	u := serverURL + "/api/nodes/lookup?node_id=" + url.QueryEscape(nodeID)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("node not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lookup: %d", resp.StatusCode)
	}
	var out struct {
		Addr          string `json:"addr"`
		OverlayIP     string `json:"overlay_ip,omitempty"`
		IceUfrag      string `json:"ice_ufrag,omitempty"`
		IcePwd        string `json:"ice_pwd,omitempty"`
		IceCandidates string `json:"ice_candidates,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Addr == "" {
		return nil, fmt.Errorf("node not found")
	}
	return &LookupResult{
		Addr:          out.Addr,
		OverlayIP:     out.OverlayIP,
		IceUfrag:      out.IceUfrag,
		IcePwd:        out.IcePwd,
		IceCandidates: out.IceCandidates,
	}, nil
}

// FetchRoutes returns ordered exits from server (Bearer).
func FetchRoutes(serverURL, token, country, city string) ([]ExitEntry, error) {
	url := serverURL + "/api/routes"
	if country != "" || city != "" {
		url += "?"
		if country != "" {
			url += "country=" + country
		}
		if city != "" {
			if country != "" {
				url += "&"
			}
			url += "city=" + city
		}
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("routes: %d", resp.StatusCode)
	}
	var out struct {
		Exits []ExitEntry `json:"exits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Exits, nil
}

// TunnelClient: TCP to exit, our proto; opt PQ + Auth.
type TunnelClient struct {
	conn       net.Conn
	r          *bufio.Reader
	mu         sync.Mutex
	stream     uint32
	paddingMax int
	morph      bool
	pqEnabled  bool
	authToken  string
	pqSecret   []byte
	pqMu       sync.Mutex
}

// DialExit connects to exit, returns TunnelClient. QUIC first if 0CDN_USE_QUIC=1 else TCP; masking/TLS from env.
func DialExit(addr string) (*TunnelClient, error) {
	if os.Getenv("0CDN_USE_QUIC") == "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := transport.DialStream(ctx, addr, transport.DefaultQUICClientTLS())
		cancel()
		if err == nil {
			tc := newTunnelClientFromConn(conn)
			if err := tc.Handshake(); err != nil {
				tc.Close()
				return nil, err
			}
			return tc, nil
		}
	}
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if os.Getenv("0CDN_MASK_TLS") == "1" {
		conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	}
	tc := newTunnelClientFromConn(conn)
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return nil, err
	}
	return tc, nil
}

func newTunnelClientFromConn(conn net.Conn) *TunnelClient {
	return NewTunnelClientFromConn(conn)
}

// NewTunnelClientFromConn wraps conn (e.g. ICE) as TunnelClient; call Handshake() then use.
func NewTunnelClientFromConn(conn net.Conn) *TunnelClient {
	tc := &TunnelClient{conn: conn, r: bufio.NewReader(conn), stream: 1}
	if os.Getenv("0CDN_MASK_PADDING") == "1" {
		n, _ := parseInt(os.Getenv("0CDN_MASK_PADDING_MAX"), 64)
		if n > proto.MaxPaddingSize {
			n = proto.MaxPaddingSize
		}
		tc.paddingMax = n
	}
	tc.morph = os.Getenv("0CDN_MASK_MORPH") == "1"
	tc.pqEnabled = os.Getenv("0CDN_PQ") == "1"
	if os.Getenv("0CDN_AGENT_AUTH") == "1" {
		tc.authToken = os.Getenv("0CDN_TOKEN")
	}
	return tc
}

func parseInt(s string, defaultVal int) (int, bool) {
	if s == "" {
		return defaultVal, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return defaultVal, false
	}
	return n, true
}

// Handshake: opt PQ (read TypePQKey timeout, use/discard), Ping, Auth if 0CDN_AGENT_AUTH=1. No PQ = timeout then Ping.
const handshakeFirstReadTimeout = 3 * time.Second

func (t *TunnelClient) Handshake() error {
	payloadBuf := make([]byte, 64*1024)
	if deadline, ok := t.conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = deadline.SetReadDeadline(time.Now().Add(handshakeFirstReadTimeout))
	}
	f, err := proto.DecodeFrame(t.r, payloadBuf)
	if deadline, ok := t.conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = deadline.SetReadDeadline(time.Time{})
	}
	if err != nil {
		if t.pqEnabled {
			return fmt.Errorf("expected TypePQKey: %w", err)
		}
		// agent likely has no PQ, proceed to Ping
	} else if f.Type == proto.TypePQKey {
		if t.pqEnabled {
			kem, err := crypto.NewPQKEMFromEnc(f.Payload)
			if err != nil {
				return err
			}
			sharedSecret, ciphertext, err := kem.Encapsulate()
			if err != nil {
				return err
			}
			t.pqMu.Lock()
			t.pqSecret = sharedSecret
			t.pqMu.Unlock()
			t.mu.Lock()
			err = proto.EncodeFrame(t.conn, &proto.Frame{Type: proto.TypePQCiphertext, StreamID: 0, Payload: ciphertext})
			t.mu.Unlock()
			if err != nil {
				return err
			}
		}
	} else {
		if t.pqEnabled {
			return fmt.Errorf("expected TypePQKey, got %d", f.Type)
		}
		return fmt.Errorf("unexpected first frame %d", f.Type)
	}
	if err := t.Ping(); err != nil {
		return err
	}
	if t.authToken != "" {
		t.mu.Lock()
		_ = proto.EncodeFrame(t.conn, &proto.Frame{Type: proto.TypeAuthRequest, StreamID: 0, Payload: proto.EncodeAuthRequest(&proto.AuthRequest{Token: []byte(t.authToken)})})
		t.mu.Unlock()
		for {
			f, err := proto.DecodeFrame(t.r, payloadBuf)
			if err != nil {
				return err
			}
			if f.Type == proto.TypeAuthResponse {
				resp, err := proto.DecodeAuthResponse(f.Payload)
				if err != nil || !resp.OK {
					return fmt.Errorf("auth failed")
				}
				break
			}
		}
	}
	return nil
}

// Ping sends Ping, waits Pong.
func (t *TunnelClient) Ping() error {
	t.mu.Lock()
	err := proto.EncodeFrame(t.conn, &proto.Frame{Type: proto.TypePing, StreamID: t.stream, Payload: nil})
	t.mu.Unlock()
	if err != nil {
		return err
	}
	f, err := proto.DecodeFrame(t.r, nil)
	if err != nil {
		return err
	}
	if f.Type != proto.TypePong {
		return fmt.Errorf("expected pong, got %d", f.Type)
	}
	return nil
}

// WriteData sends Data; PQ encrypt if set; padding/morph encode.
func (t *TunnelClient) WriteData(payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.paddingMax > 0 || t.morph {
		enc, err := proto.EncodeDataPayloadMorph(payload, t.paddingMax, t.morph)
		if err != nil {
			return err
		}
		payload = enc
	}
	t.pqMu.Lock()
	secret := t.pqSecret
	t.pqMu.Unlock()
	if len(secret) > 0 && len(payload) > 0 {
		enc, err := crypto.Seal(secret, nil, payload)
		if err != nil {
			return err
		}
		payload = enc
	}
	return proto.EncodeFrame(t.conn, &proto.Frame{Type: proto.TypeData, StreamID: t.stream, Payload: payload})
}

// ReadData reads next Data frame (blocking); skip other types; decrypt/decode if PQ/padding.
func (t *TunnelClient) ReadData(buf []byte) ([]byte, error) {
	for {
		f, err := proto.DecodeFrame(t.r, buf)
		if err != nil {
			return nil, err
		}
		if f.Type == proto.TypeData {
			payload := f.Payload
			t.pqMu.Lock()
			secret := t.pqSecret
			t.pqMu.Unlock()
			if len(secret) > 0 && len(payload) > 0 {
				dec, err := crypto.Open(secret, payload)
				if err != nil {
					continue
				}
				payload = dec
			}
			if t.paddingMax > 0 && len(payload) > 0 {
				dec, err := proto.DecodeDataPayload(payload)
				if err != nil {
					continue
				}
				payload = dec
			}
			return append([]byte(nil), payload...), nil
		}
	}
}

// Close closes conn.
func (t *TunnelClient) Close() error {
	return t.conn.Close()
}

// PickExit returns first reachable exit; tryDial = dial each until one ok.
func PickExit(exits []ExitEntry, tryDial bool) string {
	for _, e := range exits {
		if tryDial {
			conn, err := net.DialTimeout("tcp", e.Addr, 3*time.Second)
			if err != nil {
				continue
			}
			conn.Close()
		}
		return e.Addr
	}
	if len(exits) > 0 {
		return exits[0].Addr
	}
	return ""
}

// NormalizeServerURL ensures scheme (http/https).
func NormalizeServerURL(s string) string {
	s = strings.TrimSpace(s)
	if s != "" && !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	return s
}
