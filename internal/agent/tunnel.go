package agent

import (
	"bufio"
	"io"
	"log"
	"net"
	"sync"

	"dev.c0redev.0cdn/internal/crypto"
	"dev.c0redev.0cdn/internal/proto"
	"filippo.io/mlkem768"
)

// OnDataFunc is called for each Data frame; use t.WriteData to reply.
type OnDataFunc func(t *Tunnel, streamID uint32, payload []byte)

// Tunnel over a stream (QUIC or TCP). Reads frames, dispatches Data to onData. Optional PQ (encrypts Data) and Auth (token before Data).
type Tunnel struct {
	conn       io.ReadWriteCloser
	onData     OnDataFunc
	mu         sync.Mutex
	paddingMax int
	pqEnabled  bool
	authToken  string
	pqSecret   []byte
	pqMu       sync.Mutex
	decapKey   *mlkem768.DecapsulationKey
	authDone   bool
}

// TunnelOpts: optional PQ and/or Auth.
type TunnelOpts struct {
	PQEnabled bool
	AuthToken string
}

// NewTunnel wraps conn, dispatches Data to onData. paddingMax > 0 enables decode/encode masking.
func NewTunnel(conn io.ReadWriteCloser, onData OnDataFunc, paddingMax int) *Tunnel {
	return NewTunnelWithOpts(conn, onData, paddingMax, nil)
}

// NewTunnelWithOpts like NewTunnel + PQ/Auth opts.
func NewTunnelWithOpts(conn io.ReadWriteCloser, onData OnDataFunc, paddingMax int, opts *TunnelOpts) *Tunnel {
	t := &Tunnel{conn: conn, onData: onData, paddingMax: paddingMax}
	if opts != nil {
		t.pqEnabled = opts.PQEnabled
		t.authToken = opts.AuthToken
		t.authDone = opts.AuthToken == ""
	}
	return t
}

// Run reads frames until close. Pong for Ping. If PQ: send TypePQKey, handle TypePQCiphertext. If Auth: wait AuthRequest.
func (t *Tunnel) Run() error {
	defer t.conn.Close()
	r := bufio.NewReader(t.conn)
	payloadBuf := make([]byte, 64*1024)

	if t.pqEnabled {
		enc, decap, err := crypto.GenerateKeyPair()
		if err != nil {
			return err
		}
		t.decapKey = decap
		t.mu.Lock()
		err = proto.EncodeFrame(t.conn, &proto.Frame{Type: proto.TypePQKey, StreamID: 0, Payload: enc})
		t.mu.Unlock()
		if err != nil {
			return err
		}
	}

	for {
		f, err := proto.DecodeFrame(r, payloadBuf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		switch f.Type {
		case proto.TypePing:
			t.mu.Lock()
			_ = proto.EncodeFrame(t.conn, &proto.Frame{Type: proto.TypePong, StreamID: f.StreamID, Payload: nil})
			t.mu.Unlock()
		case proto.TypePQCiphertext:
			if t.decapKey != nil && len(t.pqSecret) == 0 {
				secret, err := crypto.Decapsulate(t.decapKey, f.Payload)
				if err != nil {
					continue
				}
				t.pqMu.Lock()
				t.pqSecret = secret
				t.pqMu.Unlock()
			}
		case proto.TypeAuthRequest:
			req, err := proto.DecodeAuthRequest(f.Payload)
			if err != nil {
				t.sendAuthResponse(false, "bad request")
				return nil
			}
			ok := t.authToken != "" && len(req.Token) > 0 && string(req.Token) == t.authToken
			t.authDone = true
			t.sendAuthResponse(ok, "")
			if !ok {
				return nil
			}
		case proto.TypeData:
			if !t.authDone {
				continue
			}
			if t.onData != nil {
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
				t.onData(t, f.StreamID, payload)
			}
		default:
			// ignore route etc
		}
	}
}

func (t *Tunnel) sendAuthResponse(ok bool, errMsg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	payload := proto.EncodeAuthResponse(&proto.AuthResponse{OK: ok, Error: errMsg})
	_ = proto.EncodeFrame(t.conn, &proto.Frame{Type: proto.TypeAuthResponse, StreamID: 0, Payload: payload})
}

// WriteData sends a Data frame. If paddingMax > 0, payload is encoded with masking. If PQ secret set, encrypts with ChaCha20-Poly1305.
func (t *Tunnel) WriteData(streamID uint32, payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.paddingMax > 0 {
		enc, err := proto.EncodeDataPayload(payload, t.paddingMax)
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
			log.Println("pq seal:", err)
			return err
		}
		payload = enc
	}
	return proto.EncodeFrame(t.conn, &proto.Frame{Type: proto.TypeData, StreamID: streamID, Payload: payload})
}

// Conn returns underlying conn (e.g. deadline).
func (t *Tunnel) Conn() io.ReadWriteCloser {
	return t.conn
}

// ServeTCP accepts TCP, one Tunnel per conn; opts for PQ/Auth.
func ServeTCP(ln net.Listener, onData OnDataFunc, paddingMax int, opts *TunnelOpts) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		var t *Tunnel
		if opts != nil {
			t = NewTunnelWithOpts(conn, onData, paddingMax, opts)
		} else {
			t = NewTunnel(conn, onData, paddingMax)
		}
		go t.Run()
	}
}
 