package agent

import (
	"bytes"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"dev.c0redev.0cdn/internal/tun"
)

const connectPrefix = "connect\t"
const overlayPrefix = "ip\t"

// overlay subnet 10.200.0.0/24
const overlayNetwork = "10.200.0"

// Relay: Data frames; connect -> TCP to target + relay; ip\t -> TUN or fwd by overlay_ip.
type Relay struct {
	mu               sync.Mutex
	streams          map[uint32]*streamRelay
	tunDev           *tun.Device
	overlayTunnel    *Tunnel
	overlayStreamID  uint32
	overlayResolver  OverlayResolver
	myOverlayIP      string
	forwardMu       sync.Mutex
	forwardConns    map[string]*forwardConn
	paddingMax      int
}

type forwardConn struct {
	tunnel *Tunnel
	conn   net.Conn
}

type streamRelay struct {
	tcp net.Conn
	ch  chan []byte
}

// NewRelay returns Relay + OnDataFunc. tunDev: ip\t -> TUN, TUN read -> back. resolver+myOverlayIP: fwd to other 10.200.0.x.
func NewRelay(tunDev *tun.Device) (*Relay, OnDataFunc) {
	r := &Relay{streams: make(map[uint32]*streamRelay), tunDev: tunDev, forwardConns: make(map[string]*forwardConn)}
	if tunDev != nil {
		go r.tunReadLoop()
	}
	return r, r.onData
}

// SetOverlay sets resolver and this node's overlay IP for forwarding. Call after NewRelay if agent has server URL and token.
func (r *Relay) SetOverlay(resolver OverlayResolver, myOverlayIP string) {
	r.mu.Lock()
	r.overlayResolver = resolver
	r.myOverlayIP = myOverlayIP
	r.mu.Unlock()
}

// SetPaddingMax sets Data payload padding for fwd conns.
func (r *Relay) SetPaddingMax(n int) { r.paddingMax = n }

// parseIPv4Dest returns dest IP string (e.g. "10.200.0.5") if pkt is IPv4, else "".
func parseIPv4Dest(pkt []byte) string {
	if len(pkt) < 20 {
		return ""
	}
	if pkt[0]>>4 != 4 {
		return ""
	}
	return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19]).String()
}

// inOverlaySubnet true if ip in 10.200.0.x.
func inOverlaySubnet(ip string) bool {
	return strings.HasPrefix(ip, overlayNetwork+".")
}

func (r *Relay) onData(t *Tunnel, streamID uint32, payload []byte) {
	if len(payload) > len(overlayPrefix) && bytes.HasPrefix(payload, []byte(overlayPrefix)) {
		pkt := payload[len(overlayPrefix):]
		destIP := parseIPv4Dest(pkt)
		r.mu.Lock()
		tunDev := r.tunDev
		resolver := r.overlayResolver
		myIP := r.myOverlayIP
		if tunDev != nil {
			if r.overlayTunnel == nil {
				r.overlayTunnel = t
				r.overlayStreamID = streamID
			}
		}
		r.mu.Unlock()
		// forward to peer if dest is other overlay node
		if destIP != "" && inOverlaySubnet(destIP) && destIP != myIP && resolver != nil {
			addr, err := resolver.Resolve(destIP)
			if err == nil && addr != "" {
				if fc := r.getOrCreateForward(addr); fc != nil {
					_ = fc.tunnel.WriteData(1, payload)
				}
			}
			return
		}
		// local TUN or we're the destination
		if tunDev != nil && (destIP == "" || destIP == myIP || !inOverlaySubnet(destIP)) {
			if _, err := tunDev.Write(pkt); err != nil {
				log.Println("overlay tun write:", err)
			}
		}
		return
	}
	if bytes.HasPrefix(payload, []byte(connectPrefix)) {
		target := strings.TrimSpace(string(payload[len(connectPrefix):]))
		if target == "" {
			return
		}
		tcp, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		ch := make(chan []byte, 8)
		r.mu.Lock()
		r.streams[streamID] = &streamRelay{tcp: tcp, ch: ch}
		r.mu.Unlock()
		go r.relayTunnelToTCP(tcp, ch)
		go r.relayTCPToTunnel(t, streamID, tcp)
		return
	}
	r.mu.Lock()
	sr := r.streams[streamID]
	r.mu.Unlock()
	if sr != nil {
		select {
		case sr.ch <- payload:
		default:
		}
	}
}

func (r *Relay) relayTunnelToTCP(tcp net.Conn, ch chan []byte) {
	for payload := range ch {
		if _, err := tcp.Write(payload); err != nil {
			break
		}
	}
}

func (r *Relay) relayTCPToTunnel(t *Tunnel, streamID uint32, tcp net.Conn) {
	io.Copy(&tunnelWriter{t: t, streamID: streamID}, tcp)
	r.closeStream(streamID)
}

func (r *Relay) getStream(streamID uint32) *streamRelay {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.streams[streamID]
}

func (r *Relay) closeStream(streamID uint32) {
	r.mu.Lock()
	sr := r.streams[streamID]
	delete(r.streams, streamID)
	r.mu.Unlock()
	if sr != nil {
		sr.tcp.Close()
		close(sr.ch)
	}
}

func (r *Relay) getOrCreateForward(addr string) *forwardConn {
	r.forwardMu.Lock()
	defer r.forwardMu.Unlock()
	if fc, ok := r.forwardConns[addr]; ok {
		return fc
	}
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil
	}
	r.mu.Lock()
	paddingMax := r.paddingMax
	r.mu.Unlock()
	onData := func(t *Tunnel, _ uint32, payload []byte) {
		if len(payload) > len(overlayPrefix) && bytes.HasPrefix(payload, []byte(overlayPrefix)) {
			r.mu.Lock()
			tunDev := r.tunDev
			r.mu.Unlock()
			if tunDev != nil {
				pkt := payload[len(overlayPrefix):]
				if _, err := tunDev.Write(pkt); err != nil {
					log.Println("overlay forward tun write:", err)
				}
			}
		}
	}
	tunnel := NewTunnel(conn, onData, paddingMax)
	fc := &forwardConn{tunnel: tunnel, conn: conn}
	r.forwardConns[addr] = fc
	go func() {
		_ = tunnel.Run()
		r.forwardMu.Lock()
		delete(r.forwardConns, addr)
		r.forwardMu.Unlock()
		conn.Close()
	}()
	return fc
}

func (r *Relay) tunReadLoop() {
	if r.tunDev == nil {
		return
	}
	buf := make([]byte, 64*1024)
	for {
		n, err := r.tunDev.Read(buf)
		if err != nil {
			log.Println("overlay tun read:", err)
			return
		}
		pkt := buf[:n]
		destIP := parseIPv4Dest(pkt)
		// if dest is overlay peer, forward to that peer
		if destIP != "" && inOverlaySubnet(destIP) {
			r.mu.Lock()
			resolver := r.overlayResolver
			r.mu.Unlock()
			if resolver != nil {
				addr, err := resolver.Resolve(destIP)
				if err == nil && addr != "" {
					if fc := r.getOrCreateForward(addr); fc != nil {
						payload := make([]byte, len(overlayPrefix)+n)
						copy(payload, overlayPrefix)
						copy(payload[len(overlayPrefix):], pkt)
						_ = fc.tunnel.WriteData(1, payload)
					}
					continue
				}
			}
		}
		// send to primary client tunnel
		r.mu.Lock()
		t := r.overlayTunnel
		sid := r.overlayStreamID
		r.mu.Unlock()
		if t == nil {
			continue
		}
		payload := make([]byte, len(overlayPrefix)+n)
		copy(payload, overlayPrefix)
		copy(payload[len(overlayPrefix):], pkt)
		if err := t.WriteData(sid, payload); err != nil {
			log.Println("overlay tunnel write:", err)
			return
		}
	}
}

type tunnelWriter struct {
	t         *Tunnel
	streamID  uint32
}

func (w *tunnelWriter) Write(p []byte) (n int, err error) {
	if err := w.t.WriteData(w.streamID, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
