package transport

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// streamConn wraps quic.Stream as net.Conn (TunnelClient).
type streamConn struct {
	*quic.Stream
	conn *quic.Conn
}

func (c *streamConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// DefaultQUICClientTLS TLS for QUIC client (InsecureSkipVerify, ALPN h3).
func DefaultQUICClientTLS() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h3"},
	}
}

// DialStream dials QUIC to addr, one stream, returns net.Conn.
func DialStream(ctx context.Context, addr string, tlsConfig *tls.Config) (net.Conn, error) {
	if tlsConfig == nil {
		tlsConfig = DefaultQUICClientTLS()
	}
	conn, err := quic.DialAddr(ctx, addr, tlsConfig, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	return &streamConn{Stream: stream, conn: conn}, nil
}

// ListenAddr QUIC listen on addr; tlsConfig with Certificates.
func ListenAddr(addr string, tlsConfig *tls.Config) (*quic.Listener, error) {
	if tlsConfig == nil {
		return nil, nil
	}
	return quic.ListenAddr(addr, tlsConfig, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
}
