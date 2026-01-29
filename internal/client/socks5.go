package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// SOCKS5: local listen, connect to exit, relay. Dialer gets (addr, host, port); host = 5-word ID (dots) for dial-by-ID.

const socks5Version = 5

// DialExitFunc (addr, host, port); host raw; if 5-word ID dialer lookup + connect.
type DialExitFunc func(addr, host string, port int) (net.Conn, error)

func handleSOCKS5(conn net.Conn, dialExit DialExitFunc) error {
	defer conn.Close()
	buf := make([]byte, 256)
	// greeting: VER NMETHODS METHODS
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}
	if buf[0] != socks5Version {
		return fmt.Errorf("socks version %d", buf[0])
	}
	n := int(buf[1])
	if n > 0 {
		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			return err
		}
	}
	// reply: VER METHOD (0 = no auth)
	if _, err := conn.Write([]byte{socks5Version, 0}); err != nil {
		return err
	}
	// request: VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return err
	}
	if buf[0] != socks5Version {
		return fmt.Errorf("socks version %d", buf[0])
	}
	if buf[1] != 1 {
		return fmt.Errorf("unsupported cmd %d", buf[1])
	}
	atyp := buf[3]
	var host string
	switch atyp {
	case 1:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return err
		}
		host = net.IP(buf[:4]).String()
	case 3:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return err
		}
		ln := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:ln]); err != nil {
			return err
		}
		host = string(buf[:ln])
	case 4:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return err
		}
		host = net.IP(buf[:16]).String()
	default:
		return fmt.Errorf("unsupported atyp %d", atyp)
	}
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(buf[:2])
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	remote, err := dialExit(addr, host, int(port))
	if err != nil {
		conn.Write([]byte{socks5Version, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer remote.Close()
	// reply success: VER REP RSV ATYP BND.ADDR BND.PORT
	if _, err := conn.Write([]byte{socks5Version, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	// relay
	go io.Copy(remote, conn)
	io.Copy(conn, remote)
	return nil
}

// ServeSOCKS5 listens, runs SOCKS5; dialExit(addr, host, port) opens conn.
func ServeSOCKS5(listenAddr string, dialExit DialExitFunc) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return ServeSOCKS5Listener(ln, dialExit)
}

// ServeSOCKS5Listener serves on ln; caller closes ln to stop.
func ServeSOCKS5Listener(ln net.Listener, dialExit DialExitFunc) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleSOCKS5(conn, dialExit)
	}
}
