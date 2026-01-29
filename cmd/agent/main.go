// 0cdn agent: edge exit, CDN, reports metrics.
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"dev.c0redev.0cdn/internal/agent"
	"dev.c0redev.0cdn/internal/dht"
	"dev.c0redev.0cdn/internal/overlay"
	"dev.c0redev.0cdn/internal/proto"
	"dev.c0redev.0cdn/internal/transport"
	"dev.c0redev.0cdn/internal/tun"
	"github.com/quic-go/quic-go"
	"strings"
)

func main() {
	serverURL := os.Getenv("0CDN_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8443"
	}
	token := os.Getenv("0CDN_TOKEN")
	if token == "" {
		log.Fatal("0CDN_TOKEN required")
	}
	dataDir := os.Getenv("0CDN_DATA")
	if dataDir == "" {
		dataDir = "."
	}
	nodeID, err := agent.NewNodeID(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("node_id:", nodeID.ID())

	// advertise addr (for registration and metrics)
	listenTCP := os.Getenv("0CDN_TCP_ADDR")
	if listenTCP == "" {
		listenTCP = ":4433"
	}
	ln, err := net.Listen("tcp", listenTCP)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	if os.Getenv("0CDN_MASK_TLS") == "1" {
		cert, err := agent.LoadOrGenerateCert()
		if err != nil {
			log.Fatal("tls cert:", err)
		}
		ln = tls.NewListener(ln, agent.TLSConfigServer(cert))
		log.Println("tls on")
	}

	var tunDev *tun.Device
	if os.Getenv("0CDN_TUN") == "1" {
		dev, err := tun.NewDevice(os.Getenv("0CDN_TUN_IFACE"))
		if err != nil {
			log.Println("tun:", err)
		} else {
			tunDev = dev
			if err := overlay.Up(dev.Name(), os.Getenv("0CDN_TUN_CIDR")); err != nil {
				log.Println("tun up:", err)
			} else {
				log.Println("tun", dev.Name(), "up")
			}
		}
	}
	paddingMax := 0
	if os.Getenv("0CDN_MASK_PADDING") == "1" {
		paddingMax, _ = strconv.Atoi(os.Getenv("0CDN_MASK_PADDING_MAX"))
		if paddingMax <= 0 {
			paddingMax = 64
		}
		if paddingMax > proto.MaxPaddingSize {
			paddingMax = proto.MaxPaddingSize
		}
	}
	relay, tunnelData := agent.NewRelay(tunDev)
	relay.SetPaddingMax(paddingMax)

	var dhtServer *dht.Server
	if dhtListen := os.Getenv("0CDN_DHT_LISTEN"); dhtListen != "" {
		dhtServer = dht.NewServer()
		go func() {
			if err := dhtServer.ListenAndServe(dhtListen); err != nil && !isClosed(err) {
				log.Println("dht listen:", err)
			}
		}()
		log.Println("dht on", dhtListen)
	}

	// resolve overlay_ip from server and set resolver for forwarding; optionally announce to DHT
	go func() {
		time.Sleep(2 * time.Second)
		overlayIP, err := agent.FetchMyOverlayIP(serverURL, token, nodeID.ID())
		if err != nil {
			return
		}
		resolver := agent.NewServerOverlayResolver(serverURL, token, 2*time.Minute)
		relay.SetOverlay(resolver, overlayIP)
		if overlayIP != "" {
			log.Println("overlay forward:", overlayIP)
		}
		if dhtServer != nil && overlayIP != "" {
			dhtServer.Put(nodeID.ID(), listenTCP, overlayIP)
		}
		var bootstrap []string
		if s := os.Getenv("0CDN_DHT_BOOTSTRAP"); s != "" {
			for _, p := range strings.Split(s, ",") {
				if t := strings.TrimSpace(p); t != "" {
					bootstrap = append(bootstrap, t)
				}
			}
		}
		if len(bootstrap) == 0 {
			bootstrap, _ = agent.FetchDHTBootstrap(serverURL, token)
		}
		if len(bootstrap) > 0 {
			dht.Announce(nodeID.ID(), listenTCP, overlayIP, bootstrap, 3*time.Second)
		}
	}()
	tunnelOpts := &agent.TunnelOpts{}
	if os.Getenv("0CDN_PQ") == "1" {
		tunnelOpts.PQEnabled = true
	}
	if os.Getenv("0CDN_AGENT_AUTH") == "1" && token != "" {
		tunnelOpts.AuthToken = token
	}
	go func() {
		if err := agent.ServeTCP(ln, tunnelData, paddingMax, tunnelOpts); err != nil && !isClosed(err) {
			log.Println("tcp tunnel:", err)
		}
	}()
	log.Println("tunnel tcp on", listenTCP)

	if os.Getenv("0CDN_USE_QUIC") == "1" {
		quicAddr := os.Getenv("0CDN_QUIC_ADDR")
		if quicAddr == "" {
			quicAddr = ":443"
		}
		cert, err := agent.LoadOrGenerateCert()
		if err != nil {
			log.Println("quic tls cert:", err)
		} else {
			tlsConf := agent.TLSConfigServer(cert)
			if tlsConf.NextProtos == nil {
				tlsConf.NextProtos = []string{"h3"}
			}
			ql, err := transport.ListenAddr(quicAddr, tlsConf)
			if err != nil {
				log.Println("quic listen:", err)
			} else {
				defer ql.Close()
				go func() {
					for {
						qconn, err := ql.Accept(context.Background())
						if err != nil {
							return
						}
						go handleQUICConn(qconn, tunnelData, paddingMax, tunnelOpts)
					}
				}()
				log.Println("tunnel quic on", quicAddr)
			}
		}
	}

	cdnAddr := os.Getenv("0CDN_HTTP_ADDR")
	if cdnAddr == "" {
		cdnAddr = ":8080"
	}
	cdn := agent.NewCDN(filepath.Join(dataDir, "cdn"))
	cdnSrv := &http.Server{Addr: cdnAddr, Handler: cdn}
	go func() {
		log.Println("cdn http on", cdnAddr)
		if err := cdnSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// fetch sites from server and set CDN upstreams for source_type=url
	go func() {
		time.Sleep(3 * time.Second)
		tick := time.NewTicker(2 * time.Minute)
		defer tick.Stop()
		updateSites := func() {
			sites, err := agent.FetchSites(serverURL, token)
			if err != nil || len(sites) == 0 {
				return
			}
			upstreams := make(map[string]string)
			for _, s := range sites {
				if s.SourceType == "url" && strings.TrimSpace(s.SourceValue) != "" {
					name := strings.TrimSpace(s.Name)
					if name != "" {
						upstreams[name] = strings.TrimSpace(s.SourceValue)
					}
				}
			}
			if len(upstreams) > 0 {
				cdn.SetUpstreams(upstreams)
			}
		}
		updateSites()
		for range tick.C {
			updateSites()
		}
	}()

	reporter := &agent.Reporter{
		ServerURL: serverURL,
		Token:     token,
		NodeID:    nodeID.ID(),
		Addr:      listenTCP,
	}
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
	report := func() {
		if err := reporter.Report("", "", nil, nil); err != nil {
			log.Println("metrics:", err)
		}
	}
	report()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Println("shutting down")
	ln.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = cdnSrv.Shutdown(shutdownCtx)
}

func isClosed(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "use of closed network connection"
}

func handleQUICConn(qconn *quic.Conn, onData agent.OnDataFunc, paddingMax int, opts *agent.TunnelOpts) {
	defer qconn.CloseWithError(0, "")
	ctx := context.Background()
	for {
		stream, err := qconn.AcceptStream(ctx)
		if err != nil {
			return
		}
		var t *agent.Tunnel
		if opts != nil {
			t = agent.NewTunnelWithOpts(stream, onData, paddingMax, opts)
		} else {
			t = agent.NewTunnel(stream, onData, paddingMax)
		}
		go func() { _ = t.Run() }()
	}
}
