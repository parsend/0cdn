// 0cdn client: fetches routes, connects exit, SOCKS5 proxy.
package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dev.c0redev.0cdn/internal/agent"
	"dev.c0redev.0cdn/internal/client"
	"dev.c0redev.0cdn/internal/idwords"
	"dev.c0redev.0cdn/internal/overlay"
	"dev.c0redev.0cdn/internal/proto"
	"dev.c0redev.0cdn/internal/tun"
)

func main() {
	serverURL := client.NormalizeServerURL(os.Getenv("0CDN_SERVER_URL"))
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8443"
	}
	token := os.Getenv("0CDN_TOKEN")
	if token == "" {
		log.Fatal("0CDN_TOKEN required")
	}
	if os.Getenv("0CDN_P2P_EXIT") == "1" {
		var err error
		if os.Getenv("0CDN_P2P_ICE") == "1" {
			ufrag, pwd, candidates, gerr := client.IceGatherWithSTUN()
			if gerr == nil {
				err = client.RegisterP2PExitWithICE(serverURL, token, os.Getenv("0CDN_P2P_ADDR"), "", ufrag, pwd, candidates)
			} else {
				log.Println("p2p ice gather:", gerr, ", registering without ICE")
				err = client.RegisterP2PExit(serverURL, token, "", "")
			}
		} else {
			err = client.RegisterP2PExit(serverURL, token, "", "")
		}
		if err != nil {
			log.Println("p2p register:", err)
		} else {
			log.Println("registered as P2P exit (set 0CDN_P2P_ADDR if not auto)")
		}
	}
	socksAddr := os.Getenv("0CDN_SOCKS_ADDR")
	if socksAddr == "" {
		socksAddr = "127.0.0.1:1080"
	}

	var lookupCache *client.LookupCache
	if ttlSec := os.Getenv("0CDN_DHT_CACHE_TTL"); ttlSec != "" {
		if sec, _ := strconv.Atoi(ttlSec); sec > 0 {
			lookupCache = client.NewLookupCache(time.Duration(sec) * time.Second)
			log.Println("dht lookup cache TTL", sec, "s")
		}
	}

	exits, err := client.FetchRoutes(serverURL, token, "", "")
	if err != nil {
		log.Fatal(err)
	}
	if len(exits) == 0 {
		log.Fatal("no exits from server: start the agent, then add its node_id and addr in the dashboard (Nodes), then run the client again")
	}
	exitAddr := client.PickExit(exits, true)
	if exitAddr == "" {
		exitAddr = exits[0].Addr
	}
	log.Println("using exit", exitAddr)

	var dhtBootstrap []string
	if s := os.Getenv("0CDN_DHT_BOOTSTRAP"); s != "" {
		for _, p := range strings.Split(s, ",") {
			if t := strings.TrimSpace(p); t != "" {
				dhtBootstrap = append(dhtBootstrap, t)
			}
		}
	}
	if len(dhtBootstrap) == 0 {
		peers, _ := client.FetchDHTBootstrap(serverURL, token)
		dhtBootstrap = peers
	}

	dialExit := func(addr, host string, port int) (net.Conn, error) {
		nodeID := strings.ReplaceAll(host, ".", ":")
		if idwords.ValidFiveWordID(nodeID) {
			res, err := client.LookupNodeWithDHTFull(serverURL, token, nodeID, lookupCache, dhtBootstrap)
			if err != nil || res == nil || res.Addr == "" {
				return nil, err
			}
			target := "127.0.0.1:" + strconv.Itoa(port)
			if res.IceUfrag != "" && res.IcePwd != "" && res.IceCandidates != "" {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				iceConn, err := client.IceDial(ctx, res.IceUfrag, res.IcePwd, res.IceCandidates)
				cancel()
				if err == nil && iceConn != nil {
					return client.DialExitStreamFromConn(iceConn, target)
				}
			}
			return client.DialExitStream(res.Addr, target)
		}
		return client.DialExitStream(exitAddr, addr)
	}
	socksLn, err := net.Listen("tcp", socksAddr)
	if err != nil {
		log.Fatal("socks5 listen:", err)
	}
	defer socksLn.Close()
	go func() {
		_ = client.ServeSOCKS5Listener(socksLn, dialExit)
	}()
	log.Println("socks5 on", socksAddr)

	if os.Getenv("0CDN_TUN") == "1" {
		dev, err := tun.NewDevice(os.Getenv("0CDN_TUN_IFACE"))
		if err != nil {
			log.Println("tun:", err)
		} else {
			tunExitAddr, err := overlay.ResolveExit(serverURL, token, lookupCache, dhtBootstrap)
			if err != nil || tunExitAddr == "" {
				log.Println("tun exit resolve:", err, "using default exit")
				tunExitAddr = exitAddr
			} else {
				log.Println("tun exit", tunExitAddr)
			}
			cidr := os.Getenv("0CDN_TUN_CIDR")
			if cidr == "" {
				cidr = "10.200.0.2/24"
			}
			if err := overlay.Up(dev.Name(), cidr); err != nil {
				log.Println("tun up:", err)
			}
			gw := os.Getenv("0CDN_TUN_GW")
			if gw != "" {
				_ = overlay.DefaultGW(dev.Name(), gw)
			}
			log.Println("tun", dev.Name(), cidr)
			go func() {
				if err := overlay.Run(dev, tunExitAddr); err != nil {
					log.Println("overlay:", err)
				}
			}()
		}
	}

	var p2pLn net.Listener
	if p2pListen := os.Getenv("0CDN_P2P_LISTEN"); p2pListen != "" {
		var err error
		p2pLn, err = net.Listen("tcp", p2pListen)
		if err != nil {
			log.Println("p2p listen:", err)
		} else {
			defer p2pLn.Close()
			paddingMax := 0
			if os.Getenv("0CDN_MASK_PADDING") == "1" {
				if n, _ := strconv.Atoi(os.Getenv("0CDN_MASK_PADDING_MAX")); n > 0 {
					paddingMax = n
					if paddingMax > proto.MaxPaddingSize {
						paddingMax = proto.MaxPaddingSize
					}
				} else {
					paddingMax = 64
				}
			}
			var tunnelOpts *agent.TunnelOpts
			if os.Getenv("0CDN_PQ") == "1" || (os.Getenv("0CDN_AGENT_AUTH") == "1" && token != "") {
				tunnelOpts = &agent.TunnelOpts{}
				if os.Getenv("0CDN_PQ") == "1" {
					tunnelOpts.PQEnabled = true
				}
				if os.Getenv("0CDN_AGENT_AUTH") == "1" && token != "" {
					tunnelOpts.AuthToken = token
				}
			}
			go func() {
				for {
					conn, err := p2pLn.Accept()
					if err != nil {
						return
					}
					_, onData := agent.NewRelay(nil)
					var t *agent.Tunnel
					if tunnelOpts != nil {
						t = agent.NewTunnelWithOpts(conn, onData, paddingMax, tunnelOpts)
					} else {
						t = agent.NewTunnel(conn, onData, paddingMax)
					}
					go func() { _ = t.Run() }()
				}
			}()
			log.Println("p2p listener on", p2pListen)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
	if p2pLn != nil {
		p2pLn.Close()
	}
}
