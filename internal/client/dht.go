package client

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"dev.c0redev.0cdn/internal/dht"
)

// LookupCache: node_id -> addr cache; TTL for staleness.
type LookupCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	addr    string
	expires time.Time
}

// NewLookupCache creates cache with TTL; ttl<=0 = disabled.
func NewLookupCache(ttl time.Duration) *LookupCache {
	if ttl <= 0 {
		return &LookupCache{ttl: 0, entries: make(map[string]cacheEntry)}
	}
	c := &LookupCache{ttl: ttl, entries: make(map[string]cacheEntry)}
	go c.cleanup()
	return c
}

func (c *LookupCache) cleanup() {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for range tick.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.entries {
			if v.expires.Before(now) {
				delete(c.entries, k)
			}
		}
		c.mu.Unlock()
	}
}

// Get returns addr for node_id if cached, not expired.
func (c *LookupCache) Get(nodeID string) (addr string, ok bool) {
	if c.ttl <= 0 {
		return "", false
	}
	c.mu.RLock()
	e, ok := c.entries[nodeID]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return "", false
	}
	return e.addr, true
}

// Set stores node_id -> addr with TTL.
func (c *LookupCache) Set(nodeID, addr string) {
	if c.ttl <= 0 || addr == "" {
		return
	}
	c.mu.Lock()
	c.entries[nodeID] = cacheEntry{addr: addr, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

// LookupNodeWithCache: cache first, then server; cache on success.
func LookupNodeWithCache(serverURL, token, nodeID string, cache *LookupCache) (addr string, err error) {
	return LookupNodeWithDHT(serverURL, token, nodeID, cache, nil)
}

// LookupNodeWithDHT: cache, server, then DHT bootstrap (server blocked).
func LookupNodeWithDHT(serverURL, token, nodeID string, cache *LookupCache, dhtBootstrap []string) (addr string, err error) {
	res, err := LookupNodeWithDHTFull(serverURL, token, nodeID, cache, dhtBootstrap)
	if err != nil || res == nil {
		return "", err
	}
	return res.Addr, nil
}

// LookupNodeWithDHTFull: cache/server first (+ ICE), then DHT (addr only).
func LookupNodeWithDHTFull(serverURL, token, nodeID string, cache *LookupCache, dhtBootstrap []string) (*LookupResult, error) {
	if cache != nil {
		if a, ok := cache.Get(nodeID); ok {
			return &LookupResult{Addr: a}, nil
		}
	}
	res, err := LookupNodeFull(serverURL, token, nodeID)
	if err == nil && res != nil && res.Addr != "" {
		if cache != nil {
			cache.Set(nodeID, res.Addr)
		}
		return res, nil
	}
	if len(dhtBootstrap) > 0 {
		addr := dht.Lookup(nodeID, dhtBootstrap, 5*time.Second)
		if addr != "" {
			if cache != nil {
				cache.Set(nodeID, addr)
			}
			return &LookupResult{Addr: addr}, nil
		}
	}
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// FetchDHTBootstrap returns bootstrap addrs from GET /api/dht/bootstrap.
func FetchDHTBootstrap(serverURL, token string) ([]string, error) {
	serverURL = NormalizeServerURL(serverURL)
	if serverURL == "" || token == "" {
		return nil, nil
	}
	req, err := http.NewRequest(http.MethodGet, serverURL+"/api/dht/bootstrap", nil)
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
		return nil, nil
	}
	var out struct {
		Peers []string `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	var peers []string
	for _, p := range out.Peers {
		p = strings.TrimSpace(p)
		if p != "" {
			peers = append(peers, p)
		}
	}
	return peers, nil
}
