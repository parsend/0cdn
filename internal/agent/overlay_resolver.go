package agent

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OverlayResolver: overlay_ip -> peer addr (fwd); cache TTL.
type OverlayResolver interface {
	Resolve(overlayIP string) (addr string, err error)
}

type serverOverlayResolver struct {
	serverURL string
	token     string
	client    *http.Client
	mu        sync.RWMutex
	cache     map[string]cacheEntry
	ttl       time.Duration
}

type cacheEntry struct {
	addr    string
	expires time.Time
}

// NewServerOverlayResolver calls GET /api/overlay/route, caches; serverURL with scheme, Bearer token.
func NewServerOverlayResolver(serverURL, token string, cacheTTL time.Duration) OverlayResolver {
	r := &serverOverlayResolver{
		serverURL: strings.TrimSpace(serverURL),
		token:     token,
		client:    HTTPClient(),
		cache:     make(map[string]cacheEntry),
		ttl:       cacheTTL,
	}
	if r.ttl <= 0 {
		r.ttl = 2 * time.Minute
	}
	go r.cleanup()
	return r
}

func (r *serverOverlayResolver) cleanup() {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for range tick.C {
		r.mu.Lock()
		now := time.Now()
		for k, e := range r.cache {
			if e.expires.Before(now) {
				delete(r.cache, k)
			}
		}
		r.mu.Unlock()
	}
}

func (r *serverOverlayResolver) Resolve(overlayIP string) (string, error) {
	if overlayIP == "" {
		return "", nil
	}
	r.mu.RLock()
	e, ok := r.cache[overlayIP]
	r.mu.RUnlock()
	if ok && time.Now().Before(e.expires) {
		return e.addr, nil
	}
	u := r.serverURL + "/api/overlay/route?overlay_ip=" + url.QueryEscape(overlayIP)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}
	var out struct {
		Addr string `json:"addr"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Addr == "" {
		return "", nil
	}
	r.mu.Lock()
	r.cache[overlayIP] = cacheEntry{addr: out.Addr, expires: time.Now().Add(r.ttl)}
	r.mu.Unlock()
	return out.Addr, nil
}
