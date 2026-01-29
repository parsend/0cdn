package agent

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// CDN serves by Host (e.g. mysite.0cdn): cache, disk, or upstream URL.
type CDN struct {
	RootDir   string
	mu        sync.RWMutex
	cache     map[string][]byte
	upstreams map[string]string // site name -> base URL for proxy (e.g. https://example.com)
	upMu      sync.RWMutex
	client    *http.Client
}

// NewCDN creates CDN; root dir for static files. Upstream uses HTTPClient() (proxy-aware).
func NewCDN(rootDir string) *CDN {
	return &CDN{
		RootDir:   rootDir,
		cache:     make(map[string][]byte),
		upstreams: make(map[string]string),
		client:    nil, // use HTTPClient() for upstream so 0CDN_TOR_PROXY works
	}
}

// SetUpstream sets base URL for site; empty = remove.
func (c *CDN) SetUpstream(siteName, url string) {
	c.upMu.Lock()
	defer c.upMu.Unlock()
	siteName = strings.TrimSuffix(strings.TrimSpace(siteName), ".0cdn")
	if url == "" {
		delete(c.upstreams, siteName)
		return
	}
	url = strings.TrimSuffix(strings.TrimSpace(url), "/")
	c.upstreams[siteName] = url
}

// SetUpstreams replaces upstream map (e.g. from GET /api/sites).
func (c *CDN) SetUpstreams(sites map[string]string) {
	c.upMu.Lock()
	defer c.upMu.Unlock()
	c.upstreams = make(map[string]string)
	for name, u := range sites {
		name = strings.TrimSuffix(strings.TrimSpace(name), ".0cdn")
		u = strings.TrimSuffix(strings.TrimSpace(u), "/")
		if name != "" && u != "" {
			c.upstreams[name] = u
		}
	}
}

// SetCache stores body for key.
func (c *CDN) SetCache(key string, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = body
}

// GetCache returns cached body or nil.
func (c *CDN) GetCache(key string) []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache[key]
}

// ServeHTTP: Host+path -> cache or RootDir/site/path.
func (c *CDN) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	path := r.URL.Path
	if path == "" || path == "/" {
		path = "/index.html"
	}
	key := host + path
	if body := c.GetCache(key); body != nil {
		w.Header().Set("Content-Type", inferContentType(path))
		w.WriteHeader(http.StatusOK)
		w.Write(body)
		return
	}
	if c.RootDir != "" {
		site := strings.TrimSuffix(host, ".0cdn")
		if site == host {
			site = host
		}
		fpath := filepath.Join(c.RootDir, site, filepath.Clean(path))
		if !strings.HasPrefix(fpath, filepath.Clean(c.RootDir)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		data, err := os.ReadFile(fpath)
		if err == nil {
			w.Header().Set("Content-Type", inferContentType(path))
			w.WriteHeader(http.StatusOK)
			w.Write(data)
			return
		}
	}
	// upstream: source_type=url from server
	c.upMu.RLock()
	baseURL := c.upstreams[strings.TrimSuffix(host, ".0cdn")]
	if baseURL == "" {
		baseURL = c.upstreams[host]
	}
	c.upMu.RUnlock()
	if baseURL != "" {
		upstreamURL := baseURL + path
		client := c.client
		if client == nil {
			client = HTTPClient()
		}
		resp, err := client.Get(upstreamURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil && len(data) > 0 {
				c.SetCache(key, data)
				w.Header().Set("Content-Type", inferContentType(path))
				w.WriteHeader(http.StatusOK)
				w.Write(data)
				return
			}
		}
	}
	http.NotFound(w, r)
}

func inferContentType(path string) string {
	switch filepath.Ext(path) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".ico":
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}
