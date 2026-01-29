package agent

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// FetchDHTBootstrap returns bootstrap addrs from GET /api/dht/bootstrap (DHT announce).
func FetchDHTBootstrap(serverURL, token string) ([]string, error) {
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" || token == "" {
		return nil, nil
	}
	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "https://" + serverURL
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
		if t := strings.TrimSpace(p); t != "" {
			peers = append(peers, t)
		}
	}
	return peers, nil
}

// FetchMyOverlayIP returns overlay_ip for nodeID from GET /api/nodes (relay overlay).
func FetchMyOverlayIP(serverURL, token, nodeID string) (string, error) {
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" || token == "" || nodeID == "" {
		return "", nil
	}
	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "https://" + serverURL
	}
	req, err := http.NewRequest(http.MethodGet, serverURL+"/api/nodes", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := HTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}
	var nodes []struct {
		NodeID    string `json:"node_id"`
		OverlayIP string `json:"overlay_ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		return "", err
	}
	for _, n := range nodes {
		if n.NodeID == nodeID && n.OverlayIP != "" {
			return n.OverlayIP, nil
		}
	}
	return "", nil
}

// SiteEntry: one site from GET /api/sites.
type SiteEntry struct {
	Name         string `json:"name"`
	SourceType   string `json:"source_type"`
	SourceValue  string `json:"source_value"`
}

// FetchSites returns sites for the token's user. Used by agent to set CDN upstreams (source_type=url).
func FetchSites(serverURL, token string) ([]SiteEntry, error) {
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" || token == "" {
		return nil, nil
	}
	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "https://" + serverURL
	}
	req, err := http.NewRequest(http.MethodGet, serverURL+"/api/sites", nil)
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
	var sites []SiteEntry
	if err := json.NewDecoder(resp.Body).Decode(&sites); err != nil {
		return nil, err
	}
	return sites, nil
}

// HTTPClient returns http.Client with 0CDN_TOR_PROXY / 0CDN_I2P_PROXY if set.
func HTTPClient() *http.Client {
	transport := &http.Transport{}
	if s := os.Getenv("0CDN_TOR_PROXY"); s != "" {
		if u, err := url.Parse(s); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	if s := os.Getenv("0CDN_I2P_PROXY"); s != "" {
		if u, err := url.Parse(s); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
}
