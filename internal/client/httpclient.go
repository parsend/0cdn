package client

import (
	"net/http"
	"net/url"
	"os"
	"time"
)

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
