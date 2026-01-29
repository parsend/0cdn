package client

import (
	"testing"
	"time"
)

func TestLookupCacheDisabled(t *testing.T) {
	c := NewLookupCache(0)
	c.Set("n1", "1.2.3.4:4433")
	addr, ok := c.Get("n1")
	if ok || addr != "" {
		t.Fatalf("disabled cache should miss: addr=%q ok=%v", addr, ok)
	}
}

func TestLookupCacheGetSet(t *testing.T) {
	c := NewLookupCache(5 * time.Second)
	c.Set("n1", "1.2.3.4:4433")
	addr, ok := c.Get("n1")
	if !ok || addr != "1.2.3.4:4433" {
		t.Fatalf("Get: addr=%q ok=%v", addr, ok)
	}
	addr, ok = c.Get("n2")
	if ok || addr != "" {
		t.Fatalf("Get unknown: addr=%q ok=%v", addr, ok)
	}
}

func TestLookupCacheExpiry(t *testing.T) {
	c := NewLookupCache(10 * time.Millisecond)
	c.Set("n1", "1.2.3.4:4433")
	addr, ok := c.Get("n1")
	if !ok || addr != "1.2.3.4:4433" {
		t.Fatalf("Get before expiry: addr=%q ok=%v", addr, ok)
	}
	time.Sleep(25 * time.Millisecond)
	addr, ok = c.Get("n1")
	if ok || addr != "" {
		t.Fatalf("Get after expiry should miss: addr=%q ok=%v", addr, ok)
	}
}

func TestLookupCacheSetEmptyAddr(t *testing.T) {
	c := NewLookupCache(5 * time.Second)
	c.Set("n1", "")
	addr, ok := c.Get("n1")
	if ok || addr != "" {
		t.Fatalf("Set empty addr should not store: addr=%q ok=%v", addr, ok)
	}
}
