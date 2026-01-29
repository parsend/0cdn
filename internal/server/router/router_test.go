package router

import (
	"testing"
	"time"

	"dev.c0redev.0cdn/internal/proto"
	"dev.c0redev.0cdn/internal/store"
)

func mkNode(id, addr, country, city string, rtt *int, lastSeen *time.Time) store.Node {
	return store.Node{
		NodeID: id, Addr: addr, Country: country, City: city,
		RTTMs: rtt, LastSeenAt: lastSeen, CreatedAt: time.Now(),
	}
}

func TestSelectExits_Empty(t *testing.T) {
	out := SelectExits(nil, "", "")
	if out != nil {
		t.Fatalf("expected nil, got %d", len(out))
	}
	out = SelectExits([]store.Node{}, "", "")
	if out != nil {
		t.Fatalf("expected nil, got %d", len(out))
	}
}

func TestSelectExits_Single(t *testing.T) {
	n := mkNode("n1", "1.2.3.4:4433", "RU", "Moscow", nil, nil)
	out := SelectExits([]store.Node{n}, "", "")
	if len(out) != 1 {
		t.Fatalf("expected 1 exit, got %d", len(out))
	}
	if out[0].NodeID != "n1" || out[0].Addr != "1.2.3.4:4433" {
		t.Fatalf("exit: %+v", out[0])
	}
}

func TestSelectExits_ThreeSameLocation(t *testing.T) {
	rtt1, rtt2, rtt3 := 10, 50, 30
	now := time.Now()
	nodes := []store.Node{
		mkNode("n1", "a:1", "RU", "Moscow", &rtt1, &now),
		mkNode("n2", "b:2", "RU", "Moscow", &rtt2, &now),
		mkNode("n3", "c:3", "RU", "Moscow", &rtt3, &now),
	}
	out := SelectExits(nodes, "RU", "Moscow")
	if len(out) != 3 {
		t.Fatalf("expected 3, got %d", len(out))
	}
	// same loc with hint: prefer RU/Moscow, sorted by RTT (10, 30, 50)
	if out[0].NodeID != "n1" || out[0].Addr != "a:1" {
		t.Fatalf("first should be lowest RTT: %+v", out[0])
	}
	if out[1].NodeID != "n3" {
		t.Fatalf("second: %+v", out[1])
	}
	if out[2].NodeID != "n2" {
		t.Fatalf("third: %+v", out[2])
	}
}

func TestSelectExits_GeoHint(t *testing.T) {
	rtt := 5
	now := time.Now()
	nodes := []store.Node{
		mkNode("ru1", "a:1", "RU", "Moscow", &rtt, &now),
		mkNode("ru2", "a:2", "RU", "Moscow", &rtt, &now),
		mkNode("ru3", "a:3", "RU", "Moscow", &rtt, &now),
		mkNode("de1", "b:1", "DE", "Berlin", &rtt, &now),
		mkNode("de2", "b:2", "DE", "Berlin", &rtt, &now),
		mkNode("de3", "b:3", "DE", "Berlin", &rtt, &now),
	}
	out := SelectExits(nodes, "DE", "Berlin")
	if len(out) != 6 {
		t.Fatalf("expected 6, got %d", len(out))
	}
	seen := make(map[string]bool)
	for _, e := range out {
		seen[e.NodeID] = true
	}
	for _, id := range []string{"ru1", "ru2", "ru3", "de1", "de2", "de3"} {
		if !seen[id] {
			t.Fatalf("missing exit %s", id)
		}
	}
	// DE/Berlin hint: DE nodes get priority 100 (higher than 0)
	var dePriority int32 = 0
	for _, e := range out {
		if e.Country == "DE" {
			if e.Priority > dePriority {
				dePriority = e.Priority
			}
		}
	}
	if dePriority < 100 {
		t.Fatalf("DE nodes should have priority >= 100 when hint matches, got %d", dePriority)
	}
}

func TestSelectExits_ReturnsProtoEntries(t *testing.T) {
	n := mkNode("x", "1.1.1.1:1", "US", "NYC", nil, nil)
	out := SelectExits([]store.Node{n}, "", "")
	if len(out) != 1 {
		t.Fatal("expected 1")
	}
	var _ proto.ExitEntry = out[0]
}
