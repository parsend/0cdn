package store

import (
	"testing"
)

func TestOpenMemory(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
}

func TestUserAndToken(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	id, err := db.CreateUser("alice", "hash1")
	if err != nil {
		t.Fatal(err)
	}
	if id <= 0 {
		t.Fatal("expected positive user id")
	}

	u, err := db.UserByLogin("alice")
	if err != nil || u == nil {
		t.Fatal("UserByLogin alice", err)
	}
	if u.ID != id || u.Login != "alice" {
		t.Fatalf("user mismatch: %+v", u)
	}

	tok1, err := db.CreateToken(id)
	if err != nil {
		t.Fatal(err)
	}
	if tok1 == "" {
		t.Fatal("empty token")
	}
	uid, ok := db.UserIDByToken(tok1)
	if !ok || uid != id {
		t.Fatalf("UserIDByToken: got %d %v", uid, ok)
	}

	tok2, err := db.ReplaceToken(id)
	if err != nil {
		t.Fatal(err)
	}
	if tok2 == "" || tok2 == tok1 {
		t.Fatalf("ReplaceToken should return new token")
	}
	if uid, ok := db.UserIDByToken(tok1); ok {
		t.Fatalf("old token should be invalid, got uid %d", uid)
	}
	if uid, ok := db.UserIDByToken(tok2); !ok || uid != id {
		t.Fatalf("new token should be valid: %d %v", uid, ok)
	}
}

func TestNodeCRUD(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	uid, _ := db.CreateUser("bob", "hash")
	_, _ = db.CreateToken(uid)

	if err := db.UpsertNode("n1", uid, "1.2.3.4:4433", "RU", "Moscow", nil, nil, false); err != nil {
		t.Fatal(err)
	}
	list, err := db.ListNodes(&uid)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListNodes: %v len=%d", err, len(list))
	}
	if list[0].NodeID != "n1" || list[0].Addr != "1.2.3.4:4433" {
		t.Fatalf("node: %+v", list[0])
	}

	addr, overlay, err := db.NodeAddrByID(uid, "n1")
	if err != nil || addr != "1.2.3.4:4433" {
		t.Fatalf("NodeAddrByID: addr=%q overlay=%q err=%v", addr, overlay, err)
	}

	if err := db.DeleteNode("n1", uid); err != nil {
		t.Fatal(err)
	}
	list, _ = db.ListNodes(&uid)
	if len(list) != 0 {
		t.Fatalf("expected 0 nodes after delete, got %d", len(list))
	}
}

func TestSiteCRUD(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	uid, _ := db.CreateUser("carol", "hash")
	if err := db.CreateSite(uid, "mysite", "url", "https://example.com"); err != nil {
		t.Fatal(err)
	}
	sites, err := db.SitesByUser(uid)
	if err != nil || len(sites) != 1 {
		t.Fatalf("SitesByUser: %v len=%d", err, len(sites))
	}
	sid := sites[0].ID

	s, err := db.SiteByName("mysite.0cdn")
	if err != nil || s == nil || s.Name != "mysite" {
		t.Fatalf("SiteByName: %v %+v", err, s)
	}

	if err := db.DeleteSite(sid, uid); err != nil {
		t.Fatal(err)
	}
	sites, _ = db.SitesByUser(uid)
	if len(sites) != 0 {
		t.Fatalf("expected 0 sites after delete, got %d", len(sites))
	}
}

func TestUpsertNodeOtherUser(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	u1, _ := db.CreateUser("u1", "h1")
	u2, _ := db.CreateUser("u2", "h2")
	_ = db.UpsertNode("same-node", u1, "1.1.1.1:1", "", "", nil, nil, false)
	err = db.UpsertNode("same-node", u2, "2.2.2.2:2", "", "", nil, nil, false)
	if err == nil {
		t.Fatal("expected error when other user claims same node_id")
	}
}

func TestNodeAddrByIDPublic(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	uid, _ := db.CreateUser("alice", "hash")
	_ = db.UpsertNode("p2p-node", uid, "5.5.5.5:4433", "", "", nil, nil, true)
	_ = db.UpsertNode("private-node", uid, "6.6.6.6:4433", "", "", nil, nil, false)

	addr, _, err := db.NodeAddrByIDPublic("p2p-node")
	if err != nil || addr != "5.5.5.5:4433" {
		t.Fatalf("NodeAddrByIDPublic(p2p): addr=%q err=%v", addr, err)
	}
	addr, _, err = db.NodeAddrByIDPublic("private-node")
	if err != nil || addr != "" {
		t.Fatalf("NodeAddrByIDPublic(private) should be empty: addr=%q err=%v", addr, err)
	}
	addr, _, err = db.NodeAddrByIDPublic("nonexistent")
	if err != nil || addr != "" {
		t.Fatalf("NodeAddrByIDPublic(nonexistent) should be empty: addr=%q err=%v", addr, err)
	}
}
