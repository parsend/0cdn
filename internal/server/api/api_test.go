package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"dev.c0redev.0cdn/internal/server/auth"
	"dev.c0redev.0cdn/internal/store"
)

func TestAPI(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := New(db)

	t.Run("health", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rr := httptest.NewRecorder()
		srv.HandleHealth(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("health: got %d", rr.Code)
		}
		var out struct{ Status string }
		if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		if out.Status != "ok" {
			t.Fatalf("status: %q", out.Status)
		}
	})

	t.Run("ready", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rr := httptest.NewRecorder()
		srv.HandleReady(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("ready: got %d", rr.Code)
		}
	})

	t.Run("register_short_password_rejected", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"login": "x", "password": "12345"})
		req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		srv.HandleRegister(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("short password: expected 400, got %d", rr.Code)
		}
	})

	t.Run("register_and_login", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"login": "testuser", "password": "pass123"})
		req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		srv.HandleRegister(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("register: got %d %s", rr.Code, rr.Body.String())
		}

		req = httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr = httptest.NewRecorder()
		srv.HandleLogin(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("login: got %d", rr.Code)
		}
		var tok struct{ Token string }
		if err := json.NewDecoder(rr.Body).Decode(&tok); err != nil || tok.Token == "" {
			t.Fatalf("login token: %v %q", err, tok.Token)
		}

		t.Run("password_change", func(t *testing.T) {
			// wrong old password -> 401
			bodyPw, _ := json.Marshal(map[string]string{"old_password": "wrong", "new_password": "newpass123"})
			reqPw := httptest.NewRequest(http.MethodPost, "/api/password", bytes.NewReader(bodyPw))
			reqPw.Header.Set("Authorization", "Bearer "+tok.Token)
			reqPw.Header.Set("Content-Type", "application/json")
			rrPw := httptest.NewRecorder()
			srv.HandlePassword(rrPw, reqPw)
			if rrPw.Code != http.StatusUnauthorized {
				t.Fatalf("password wrong old: expected 401, got %d", rrPw.Code)
			}
			// correct old -> 204
			bodyPw, _ = json.Marshal(map[string]string{"old_password": "pass123", "new_password": "newpass123"})
			reqPw = httptest.NewRequest(http.MethodPost, "/api/password", bytes.NewReader(bodyPw))
			reqPw.Header.Set("Authorization", "Bearer "+tok.Token)
			reqPw.Header.Set("Content-Type", "application/json")
			rrPw = httptest.NewRecorder()
			srv.HandlePassword(rrPw, reqPw)
			if rrPw.Code != http.StatusNoContent {
				t.Fatalf("password change: expected 204, got %d %s", rrPw.Code, rrPw.Body.String())
			}
			// login with new password works
			bodyNew, _ := json.Marshal(map[string]string{"login": "testuser", "password": "newpass123"})
			reqLogin := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(bodyNew))
			reqLogin.Header.Set("Content-Type", "application/json")
			rrLogin := httptest.NewRecorder()
			srv.HandleLogin(rrLogin, reqLogin)
			if rrLogin.Code != http.StatusOK {
				t.Fatalf("login with new password: got %d", rrLogin.Code)
			}
			// old password fails
			reqLogin = httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
			reqLogin.Header.Set("Content-Type", "application/json")
			rrLogin = httptest.NewRecorder()
			srv.HandleLogin(rrLogin, reqLogin)
			if rrLogin.Code == http.StatusOK {
				t.Fatal("old password should not work after change")
			}
		})

		t.Run("token_regenerate_invalidates_old", func(t *testing.T) {
			oldToken := tok.Token
			req := httptest.NewRequest(http.MethodPost, "/api/token", nil)
			req.Header.Set("Authorization", "Bearer "+oldToken)
			rr := httptest.NewRecorder()
			srv.HandleToken(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("token: got %d", rr.Code)
			}
			var newTok struct{ Token string }
			json.NewDecoder(rr.Body).Decode(&newTok)
			if newTok.Token == "" || newTok.Token == oldToken {
				t.Fatal("expected new different token")
			}
			reqGet := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
			reqGet.Header.Set("Authorization", "Bearer "+oldToken)
			rrGet := httptest.NewRecorder()
			srv.HandleNodes(rrGet, reqGet)
			if rrGet.Code != http.StatusUnauthorized {
				t.Fatalf("old token should be 401, got %d", rrGet.Code)
			}
			reqGet.Header.Set("Authorization", "Bearer "+newTok.Token)
			rrGet = httptest.NewRecorder()
			srv.HandleNodes(rrGet, reqGet)
			if rrGet.Code != http.StatusOK {
				t.Fatalf("new token should be 200, got %d", rrGet.Code)
			}
		})
	})

	t.Run("nodes_add_list", func(t *testing.T) {
		hash, _ := auth.HashPassword("p")
		uid, _ := db.CreateUser("nuser", hash)
		tok, _ := db.CreateToken(uid)

		req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		srv.HandleNodes(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("list nodes: %d", rr.Code)
		}
		var nodes []NodeDTO
		json.NewDecoder(rr.Body).Decode(&nodes)
		if len(nodes) != 0 {
			t.Fatalf("expected 0 nodes, got %d", len(nodes))
		}

		body, _ := json.Marshal(map[string]interface{}{"addr": "1.2.3.4:4433", "node_id": "abc:def:ghi:jkl:mno", "is_p2p": false})
		req = httptest.NewRequest(http.MethodPost, "/api/nodes", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		rr = httptest.NewRecorder()
		srv.HandleNodes(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("add node: %d %s", rr.Code, rr.Body.String())
		}

		req = httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rr = httptest.NewRecorder()
		srv.HandleNodes(rr, req)
		json.NewDecoder(rr.Body).Decode(&nodes)
		if len(nodes) != 1 || nodes[0].NodeID != "abc:def:ghi:jkl:mno" {
			t.Fatalf("expected 1 node: %+v", nodes)
		}
	})

	t.Run("lookup_p2p_fallback", func(t *testing.T) {
		hashA, _ := auth.HashPassword("a")
		hashB, _ := auth.HashPassword("b")
		uidA, _ := db.CreateUser("userA", hashA)
		uidB, _ := db.CreateUser("userB", hashB)
		tokA, _ := db.CreateToken(uidA)
		tokB, _ := db.CreateToken(uidB)
		_ = db.UpsertNode("p2p:node:id:five:words", uidA, "9.9.9.9:4433", "", "", nil, nil, true)
		req := httptest.NewRequest(http.MethodGet, "/api/nodes/lookup?node_id=p2p:node:id:five:words", nil)
		req.Header.Set("Authorization", "Bearer "+tokB)
		rr := httptest.NewRecorder()
		srv.HandleNodesLookup(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("lookup P2P fallback: got %d", rr.Code)
		}
		var out struct{ Addr string }
		json.NewDecoder(rr.Body).Decode(&out)
		if out.Addr != "9.9.9.9:4433" {
			t.Fatalf("lookup P2P: addr=%q", out.Addr)
		}
		_ = tokA
	})
}
