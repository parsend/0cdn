package api

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"dev.c0redev.0cdn/internal/server/auth"
	"dev.c0redev.0cdn/internal/server/router"
	"dev.c0redev.0cdn/internal/store"
)

// Server holds API deps.
type Server struct {
	DB           *store.DB
	iceSignalsMu sync.Mutex
	iceSignals   map[string]iceSignal
	rateLimitMu  sync.Mutex
	rateLimit    map[string]rateLimitEntry
}

type rateLimitEntry struct {
	count int
	until time.Time
}

const rateLimitWindow = time.Minute
const rateLimitMaxPerIP = 120
const rateLimitMaxPerToken = 300

type iceSignal struct {
	Ufrag      string `json:"ufrag"`
	Pwd        string `json:"pwd"`
	Candidates string `json:"candidates"`
}

// New returns API server.
func New(db *store.DB) *Server {
	return &Server{DB: db, iceSignals: make(map[string]iceSignal), rateLimit: make(map[string]rateLimitEntry)}
}

// allowLookup false if rate limit (per IP/token); call before lookup/overlay.
func (s *Server) allowLookup(r *http.Request) bool {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	token := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	now := time.Now()
	s.rateLimitMu.Lock()
	defer s.rateLimitMu.Unlock()
	check := func(key string, max int) bool {
		e, ok := s.rateLimit[key]
		if !ok || now.After(e.until) {
			s.rateLimit[key] = rateLimitEntry{count: 1, until: now.Add(rateLimitWindow)}
			return true
		}
		if e.count >= max {
			return false
		}
		e.count++
		s.rateLimit[key] = e
		return true
	}
	if !check("ip:"+ip, rateLimitMaxPerIP) {
		return false
	}
	if token != "" {
		tk := token
		if len(tk) > 32 {
			tk = tk[:32]
		}
		if !check("token:"+tk, rateLimitMaxPerToken) {
			return false
		}
	}
	return true
}

// LoginRequest body.
type LoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// RegisterRequest body.
type RegisterRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// TokenResponse body.
type TokenResponse struct {
	Token string `json:"token"`
}

// RoutesResponse body (for client).
type RoutesResponse struct {
	Exits []ExitDTO `json:"exits"`
}

type ExitDTO struct {
	NodeID    string `json:"node_id"`
	Addr      string `json:"addr"`
	OverlayIP string `json:"overlay_ip,omitempty"`
	Priority  int32  `json:"priority"`
	Country   string `json:"country"`
	City      string `json:"city"`
	IsP2P     bool   `json:"is_p2p"`
}

// NodeDTO for GET /api/nodes list (snake_case json).
type NodeDTO struct {
	ID         int64   `json:"id"`
	NodeID     string  `json:"node_id"`
	UserID     int64   `json:"user_id"`
	Addr       string  `json:"addr"`
	OverlayIP  string  `json:"overlay_ip,omitempty"`
	Country    string  `json:"country,omitempty"`
	City       string  `json:"city,omitempty"`
	RTTMs      *int    `json:"rtt_ms,omitempty"`
	LoadFactor *float64 `json:"load_factor,omitempty"`
	IsP2P      bool    `json:"is_p2p"`
	LastSeenAt *string `json:"last_seen_at,omitempty"`
	CreatedAt  string  `json:"created_at"`
}

// AddNodeRequest body (IP + node_id).
type AddNodeRequest struct {
	Addr           string `json:"addr"`
	NodeID         string `json:"node_id"`
	IsP2P          bool   `json:"is_p2p,omitempty"`
	IceUfrag       string `json:"ice_ufrag,omitempty"`
	IcePwd         string `json:"ice_pwd,omitempty"`
	IceCandidates  string `json:"ice_candidates,omitempty"`
}

// CreateSiteRequest body.
type CreateSiteRequest struct {
	Name        string `json:"name"`
	SourceType  string `json:"source_type"`
	SourceValue string `json:"source_value"`
}

// AgentMetricsRequest body (agent metrics).
type AgentMetricsRequest struct {
	NodeID     string   `json:"node_id"`
	Addr       string   `json:"addr,omitempty"`
	Country    string   `json:"country"`
	City       string   `json:"city"`
	RTTMs      *int     `json:"rtt_ms,omitempty"`
	LoadFactor *float64 `json:"load_factor,omitempty"`
}

// HandleHealth GET /health (lb/k8s).
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct{ Status string `json:"status"` }{Status: "ok"})
}

// HandleReady GET /ready; 200 if DB ok else 503.
func (s *Server) HandleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.DB.Ping(); err != nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// HandleRegister POST /api/register
func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Login = strings.TrimSpace(req.Login)
	if req.Login == "" || req.Password == "" {
		http.Error(w, "login and password required", http.StatusBadRequest)
		return
	}
	const minPasswordLen = 6
	if len(req.Password) < minPasswordLen {
		http.Error(w, "password must be at least 6 characters", http.StatusBadRequest)
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_, err = s.DB.CreateUser(req.Login, hash)
	if err != nil {
		http.Error(w, "login already exists", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// HandleLogin POST /api/login -> { "token": "..." }
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	u, err := s.DB.UserByLogin(strings.TrimSpace(req.Login))
	if err != nil || u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !auth.CheckPassword(req.Password, u.PasswordHash) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tok, err := s.DB.CreateToken(u.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{Token: tok})
}

// RequireToken returns user id if Bearer valid; else 0, false.
func (s *Server) RequireToken(r *http.Request) (int64, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return 0, false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	if tok == "" {
		return 0, false
	}
	return s.DB.UserIDByToken(tok)
}

// HandleToken POST /api/token (regenerate); Bearer.
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := s.RequireToken(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tok, err := s.DB.ReplaceToken(userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{Token: tok})
}

// PasswordRequest body for POST /api/password.
type PasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// HandlePassword POST /api/password; Bearer; update user password.
func (s *Server) HandlePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := s.RequireToken(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req PasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.NewPassword == "" || len(req.NewPassword) < 6 {
		http.Error(w, "new password must be at least 6 characters", http.StatusBadRequest)
		return
	}
	u, err := s.DB.UserByID(userID)
	if err != nil || u == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !auth.CheckPassword(req.OldPassword, u.PasswordHash) {
		http.Error(w, "wrong password", http.StatusUnauthorized)
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.DB.UpdateUserPassword(userID, hash); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleNodesLookup GET /api/nodes/lookup?node_id=...; own nodes first, then P2P.
func (s *Server) HandleNodesLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.allowLookup(r) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	userID, ok := s.RequireToken(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}
	addr, overlayIP, err := s.DB.NodeAddrByID(userID, nodeID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if addr == "" {
		addr, overlayIP, err = s.DB.NodeAddrByIDPublic(nodeID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	if addr == "" {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}
	_, _, iceUfrag, icePwd, iceCandidates, _ := s.DB.NodeICEByID(nodeID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Addr          string `json:"addr"`
		OverlayIP     string `json:"overlay_ip,omitempty"`
		IceUfrag      string `json:"ice_ufrag,omitempty"`
		IcePwd        string `json:"ice_pwd,omitempty"`
		IceCandidates string `json:"ice_candidates,omitempty"`
	}{Addr: addr, OverlayIP: overlayIP, IceUfrag: iceUfrag, IcePwd: icePwd, IceCandidates: iceCandidates})
}

// HandleNodes GET /api/nodes (list), POST (add)
func (s *Server) HandleNodes(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.RequireToken(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		nodes, err := s.DB.ListNodes(&userID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		dtos := make([]NodeDTO, len(nodes))
		for i := range nodes {
			dtos[i] = nodeToDTO(nodes[i])
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(dtos)
	case http.MethodPost:
		var req AddNodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req.Addr = strings.TrimSpace(req.Addr)
		req.NodeID = strings.TrimSpace(req.NodeID)
		if req.Addr == "" || req.NodeID == "" {
			http.Error(w, "addr and node_id required", http.StatusBadRequest)
			return
		}
		if err := s.DB.UpsertNode(req.NodeID, userID, req.Addr, "", "", nil, nil, req.IsP2P); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if req.IceUfrag != "" || req.IcePwd != "" || req.IceCandidates != "" {
			_ = s.DB.UpdateNodeICE(req.NodeID, strings.TrimSpace(req.IceUfrag), strings.TrimSpace(req.IcePwd), strings.TrimSpace(req.IceCandidates))
		}
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ConfigResponse GET /api/config (stun/turn URLs).
type ConfigResponse struct {
	StunURL string `json:"stun_url,omitempty"`
	TurnURL string `json:"turn_url,omitempty"`
}

// HandleConfig GET /api/config; stun_url, turn_url from env; Bearer opt.
func (s *Server) HandleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out := ConfigResponse{
		StunURL: strings.TrimSpace(os.Getenv("0CDN_STUN_URL")),
		TurnURL: strings.TrimSpace(os.Getenv("0CDN_TURN_URL")),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// HandleRoutes GET /api/routes; Bearer; ordered exits.
func (s *Server) HandleRoutes(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.RequireToken(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	country := r.URL.Query().Get("country")
	city := r.URL.Query().Get("city")
	nodes, err := s.DB.ListNodes(nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = userID
	exits := router.SelectExits(nodes, country, city)
	const maxExits = 64
	if len(exits) > maxExits {
		exits = exits[:maxExits]
	}
	dtos := make([]ExitDTO, len(exits))
	for i := range exits {
		dtos[i] = ExitDTO{
			NodeID:    exits[i].NodeID,
			Addr:      exits[i].Addr,
			OverlayIP: exits[i].OverlayIP,
			Priority:  exits[i].Priority,
			Country:   exits[i].Country,
			City:      exits[i].City,
			IsP2P:     exits[i].IsP2P,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RoutesResponse{Exits: dtos})
}

// HandleSites GET/POST /api/sites (list/create)
func (s *Server) HandleSites(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.RequireToken(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		sites, err := s.DB.SitesByUser(userID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sites)
	case http.MethodPost:
		var req CreateSiteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		if strings.HasSuffix(req.Name, ".0cdn") {
			req.Name = strings.TrimSuffix(req.Name, ".0cdn")
		}
		if err := s.DB.CreateSite(userID, req.Name, req.SourceType, req.SourceValue); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleDeleteNode POST /api/nodes/delete { node_id }
func (s *Server) HandleDeleteNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := s.RequireToken(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}
	if err := s.DB.DeleteNode(req.NodeID, userID); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleDeleteSite POST /api/sites/delete { id }
func (s *Server) HandleDeleteSite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := s.RequireToken(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.ID <= 0 {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	if err := s.DB.DeleteSite(req.ID, userID); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleOverlayRoute GET /api/overlay/route?overlay_ip= or ?node_id=; addr, node_id for agent fwd; Bearer.
func (s *Server) HandleOverlayRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.allowLookup(r) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	userID, ok := s.RequireToken(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	overlayIP := strings.TrimSpace(r.URL.Query().Get("overlay_ip"))
	nodeIDQ := strings.TrimSpace(r.URL.Query().Get("node_id"))
	var addr, nodeID string
	var err error
	if overlayIP != "" {
		addr, nodeID, err = s.DB.NodeByOverlayIP(overlayIP)
	} else if nodeIDQ != "" {
		addr, _, err = s.DB.NodeAddrByID(userID, nodeIDQ)
		if err == nil && addr != "" {
			nodeID = nodeIDQ
		}
		if addr == "" {
			addr, _, err = s.DB.NodeAddrByIDPublic(nodeIDQ)
			if err == nil && addr != "" {
				nodeID = nodeIDQ
			}
		}
		if addr == "" {
			nodes, _ := s.DB.ListNodes(&userID)
			for _, n := range nodes {
				if n.NodeID == nodeIDQ {
					addr, nodeID = n.Addr, n.NodeID
					break
				}
			}
		}
	}
	if err != nil || addr == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Addr   string `json:"addr"`
		NodeID string `json:"node_id"`
	}{Addr: addr, NodeID: nodeID})
}

// HandleIceSignalPOST POST /api/nodes/ice-signal { node_id, ufrag, pwd, candidates }; Bearer.
func (s *Server) HandleIceSignalPOST(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, ok := s.RequireToken(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		NodeID    string `json:"node_id"`
		Ufrag     string `json:"ufrag"`
		Pwd       string `json:"pwd"`
		Candidates string `json:"candidates"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}
	s.iceSignalsMu.Lock()
	s.iceSignals[req.NodeID] = iceSignal{Ufrag: req.Ufrag, Pwd: req.Pwd, Candidates: req.Candidates}
	s.iceSignalsMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// HandleIceSignalGET GET /api/nodes/ice-signal?node_id=...; return signal, clear; Bearer.
func (s *Server) HandleIceSignalGET(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, ok := s.RequireToken(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}
	s.iceSignalsMu.Lock()
	sig, ok := s.iceSignals[nodeID]
	if ok {
		delete(s.iceSignals, nodeID)
	}
	s.iceSignalsMu.Unlock()
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct{}{})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sig)
}

// HandleDHTBootstrap GET /api/dht/bootstrap; addrs for DHT; Bearer.
func (s *Server) HandleDHTBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, ok := s.RequireToken(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	nodes, err := s.DB.ListNodes(nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var addrs []string
	seen := make(map[string]bool)
	for _, n := range nodes {
		if n.Addr != "" && !seen[n.Addr] {
			seen[n.Addr] = true
			addrs = append(addrs, n.Addr)
		}
	}
	const maxBootstrap = 32
	if len(addrs) > maxBootstrap {
		addrs = addrs[:maxBootstrap]
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Peers []string `json:"peers"`
	}{Peers: addrs})
}

// HandleAgentMetrics POST /api/agent/metrics; Bearer; agent reports metrics.
func (s *Server) HandleAgentMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := s.RequireToken(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req AgentMetricsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}
	// ensure node belongs to this user
	nodes, err := s.DB.ListNodes(&userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var found bool
	for _, n := range nodes {
		if n.NodeID == req.NodeID {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "node not found or not yours", http.StatusForbidden)
		return
	}
	if err := s.DB.UpdateNodeMetrics(req.NodeID, req.Country, req.City, req.RTTMs, req.LoadFactor); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CORS adds Access-Control-Allow-Origin for browser.
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func nodeToDTO(n store.Node) NodeDTO {
	d := NodeDTO{
		ID: n.ID, NodeID: n.NodeID, UserID: n.UserID, Addr: n.Addr, OverlayIP: n.OverlayIP,
		Country: n.Country, City: n.City, RTTMs: n.RTTMs, LoadFactor: n.LoadFactor,
		IsP2P: n.IsP2P, CreatedAt: n.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if n.LastSeenAt != nil {
		s := n.LastSeenAt.Format("2006-01-02T15:04:05Z07:00")
		d.LastSeenAt = &s
	}
	return d
}

// Mount registers routes on mux.
func (s *Server) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/health", s.HandleHealth)
	mux.HandleFunc("/ready", s.HandleReady)
	mux.HandleFunc("/api/register", s.HandleRegister)
	mux.HandleFunc("/api/login", s.HandleLogin)
	mux.HandleFunc("/api/token", s.HandleToken)
	mux.HandleFunc("/api/password", s.HandlePassword)
	mux.HandleFunc("/api/nodes/lookup", s.HandleNodesLookup)
	mux.HandleFunc("/api/nodes", s.HandleNodes)
	mux.HandleFunc("/api/routes", s.HandleRoutes)
	mux.HandleFunc("/api/sites", s.HandleSites)
	mux.HandleFunc("/api/nodes/delete", s.HandleDeleteNode)
	mux.HandleFunc("/api/sites/delete", s.HandleDeleteSite)
	mux.HandleFunc("/api/agent/metrics", s.HandleAgentMetrics)
	mux.HandleFunc("/api/overlay/route", s.HandleOverlayRoute)
	mux.HandleFunc("/api/dht/bootstrap", s.HandleDHTBootstrap)
	mux.HandleFunc("/api/config", s.HandleConfig)
	mux.HandleFunc("/api/nodes/ice-signal", s.HandleIceSignal)
}

// HandleIceSignal routes POST/GET ice-signal.
func (s *Server) HandleIceSignal(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.HandleIceSignalPOST(w, r)
		return
	}
	if r.Method == http.MethodGet {
		s.HandleIceSignalGET(w, r)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
