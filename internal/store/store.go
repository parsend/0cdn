package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps sqlite (control plane).
type DB struct {
	*sql.DB
}

// Open opens db at path, runs migrations.
func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			login TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id),
			token TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS nodes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id TEXT NOT NULL UNIQUE,
			user_id INTEGER NOT NULL REFERENCES users(id),
			addr TEXT NOT NULL,
			country TEXT,
			city TEXT,
			rtt_ms INTEGER,
			load_factor REAL,
			is_p2p INTEGER NOT NULL DEFAULT 0,
			last_seen_at TEXT,
			created_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS sites (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id),
			name TEXT NOT NULL,
			source_type TEXT NOT NULL,
			source_value TEXT,
			created_at TEXT NOT NULL,
			UNIQUE(user_id, name)
		);
		CREATE INDEX IF NOT EXISTS idx_nodes_user ON nodes(user_id);
		CREATE INDEX IF NOT EXISTS idx_nodes_geo ON nodes(country, city);
		CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token);
	`)
	if err != nil {
		return err
	}
	_, _ = db.Exec("ALTER TABLE nodes ADD COLUMN overlay_ip TEXT")
	_, _ = db.Exec("ALTER TABLE nodes ADD COLUMN ice_ufrag TEXT")
	_, _ = db.Exec("ALTER TABLE nodes ADD COLUMN ice_pwd TEXT")
	_, _ = db.Exec("ALTER TABLE nodes ADD COLUMN ice_candidates TEXT")
	return nil
}

// User: login, password hash.
type User struct {
	ID           int64
	Login        string
	PasswordHash string
	CreatedAt    time.Time
}

// CreateUser inserts user; err if login exists.
func (db *DB) CreateUser(login, passwordHash string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := db.Exec("INSERT INTO users (login, password_hash, created_at) VALUES (?, ?, ?)", login, passwordHash, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UserByLogin returns user by login or nil.
func (db *DB) UserByLogin(login string) (*User, error) {
	var u User
	var t string
	err := db.QueryRow("SELECT id, login, password_hash, created_at FROM users WHERE login = ?", login).Scan(&u.ID, &u.Login, &u.PasswordHash, &t)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339, t)
	return &u, nil
}

// UserByID returns user by id or nil.
func (db *DB) UserByID(id int64) (*User, error) {
	var u User
	var t string
	err := db.QueryRow("SELECT id, login, password_hash, created_at FROM users WHERE id = ?", id).Scan(&u.ID, &u.Login, &u.PasswordHash, &t)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339, t)
	return &u, nil
}

// CreateToken inserts token for user, returns token str.
func (db *DB) CreateToken(userID int64) (string, error) {
	tok := randToken()
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec("INSERT INTO tokens (user_id, token, created_at) VALUES (?, ?, ?)", userID, tok, now)
	if err != nil {
		return "", err
	}
	return tok, nil
}

// UpdateUserPassword sets password hash for user.
func (db *DB) UpdateUserPassword(userID int64, passwordHash string) error {
	_, err := db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", passwordHash, userID)
	return err
}

// ReplaceToken deletes user tokens, creates one new (regenerate).
func (db *DB) ReplaceToken(userID int64) (string, error) {
	if _, err := db.Exec("DELETE FROM tokens WHERE user_id = ?", userID); err != nil {
		return "", err
	}
	return db.CreateToken(userID)
}

// UserIDByToken returns user id for token; 0, false if invalid.
func (db *DB) UserIDByToken(token string) (int64, bool) {
	var id int64
	err := db.QueryRow("SELECT user_id FROM tokens WHERE token = ?", token).Scan(&id)
	if err != nil {
		return 0, false
	}
	return id, true
}

// Node: edge or P2P (addr, overlay_ip, geo, rtt, load, ice).
type Node struct {
	ID         int64
	NodeID     string
	UserID     int64
	Addr       string
	OverlayIP  string
	Country    string
	City       string
	RTTMs      *int
	LoadFactor *float64
	IsP2P      bool
	LastSeenAt *time.Time
	CreatedAt  time.Time
}

// UpsertNode insert/update by node_id (unique). If exists: update addr, geo, rtt, load, last_seen. Err if node belongs to another user.
func (db *DB) UpsertNode(nodeID string, userID int64, addr, country, city string, rttMs *int, loadFactor *float64, isP2P bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	var existingUser int64
	err := db.QueryRow("SELECT user_id FROM nodes WHERE node_id = ?", nodeID).Scan(&existingUser)
	if err == nil {
		if existingUser != userID {
			return fmt.Errorf("node already registered by another user")
		}
		var rtt interface{}
		var load interface{}
		if rttMs != nil {
			rtt = *rttMs
		}
		if loadFactor != nil {
			load = *loadFactor
		}
		p2p := 0
		if isP2P {
			p2p = 1
		}
		_, err = db.Exec("UPDATE nodes SET addr=?, country=?, city=?, rtt_ms=?, load_factor=?, is_p2p=?, last_seen_at=? WHERE node_id=?",
			addr, country, city, rtt, load, p2p, now, nodeID)
		return err
	}
	overlayIP := db.nextOverlayIP()
	_, err = db.Exec("INSERT INTO nodes (node_id, user_id, addr, overlay_ip, country, city, rtt_ms, load_factor, is_p2p, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		nodeID, userID, addr, overlayIP, country, city, rttMs, loadFactor, isP2P, now, now)
	return err
}

// nextOverlayIP picks next free from 10.200.0.2..254.
func (db *DB) nextOverlayIP() string {
	used := make(map[string]bool)
	rows, err := db.Query("SELECT overlay_ip FROM nodes WHERE overlay_ip IS NOT NULL AND overlay_ip != ''")
	if err != nil {
		return ""
	}
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			used[ip] = true
		}
	}
	rows.Close()
	for i := 2; i <= 254; i++ {
		ip := fmt.Sprintf("10.200.0.%d", i)
		if !used[ip] {
			return ip
		}
	}
	return ""
}

// RegisterNode binds node to user (add by IP+node_id).
func (db *DB) RegisterNode(nodeID string, userID int64, addr string) error {
	return db.UpsertNode(nodeID, userID, addr, "", "", nil, nil, false)
}

// UpdateNodeMetrics sets rtt, load, geo, last_seen for node.
func (db *DB) UpdateNodeMetrics(nodeID, country, city string, rttMs *int, loadFactor *float64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	var rtt, load interface{}
	if rttMs != nil {
		rtt = *rttMs
	}
	if loadFactor != nil {
		load = *loadFactor
	}
	_, err := db.Exec("UPDATE nodes SET country=?, city=?, rtt_ms=?, load_factor=?, last_seen_at=? WHERE node_id=?",
		country, city, rtt, load, now, nodeID)
	return err
}

// DeleteNode removes node; err if not found or not user's.
func (db *DB) DeleteNode(nodeID string, userID int64) error {
	res, err := db.Exec("DELETE FROM nodes WHERE node_id = ? AND user_id = ?", nodeID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("node not found or not yours")
	}
	return nil
}

// NodeAddrByID returns addr, overlay_ip for node_id (user's nodes; lookup API).
func (db *DB) NodeAddrByID(userID int64, nodeID string) (addr, overlayIP string, err error) {
	err = db.QueryRow("SELECT addr, COALESCE(overlay_ip, '') FROM nodes WHERE node_id = ? AND user_id = ?", nodeID, userID).Scan(&addr, &overlayIP)
	if err == sql.ErrNoRows {
		return "", "", nil
	}
	return addr, overlayIP, err
}

// NodeAddrByIDPublic returns addr, overlay_ip for node_id if is_p2p=1 (public/DHT lookup).
func (db *DB) NodeAddrByIDPublic(nodeID string) (addr, overlayIP string, err error) {
	err = db.QueryRow("SELECT addr, COALESCE(overlay_ip, '') FROM nodes WHERE node_id = ? AND is_p2p = 1", nodeID).Scan(&addr, &overlayIP)
	if err == sql.ErrNoRows {
		return "", "", nil
	}
	return addr, overlayIP, err
}

// NodeByOverlayIP returns addr, node_id for overlay_ip (e.g. 10.200.0.5); agent overlay fwd.
func (db *DB) NodeByOverlayIP(overlayIP string) (addr, nodeID string, err error) {
	if overlayIP == "" {
		return "", "", nil
	}
	err = db.QueryRow("SELECT addr, node_id FROM nodes WHERE overlay_ip = ?", overlayIP).Scan(&addr, &nodeID)
	if err == sql.ErrNoRows {
		return "", "", nil
	}
	return addr, nodeID, err
}

// NodeICEByID returns addr, overlay_ip, ice_* for node_id (ICE dial).
func (db *DB) NodeICEByID(nodeID string) (addr, overlayIP, iceUfrag, icePwd, iceCandidates string, err error) {
	if nodeID == "" {
		return "", "", "", "", "", nil
	}
	err = db.QueryRow("SELECT addr, COALESCE(overlay_ip,''), COALESCE(ice_ufrag,''), COALESCE(ice_pwd,''), COALESCE(ice_candidates,'') FROM nodes WHERE node_id = ?", nodeID).Scan(&addr, &overlayIP, &iceUfrag, &icePwd, &iceCandidates)
	if err == sql.ErrNoRows {
		return "", "", "", "", "", nil
	}
	return addr, overlayIP, iceUfrag, icePwd, iceCandidates, err
}

// UpdateNodeICE sets ice_* for node_id (P2P+ICE).
func (db *DB) UpdateNodeICE(nodeID, iceUfrag, icePwd, iceCandidates string) error {
	_, err := db.Exec("UPDATE nodes SET ice_ufrag=?, ice_pwd=?, ice_candidates=? WHERE node_id=?", iceUfrag, icePwd, iceCandidates, nodeID)
	return err
}

// ListNodes returns nodes; opt filter by user_id (routing).
func (db *DB) ListNodes(userID *int64) ([]Node, error) {
	var rows *sql.Rows
	var err error
	if userID != nil {
		rows, err = db.Query("SELECT id, node_id, user_id, addr, COALESCE(overlay_ip,''), country, city, rtt_ms, load_factor, is_p2p, last_seen_at, created_at FROM nodes WHERE user_id = ?", *userID)
	} else {
		rows, err = db.Query("SELECT id, node_id, user_id, addr, COALESCE(overlay_ip,''), country, city, rtt_ms, load_factor, is_p2p, last_seen_at, created_at FROM nodes")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Node
	for rows.Next() {
		var n Node
		var rtt sql.NullInt64
		var loadF sql.NullFloat64
		var lastSeen, createdAt string
		var p2p int
		err := rows.Scan(&n.ID, &n.NodeID, &n.UserID, &n.Addr, &n.OverlayIP, &n.Country, &n.City, &rtt, &loadF, &p2p, &lastSeen, &createdAt)
		if err != nil {
			return nil, err
		}
		n.IsP2P = p2p == 1
		if rtt.Valid {
			ms := int(rtt.Int64)
			n.RTTMs = &ms
		}
		if loadF.Valid {
			n.LoadFactor = &loadF.Float64
		}
		if lastSeen != "" {
			t, _ := time.Parse(time.RFC3339, lastSeen)
			n.LastSeenAt = &t
		}
		n.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		list = append(list, n)
	}
	return list, rows.Err()
}

// Site: .0cdn site (name, source_type, source_value).
type Site struct {
	ID          int64
	UserID      int64
	Name        string
	SourceType  string
	SourceValue string
	CreatedAt   time.Time
}

// CreateSite adds site for user (name w/o .0cdn suffix).
func (db *DB) CreateSite(userID int64, name, sourceType, sourceValue string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec("INSERT INTO sites (user_id, name, source_type, source_value, created_at) VALUES (?, ?, ?, ?, ?)",
		userID, name, sourceType, sourceValue, now)
	return err
}

// DeleteSite removes site; err if not user's.
func (db *DB) DeleteSite(siteID int64, userID int64) error {
	res, err := db.Exec("DELETE FROM sites WHERE id = ? AND user_id = ?", siteID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("site not found or not yours")
	}
	return nil
}

// SitesByUser returns user's sites.
func (db *DB) SitesByUser(userID int64) ([]Site, error) {
	rows, err := db.Query("SELECT id, user_id, name, source_type, source_value, created_at FROM sites WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Site
	for rows.Next() {
		var s Site
		var t string
		err := rows.Scan(&s.ID, &s.UserID, &s.Name, &s.SourceType, &s.SourceValue, &t)
		if err != nil {
			return nil, err
		}
		s.CreatedAt, _ = time.Parse(time.RFC3339, t)
		list = append(list, s)
	}
	return list, rows.Err()
}

// SiteByName returns site by name (mysite.0cdn or mysite).
func (db *DB) SiteByName(name string) (*Site, error) {
	// strip .0cdn if present
	if len(name) > 5 && name[len(name)-5:] == ".0cdn" {
		name = name[:len(name)-5]
	}
	var s Site
	var t string
	err := db.QueryRow("SELECT id, user_id, name, source_type, source_value, created_at FROM sites WHERE name = ?", name).Scan(&s.ID, &s.UserID, &s.Name, &s.SourceType, &s.SourceValue, &t)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.CreatedAt, _ = time.Parse(time.RFC3339, t)
	return &s, nil
}
