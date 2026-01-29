package agent

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"dev.c0redev.0cdn/internal/idwords"
)

// NodeID: unique id for this agent (persisted).
type NodeID struct {
	mu   sync.Mutex
	id   string
	path string
}

// NewNodeID loads or generates node id, persisted at dataDir/node_id.
func NewNodeID(dataDir string) (*NodeID, error) {
	path := filepath.Join(dataDir, "node_id")
	if path == "node_id" {
		path = filepath.Join(".", "node_id")
	}
	n := &NodeID{path: path}
	if err := n.load(); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *NodeID) load() error {
	b, err := os.ReadFile(n.path)
	if err == nil {
		id := strings.TrimSpace(string(b))
		if id != "" {
			n.mu.Lock()
			n.id = id
			n.mu.Unlock()
			return nil
		}
	}
	// generate new 5-word id
	n.mu.Lock()
	n.id = idwords.GenerateFiveWordID()
	n.mu.Unlock()
	return os.WriteFile(n.path, []byte(n.id), 0600)
}

// ID returns node id str.
func (n *NodeID) ID() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.id
}
