package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"dev.c0redev.0cdn/internal/idwords"
)

// RegisterP2PExit registers client as P2P exit (addr = public, e.g. STUN or 0CDN_P2P_ADDR; nodeID = unique)
func RegisterP2PExit(serverURL, token, addr, nodeID string) error {
	return RegisterP2PExitWithICE(serverURL, token, addr, nodeID, "", "", "")
}

// RegisterP2PExitWithICE registers P2P exit + ICE candidates (ufrag, pwd, candidates) for NAT.
func RegisterP2PExitWithICE(serverURL, token, addr, nodeID, iceUfrag, icePwd, iceCandidates string) error {
	serverURL = NormalizeServerURL(serverURL)
	if serverURL == "" {
		return fmt.Errorf("0CDN_SERVER_URL required")
	}
	if token == "" {
		return fmt.Errorf("0CDN_TOKEN required")
	}
	if addr == "" {
		addr = os.Getenv("0CDN_P2P_ADDR")
	}
	if addr == "" {
		return fmt.Errorf("P2P exit requires 0CDN_P2P_ADDR (public IP:port)")
	}
	if nodeID == "" {
		nodeID = os.Getenv("0CDN_NODE_ID")
	}
	if nodeID == "" {
		nodeID = idwords.GenerateFiveWordID()
	}
	body := map[string]interface{}{
		"addr":     addr,
		"node_id":  nodeID,
		"is_p2p":   true,
		"ice_ufrag": iceUfrag,
		"ice_pwd":   icePwd,
		"ice_candidates": iceCandidates,
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/nodes", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := HTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register P2P: %d", resp.StatusCode)
	}
	return nil
}
