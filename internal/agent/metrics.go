package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Reporter pushes node metrics to server.
type Reporter struct {
	ServerURL string
	Token     string
	NodeID    string
	Addr      string
}

// Report sends geo, rtt_ms, load_factor to POST /api/agent/metrics.
func (r *Reporter) Report(country, city string, rttMs *int, loadFactor *float64) error {
	body := map[string]interface{}{
		"node_id": r.NodeID,
		"addr":    r.Addr,
		"country": country,
		"city":    city,
	}
	if rttMs != nil {
		body["rtt_ms"] = *rttMs
	}
	if loadFactor != nil {
		body["load_factor"] = *loadFactor
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, r.ServerURL+"/api/agent/metrics", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := HTTPClient().Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return errStatus(resp.StatusCode)
	}
	return nil
}

type errStatus int

func (e errStatus) Error() string {
	return fmt.Sprintf("server returned %d", e)
}
