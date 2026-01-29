package client

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pion/ice/v3"
	"github.com/pion/stun/v2"
)

// IceGather gathers local ICE candidates (stunURL from 0CDN_STUN_URL); returns ufrag, pwd, candidates (one per line).
func IceGather(stunURL string) (ufrag, pwd, candidates string, err error) {
	config := &ice.AgentConfig{}
	if stunURL != "" {
		uri, parseErr := stun.ParseURI(stunURL)
		if parseErr == nil {
			config.Urls = []*stun.URI{uri}
		}
	}
	agent, err := ice.NewAgent(config)
	if err != nil {
		return "", "", "", err
	}
	defer agent.Close()
	if err := agent.GatherCandidates(); err != nil {
		return "", "", "", err
	}
	// wait briefly for gathering
	time.Sleep(500 * time.Millisecond)
	ufrag, pwd, err = agent.GetLocalUserCredentials()
	if err != nil {
		return "", "", "", err
	}
	list, err := agent.GetLocalCandidates()
	if err != nil {
		return ufrag, pwd, "", err
	}
	var lines []string
	for _, c := range list {
		lines = append(lines, c.Marshal())
	}
	return ufrag, pwd, strings.Join(lines, "\n"), nil
}

// IceDial connects via ICE (ufrag, pwd, candidates from signaling). Returns net.Conn for proto; ctx with timeout.
func IceDial(ctx context.Context, remoteUfrag, remotePwd, candidates string) (net.Conn, error) {
	if remoteUfrag == "" || remotePwd == "" {
		return nil, nil
	}
	config := &ice.AgentConfig{}
	agent, err := ice.NewAgent(config)
	if err != nil {
		return nil, err
	}
	if err := agent.SetRemoteCredentials(remoteUfrag, remotePwd); err != nil {
		agent.Close()
		return nil, err
	}
	for _, line := range strings.Split(strings.TrimSpace(candidates), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		c, err := ice.UnmarshalCandidate(line)
		if err != nil {
			continue
		}
		_ = agent.AddRemoteCandidate(c)
	}
	conn, err := agent.Dial(ctx, remoteUfrag, remotePwd)
	if err != nil {
		agent.Close()
		return nil, err
	}
	return &iceConnWrap{Conn: conn, agent: agent}, nil
}

type iceConnWrap struct {
	*ice.Conn
	agent *ice.Agent
}

func (w *iceConnWrap) Close() error {
	err := w.Conn.Close()
	w.agent.Close()
	return err
}

// IceGatherWithSTUN gathers candidates from 0CDN_STUN_URL; returns ufrag, pwd, candidates.
func IceGatherWithSTUN() (ufrag, pwd, candidates string, err error) {
	stunURL := os.Getenv("0CDN_STUN_URL")
	return IceGather(stunURL)
}
