package router

import (
	"sort"

	"dev.c0redev.0cdn/internal/proto"
	"dev.c0redev.0cdn/internal/store"
)

// SelectExits returns ordered exits. Rule: >=3 same location -> by RTT; else availability, geo, load.
func SelectExits(nodes []store.Node, geoCountry, geoCity string) []proto.ExitEntry {
	if len(nodes) == 0 {
		return nil
	}
	// group by location
	byLoc := make(map[string][]store.Node)
	for _, n := range nodes {
		loc := n.Country + "\x00" + n.City
		byLoc[loc] = append(byLoc[loc], n)
	}
	var out []proto.ExitEntry
	added := make(map[string]bool)
	// prefer location with >= 3 nodes, sorted by RTT
	for loc, list := range byLoc {
		if len(list) < 3 {
			continue
		}
		// same country+city as client hint wins
		prefer := (geoCountry != "" && geoCity != "" && loc == geoCountry+"\x00"+geoCity)
		sorted := make([]store.Node, len(list))
		copy(sorted, list)
		sort.Slice(sorted, func(i, j int) bool {
			ri, rj := rttOrMax(sorted[i]), rttOrMax(sorted[j])
			return ri < rj
		})
		for _, n := range sorted {
			if added[n.NodeID] {
				continue
			}
			added[n.NodeID] = true
			prio := int32(0)
			if prefer {
				prio = 100
			}
			out = append(out, nodeToExit(n, prio))
		}
	}
	// rest: by availability (last_seen), then geo, then load
	rest := make([]store.Node, 0)
	for _, n := range nodes {
		if !added[n.NodeID] {
			rest = append(rest, n)
		}
	}
	sort.Slice(rest, func(i, j int) bool {
		// prefer recently seen
		si, sj := lastSeenUnix(rest[i]), lastSeenUnix(rest[j])
		if si != sj {
			return si > sj
		}
		li, lj := loadOrZero(rest[i]), loadOrZero(rest[j])
		return li < lj
	})
	for _, n := range rest {
		out = append(out, nodeToExit(n, 0))
	}
	return out
}

func rttOrMax(n store.Node) int {
	if n.RTTMs != nil {
		return *n.RTTMs
	}
	return 999999
}

func loadOrZero(n store.Node) float64 {
	if n.LoadFactor != nil {
		return *n.LoadFactor
	}
	return 0
}

func lastSeenUnix(n store.Node) int64 {
	if n.LastSeenAt != nil {
		return n.LastSeenAt.Unix()
	}
	return 0
}

func nodeToExit(n store.Node, priorityBonus int32) proto.ExitEntry {
	prio := priorityBonus
	if n.RTTMs != nil {
		prio += int32(1000 - *n.RTTMs)
	}
	return proto.ExitEntry{
		NodeID:    n.NodeID,
		Addr:      n.Addr,
		OverlayIP: n.OverlayIP,
		Priority:  prio,
		Country:   n.Country,
		City:      n.City,
		IsP2P:     n.IsP2P,
	}
}
