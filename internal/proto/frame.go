package proto

// Frame: on-wire msg (header + opt payload).
type Frame struct {
	Type    FrameType
	StreamID uint32
	Payload  []byte
}

// AuthRequest payload: token (len-prefixed).
type AuthRequest struct {
	Token []byte
}

// AuthResponse payload: ok (1 byte) + optional error message.
type AuthResponse struct {
	OK    bool
	Error string
}

// RouteRequest: client asks for exits (opt geo hint).
type RouteRequest struct {
	GeoCountry string
	GeoCity    string
}

// RouteResponse: list of exits.
type RouteResponse struct {
	Exits []ExitEntry
}

// ExitEntry: one exit in route reply.
type ExitEntry struct {
	NodeID    string
	Addr      string
	OverlayIP string
	Priority  int32
	Country   string
	City      string
	IsP2P     bool
}
