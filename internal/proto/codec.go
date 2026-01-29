package proto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

var ErrShortRead = errors.New("short read")
var ErrInvalidFrame = errors.New("invalid frame")

// EncodeFrame writes 9-byte header + payload to w (payload opt).
func EncodeFrame(w io.Writer, f *Frame) error {
	if len(f.Payload) > 0xffffffff {
		return errors.New("payload too large")
	}
	header := [FrameHeaderSize]byte{}
	header[0] = byte(f.Type)
	binary.LittleEndian.PutUint32(header[1:5], f.StreamID)
	binary.LittleEndian.PutUint32(header[5:9], uint32(len(f.Payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return err
		}
	}
	return nil
}

// DecodeFrame reads one frame; payloadBuf opt (nil = alloc).
func DecodeFrame(r io.Reader, payloadBuf []byte) (*Frame, error) {
	var header [FrameHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, err
	}
	ft := FrameType(header[0])
	streamID := binary.LittleEndian.Uint32(header[1:5])
	length := binary.LittleEndian.Uint32(header[5:9])
	var payload []byte
	if length > 0 {
		if length > MaxPayloadSize {
			return nil, ErrInvalidFrame
		}
		if payloadBuf != nil && cap(payloadBuf) >= int(length) {
			payload = payloadBuf[:length]
		} else {
			payload = make([]byte, length)
		}
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}
	return &Frame{Type: ft, StreamID: streamID, Payload: payload}, nil
}

// EncodeAuthRequest serializes AuthRequest.
func EncodeAuthRequest(req *AuthRequest) []byte {
	b := make([]byte, 0, 4+len(req.Token))
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, uint32(len(req.Token)))
	b = append(b, tmp...)
	b = append(b, req.Token...)
	return b
}

// DecodeAuthRequest parses payload -> AuthRequest.
func DecodeAuthRequest(payload []byte) (*AuthRequest, error) {
	if len(payload) < 4 {
		return nil, ErrInvalidFrame
	}
	ln := binary.LittleEndian.Uint32(payload[:4])
	if uint32(len(payload)) < 4+ln {
		return nil, ErrInvalidFrame
	}
	return &AuthRequest{Token: append([]byte(nil), payload[4:4+ln]...)}, nil
}

// EncodeAuthResponse serializes AuthResponse.
func EncodeAuthResponse(res *AuthResponse) []byte {
	var ok byte
	if res.OK {
		ok = 1
	}
	b := []byte{ok}
	if !res.OK && res.Error != "" {
		eb := []byte(res.Error)
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, uint32(len(eb)))
		b = append(b, tmp...)
		b = append(b, eb...)
	}
	return b
}

// DecodeAuthResponse parses payload -> AuthResponse.
func DecodeAuthResponse(payload []byte) (*AuthResponse, error) {
	if len(payload) < 1 {
		return nil, ErrInvalidFrame
	}
	res := &AuthResponse{OK: payload[0] == 1}
	if !res.OK && len(payload) >= 5 {
		ln := binary.LittleEndian.Uint32(payload[1:5])
		if uint32(len(payload)) >= 5+ln {
			res.Error = string(payload[5 : 5+ln])
		}
	}
	return res, nil
}

// EncodeRouteResponse serializes RouteResponse (count + per-exit nodeID, addr, priority, geo, isP2P).
func EncodeRouteResponse(res *RouteResponse) []byte {
	buf := new(bytes.Buffer)
	tmp4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp4, uint32(len(res.Exits)))
	buf.Write(tmp4)
	for _, e := range res.Exits {
		writeStr(buf, e.NodeID)
		writeStr(buf, e.Addr)
		writeStr(buf, e.OverlayIP)
		binary.LittleEndian.PutUint32(tmp4, uint32(e.Priority))
		buf.Write(tmp4)
		writeStr(buf, e.Country)
		writeStr(buf, e.City)
		var p2p byte
		if e.IsP2P {
			p2p = 1
		}
		buf.WriteByte(p2p)
	}
	return buf.Bytes()
}

func writeStr(w *bytes.Buffer, s string) {
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, uint32(len(s)))
	w.Write(tmp)
	w.WriteString(s)
}

func readStr(r *bytes.Reader) (string, error) {
	var ln [4]byte
	if _, err := io.ReadFull(r, ln[:]); err != nil {
		return "", err
	}
	n := binary.LittleEndian.Uint32(ln[:])
	if n > 1024 {
		return "", ErrInvalidFrame
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

// DecodeRouteResponse parses payload -> RouteResponse.
func DecodeRouteResponse(payload []byte) (*RouteResponse, error) {
	r := bytes.NewReader(payload)
	var count uint32
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return nil, err
	}
	if count > 256 {
		return nil, ErrInvalidFrame
	}
	res := &RouteResponse{Exits: make([]ExitEntry, 0, count)}
	for i := uint32(0); i < count; i++ {
		nodeID, err := readStr(r)
		if err != nil {
			return nil, err
		}
		addr, err := readStr(r)
		if err != nil {
			return nil, err
		}
		overlayIP, _ := readStr(r)
		var prio uint32
		if err := binary.Read(r, binary.LittleEndian, &prio); err != nil {
			return nil, err
		}
		country, _ := readStr(r)
		city, _ := readStr(r)
		p2p, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		res.Exits = append(res.Exits, ExitEntry{
			NodeID: nodeID, Addr: addr, OverlayIP: overlayIP, Priority: int32(prio),
			Country: country, City: city, IsP2P: p2p == 1,
		})
	}
	return res, nil
}

// EncodeRouteRequest optional geo hint.
func EncodeRouteRequest(req *RouteRequest) []byte {
	buf := new(bytes.Buffer)
	writeStr(buf, req.GeoCountry)
	writeStr(buf, req.GeoCity)
	return buf.Bytes()
}

// DecodeRouteRequest parses payload -> RouteRequest; empty ok (no geo).
func DecodeRouteRequest(payload []byte) (*RouteRequest, error) {
	if len(payload) == 0 {
		return &RouteRequest{}, nil
	}
	r := bytes.NewReader(payload)
	country, err := readStr(r)
	if err != nil {
		return nil, err
	}
	city, _ := readStr(r)
	return &RouteRequest{GeoCountry: country, GeoCity: city}, nil
}

// MorphBucketSizes target sizes for morph (HTTPS-like); 0CDN_MASK_MORPH=1.
var MorphBucketSizes = []int{256, 512, 768, 1024, 1400, 1500}

// EncodeDataPayload adds opt padding: [1: padLen][padLen random][payload]. paddingMax<=0 = unchanged; morph = bucket sizes.
func EncodeDataPayload(payload []byte, paddingMax int) ([]byte, error) {
	return EncodeDataPayloadMorph(payload, paddingMax, false)
}

// EncodeDataPayloadMorph like EncodeDataPayload + opt morph (nearest bucket, DPI evasion).
func EncodeDataPayloadMorph(payload []byte, paddingMax int, morph bool) ([]byte, error) {
	if paddingMax <= 0 && !morph {
		return payload, nil
	}
	needSize := 1 + len(payload)
	var padLen int
	if morph && len(MorphBucketSizes) > 0 {
		b := make([]byte, 1)
		rand.Read(b)
		idx := int(b[0]) % len(MorphBucketSizes)
		target := MorphBucketSizes[idx]
		if target < needSize {
			for _, t := range MorphBucketSizes {
				if t >= needSize {
					target = t
					break
				}
			}
			if target < needSize {
				target = needSize
			}
		}
		padLen = target - needSize
		if padLen < 0 {
			padLen = 0
		}
		if padLen > MaxPaddingSize {
			padLen = MaxPaddingSize
		}
		if paddingMax > 0 && padLen > paddingMax {
			padLen = paddingMax
		}
	} else if paddingMax > 0 {
		if paddingMax > MaxPaddingSize {
			paddingMax = MaxPaddingSize
		}
		b := make([]byte, 1)
		rand.Read(b)
		padLen = int(b[0]) % (paddingMax + 1)
	}
	out := make([]byte, 1+padLen+len(payload))
	out[0] = byte(padLen)
	if padLen > 0 {
		rand.Read(out[1 : 1+padLen])
	}
	copy(out[1+padLen:], payload)
	return out, nil
}

// DecodeDataPayload strips padding: first byte = padLen, skip, return rest.
func DecodeDataPayload(encoded []byte) ([]byte, error) {
	if len(encoded) < 1 {
		return encoded, nil
	}
	padLen := int(encoded[0])
	if len(encoded) < 1+padLen {
		return nil, ErrInvalidFrame
	}
	return encoded[1+padLen:], nil
}
