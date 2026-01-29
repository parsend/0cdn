package proto

import (
	"bytes"
	"io"
	"testing"
)

func TestEncodeDecodeFrame(t *testing.T) {
	f := &Frame{Type: TypePing, StreamID: 1, Payload: []byte("hello")}
	var buf bytes.Buffer
	if err := EncodeFrame(&buf, f); err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeFrame(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type != f.Type || dec.StreamID != f.StreamID || !bytes.Equal(dec.Payload, f.Payload) {
		t.Fatalf("roundtrip: got %+v", dec)
	}
}

func TestDecodeFrameEmptyPayload(t *testing.T) {
	f := &Frame{Type: TypePong, StreamID: 0, Payload: nil}
	var buf bytes.Buffer
	if err := EncodeFrame(&buf, f); err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeFrame(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type != f.Type || dec.StreamID != f.StreamID || len(dec.Payload) != 0 {
		t.Fatalf("roundtrip empty: got %+v", dec)
	}
}

func TestEncodeDecodeAuthRequest(t *testing.T) {
	req := &AuthRequest{Token: []byte("secret-token")}
	b := EncodeAuthRequest(req)
	dec, err := DecodeAuthRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Token, req.Token) {
		t.Fatalf("roundtrip: got %q", dec.Token)
	}
}

func TestDecodeFrameShortRead(t *testing.T) {
	r := bytes.NewReader([]byte{0x01, 0x00, 0x00}) // only 3 bytes, need 9
	_, err := DecodeFrame(r, nil)
	if err == nil {
		t.Fatal("expected error on short read")
	}
	if err != io.EOF {
		_ = err
	}
}
