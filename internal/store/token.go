package store

import (
	"crypto/rand"
	"encoding/hex"
)

func randToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}
