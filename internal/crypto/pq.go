// Package crypto: PQ KEM (ML-KEM-768) + ChaCha20-Poly1305 for tunnel.
package crypto

import (
	"crypto/rand"
	"errors"
	"io"

	"filippo.io/mlkem768"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// SharedKeySize is the ML-KEM shared secret size (32 bytes).
	SharedKeySize = 32
	// NonceSize for ChaCha20-Poly1305.
	NonceSize = chacha20poly1305.NonceSize
)

// PQKEM holds enc key; client encapsulates.
type PQKEM struct {
	Enc []byte
}

// NewPQKEMFromEnc stores enc key (1184 bytes).
func NewPQKEMFromEnc(encKey []byte) (*PQKEM, error) {
	return &PQKEM{Enc: encKey}, nil
}

// Encapsulate generates secret + ciphertext; caller sends to peer.
func (p *PQKEM) Encapsulate() (sharedSecret []byte, ciphertext []byte, err error) {
	ciphertext, sharedSecret, err = mlkem768.Encapsulate(p.Enc)
	if err != nil {
		return nil, nil, err
	}
	return sharedSecret, ciphertext, nil
}

// Decapsulate recovers secret from ciphertext (decap key).
func Decapsulate(decapKey *mlkem768.DecapsulationKey, ciphertext []byte) ([]byte, error) {
	return mlkem768.Decapsulate(decapKey, ciphertext)
}

// GenerateKeyPair ML-KEM-768 key pair (agent).
func GenerateKeyPair() (enc []byte, decap *mlkem768.DecapsulationKey, err error) {
	decap, err = mlkem768.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	enc = decap.EncapsulationKey()
	return enc, decap, nil
}

// Seal encrypts with key; prepends nonce to result.
func Seal(key []byte, nonce []byte, plaintext []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("key size must be 32")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceSize {
		nonce = make([]byte, NonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts (first NonceSize = nonce) with key.
func Open(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("key size must be 32")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < NonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:NonceSize], ciphertext[NonceSize:]
	return aead.Open(nil, nonce, ct, nil)
}
