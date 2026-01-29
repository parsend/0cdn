package auth

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	if hash == "" || hash == "secret" {
		t.Fatal("hash should be non-empty and different from password")
	}
	hash2, _ := HashPassword("secret")
	if hash == hash2 {
		t.Fatal("hashes should differ (salt)")
	}
}

func TestCheckPassword(t *testing.T) {
	hash, _ := HashPassword("mypass")
	if !CheckPassword("mypass", hash) {
		t.Fatal("correct password should match")
	}
	if CheckPassword("wrong", hash) {
		t.Fatal("wrong password should not match")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("a", "a") {
		t.Fatal("equal strings")
	}
	if ConstantTimeEqual("a", "b") {
		t.Fatal("different strings")
	}
	if ConstantTimeEqual("ab", "a") {
		t.Fatal("different length")
	}
}
