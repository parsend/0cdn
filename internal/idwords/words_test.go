package idwords

import (
	"strings"
	"testing"
)

func TestGenerateFiveWordID(t *testing.T) {
	id := GenerateFiveWordID()
	if id == "" {
		t.Fatal("empty id")
	}
	parts := strings.Split(id, ":")
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d: %q", len(parts), id)
	}
	for i, p := range parts {
		if p == "" {
			t.Fatalf("part %d empty", i)
		}
	}
	if !ValidFiveWordID(id) {
		t.Fatalf("generated id should be valid: %q", id)
	}
}

func TestValidFiveWordID(t *testing.T) {
	valid := GenerateFiveWordID()
	if !ValidFiveWordID(valid) {
		t.Fatalf("expected valid: %q", valid)
	}
	if ValidFiveWordID("") {
		t.Fatal("empty should be invalid")
	}
	if ValidFiveWordID("a:b:c") {
		t.Fatal("3 parts should be invalid")
	}
	if ValidFiveWordID("x:y:z:w:v") {
		t.Fatal("unknown words should be invalid")
	}
	if ValidFiveWordID("word.word.word.word.word") {
		t.Fatal("dots instead of colons should be invalid")
	}
}
