package idwords

import (
	"crypto/rand"
	"embed"
	"encoding/binary"
	"strings"
	"sync"
)

//go:embed words.txt
var wordsFS embed.FS

var (
	wordlist   []string
	wordlistMu sync.Once
)

func loadWordlist() {
	wordlistMu.Do(func() {
		b, _ := wordsFS.ReadFile("words.txt")
		s := strings.TrimSpace(string(b))
		if s != "" {
			wordlist = strings.Split(s, "\n")
			for i, w := range wordlist {
				wordlist[i] = strings.TrimSpace(w)
			}
		}
	})
}

// GenerateFiveWordID returns new id word1:word2:word3:word4:word5.
func GenerateFiveWordID() string {
	loadWordlist()
	n := len(wordlist)
	if n == 0 {
		return ""
	}
	// 2 bytes per word for uniform choice in [0, n)
	b := make([]byte, 10)
	rand.Read(b)
	parts := make([]string, 5)
	for i := 0; i < 5; i++ {
		idx := binary.BigEndian.Uint16(b[i*2:]) % uint16(n)
		parts[i] = wordlist[idx]
	}
	return strings.Join(parts, ":")
}

// ValidFiveWordID true if s is five words from list, ":" joined.
func ValidFiveWordID(s string) bool {
	loadWordlist()
	parts := strings.Split(s, ":")
	if len(parts) != 5 {
		return false
	}
	set := make(map[string]bool)
	for _, w := range wordlist {
		if w != "" {
			set[w] = true
		}
	}
	for _, p := range parts {
		if p == "" || !set[p] {
			return false
		}
	}
	return true
}
