package crack

import (
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

// HashSHA512 returns the lowercase hex-encoded SHA512 digest of the given string.
func HashSHA512(s string) string {
	sum := sha512.Sum512([]byte(s))
	return hex.EncodeToString(sum[:])
}

// CrackSHA512 reads the wordlist line by line, hashes each candidate with SHA512,
// and compares it to targetHash. Each attempt is written to w (nil = off).
func CrackSHA512(wordlistPath, targetHash string, w *bufio.Writer) (Result, error) {
	targetHash = strings.ToLower(strings.TrimSpace(targetHash))

	file, err := os.Open(wordlistPath)
	if err != nil {
		return Result{}, fmt.Errorf("opening wordlist: %w", err)
	}
	defer file.Close()

	start := time.Now()
	attempts := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		candidate := strings.TrimRight(scanner.Text(), "\r\n")
		if candidate == "" {
			continue
		}
		attempts++
		digest := HashSHA512(candidate)

		if w != nil {
			fmt.Fprintf(w, "[%06d] %-32s -> %s\n", attempts, candidate, digest)
		}

		if digest == targetHash {
			return Result{true, candidate, digest, attempts, time.Since(start)}, scanner.Err()
		}
	}

	return Result{false, "", targetHash, attempts, time.Since(start)}, scanner.Err()
}
