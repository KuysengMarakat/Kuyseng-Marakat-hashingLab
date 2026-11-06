package crack

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

// HashSHA1 returns the lowercase hex-encoded SHA1 digest of the given string.
func HashSHA1(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// CrackSHA1 reads the wordlist line by line, hashes each candidate with SHA1,
// and compares it to targetHash. Each attempt is written to w (nil = off).
func CrackSHA1(wordlistPath, targetHash string, w *bufio.Writer) (Result, error) {
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
		digest := HashSHA1(candidate)

		if w != nil {
			fmt.Fprintf(w, "[%06d] %-32s -> %s\n", attempts, candidate, digest)
		}

		if digest == targetHash {
			return Result{true, candidate, digest, attempts, time.Since(start)}, scanner.Err()
		}
	}

	return Result{false, "", targetHash, attempts, time.Since(start)}, scanner.Err()
}
