// Package crack provides MD5 hashing and dictionary-attack helpers.
package crack

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

// Hash returns the lowercase hex-encoded MD5 digest of the given string.
func Hash(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Result holds the outcome of a cracking run.
type Result struct {
	Found    bool
	Password string
	Hash     string
	Attempts int
	Elapsed  time.Duration
}

// CrackMD5 reads the wordlist line by line, hashes each candidate with MD5,
// and compares it to targetHash. Each attempt is written to w (nil = off).
func CrackMD5(wordlistPath, targetHash string, w *bufio.Writer) (Result, error) {
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
		digest := Hash(candidate)

		if w != nil {
			fmt.Fprintf(w, "[%06d] %-32s -> %s\n", attempts, candidate, digest)
		}

		if digest == targetHash {
			return Result{true, candidate, digest, attempts, time.Since(start)}, scanner.Err()
		}
	}

	return Result{false, "", targetHash, attempts, time.Since(start)}, scanner.Err()
}