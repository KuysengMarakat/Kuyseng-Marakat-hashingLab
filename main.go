// Hashing Lab: Password Cracking (Labs 1-4)
//
// Reads the nord_vpn wordlist, hashes each word, and compares it to the
// target hashes for MD5 (Lab 1), SHA1 (Lab 2) and SHA512 (Lab 3). Lab 4
// is a mini-CTF: a leaked URL hides an MD5 hash as percent-encoded bytes.
//
// All attempts and results are also written to verbose.txt.
package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"

	"hashing_lab/utils/crack"
)

const (
	wordlistPath = "nord_vpn.txt"
	verbosePath  = "verbose.txt"

	md5Target    = "6a85dfd77d9cb35770c9dc6728d73d3f"
	sha1Target   = "aa1c7d931cf140bb35a5a16adeb83a551649c3b9"
	sha512Target = "485f5c36c6f8474f53a3b0e361369ee3e32ee0de2f368b87b847dd23cb284b316bb0f026ada27df76c31ae8fa8696708d14b4d8fa352dbd8a31991b90ca5dd38"
)

// report prints and logs the outcome of one cracking lab.
func report(w *bufio.Writer, lab, algo, target string, r crack.Result, err error) {
	if err != nil {
		msg := fmt.Sprintf("\n[%s] %s ERROR: %v\n", lab, algo, err)
		fmt.Print(msg)
		fmt.Fprint(w, msg)
		return
	}

	var summary string
	if r.Found {
		summary = fmt.Sprintf("\n[%s] %s\n  Target   : %s\n  [+] CRACKED -> %q\n  Attempts : %d\n  Elapsed  : %s\n",
			lab, algo, target, r.Password, r.Attempts, r.Elapsed)
	} else {
		summary = fmt.Sprintf("\n[%s] %s\n  Target   : %s\n  [-] not found in wordlist (%d attempts)\n",
			lab, algo, target, r.Attempts)
	}
	fmt.Print(summary)
	fmt.Fprint(w, summary)
}

// lab4 solves the Mini-CTF: URL-decode the hidden MD5 hash, then confirm
// which cat-related password produces it, and print the CTF flag.
func lab4(w *bufio.Writer) {
	header := "\n[Lab 4] Mini-CTF (Cat Leak)\n"
	fmt.Print(header)
	fmt.Fprint(w, header)

	// The leaked Google-search URL carried the hash as percent-encoded bytes.
	encoded := "%62%36%63%63%62%34%65%63%65%35%34%35%34%64%63%61%65%35%31%37%37%38%62%33%65%32%33%39%65%62%63%32"
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		fmt.Fprintf(w, "  decode error: %v\n", err)
		return
	}
	line := fmt.Sprintf("  URL-decoded MD5 hash: %s\n", decoded)
	fmt.Print(line)
	fmt.Fprint(w, line)

	// The password is cat-related; confirm which candidate matches the MD5.
	candidates := []string{"meow", "meowmeow", "meowmeowmeow", "cat", "catcat", "kitty", "kittycat"}
	for _, c := range candidates {
		if crack.Hash(c) == decoded {
			out := fmt.Sprintf("  [+] password: %q\n  [+] FLAG: cryptoCTF{%s}\n", c, c)
			fmt.Print(out)
			fmt.Fprint(w, out)
			return
		}
	}
	miss := "  [-] no candidate matched the hash\n"
	fmt.Print(miss)
	fmt.Fprint(w, miss)
}

func main() {
	// "go run . lab0" runs the interactive Lab 0 proof program instead.
	if len(os.Args) > 1 && os.Args[1] == "lab0" {
		runLab0()
		return
	}

	vf, err := os.Create(verbosePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating %s: %v\n", verbosePath, err)
		os.Exit(1)
	}
	defer vf.Close()
	vw := bufio.NewWriter(vf)
	defer vw.Flush()

	banner := fmt.Sprintf("======== Hashing Lab: Password Cracking ========\nWordlist: %s\n", wordlistPath)
	fmt.Print(banner)
	fmt.Fprint(vw, banner)

	// Lab 1: MD5
	fmt.Fprint(vw, "\n----- Lab 1: MD5 attempts -----\n")
	r1, e1 := crack.CrackMD5(wordlistPath, md5Target, vw)
	report(vw, "Lab 1", "MD5", md5Target, r1, e1)

	// Lab 2: SHA1
	fmt.Fprint(vw, "\n----- Lab 2: SHA1 attempts -----\n")
	r2, e2 := crack.CrackSHA1(wordlistPath, sha1Target, vw)
	report(vw, "Lab 2", "SHA1", sha1Target, r2, e2)

	// Lab 3: SHA512
	fmt.Fprint(vw, "\n----- Lab 3: SHA512 attempts -----\n")
	r3, e3 := crack.CrackSHA512(wordlistPath, sha512Target, vw)
	report(vw, "Lab 3", "SHA512", sha512Target, r3, e3)

	// Lab 4: Mini-CTF
	lab4(vw)

	done := "\n================ Done ================\n"
	fmt.Print(done)
	fmt.Fprint(vw, done)
}
