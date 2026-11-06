# Hashing Lab — Password Cracking (Go)

Dictionary-attack tool for the Cryptography hashing labs. It reads a public
wordlist (`nord_vpn.txt`), hashes every word with MD5 / SHA1 / SHA512, and
compares each result to a target hash to recover the original password.
Every attempt is also written to `verbose.txt`.

## Project structure

```
Hashing_lab/
├── go.mod                   # module hashing_lab (no external dependencies)
├── main.go                  # runs Lab 1-4, writes verbose.txt
├── nord_vpn.txt             # wordlist (1,437 passwords)
├── verbose.txt              # saved verbose output of a run
├── utils/
│   └── crack/
│       ├── md5.go           # Hash + CrackMD5      (crypto/md5)
│       ├── sha1.go          # HashSHA1 + CrackSHA1   (crypto/sha1)
│       └── sha512.go        # HashSHA512 + CrackSHA512 (crypto/sha512)
├── lab0.go                  # Lab 0 "name + hashing" proof program (helpers)
└── README.md
```

## How to run

```bash
# Run all four labs (also writes/overwrites verbose.txt)
go run .

# Or build then run
go build -o crack .
./crack          # Windows: crack.exe

# Run the separate Lab 0 proof program
go run . lab0
```

## Results

| Lab | Algorithm | Target hash (short)     | Password      |
| --- | --------- | ----------------------- | ------------- |
| 1   | MD5       | `6a85dfd7…28d73d3f`  | `Google101` |
| 2   | SHA1      | `aa1c7d93…1649c3b9`  | `Princess1` |
| 3   | SHA512    | `485f5c36…0ca5dd38`  | `Gutter11`  |
| 4   | MD5 (CTF) | `b6ccb4ec…3e239ebc2` | `meowmeow`  |

### Lab 4 — Mini-CTF (Cat Leak)

The leaked Google-search URL hid the password hash as percent-encoded bytes.
URL-decoding the query string reveals the real MD5 hash:

```
%62%36%63%63...%65%62%63%32  --URL-decode-->  b6ccb4ece5454dcae51778b3e239ebc2
```

That decoded value is the MD5 of the cat-related password `meowmeow`.

**Flag:** `cryptoCTF{meowmeow}`

This matches the challenge regex `^cryptoCTF\{(?:\x6d\x65\x6f\x77){2}\}$`,
where `\x6d\x65\x6f\x77` = `meow`, repeated twice → `meowmeow`.

## Notes

- Each cracker stops as soon as it finds a match, so the wordlist is not always
  scanned to the end (see the `Attempts` count per lab).
- These are weak, known passwords from a public breach wordlist. The exercise
  shows why fast, unsalted hashes (MD5/SHA1/SHA512) are a poor choice for storing
  passwords, and why slow, salted schemes like **bcrypt** / **argon2** are used
  instead — which is the point Lab 4's story makes.
