// Lab 0: Name + Hashing proof program.
// This lives in the same package as main.go, so its entry point is runLab0()
// (not main). Run it with:  go run . lab0
package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// proofMe calculates and compares hashes of two inputs.
func proofMe(input1, input2 string) {

	// MD5
	hashA := md5.Sum([]byte(input1))
	hashB := md5.Sum([]byte(input2))
	compareHash("MD5", hashA[:], hashB[:])

	// SHA1
	hashA1 := sha1.Sum([]byte(input1))
	hashB1 := sha1.Sum([]byte(input2))
	compareHash("SHA1", hashA1[:], hashB1[:])

	// SHA256
	hashA256 := sha256.Sum256([]byte(input1))
	hashB256 := sha256.Sum256([]byte(input2))
	compareHash("SHA256", hashA256[:], hashB256[:])

	// SHA512
	hashA512 := sha512.Sum512([]byte(input1))
	hashB512 := sha512.Sum512([]byte(input2))
	compareHash("SHA512", hashA512[:], hashB512[:])

	// SHA3-256
	hashA3 := sha3.Sum256([]byte(input1))
	hashB3 := sha3.Sum256([]byte(input2))
	compareHash("SHA3-256", hashA3[:], hashB3[:])
}

// compareHash displays and compares two hash values.
func compareHash(name string, outputA, outputB []byte) {

	fmt.Println("\nHash Algorithm:", name)
	fmt.Println("Output A:", hex.EncodeToString(outputA))
	fmt.Println("Output B:", hex.EncodeToString(outputB))

	if hex.EncodeToString(outputA) == hex.EncodeToString(outputB) {
		fmt.Println("Result: Match!")
	} else {
		fmt.Println("Result: No Match!")
	}
}

// runLab0 is the interactive entry point for Lab 0.
func runLab0() {

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("======= Name + Hashing Program =======")

	fmt.Print("Please input value 1: ")
	input1, _ := reader.ReadString('\n')
	input1 = strings.TrimSpace(input1)

	fmt.Print("Please input value 2: ")
	input2, _ := reader.ReadString('\n')
	input2 = strings.TrimSpace(input2)

	proofMe(input1, input2)
}
