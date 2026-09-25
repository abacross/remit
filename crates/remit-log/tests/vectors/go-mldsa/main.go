// Generates ML-DSA-44 cosignature vectors with the reference implementation
// (transparency-dev/formats, filippo.io/mldsa), and verifies cosignatures made elsewhere.
//
//	go run . gen                   > vectors.json
//	go run . verify <note> <vkey>  exits 0 if the note carries a valid cosignature by vkey
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"filippo.io/mldsa"
	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) == 4 && os.Args[1] == "verify" {
		text, err := os.ReadFile(os.Args[2])
		check(err)
		v, err := fnote.NewMLDSAVerifier(os.Args[3])
		check(err)
		n, err := note.Open(text, note.VerifierList(v))
		if err != nil {
			fmt.Println("REJECTED:", err)
			os.Exit(1)
		}
		fmt.Printf("verified %d signature(s) by %s\n", len(n.Sigs), v.Name())
		return
	}
	logSeed := make([]byte, 32)
	witSeed := make([]byte, 32)
	for i := range logSeed {
		logSeed[i] = byte(i)
		witSeed[i] = byte(0xc0 + i)
	}
	logName := "log.example.com/remit-test"
	witName := "witness.example.com/pq"
	logVkey, err := note.NewEd25519VerifierKey(logName, ed25519.NewKeyFromSeed(logSeed).Public().(ed25519.PublicKey))
	check(err)
	lv, err := note.NewVerifier(logVkey)
	check(err)
	logSigner, err := note.NewSigner(fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", logName, lv.KeyHash(), base64.StdEncoding.EncodeToString(append([]byte{1}, logSeed...))))
	check(err)
	witSigner, err := fnote.NewMLDSASigner(fmt.Sprintf("PRIVATE+KEY+%s+00000000+%s", witName, base64.StdEncoding.EncodeToString(append([]byte{6}, witSeed...))))
	check(err)
	priv, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), witSeed)
	check(err)
	pub := append([]byte{6}, priv.PublicKey().Bytes()...)
	sum := sha256.Sum256(append([]byte(witName+"\n"), pub...))
	witVkey := fmt.Sprintf("%s+%x+%s", witName, sum[:4], base64.StdEncoding.EncodeToString(pub))
	witVerifier, err := fnote.NewMLDSAVerifier(witVkey)
	check(err)
	body := logName + "\n8\nXcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=\n"
	signed, err := note.Sign(&note.Note{Text: body}, logSigner, witSigner)
	check(err)
	_, err = note.Open(signed, note.VerifierList(lv, witVerifier))
	check(err)
	out := map[string]string{
		"witness_seed_hex": fmt.Sprintf("%x", witSeed),
		"witness_name":     witName,
		"witness_vkey":     witVkey,
		"log_vkey":         logVkey,
		"body":             body,
		"cosigned":         string(signed),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	check(enc.Encode(out))
}
