// Generates signed-note, checkpoint and cosignature vectors with the reference Go
// implementations, from fixed seeds, for remit-log's interoperability tests.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)


func main() {
	logSeed := make([]byte, 32)
	witSeed := make([]byte, 32)
	for i := range logSeed {
		logSeed[i] = byte(i)
		witSeed[i] = byte(0xa0 + i)
	}
	logName := "log.example.com/remit-test"
	witName := "witness.example.com/w1"
	logPub := ed25519.NewKeyFromSeed(logSeed).Public().(ed25519.PublicKey)
	witPub := ed25519.NewKeyFromSeed(witSeed).Public().(ed25519.PublicKey)

	logVkey, err := note.NewEd25519VerifierKey(logName, logPub)
	check(err)
	// A signer key in the sumdb format: PRIVATE+KEY+<name>+<hash>+base64(0x01 || seed).
	v, err := note.NewVerifier(logVkey)
	check(err)
	logSkey := fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", logName, v.KeyHash(), base64.StdEncoding.EncodeToString(append([]byte{1}, logSeed...)))
	signer, err := note.NewSigner(logSkey)
	check(err)

	body := logName + "\n8\nXcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=\n"
	signed, err := note.Sign(&note.Note{Text: body}, signer)
	check(err)

	// vkey per signed-note: name+hex(key ID)+base64(type || key), type 0x04 (tlog-cosignature).
	h := sha256.Sum256(append(append([]byte(witName+"\n"), 4), witPub...))
	witVkey := fmt.Sprintf("%s+%x+%s", witName, h[:4], base64.StdEncoding.EncodeToString(append([]byte{4}, witPub...)))
	wv, err := fnote.NewVerifierForCosignatureV1(witVkey)
	check(err)
	witSkey := fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", witName, wv.KeyHash(), base64.StdEncoding.EncodeToString(append([]byte{4}, witSeed...)))
	cosigner, err := fnote.NewSignerForCosignatureV1(witSkey)
	check(err)
	cosigned, err := note.Sign(&note.Note{Text: body}, signer, cosigner)
	check(err)

	// Round trip through the reference verifiers.
	n, err := note.Open(cosigned, note.VerifierList(v, wv))
	check(err)
	if len(n.Sigs) != 2 {
		panic("expected two verified signatures")
	}

	out := map[string]string{
		"log_seed_hex":     fmt.Sprintf("%x", logSeed),
		"log_vkey":         logVkey,
		"witness_seed_hex": fmt.Sprintf("%x", witSeed),
		"witness_vkey":     witVkey,
		"body":             body,
		"signed":           string(signed),
		"cosigned":         string(cosigned),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	check(enc.Encode(out))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
