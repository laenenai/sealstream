package sealstream_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/laenenai/sealstream"
)

// vector is one frozen stream: a known key, a known binding, known plaintext,
// and the exact ciphertext this format produces.
type vector struct {
	Name      string `json:"name"`
	KeyHex    string `json:"key_hex"`
	Binding   string `json:"binding"`
	Plaintext string `json:"plaintext"`
	CipherHex string `json:"cipher_hex"`
}

func vectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vs) == 0 {
		t.Fatal("no vectors")
	}
	return vs
}

// The claim: this format is frozen.
//
// It matters because two consumers can each pass their own round-trip tests and
// still disagree — a round trip proves a reader understands its own writer, not
// that either agrees with the format. That disagreement is undetectable until a
// real stream fails to open, by which time it is somebody's data.
func TestGoldenVectorsStillDecode(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			key, err := hex.DecodeString(v.KeyHex)
			if err != nil {
				t.Fatalf("key: %v", err)
			}
			cipher, err := hex.DecodeString(v.CipherHex)
			if err != nil {
				t.Fatalf("cipher: %v", err)
			}
			r, err := sealstream.NewReader(bytes.NewReader(cipher), key, sealstream.Binding(v.Binding))
			if err != nil {
				t.Fatalf("NewReader: %v", err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != v.Plaintext {
				t.Errorf("decoded %d bytes, want %d", len(got), len(v.Plaintext))
			}
		})
	}
}

// There is deliberately NO test asserting the writer reproduces a vector's
// bytes.
//
// It cannot hold, and it should not: the nonce is random per stream — see
// TestCiphertextIsNotDeterministic — because a deterministic GCM nonce under a
// reused key is a key-recovery bug, not a convenience. So byte-equality is not
// a property this format has, and a test asserting it would have to be
// "fixed" by breaking the cipher.
//
// TestGoldenVectorsStillDecode is the assertion that actually pins the format,
// and it holds regardless of the nonce: the header, the framing, the AAD
// construction and the frame sequence are all exercised by decoding a stream
// written before any future change.

// A vector decrypted under the wrong binding must fail to authenticate: the
// binding is in the AAD precisely so a stream cannot be replayed into another
// slot.
func TestAVectorRefusesTheWrongBinding(t *testing.T) {
	v := vectors(t)[1] // "short" — non-empty, so authentication has something to check
	key, _ := hex.DecodeString(v.KeyHex)
	cipher, _ := hex.DecodeString(v.CipherHex)

	r, err := sealstream.NewReader(bytes.NewReader(cipher), key, sealstream.Binding("input:someoneelse"))
	if err != nil {
		return // refused at construction is also correct
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Error("a stream decrypted under a different binding")
	}
}
