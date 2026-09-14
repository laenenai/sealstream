package sealstream_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/laenenai/sealstream"
)

// AUDIT.md §10. The stream had no version and no magic: the first byte was a
// random nonce byte, so old ciphertext and new were indistinguishable. Any
// change to the format would have orphaned every artefact already written
// rather than upgrading it.
func TestTheStreamDeclaresItsFormat(t *testing.T) {
	key := bytes.Repeat([]byte{7}, sealstream.KeySize)
	out := seal(t, key, []byte("hello"), sealstream.InputBinding("s1"))

	if !bytes.HasPrefix(out, sealstream.Magic) {
		t.Errorf("stream starts %x, want the magic %x", out[:4], sealstream.Magic)
	}
	if got := out[len(sealstream.Magic)]; got != sealstream.Version {
		t.Errorf("version byte = %d, want %d", got, sealstream.Version)
	}
}

func TestAVersionedStreamStillRoundTrips(t *testing.T) {
	key := bytes.Repeat([]byte{7}, sealstream.KeySize)
	plain := bytes.Repeat([]byte("a document"), 20000) // several frames
	out := seal(t, key, plain, sealstream.InputBinding("s1"))

	r, err := sealstream.NewReader(bytes.NewReader(out), key, sealstream.InputBinding("s1"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("the plaintext did not survive")
	}
}

// A reader that met a format it does not know must say so, rather than
// reporting an authentication failure that sends somebody looking for an
// attacker.
func TestAnUnknownVersionIsRefusedClearly(t *testing.T) {
	key := bytes.Repeat([]byte{7}, sealstream.KeySize)
	out := seal(t, key, []byte("hello"), sealstream.InputBinding("s1"))
	out[len(sealstream.Magic)] = 99 // a version from the future

	r, err := sealstream.NewReader(bytes.NewReader(out), key, sealstream.InputBinding("s1"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	_, err = io.ReadAll(r)
	if !errors.Is(err, sealstream.ErrUnsupportedVersion) {
		t.Errorf("err = %v, want ErrUnsupportedVersion", err)
	}
	// Every existing caller classifies on ErrCorrupt, and a stream this reader
	// cannot authenticate is unreadable to it whatever the cause — so the old
	// classification must keep working.
	if !errors.Is(err, sealstream.ErrCorrupt) {
		t.Error("an unsupported version is not classified as corrupt; callers would treat it as a transport fault and retry forever")
	}
}

// Bytes that are not one of our streams at all — a plain PDF handed to the
// reader by mistake — should fail on the magic rather than after a GCM tag
// check that takes the long way round to the same answer.
func TestForeignBytesAreRefusedOnTheMagic(t *testing.T) {
	key := bytes.Repeat([]byte{7}, sealstream.KeySize)
	r, err := sealstream.NewReader(bytes.NewReader([]byte("%PDF-1.7\nnot a sealed stream at all")), key, sealstream.InputBinding("s1"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if _, err := io.ReadAll(r); !errors.Is(err, sealstream.ErrCorrupt) {
		t.Errorf("err = %v, want ErrCorrupt", err)
	}
}

func TestATruncatedHeaderIsCorruptNotATransportError(t *testing.T) {
	key := bytes.Repeat([]byte{7}, sealstream.KeySize)
	out := seal(t, key, []byte("hello"), sealstream.InputBinding("s1"))

	for _, n := range []int{0, 1, 3, 4, 8, 11} {
		r, err := sealstream.NewReader(bytes.NewReader(out[:n]), key, sealstream.InputBinding("s1"))
		if err != nil {
			t.Fatalf("NewReader: %v", err)
		}
		if _, err := io.ReadAll(r); !errors.Is(err, sealstream.ErrCorrupt) {
			t.Errorf("truncated to %d bytes: err = %v, want ErrCorrupt", n, err)
		}
	}
}

// A rewritten nonce prefix must fail authentication.
//
// Note what this does NOT prove: that the magic and version are in the AAD.
// Changing a nonce byte fails GCM on its own, so this test passes even with the
// header removed from the additional data entirely — which an earlier version
// of it claimed to disprove. The AAD property is pinned white-box, in
// aad_internal_test.go, because with one version defined it cannot be observed
// from out here at all.
func TestARewrittenNoncePrefixFailsAuthentication(t *testing.T) {
	key := bytes.Repeat([]byte{7}, sealstream.KeySize)
	out := seal(t, key, []byte("hello"), sealstream.InputBinding("s1"))

	tampered := bytes.Clone(out)
	tampered[len(sealstream.Magic)+1] ^= 0xFF // first byte of the nonce prefix

	r, _ := sealstream.NewReader(bytes.NewReader(tampered), key, sealstream.InputBinding("s1"))
	if _, err := io.ReadAll(r); !errors.Is(err, sealstream.ErrCorrupt) {
		t.Errorf("a rewritten nonce prefix was accepted: %v", err)
	}
}
