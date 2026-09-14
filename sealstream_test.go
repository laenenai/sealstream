package sealstream_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/laenenai/sealstream"
)

const (
	jobA = "Kd9xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	jobB = "Lm2pBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	streamA = "s1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	streamB = "s2BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

var (
	bindA = sealstream.InputBinding(streamA)
	bindB = sealstream.InputBinding(streamB)
	outA  = sealstream.OutputBinding(jobA, "markdown")
)

// noncePrefix is the per-object header, ahead of the first frame.
const noncePrefix = 8

func key(t *testing.T, fill byte) []byte {
	t.Helper()
	k := make([]byte, 32)
	for i := range k {
		k[i] = fill
	}
	return k
}

func plaintext(t *testing.T, n int) []byte {
	t.Helper()
	p := make([]byte, n)
	if _, err := rand.Read(p); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return p
}

func seal(t *testing.T, k, pt []byte, b sealstream.Binding) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := sealstream.NewWriter(&buf, k, b)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := w.Write(pt); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

func open(t *testing.T, k, ct []byte, b sealstream.Binding) ([]byte, error) {
	t.Helper()
	r, err := sealstream.NewReader(bytes.NewReader(ct), k, b)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// ── round trip ───────────────────────────────────────────────────────────────

func TestRoundTripIsByteIdentical(t *testing.T) {
	sizes := []int{
		0, 1, 1024,
		sealstream.FrameSize - 1, sealstream.FrameSize, sealstream.FrameSize + 1,
		2 * sealstream.FrameSize, 2*sealstream.FrameSize + 7,
		5 * sealstream.FrameSize,
	}
	k := key(t, 0x11)
	for _, n := range sizes {
		pt := plaintext(t, n)
		got, err := open(t, k, seal(t, k, pt, bindA), bindA)
		if err != nil {
			t.Fatalf("size %d: open: %v", n, err)
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("size %d: round trip differs", n)
		}
	}
}

func TestWritesInManySmallPiecesRoundTrip(t *testing.T) {
	k := key(t, 0x11)
	pt := plaintext(t, 3*sealstream.FrameSize+13)

	var buf bytes.Buffer
	w, err := sealstream.NewWriter(&buf, k, outA)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for off := 0; off < len(pt); off += 997 {
		end := min(off+997, len(pt))
		if _, err := w.Write(pt[off:end]); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := open(t, k, buf.Bytes(), outA)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Error("round trip differs")
	}
}

// Two seals of the same plaintext must differ: the nonce prefix is random per
// object, so ciphertext is never deterministic.
func TestCiphertextIsNotDeterministic(t *testing.T) {
	k, pt := key(t, 0x11), plaintext(t, 4096)
	if bytes.Equal(seal(t, k, pt, bindA), seal(t, k, pt, bindA)) {
		t.Error("two seals produced identical ciphertext")
	}
}

// ── truncation ───────────────────────────────────────────────────────────────

func TestTruncationIsDetected(t *testing.T) {
	k := key(t, 0x11)
	ct := seal(t, k, plaintext(t, 3*sealstream.FrameSize+100), bindA)

	cuts := map[string]int{
		"mid first frame":      1000,
		"one byte short":       len(ct) - 1,
		"final frame removed":  sealstream.FrameSize + 16 + noncePrefix,
		"everything but nonce": noncePrefix,
		"empty":                0,
	}
	for name, n := range cuts {
		t.Run(name, func(t *testing.T) {
			if _, err := open(t, k, ct[:n], bindA); err == nil {
				t.Error("truncated stream decrypted without error")
			}
		})
	}
}

// A stream cut exactly at a frame boundary must not look complete: the last
// surviving frame was sealed as non-final and must fail to open as final.
func TestTruncationAtAFrameBoundaryIsDetected(t *testing.T) {
	k := key(t, 0x11)
	ct := seal(t, k, plaintext(t, 3*sealstream.FrameSize), bindA)
	boundary := noncePrefix + 2*(sealstream.FrameSize+16)
	if _, err := open(t, k, ct[:boundary], bindA); err == nil {
		t.Error("stream truncated at a frame boundary decrypted without error")
	}
}

func TestAppendedDataIsDetected(t *testing.T) {
	k := key(t, 0x11)
	ct := seal(t, k, plaintext(t, 1000), bindA)
	if _, err := open(t, k, append(ct, 0x00), bindA); err == nil {
		t.Error("stream with appended data decrypted without error")
	}
}

// ── binding ──────────────────────────────────────────────────────────────────

// Without AAD binding a confused deputy could serve job A's output for job B
// and the cryptography would not object.
func TestAADBindsToTheJob(t *testing.T) {
	k := key(t, 0x11)
	ct := seal(t, k, plaintext(t, 4096), outA)
	if _, err := open(t, k, ct, sealstream.OutputBinding(jobB, "markdown")); err == nil {
		t.Error("job A's output decrypted under job B's AAD")
	}
}

func TestAADBindsToTheRole(t *testing.T) {
	k := key(t, 0x11)
	ct := seal(t, k, plaintext(t, 4096), bindA)
	if _, err := open(t, k, ct, outA); err == nil {
		t.Error("an input decrypted as an output")
	}
}

// Frame index is in the AAD, so reordering frames must fail.
func TestFrameReorderingIsDetected(t *testing.T) {
	k := key(t, 0x11)
	ct := seal(t, k, plaintext(t, 3*sealstream.FrameSize), bindA)

	const fr = sealstream.FrameSize + 16
	swapped := make([]byte, len(ct))
	copy(swapped, ct[:noncePrefix])
	copy(swapped[noncePrefix:], ct[noncePrefix+fr:noncePrefix+2*fr])
	copy(swapped[noncePrefix+fr:], ct[noncePrefix:noncePrefix+fr])
	copy(swapped[noncePrefix+2*fr:], ct[noncePrefix+2*fr:])

	if _, err := open(t, k, swapped, bindA); err == nil {
		t.Error("reordered frames decrypted without error")
	}
}

func TestBitFlipIsDetected(t *testing.T) {
	k := key(t, 0x11)
	ct := seal(t, k, plaintext(t, 4096), bindA)
	for _, i := range []int{0, 7, 8, 100, len(ct) - 1} {
		corrupt := bytes.Clone(ct)
		corrupt[i] ^= 0x01
		if _, err := open(t, k, corrupt, bindA); err == nil {
			t.Errorf("bit flip at %d decrypted without error", i)
		}
	}
}

// ── keys ─────────────────────────────────────────────────────────────────────

// The wrong DEK must fail, and must not emit partial plaintext.
func TestWrongKeyFailsAndEmitsNothing(t *testing.T) {
	ct := seal(t, key(t, 0x11), plaintext(t, 3*sealstream.FrameSize), bindA)

	r, err := sealstream.NewReader(bytes.NewReader(ct), key(t, 0x22), bindA)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	buf := make([]byte, sealstream.FrameSize)
	n, err := r.Read(buf)
	if err == nil {
		t.Fatal("read with the wrong key succeeded")
	}
	if errors.Is(err, io.EOF) {
		t.Error("wrong key reported EOF rather than an authentication failure")
	}
	if n != 0 {
		t.Errorf("emitted %d bytes of unauthenticated plaintext", n)
	}
}

func TestKeyMustBe32Bytes(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := sealstream.NewWriter(io.Discard, make([]byte, n), bindA); err == nil {
			t.Errorf("NewWriter accepted a %d-byte key", n)
		}
		if _, err := sealstream.NewReader(bytes.NewReader(nil), make([]byte, n), bindA); err == nil {
			t.Errorf("NewReader accepted a %d-byte key", n)
		}
	}
}

// The 0x00 separator is what makes the AAD unambiguous, so a binding that
// contains one would break the parse it exists to guarantee.
func TestBindingMustBeWellFormed(t *testing.T) {
	k := key(t, 0x11)
	for _, b := range []sealstream.Binding{"", "input:a\x00b", "\x00"} {
		if _, err := sealstream.NewWriter(io.Discard, k, b); err == nil {
			t.Errorf("NewWriter accepted binding %q", b)
		}
	}
}

// Two inputs of the SAME job, sealed under the SAME key, must not be
// interchangeable. §1.1 forbids inferring page order from timing, so order is
// exactly the property that most needs binding.
func TestInputsOfOneJobAreNotInterchangeable(t *testing.T) {
	k := key(t, 0x11)
	ct := seal(t, k, []byte("this is page 2"), bindB)
	if _, err := open(t, k, ct, bindA); err == nil {
		t.Error("page 2 opened as page 1")
	}
}

// markdown, thumbnail and merged_pdf share a job and a DEK. Substituting one for
// another must fail.
func TestArtifactsOfOneJobAreNotInterchangeable(t *testing.T) {
	k := key(t, 0x11)
	ct := seal(t, k, []byte("a thumbnail"), sealstream.OutputBinding(jobA, "thumbnail"))
	if _, err := open(t, k, ct, sealstream.OutputBinding(jobA, "markdown")); err == nil {
		t.Error("the thumbnail opened as markdown")
	}
}

func TestAnInputDoesNotOpenAsAnOutput(t *testing.T) {
	k := key(t, 0x11)
	ct := seal(t, k, plaintext(t, 4096), bindA)
	if _, err := open(t, k, ct, sealstream.OutputBinding(jobA, "markdown")); err == nil {
		t.Error("an input opened as an output")
	}
}

// errReader fails partway, the way a reset connection to the object store would.
type errReader struct {
	r   io.Reader
	err error
}

func (e *errReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err == io.EOF {
		return n, e.err
	}
	return n, err
}

// §6.1 needs a transport failure told apart from a tampered stream: one is
// retryable and the other is not. Reporting both as corruption makes the
// caller do the wrong thing for the transient case.
func TestTransportErrorIsNotReportedAsCorruption(t *testing.T) {
	k := key(t, 0x11)
	ct := seal(t, k, plaintext(t, 3*sealstream.FrameSize), bindA)

	boom := errors.New("connection reset by peer")
	r, err := sealstream.NewReader(&errReader{r: bytes.NewReader(ct), err: boom}, k, bindA)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	_, err = io.ReadAll(r)
	if err == nil {
		t.Fatal("a reset connection read as a complete stream")
	}
	if errors.Is(err, sealstream.ErrCorrupt) {
		t.Errorf("transport failure reported as corruption: %v", err)
	}
	if !errors.Is(err, boom) {
		t.Errorf("underlying error lost: %v", err)
	}
}
