// Package sealstream seals a byte stream into authenticated, slot-bound chunks.
//
// It is a module rather than a package copied into each service that needs it,
// because both sides of every transfer must frame identically. A second copy of
// an AEAD format is the kind of duplication that fails silently: each copy
// passes its own round-trip tests while disagreeing with the other, and the
// disagreement surfaces only when a real stream will not open.
// testdata/vectors.json is what stops that.
//
// A document is never sealed in one shot. Doing so would mean either buffering
// it whole or emitting plaintext before its authentication tag verifies, and
// both are unacceptable for a large object. So the stream is a sequence of
// independently sealed frames, and a reader returns plaintext only after the
// frame carrying it has authenticated.
//
// Wire format:
//
//	[Magic "DPF"][version byte][8-byte random nonce prefix][frame 0]…[final frame]
//
// Each frame is AES-256-GCM over at most FrameSize bytes of plaintext, so it is
// FrameSize+Overhead bytes on the wire. Only the final frame may be shorter,
// and it may be empty.
//
// The nonce is the 8-byte per-object prefix followed by a 4-byte big-endian
// frame counter — 12 bytes, GCM's standard nonce length. The split is 8 random
// and 4 counted rather than the reverse: an object is capped at 50 MiB, so a
// 32-bit counter has headroom it will never use, while a 32-bit random prefix
// would collide across the objects sharing one per-document DEK. See the
// constants below for the arithmetic. The prefix is random per object, so two
// seals of the same plaintext under the same key never produce the same bytes.
//
// The magic and the version byte are also the first bytes of every frame's
// additional data, so a stream cannot be re-labelled as another format or
// another version without failing authentication.
//
// Changing anything above orphans every artefact already written rather than
// upgrading it, which is what the version byte exists to make survivable: a
// reader can recognise a format it does not implement and say so
// (ErrUnsupportedVersion) instead of reporting corruption.
//
// The magic stays "DPF", from the service that first wrote these streams.
// Changing it would orphan every artefact for the sake of a name.
//
// The additional data binds each frame to one specific object and to its
// position within it:
//
//	binding ‖ 0x00 ‖ frameIndex ‖ finalFlag
//
// The binding names the object, not merely its job. A job-scoped binding would
// leave every input of a document interchangeable with every other — and §1.1
// forbids inferring page order from upload timing, so ordering is exactly the
// property that most needs protecting. It would equally leave markdown,
// thumbnail and merged_pdf mutually substitutable, since they share a job and
// a DEK.
//
// Inputs are sealed before a job exists — the caller uploads files and only then
// submits the job that names them — so an input binds to a caller-minted stream
// id rather than to a job id. Outputs bind to the job and the artifact.
//
// The final flag is inside the AAD rather than beside it so that it cannot be
// flipped: an attacker who truncates the stream cannot re-label the last
// surviving frame as final. The 0x00 separator keeps the concatenation
// unambiguous, which is why a binding may not contain one.
package sealstream

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// FrameSize is the plaintext carried by one frame.
	FrameSize = 64 * 1024

	// Overhead is the GCM tag appended to each frame.
	Overhead = 16

	// KeySize is the DEK length. AES-256 only.
	KeySize = 32

	// Version is the format this writer produces.
	//
	// It exists because the stream had none. The first byte was a random nonce
	// byte, so an old stream and a new one were indistinguishable and any
	// change to the format would have orphaned every artefact already written
	// rather than upgrading it (AUDIT.md §10). Added while artefacts live at
	// most seven days, which is the only cheap moment to do it.
	Version = 1

	magicSize  = 3
	headerSize = magicSize + 1 + noncePrefixSize

	// noncePrefixSize is 8 rather than 4 because the counter needs far less
	// room than the prefix does. An object is capped at 50 MiB — 800 frames —
	// so a 32-bit counter has 2^32 frames of headroom it will never use, while
	// a 32-bit random prefix would collide across the ~53 objects that share
	// one per-document DEK with probability around 3e-7. GCM nonce reuse leaks
	// plaintext and the authentication key, so the split is 8 random bytes and
	// a 4-byte counter: 256 TiB per object, and collisions around 1e-16.
	noncePrefixSize  = 8
	nonceCounterSize = 4
	maxFrames        = uint64(1) << (8 * nonceCounterSize)

	frameOnWire = FrameSize + Overhead
)

// Magic marks a stream as this format.
//
// Not a security property — the authentication is the GCM tag — but it turns
// "somebody handed the reader a PDF" into a clear answer instead of a tag
// mismatch, which reads like tampering and sends people looking for an
// attacker who is not there.
var Magic = []byte("DPF")

var _ = [1]struct{}{}[len(Magic)-magicSize] // Magic and magicSize must agree

// ErrUnsupportedVersion reports a stream written in a format this reader does
// not know.
//
// It wraps ErrCorrupt as well, deliberately: every existing caller classifies
// on ErrCorrupt, and a stream this reader cannot authenticate is unreadable to
// it whatever the cause. Without that, an unknown version would look like a
// transport fault and be retried forever.
var ErrUnsupportedVersion = errors.New("sealstream: unsupported format version")

// Binding names the one object a stream may be. It is authenticated, so a
// stream sealed under one binding can never be opened under another.
//
// Use InputBinding and OutputBinding rather than building one by hand.
type Binding string

// InputBinding binds an uploaded input to its caller-minted stream id.
//
// The stream id exists because an input is sealed before any job id does: the
// caller uploads files first and submits the job that names them second. It is
// carried back to this service in inputs[].stream so the input can be opened.
func InputBinding(stream string) Binding { return Binding("input:" + stream) }

// OutputBinding binds a generated artefact to its job and its kind, so the
// artefacts of one job cannot be substituted for one another.
func OutputBinding(job, artifact string) Binding {
	return Binding("output:" + job + ":" + artifact)
}

// ErrCorrupt reports a stream that failed to authenticate — truncated,
// reordered, modified, or opened with the wrong key or binding. The causes are
// deliberately indistinguishable from one another.
//
// It is NOT returned for a transport failure. §6.1 needs those told apart: a
// reset connection is retryable and a tampered stream is not, so an I/O error
// is wrapped and returned as itself.
var ErrCorrupt = errors.New("sealstream: stream failed to authenticate")

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("sealstream: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sealstream: %w", err)
	}
	return cipher.NewGCM(block)
}

func validate(b Binding) error {
	if b == "" {
		return errors.New("sealstream: binding must not be empty")
	}
	if strings.ContainsRune(string(b), 0x00) {
		return errors.New("sealstream: binding must not contain a NUL, which separates the AAD fields")
	}
	return nil
}

type binder struct {
	prefix [noncePrefixSize]byte
	aad    []byte // magic ‖ version ‖ binding ‖ 0x00, awaiting index and flag
}

// newBinder builds the additional data every frame is authenticated under.
//
// **The magic and version are in it.** A version byte that is merely present
// rather than authenticated is a downgrade waiting to happen: a reader that one
// day accepts two versions would otherwise let a v2 stream be reinterpreted as
// v1, with whatever weaknesses v1 had. Today the literal check in next() is
// what enforces it — there is only one version — so this is the property that
// makes the version byte worth anything at all later. It is pinned by a
// white-box test, because with one version it cannot be observed from outside.
func newBinder(b Binding) binder {
	var bd binder
	bd.aad = append(bd.aad, Magic...)
	bd.aad = append(bd.aad, Version)
	bd.aad = append(bd.aad, b...)
	bd.aad = append(bd.aad, 0x00)
	return bd
}

// header is the bytes that precede the first frame.
func (b *binder) header() []byte {
	h := make([]byte, 0, headerSize)
	h = append(h, Magic...)
	h = append(h, Version)
	return append(h, b.prefix[:]...)
}

func (b *binder) nonce(index uint64) []byte {
	n := make([]byte, 0, noncePrefixSize+nonceCounterSize)
	n = append(n, b.prefix[:]...)
	return binary.BigEndian.AppendUint32(n, uint32(index))
}

func (b *binder) additionalData(index uint64, final bool) []byte {
	ad := binary.BigEndian.AppendUint32(append([]byte(nil), b.aad...), uint32(index))
	if final {
		return append(ad, 0x01)
	}
	return append(ad, 0x00)
}

// ── writer ───────────────────────────────────────────────────────────────────

// Writer seals a plaintext stream. Close must be called: it writes the final
// frame, which is what makes truncation detectable.
type Writer struct {
	w      io.Writer
	aead   cipher.AEAD
	binder binder

	buf    []byte
	index  uint64
	header bool
	closed bool
	err    error
}

// NewWriter returns a Writer sealing to w under key, bound to b.
//
// A Writer is not safe for concurrent use, and must be discarded after any
// method returns an error.
func NewWriter(w io.Writer, key []byte, b Binding) (*Writer, error) {
	if err := validate(b); err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	fw := &Writer{w: w, aead: aead, binder: newBinder(b)}
	if _, err := rand.Read(fw.binder.prefix[:]); err != nil {
		return nil, fmt.Errorf("sealstream: nonce prefix: %w", err)
	}
	return fw, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, errors.New("sealstream: write after close")
	}

	w.buf = append(w.buf, p...)
	// Strictly greater: a buffer of exactly FrameSize is held back, because we
	// cannot know it is non-final until more plaintext arrives.
	for len(w.buf) > FrameSize {
		if err := w.flush(w.buf[:FrameSize], false); err != nil {
			return 0, err
		}
		// Slide rather than reslice, so the backing array is not reallocated
		// once per frame over a long stream.
		w.buf = w.buf[:copy(w.buf, w.buf[FrameSize:])]
	}
	return len(p), nil
}

// Close writes the final frame. A stream without one cannot be opened.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return nil
	}
	w.closed = true
	return w.flush(w.buf, true)
}

func (w *Writer) flush(plain []byte, final bool) error {
	if w.index >= maxFrames {
		w.err = errors.New("sealstream: frame counter exhausted")
		return w.err
	}
	if !w.header {
		if _, err := w.w.Write(w.binder.header()); err != nil {
			w.err = err
			return err
		}
		w.header = true
	}

	sealed := w.aead.Seal(nil, w.binder.nonce(w.index), plain, w.binder.additionalData(w.index, final))
	if _, err := w.w.Write(sealed); err != nil {
		w.err = err
		return err
	}
	w.index++
	return nil
}

// ── reader ───────────────────────────────────────────────────────────────────

// Reader opens a sealed stream. It never returns plaintext from a frame that
// has not authenticated.
type Reader struct {
	r      *bufio.Reader
	aead   cipher.AEAD
	binder binder

	plain  []byte
	index  uint64
	header bool
	done   bool
	err    error
}

// NewReader returns a Reader opening r under key, bound to b. The nonce prefix
// is read lazily, on the first Read.
//
// A Reader is not safe for concurrent use.
func NewReader(r io.Reader, key []byte, b Binding) (*Reader, error) {
	if err := validate(b); err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &Reader{
		r:      bufio.NewReaderSize(r, frameOnWire),
		aead:   aead,
		binder: newBinder(b),
	}, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	for len(r.plain) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.done {
			return 0, io.EOF
		}
		if err := r.next(); err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

func (r *Reader) next() error {
	if !r.header {
		h := make([]byte, headerSize)
		if _, err := io.ReadFull(r.r, h); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("%w: header", ErrCorrupt)
			}
			return fmt.Errorf("sealstream: read header: %w", err)
		}
		if !bytes.Equal(h[:len(Magic)], Magic) {
			return fmt.Errorf("%w: not a sealed stream", ErrCorrupt)
		}
		if v := h[len(Magic)]; v != Version {
			// Both errors, so callers classifying on either are right (§6.1).
			return fmt.Errorf("%w: %w: version %d, this reader speaks %d",
				ErrCorrupt, ErrUnsupportedVersion, v, Version)
		}
		copy(r.binder.prefix[:], h[len(Magic)+1:])
		r.header = true
	}
	if r.index >= maxFrames {
		return fmt.Errorf("%w: frame counter exhausted", ErrCorrupt)
	}

	buf := make([]byte, frameOnWire)
	n, err := io.ReadFull(r.r, buf)

	final := false
	switch {
	case err == nil:
		// A full frame. It is final only if nothing follows it — and only a
		// clean EOF means that. Any other peek error is the transport failing,
		// which must not be laundered into an authentication verdict.
		if _, peekErr := r.r.Peek(1); peekErr != nil {
			if !errors.Is(peekErr, io.EOF) {
				return fmt.Errorf("sealstream: read frame %d: %w", r.index, peekErr)
			}
			final = true
		}
	case errors.Is(err, io.ErrUnexpectedEOF):
		// A short frame is necessarily the last one on the wire. Whether it is
		// the one the writer sealed as final is for the AEAD to decide.
		final = true
	case errors.Is(err, io.EOF):
		// Nothing read at all: a valid stream always carries at least one
		// frame, so this is truncation rather than completion.
		return fmt.Errorf("%w: no frame", ErrCorrupt)
	default:
		return fmt.Errorf("sealstream: read frame %d: %w", r.index, err)
	}

	plain, openErr := r.aead.Open(nil, r.binder.nonce(r.index), buf[:n], r.binder.additionalData(r.index, final))
	if openErr != nil {
		return ErrCorrupt
	}

	r.plain = plain
	r.index++
	r.done = final
	return nil
}
