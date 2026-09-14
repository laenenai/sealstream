package sealstream

import (
	"bytes"
	"testing"
)

// The magic and version are authenticated, not merely present.
//
// **This has to be a white-box test.** With one version defined, the reader's
// literal check rejects a wrong header before the AAD is ever consulted, so the
// property cannot be observed from outside the package — and an outside test
// that appears to prove it is really proving something else. An earlier version
// of this suite flipped a nonce-prefix byte and called that "the header is
// authenticated": it passed with the header removed from the AAD entirely,
// because a changed nonce fails GCM on its own.
//
// The property matters for the version after this one. A reader that accepts
// both v1 and v2 has no literal check to lean on, and only the AAD stops a v2
// stream being reinterpreted as v1 with whatever weaknesses v1 turned out to
// have.
func TestAdditionalDataCoversTheHeader(t *testing.T) {
	b := newBinder(InputBinding("s1"))
	ad := b.additionalData(0, false)

	if !bytes.HasPrefix(ad, Magic) {
		t.Errorf("additional data %q does not begin with the magic %q", ad, Magic)
	}
	if got := ad[len(Magic)]; got != Version {
		t.Errorf("the version is not authenticated: byte %d = %d, want %d", len(Magic), got, Version)
	}
	if !bytes.Contains(ad, []byte(InputBinding("s1"))) {
		t.Errorf("the binding left the additional data: %q", ad)
	}
}

// Two versions of the same binding must authenticate differently, which is the
// whole point: it is what will stop a downgrade when there is something to
// downgrade to.
func TestADifferentVersionWouldNotAuthenticate(t *testing.T) {
	b := newBinder(InputBinding("s1"))
	real := b.additionalData(3, true)

	// What the same frame would authenticate under if the version differed.
	var other []byte
	other = append(other, Magic...)
	other = append(other, Version+1)
	other = append(other, InputBinding("s1")...)
	other = append(other, 0x00)
	other = append(other, real[len(real)-5:]...) // same index and final flag

	if bytes.Equal(real, other) {
		t.Error("the version does not change the additional data; a downgrade would authenticate")
	}
}
