# sealstream

A chunked AEAD stream: authenticated, bound to a slot, and safe to read before
you have seen the end of it.

```go
w, _ := sealstream.NewWriter(dst, key, sealstream.InputBinding(id))
w.Write(plaintext)
w.Close()

r, _ := sealstream.NewReader(src, key, sealstream.InputBinding(id))
io.Copy(out, r)   // yields plaintext only after each frame authenticates
```

## Why it is chunked

Sealing an object in one shot means either buffering it whole or emitting
plaintext before its authentication tag verifies. Neither is acceptable for a
large object, so the stream is a sequence of independently sealed frames and a
reader returns bytes only once the frame carrying them has authenticated. The
final frame is flagged, so a truncated stream fails rather than looking
complete.

| | |
|---|---|
| **Header** | `"DPF" ‖ version`, then an 8-byte nonce prefix — 12 bytes, once per stream |
| **Frame** | AES-256-GCM over at most 64 KiB of plaintext |
| **Nonce** | the 8-byte per-stream prefix and a 4-byte big-endian counter |
| **AAD** | `magic ‖ version ‖ binding ‖ 0x00 ‖ frame index ‖ final flag` |

## Why it is bound

The binding names *which object* a stream is, and it is authenticated. Without
it, a confused deputy could serve one object's bytes in answer to a request for
another and the cryptography would not object. Binding the frame index too means
frames cannot be reordered or dropped.

A binding that names only the job, rather than the object within it, leaves
every object of that job interchangeable — which is a real mistake and an easy
one, so the constructors take the object.

## The format is frozen by vectors, not by review

`testdata/vectors.json` holds streams written by this code, with their keys,
bindings and plaintext, and the suite reads them back.

A round-trip test proves only that a reader understands its own writer. Two
implementations can each pass their own round trips and still disagree,
undetectably, until a real stream will not open — by which time it is somebody's
data.

There is deliberately **no** test asserting the writer reproduces a vector's
bytes. The nonce is random per stream, because a deterministic GCM nonce under a
reused key is a key-recovery bug. Byte-equality is not a property this format
has, and a test asserting it would be asserting a vulnerability.

## The magic bytes are `DPF`

They came from the service that first wrote them, and they stay. Changing them
orphans every stream already written, and the format is not tied to a
repository just because its name once was.

## Versioning

The header carries a version and the AAD covers it, so a reader that one day
accepts two versions cannot be tricked into reading a new stream under old
rules. There is one version today; the byte exists so there can be a second.
