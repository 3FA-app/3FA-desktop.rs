# Secure Bluetooth protocol v1

Status: cryptographic transport implemented; operating-system Bluetooth adapters not yet enabled.

The Rust desktop app and its Flutter companion treat every Bluetooth bearer as an attacker-controlled byte stream. Bluetooth pairing and link encryption are useful defense in depth, but they do not replace the application-layer handshake in `src/secure_bluetooth.rs` and `lib/src/secure_bluetooth.dart`.

## Security goal and limits

Protocol v1 protects the confidentiality, integrity, ordering, and peer-confirmed origin of short-lived desktop-to-desktop messages. It uses:

- a fresh X25519 key pair and 128-bit random contribution from each peer;
- a transcript-bound HKDF-SHA256 expansion into independent directional keys and nonce prefixes;
- an explicitly compared six-digit short authentication string (SAS) before either side obtains an encryption API; and
- ChaCha20-Poly1305 frames with authenticated headers, transcript, session identifier, direction, and counter.

The SAS provides about 20 bits of active-man-in-the-middle detection for one carefully compared handshake. It is not a device certificate and it is ineffective when a user accepts without comparing both displays. Adapters must rate-limit new pairing attempts and explain that both screens must show the same digits.

The protocol does not hide device identifiers, message lengths, timing, radio metadata, or the fact that two devices communicate. It does not provide unattended pairing, durable trust, session resumption, group messaging, or protection after an endpoint is compromised.

## State machine and invariants

The implementation exposes three disjoint states:

```text
one-use pairing secret --derive(peer hello)--> pending keys
pending keys --confirm(equal SAS, <= 2 minutes)--> active session
pending/active --drop, mismatch, expiry, or limit--> terminal
```

The public API and tests enforce these invariants:

1. No application plaintext can be encrypted or decrypted before SAS confirmation.
2. A pairing private key is generated for one handshake, consumed once, never serialized, and destroyed after key agreement.
3. Initiator transmit material equals responder receive material, while the opposite direction uses different material.
4. The canonical initiator hello precedes the canonical responder hello in every transcript, independent of local role.
5. A `(directional key, nonce)` pair is never reused: the four-byte direction-specific prefix is followed by an eight-byte big-endian counter.
6. Receive counters must be exact. Replayed, skipped, duplicated, and reordered frames fail before decryption and do not advance state.
7. Unknown versions, roles, message types, trailing bytes, invalid identifiers, all-zero contributions, all-zero public keys, reflected keys, and low-order X25519 results fail closed.
8. A session accepts at most 4,096 frames per direction, at most 16 KiB of plaintext per frame, and remains active for at most five minutes.
9. Cryptographic failures have bounded, input-independent public messages. Logs and telemetry must never contain hellos, frames, SAS values, key material, or plaintext.

## Canonical encodings

All integers are unsigned and big-endian. Text is strict ASCII. Lengths include only the field named.

Hello (`3FBH`, version 1):

| Field | Bytes |
| --- | ---: |
| Magic | 4 |
| Version | 1 |
| Role (`0` initiator, `1` responder) | 1 |
| Session identifier | 16 |
| Random contribution | 16 |
| Device identifier length | 1 |
| Device identifier (`[A-Za-z0-9_-]`, 8–64 bytes) | variable |
| X25519 public key | 32 |

The responder copies the initiator's session identifier. The handshake transcript is:

```text
"3fa-secure-bluetooth-v1"
|| uint16(len(initiator_hello)) || initiator_hello
|| uint16(len(responder_hello)) || responder_hello
```

Both sides compute `transcript_hash = SHA-256(transcript)` and:

```text
HKDF-SHA256(
  salt = transcript_hash,
  input_key_material = X25519(local_private, peer_public),
  info = "3fa-secure-bluetooth-v1",
  output_length = 104
)
```

The expansion is split into the initiator transmit key (32), responder transmit key (32), initiator nonce prefix (4), responder nonce prefix (4), and SAS material (32). The SAS is the first four SAS-material bytes interpreted as a big-endian integer modulo 1,000,000 and zero-padded to six digits.

Encrypted frame (`3FBE`, version 1):

| Field | Bytes |
| --- | ---: |
| Magic | 4 |
| Version | 1 |
| Message type (`1` control, `2` enrollment, `3` vault transfer) | 1 |
| Directional counter | 8 |
| Ciphertext-plus-tag length | 2 |
| ChaCha20 ciphertext | variable |
| Poly1305 tag | 16 |

The nonce is `directional_prefix || counter`. The authenticated additional data is `transcript_hash || session_id || frame_header`. A Bluetooth adapter may fragment and reassemble a complete hello or frame, but it must pass only exact canonical messages to this layer.

## Cross-language conformance

Rust and Dart use the same fixed seeds, contributions, identifiers, SAS (`621942`), and encrypted `cross-language` frame in their unit tests. Any protocol change that alters the vector is a new wire version, not a silent v1 edit. Both suites must pass before either desktop app ships the change.

`formal/secure_bluetooth_model.py` exhaustively explores a finite abstraction of
the lifecycle, expiry, directional counters, tamper, replay, reordering, and
disposal rules. `just formal` checks this model with the existing desktop state
models. The formal abstraction complements the byte-level cryptographic tests;
it does not replace cryptographic review.

Companion implementation: `../3fa-client-ui.dart/lib/src/secure_bluetooth.dart` in the coordinated local checkout.

## Adapter acceptance gate

OS-specific Bluetooth work is intentionally the next change, after this substrate. A macOS, Windows, or Linux adapter is acceptable only when it:

- requests Bluetooth permissions only in a build that contains a reachable pairing flow;
- prefers authenticated LE Secure Connections where the platform permits, while still requiring this protocol;
- advertises only a random, protocol-scoped service identifier and never puts secrets in names or advertisements;
- applies strict connection, reassembly, byte, attempt, and timeout limits before parsing;
- never exposes application plaintext to GATT/L2CAP callbacks or persists session material;
- renders a deliberate two-device SAS confirmation step with cancel and timeout behavior;
- disables background/unattended vault transfer; and
- passes shared Rust/Dart vectors plus platform tests for tamper, replay, cancellation, permission denial, radio loss, and reconnect-with-a-new-handshake.

Until that gate is satisfied, the repositories should not add Bluetooth entitlements, platform manifests, or runtime permissions.
