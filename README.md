# shamir-words

> **Alpha:** the opt-in v3 typed envelope is shipping as `1.2.0-alpha.1` for
> integration testing. Automated and cross-repository tests pass, but the full
> paper-share and Heartwood hardware restore ceremony has not run. Existing v2
> shares remain unchanged; use v3 with test secrets and keep another backup.

**Nostr:** [`npub1mgvlrnf5hm9yf0n5mf9nqmvarhvxkc6remu5ec3vf8r0txqkuk7su0e7q2`](https://njump.me/npub1mgvlrnf5hm9yf0n5mf9nqmvarhvxkc6remu5ec3vf8r0txqkuk7su0e7q2)

[![npm](https://img.shields.io/npm/v/@forgesworn/shamir-words)](https://www.npmjs.com/package/@forgesworn/shamir-words)
[![CI](https://github.com/forgesworn/shamir-words/actions/workflows/ci.yml/badge.svg)](https://github.com/forgesworn/shamir-words/actions/workflows/ci.yml)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

**Split secrets into human-readable word shares that can be spoken, written down, or stored separately.**

Backing up cryptographic keys is hard. Raw byte shares are error-prone to transcribe and impossible to read over the phone. shamir-words combines [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) over GF(256) with [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) word encoding, so each share becomes a list of familiar English words — just like a Bitcoin seed phrase.

## Why shamir-words?

- **Human-readable shares** — each share is a BIP-39 word list, not a hex blob
- **Threshold recovery** — any _t_ of _n_ shares reconstruct the secret; fewer reveal nothing
- **Integrity checking** — SHA-256 checksum detects transcription errors before reconstruction
- **Typed v3 envelopes** — opt-in magic/version and payload semantics prevent recovered bytes being mistaken for the wrong kind of key
- **Minimal dependencies** — only `@noble/hashes` and `@scure/bip39` (audited cryptographic libraries)
- **TypeScript-first** — full type safety with exported interfaces and error classes

## Install

```bash
npm install @forgesworn/shamir-words
```

## Quick Start

```typescript
import {
  splitSecret,
  reconstructSecret,
  shareToWords,
  wordsToShare,
} from '@forgesworn/shamir-words';

// Your secret (e.g. a 32-byte private key)
const secret = new Uint8Array([
  0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
]);

// Split into 5 shares, any 3 can reconstruct
const shares = splitSecret(secret, 3, 5);

// Convert each share to speakable words
const wordShares = shares.map(shareToWords);
// e.g. ["abandon", "ability", "able", ...] — one word list per share

// Later: decode words back to shares and reconstruct
const decoded = wordShares.map(wordsToShare);
const recovered = reconstructSecret(decoded, 3);
// recovered === secret
```

## API

### `splitSecret(secret, threshold, shares)`

Split a secret into Shamir shares over GF(256).

| Parameter | Type | Description |
|-----------|------|-------------|
| `secret` | `Uint8Array` | The secret to split (1-255 bytes) |
| `threshold` | `number` | Minimum shares needed to reconstruct (2-255) |
| `shares` | `number` | Total shares to create (threshold-255) |

Returns `ShamirShare[]`.

### `reconstructSecret(shares, threshold)`

Reconstruct a secret from shares using Lagrange interpolation.

| Parameter | Type | Description |
|-----------|------|-------------|
| `shares` | `ShamirShare[]` | At least `threshold` shares |
| `threshold` | `number` | The threshold used during splitting |

Returns `Uint8Array` — the original secret.

### `shareToWords(share)`

Encode a share as BIP-39 words. The word list embeds the share ID, threshold, data, and a SHA-256 checksum byte for integrity.

Returns `string[]`.

### `wordsToShare(words)`

Decode BIP-39 words back to a share. Verifies the checksum and rejects corrupted or tampered input.

Returns `ShamirShare`.

### `splitSecretToWordsV3(secret, threshold, shares, { payloadKind })`

Safely split and encode new ForgeSworn recovery material. Every v3 share binds
the payload meaning and a 64-bit error-detection fingerprint of the original
secret. Supported meanings are `opaque`, `bip39-entropy`, `raw-nsec-v1`,
`nsec-tree-root-v1`, `nsec-tree-mnemonic-v1`, `nsec-tree-nsec-v1`, and
`forgesworn-recovery-words-v1`.

```typescript
const wordShares = splitSecretToWordsV3(secret, 2, 3, {
  payloadKind: 'forgesworn-recovery-words-v1',
});

const recovered = reconstructWordsV3(wordShares.slice(0, 2));
// recovered.payloadKind is preserved and mixed share sets are rejected.
recovered.secret.fill(0);
```

The lower-level `shareToWordsV3(share, { payloadKind, secret })` is available
when shares were split separately. Supplying the original secret binds the
same fingerprint into every share. `shareToWords()` remains the frozen
historical v2 encoder.

### `wordsToShareV3(words)`

Strictly decode v3, returning
`{ formatVersion: 3, payloadKind, secretFingerprint, share }`. It never falls
back to v2, so a damaged typed header cannot silently change meaning.
`reconstructWordsV3()` additionally rejects inconsistent metadata and checks
the fingerprint after reconstruction, catching shares mixed across split
operations. `decodeWordsEnvelope(words)` is the explicit migration decoder for
a collection that may contain old v2 paper shares; it reports v2 as `opaque`
with no fingerprint.

### Types

```typescript
interface ShamirShare {
  id: number;        // 1-255 (the x-coordinate)
  threshold: number; // 2-255 (minimum shares for reconstruction)
  data: Uint8Array;  // evaluated polynomial bytes
}
```

### Error Classes

- `ShamirError` — base class for all errors
- `ShamirValidationError` — invalid inputs (wrong types, out-of-range values)
- `ShamirCryptoError` — cryptographic failures (e.g. GF(256) zero inverse)

## Wire Format

Historical v2 (`shareToWords`) remains:

```
[data_length, threshold, share_id, ...data, checksum]
```

The byte stream is split into 11-bit groups, each mapped to a BIP-39 word. The checksum is the first byte of SHA-256 over the preceding bytes.

Opt-in v3 (`shareToWordsV3`) packs:

```
[0x00, 0x46, 0x53, 3, payload_kind, data_length, threshold, share_id,
 secret_fingerprint_8, ...data, checksum_4]
```

The leading zero can never be a valid v2 data length. The checksum is the first
four bytes of SHA-256 over the preceding bytes. The secret fingerprint is the
first eight bytes of a domain-separated SHA-256 over the payload kind and
original secret. Both are integrity and error detection, not authentication.

## Limitations

- Secret size: 1-255 bytes (covers all standard key sizes up to 255 bytes)
- Share count: up to 255 (the GF(256) field size minus zero)
- Threshold: 2-255 (single-share schemes are just copying, not secret sharing)

## Part of the ForgeSworn Toolkit

[ForgeSworn](https://forgesworn.dev) builds open-source cryptographic identity, payments, and coordination tools for Nostr.

| Library | What it does |
|---------|-------------|
| [nsec-tree](https://github.com/forgesworn/nsec-tree) | Deterministic sub-identity derivation (uses shamir-words for recovery) |
| [dominion](https://github.com/forgesworn/dominion) | Epoch-based encrypted access control (Shamir key distribution) |
| [ring-sig](https://github.com/forgesworn/ring-sig) | SAG/LSAG ring signatures on secp256k1 |
| [range-proof](https://github.com/forgesworn/range-proof) | Pedersen commitment range proofs |
| [canary-kit](https://github.com/forgesworn/canary-kit) | Coercion-resistant spoken verification |
| [spoken-token](https://github.com/forgesworn/spoken-token) | Human-speakable verification tokens |
| [toll-booth](https://github.com/forgesworn/toll-booth) | L402 payment middleware |
| [nostr-attestations](https://github.com/forgesworn/nostr-attestations) | NIP-VA verifiable attestations |
| [geohash-kit](https://github.com/forgesworn/geohash-kit) | Geohash toolkit with polygon coverage |

## Licence

[MIT](LICENCE)
