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
- **Minimal dependencies**: `@noble/hashes` (SHA-256) and `@scure/bip39` (wordlist), both audited cryptographic libraries, plus `@forgesworn/shamir-core`, which supplies `splitSecret`, `reconstructSecret` and the error classes that this package re-exports
- **TypeScript-first** — full type safety with exported interfaces and error classes

## Install

```bash
npm install @forgesworn/shamir-words@alpha
```

The v3 typed envelope ships in `1.2.0-alpha.1`, which is published under the
`alpha` dist-tag. A plain `npm install @forgesworn/shamir-words` resolves the
`latest` tag (currently `1.1.0`), which has only the v2 functions
(`splitSecret`, `reconstructSecret`, `shareToWords`, `wordsToShare`) and none
of the `*V3` functions or `decodeWordsEnvelope`. Install `@alpha`, or pin
`@forgesworn/shamir-words@1.2.0-alpha.1`, to use v3.

ESM only. Requires Node.js 20.19 or later, the floor set by `@noble/hashes` v2.

## Quick Start

This example uses only the v2 functions, so it works on both tags.

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

Split a secret into Shamir shares over GF(256). Re-exported from `@forgesworn/shamir-core`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `secret` | `Uint8Array` | The secret to split: non-empty, and at most 255 bytes if the shares will be encoded as words |
| `threshold` | `number` | Minimum shares needed to reconstruct (2-255) |
| `shares` | `number` | Total shares to create (threshold-255) |

Returns `ShamirShare[]` with IDs `1` to `shares`. Throws `ShamirValidationError`
for a secret that is not a non-empty `Uint8Array`, a non-integer `threshold` or
`shares`, `threshold` outside 2-255, `shares` below `threshold`, or `shares`
above 255. The 255-byte secret limit comes from the single-byte length prefix
in the word formats: `splitSecret` itself (as of `@forgesworn/shamir-core`
1.0.3) does not check an upper bound, but `shareToWords`, `shareToWordsV3` and `splitSecretToWordsV3` throw
`ShamirValidationError` for share data longer than 255 bytes.

### `reconstructSecret(shares, threshold)`

Reconstruct a secret from shares using Lagrange interpolation. Re-exported from
`@forgesworn/shamir-core`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `shares` | `ShamirShare[]` | At least `threshold` shares |
| `threshold` | `number` | The threshold used during splitting |

Returns `Uint8Array`, the original secret.

Only the first `threshold` entries of `shares` are used. Any further shares are
ignored and are not validated, so a duplicate ID or bad data beyond that point
goes unnoticed. Throws `ShamirValidationError` when:

- `threshold` is not a safe integer of at least 2
- `shares` is not an array, or has fewer than `threshold` entries (too few shares)
- a used share is not an object, has an `id` that is not an integer in 1-255, or has `data` that is not a `Uint8Array`
- two used shares have the same `id` (duplicate IDs)
- a used share carries an integer `threshold` that differs from the `threshold` argument (threshold mismatch)
- the used shares have empty data, or data of different lengths

Shares that are structurally valid but wrong, such as shares from two different
splits or shares with altered bytes, do not throw: you get incorrect bytes
back. Compare the result with a known hash, or use `reconstructWordsV3`, which
checks a fingerprint of the original secret.

### `shareToWords(share)`

Encode a share as BIP-39 words. The word list embeds the share ID, threshold, data, and a SHA-256 checksum byte for integrity.

Returns `string[]`. Throws `ShamirValidationError` if the share is not an object,
its `id` is not an integer in 1-255, its `threshold` is not an integer in
2-255, or its `data` is empty, not a `Uint8Array`, or longer than 255 bytes.

### `wordsToShare(words)`

Decode BIP-39 words back to a share. Verifies the checksum and rejects corrupted or tampered input.

Returns `ShamirShare`. Throws `ShamirValidationError` for input that is not an
array, an empty list or one longer than 256 words, a word that is not a string
or not in the BIP-39 English wordlist, non-zero padding bits, a word count that
does not match the encoded data length, a threshold outside 2-255, a share ID
of 0, or a checksum mismatch. Words are matched case-insensitively after
trimming.

### `splitSecretToWordsV3(secret, threshold, shares, { payloadKind })`

Safely split and encode new ForgeSworn recovery material. Every v3 share binds
the payload meaning and a 64-bit error-detection fingerprint of the original
secret. Supported meanings are `opaque`, `bip39-entropy`, `raw-nsec-v1`,
`nsec-tree-root-v1`, `nsec-tree-mnemonic-v1`, `nsec-tree-nsec-v1`, and
`forgesworn-recovery-words-v1`.

`payloadKind` is required and has no default. A missing or unrecognised value
throws `ShamirValidationError`. It is a label that the library binds into every
share header and into the fingerprint; it does not check the secret's contents
or length against the kind. The `options` argument takes only `payloadKind`:
the secret is the first argument. Returns one word list per share
(`string[][]`).

```typescript
import {
  splitSecretToWordsV3,
  reconstructWordsV3,
} from '@forgesworn/shamir-words';

// A random test secret: use test secrets only while v3 is alpha.
const secret = crypto.getRandomValues(new Uint8Array(32));

// 2-of-3 typed shares; every share carries the payload kind and fingerprint.
const wordShares = splitSecretToWordsV3(secret, 2, 3, {
  payloadKind: 'forgesworn-recovery-words-v1',
});

// Any 2 of the 3 word lists reconstruct the secret.
const recovered = reconstructWordsV3(wordShares.slice(0, 2));
// recovered.payloadKind === 'forgesworn-recovery-words-v1'
// recovered.secretFingerprint is 16 lowercase hex characters
// recovered.secret holds the same bytes as `secret`
recovered.secret.fill(0); // the caller owns this buffer and must zero it
secret.fill(0);
```

### `reconstructWordsV3(wordShares)`

Strictly decode and reconstruct typed v3 shares. `wordShares` is a `string[][]`,
one word list per share. Returns `ReconstructedWordsV3`. Every supplied share
must agree on payload kind, secret fingerprint, threshold and data length, and
the fingerprint is checked again against the reconstructed secret, which
catches shares mixed across independently randomised splits.

Every word list is decoded and checked for consistency, but, as with
`reconstructSecret`, only the first `threshold` shares are interpolated, so
order matters when you pass more than `threshold` lists. Duplicate IDs are
detected only among those first `threshold` shares. Every rejection throws
`ShamirValidationError`; see [Errors and edge cases](#errors-and-edge-cases).

### `shareToWordsV3(share, { payloadKind, secret })`

Encode one share in the v3 envelope. Use it when shares were split separately
with `splitSecret`. `payloadKind` is required, and `secret` must be the original
secret, as a `Uint8Array` of the same length as `share.data`. The secret is
only hashed to make the fingerprint and is never written into a share; supplying
the same secret for every share binds the same fingerprint into all of them.
Returns `string[]`. `shareToWords()` remains the frozen historical v2 encoder.

### `wordsToShareV3(words)`

Strictly decode one v3 word list, returning a `DecodedWordsEnvelope` with
`formatVersion: 3`. It never falls back to v2, so a damaged typed header cannot
silently change meaning, and a v2 word list is rejected. It checks the
envelope, the four-byte checksum and the canonical word count, but it cannot
check the fingerprint on its own: that needs the reconstructed secret, which
`reconstructWordsV3()` does.

### `decodeWordsEnvelope(words)`

The explicit migration decoder for a collection that may contain old v2 paper
shares. A word list whose first decoded byte is zero is decoded as v3 (as
`wordsToShareV3` does); anything else is decoded as v2 (as `wordsToShare`
does) and reported with `formatVersion: 2`, `payloadKind: 'opaque'` and
`secretFingerprint: null`. Returns `DecodedWordsEnvelope`.

### `SHAMIR_WORDS_FORMAT_VERSION`

Exported constant, `3`. It is the format version written into every v3 envelope.

### Types

```typescript
interface ShamirShare {
  id: number;        // 1-255 (the x-coordinate)
  threshold: number; // 2-255 (minimum shares for reconstruction)
  data: Uint8Array;  // evaluated polynomial bytes
}

// Meaning label for the secret a v3 share set reconstructs.
type WordSharePayloadKind =
  | 'opaque'
  | 'bip39-entropy'
  | 'raw-nsec-v1'
  | 'nsec-tree-root-v1'
  | 'nsec-tree-mnemonic-v1'
  | 'nsec-tree-nsec-v1'
  | 'forgesworn-recovery-words-v1';

interface ShareToWordsV3Options {
  payloadKind: WordSharePayloadKind; // required, no default
  secret: Uint8Array;                // original secret, same length as share.data
}

interface DecodedWordsEnvelope {
  formatVersion: 2 | 3;              // 2 = historical v2, 3 = typed envelope
  payloadKind: WordSharePayloadKind; // always 'opaque' for v2
  secretFingerprint: string | null;  // 16 lowercase hex characters for v3, null for v2
  share: ShamirShare;
}

interface ReconstructedWordsV3 {
  payloadKind: WordSharePayloadKind;
  secretFingerprint: string;         // 16 lowercase hex characters
  secret: Uint8Array;                // caller-owned: zero it with .fill(0) when done
}
```

`ShamirShare` is a type re-exported from `@forgesworn/shamir-core`.
`splitSecretToWordsV3` takes `Pick<ShareToWordsV3Options, 'payloadKind'>` as its
fourth argument.

### Error Classes

Re-exported from `@forgesworn/shamir-core`.

- `ShamirError`: base class for all errors
- `ShamirValidationError`: invalid inputs (wrong types, out-of-range values, malformed or corrupted words, inconsistent shares)
- `ShamirCryptoError`: internal cryptographic failures (the GF(256) inverse of zero). Valid, distinct share IDs cannot trigger it, and none of the rejections listed below throw it.

## Errors and edge cases

Every validation failure in this package throws `ShamirValidationError`. This
table covers inputs that satisfy the TypeScript signatures.

| Function | Rejected input | Error class |
|----------|----------------|-------------|
| `splitSecret`, `splitSecretToWordsV3` | empty or non-`Uint8Array` secret, non-integer or out-of-range `threshold` or `shares` | `ShamirValidationError` |
| `splitSecretToWordsV3`, `shareToWords`, `shareToWordsV3` | share data over 255 bytes (so a secret over 255 bytes) | `ShamirValidationError` |
| `shareToWordsV3`, `splitSecretToWordsV3` | missing or unrecognised `payloadKind` | `ShamirValidationError` |
| `shareToWordsV3` | `secret` not a `Uint8Array` of the same length as `share.data` | `ShamirValidationError` |
| `wordsToShare`, `wordsToShareV3`, `decodeWordsEnvelope` | not an array, empty, over 256 words, unknown word, non-zero padding, wrong word count, word list too short, checksum mismatch, threshold below 2, share ID 0 | `ShamirValidationError` |
| `wordsToShareV3`, `reconstructWordsV3`, `decodeWordsEnvelope` (v3 input) | not a v3 envelope (including a v2 share), unsupported format version, unsupported payload kind, zero data length | `ShamirValidationError` |
| `reconstructWordsV3` | `wordShares` not an array or empty | `ShamirValidationError` |
| `reconstructWordsV3` | shares disagree on payload kind, secret fingerprint, threshold or data length | `ShamirValidationError` |
| `reconstructWordsV3` | fewer shares than the threshold, or duplicate share IDs among the first `threshold` shares | `ShamirValidationError` |
| `reconstructWordsV3` | reconstructed secret does not match the embedded fingerprint (shares mixed across splits, or wrong data) | `ShamirValidationError` |
| `reconstructSecret` | too few shares, duplicate IDs, threshold mismatch, inconsistent data lengths (see above) | `ShamirValidationError` |

Wrong shares that still pass every structural check make `reconstructSecret`
return incorrect bytes without throwing. `reconstructWordsV3` turns that case
into a `ShamirValidationError` by checking the fingerprint, which is an
error-detection check on 64 bits, not authentication.

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

The `payload_kind` byte maps to `WordSharePayloadKind` as follows (the codes are
not in the order of the type union):

| Code | Payload kind |
|------|--------------|
| 0 | `opaque` |
| 1 | `bip39-entropy` |
| 2 | `raw-nsec-v1` |
| 3 | `nsec-tree-root-v1` |
| 4 | `forgesworn-recovery-words-v1` |
| 5 | `nsec-tree-mnemonic-v1` |
| 6 | `nsec-tree-nsec-v1` |

## Limitations

- Secret size: 1-255 bytes when shares are encoded as words (the limit comes from the single-byte length prefix; `splitSecret` alone does not enforce an upper bound)
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
