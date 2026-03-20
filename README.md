# shamir-words

**Nostr:** [`npub1mgvlrnf5hm9yf0n5mf9nqmvarhvxkc6remu5ec3vf8r0txqkuk7su0e7q2`](https://njump.me/npub1mgvlrnf5hm9yf0n5mf9nqmvarhvxkc6remu5ec3vf8r0txqkuk7su0e7q2)

**Split secrets into human-readable word shares that can be spoken, written down, or stored separately.**

Backing up cryptographic keys is hard. Raw byte shares are error-prone to transcribe and impossible to read over the phone. shamir-words combines [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) over GF(256) with [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) word encoding, so each share becomes a list of familiar English words — just like a Bitcoin seed phrase.

## Why shamir-words?

- **Human-readable shares** — each share is a BIP-39 word list, not a hex blob
- **Threshold recovery** — any _t_ of _n_ shares reconstruct the secret; fewer reveal nothing
- **Integrity checking** — SHA-256 checksum detects transcription errors before reconstruction
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

Each word-encoded share packs bytes as:

```
[data_length, threshold, share_id, ...data, checksum]
```

The byte stream is split into 11-bit groups, each mapped to a BIP-39 word. The checksum is the first byte of SHA-256 over the preceding bytes.

## Limitations

- Secret size: 1-255 bytes (covers all standard key sizes up to 255 bytes)
- Share count: up to 255 (the GF(256) field size minus zero)
- Threshold: 2-255 (single-share schemes are just copying, not secret sharing)

## Licence

[MIT](LICENCE)
