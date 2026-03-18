# CLAUDE.md — shamir-words

## What this is

TypeScript library for Shamir's Secret Sharing over GF(256) with BIP-39 word encoding. Single source file, no CLI, pure library.

## Build & test

```bash
npm install
npm run build        # tsc → dist/
npm test             # vitest run
npm run typecheck    # tsc --noEmit
```

## Architecture

- `src/index.ts` — entire library (GF(256) arithmetic, Shamir split/reconstruct, BIP-39 word encoding)
- `tests/index.test.ts` — comprehensive test suite (vitest)
- `dist/` — compiled output (committed for quick consumption, rebuilt by CI)

## Conventions

- **British English** in docs and comments (licence, serialise, colour)
- **Strict TypeScript** — `noUncheckedIndexedAccess` enabled
- **Error hierarchy** — `ShamirError` → `ShamirValidationError` / `ShamirCryptoError`
- **Zero secrets in memory** — polynomial coefficients are zeroed after use (`zeroBytes`)
- **Audited deps only** — `@noble/hashes` and `@scure/bip39` (no homebrew crypto)

## Wire format (v2)

Word-encoded shares pack as: `[data_length, threshold, share_id, ...data, checksum]` → 11-bit groups → BIP-39 words. The checksum is the first byte of SHA-256 over the preceding bytes.

## Gotchas

- Share IDs are 1-indexed (1–255), not 0-indexed — 0 is not a valid GF(256) evaluation point
- Secret max size is 255 bytes (limited by the single-byte length prefix in the wire format)
- `reconstructSecret` uses only the first `threshold` shares from the array
- The threshold is embedded in the word encoding, so `wordsToShare` recovers it automatically
