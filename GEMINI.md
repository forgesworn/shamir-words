# GEMINI.md -- @forgesworn/shamir-words

TypeScript library for Shamir's Secret Sharing over GF(256) with BIP-39 word encoding. Secrets are split into human-readable mnemonic shares that can be exchanged and later combined to reconstruct the original secret.

## Commands

```bash
npm install          # install dependencies
npm run build        # compile TypeScript → dist/
npm test             # run vitest test suite
npm run typecheck    # type-check without emitting output
npm run clean        # remove dist/
```

## Dependencies

- `@forgesworn/shamir-core` -- core GF(256) and Shamir arithmetic
- `@noble/hashes` v2 -- SHA-256 for wire format checksum
- `@scure/bip39` v2 -- BIP-39 wordlist and encoding utilities
- No other runtime dependencies. Do not introduce homebrew crypto.

## Structure

```
src/index.ts          -- entire library (GF arithmetic, split/reconstruct, BIP-39 encoding)
tests/index.test.ts   -- comprehensive vitest suite
dist/                 -- compiled output (committed; rebuilt by CI)
examples/             -- usage examples
```

## Conventions

- British English in all docs and comments -- licence, serialise, colour, initialise
- ESM-only (`"type": "module"`) -- no CommonJS
- Strict TypeScript -- `noUncheckedIndexedAccess` enabled
- Error hierarchy -- `ShamirError` base class, with `ShamirValidationError` and `ShamirCryptoError` subtypes
- Zero secrets in memory -- polynomial coefficients zeroed via `zeroBytes` after use
- Commit format: `type: description` (e.g. `feat:`, `fix:`, `docs:`, `refactor:`)
- No `Co-Authored-By` lines in commits

## Testing

Tests use vitest. Run `npm test` for a single pass or `npm run test:watch` for watch mode. Write or update tests before changing library behaviour. The test file covers GF(256) arithmetic, split/reconstruct round-trips, word encoding/decoding, error cases, and edge cases for share ID and secret size limits.

## Wire Format (v2)

Shares serialise as: `[data_length, threshold, share_id, ...data, checksum]` packed into 11-bit groups mapped to BIP-39 words.

Key constraints:
- Share IDs are 1-indexed (1--255) -- 0 is not a valid GF(256) evaluation point
- Secret max 255 bytes -- single-byte length prefix in the wire format
- `reconstructSecret` uses only the first `threshold` shares from the input array
- `wordsToShare` recovers threshold automatically from the encoding

## Release

Releases are automated via semantic-release on push to `main`. Do not manually edit `CHANGELOG.md` or bump versions in `package.json`. Work on a branch, merge to `main` only when complete.
