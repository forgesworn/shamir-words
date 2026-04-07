# AGENTS.md — @forgesworn/shamir-words

Instructions in this file apply to the entire repository.

## Project Summary

`@forgesworn/shamir-words` is a TypeScript library implementing Shamir's Secret Sharing over GF(256) with BIP-39 word encoding. Secrets are split into human-readable mnemonic shares that can be exchanged, stored, and later combined to reconstruct the original secret. The entire library lives in a single source file with no CLI surface.

## Key Commands

```bash
npm install          # install dependencies
npm run build        # compile TypeScript → dist/
npm test             # run vitest test suite
npm run typecheck    # type-check without emitting
npm run clean        # remove dist/
```

## Repository Structure

```
src/
  index.ts           # entire library: GF(256) arithmetic, split/reconstruct, word encoding
tests/
  index.test.ts      # comprehensive vitest suite
dist/                # compiled output — committed for quick consumption, rebuilt by CI
examples/            # usage examples
```

## Coding Conventions

- **British English** in all docs and code comments — licence, serialise, colour, initialise
- **ESM-only** (`"type": "module"`) — no CommonJS exports
- **Strict TypeScript** — `noUncheckedIndexedAccess` and strict mode enabled
- **Error hierarchy** — throw `ShamirValidationError` for bad inputs, `ShamirCryptoError` for internal failures; both extend `ShamirError`
- **Zero secrets in memory** — polynomial coefficients must be zeroed via `zeroBytes` after use
- **Audited dependencies only** — `@noble/hashes` v2 and `@scure/bip39` v2; never introduce homebrew crypto

## Wire Format (v2)

Word-encoded shares pack as: `[data_length, threshold, share_id, ...data, checksum]` packed into 11-bit groups and mapped to BIP-39 words. The checksum is the first byte of SHA-256 over the preceding bytes. `wordsToShare` recovers threshold automatically from the encoding.

Key constraints:
- Share IDs are 1-indexed (1–255) — 0 is not a valid GF(256) evaluation point
- Secret max size is 255 bytes — limited by the single-byte length prefix in the wire format
- `reconstructSecret` uses only the first `threshold` shares from the array

## Working Guidelines

- Write or update tests before changing library behaviour (TDD)
- Do not add dependencies without a strong justification; prefer `@noble/*` / `@scure/*` ecosystem
- The `dist/` directory is committed — always run `npm run build` before committing source changes
- Commit messages use `type: description` format (e.g. `feat:`, `fix:`, `docs:`, `refactor:`)
- Do not add `Co-Authored-By` lines to commits

## Release Notes

Releases are automated via semantic-release triggered on push to `main`. Do not manually edit `CHANGELOG.md` or bump versions in `package.json` — semantic-release handles both. Work on a feature branch and merge to `main` only when complete.
