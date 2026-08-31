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

## Wire Formats

- Historical v2 (`shareToWords` / `wordsToShare`) is frozen as `[data_length, threshold, share_id, ...data, checksum_1]`.
- Opt-in v3 is `[0x00, "FS", 3, payload_kind, data_length, threshold, share_id, secret_fingerprint_8, ...data, checksum_4]`. The zero sentinel cannot collide with v2's non-zero length. Prefer `splitSecretToWordsV3` / `reconstructWordsV3`, which bind and re-check the original secret so mixed split sets fail closed. `decodeWordsEnvelope` is the explicit migration decoder.
- Never silently change `shareToWords`; paper v2 shares are load-bearing. New ForgeSworn recovery flows should use strict v3, retain the decoded payload kind, and verify the v3 secret fingerprint through reconstruction.

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

Version bumps and changelog entries are manual. After merging to `main`, create
a GitHub Release for the matching tag; `forgesworn/anvil` runs the release gates
and publishes through npm OIDC. Prereleases must set `publishConfig.tag` so they
cannot move npm's `latest` tag. Work on a feature branch and merge to `main`
only when complete.
