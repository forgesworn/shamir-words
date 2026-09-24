# AGENTS.md: @forgesworn/shamir-words

Instructions in this file apply to the entire repository.

## Project Summary

`@forgesworn/shamir-words` is a TypeScript library implementing Shamir's Secret Sharing over GF(256) with BIP-39 word encoding. Secrets are split into human-readable mnemonic shares that can be exchanged, stored, and later combined to reconstruct the original secret. The entire library lives in a single source file with no CLI surface. An opt-in v3 typed envelope (alpha) adds payload-kind metadata and a secret fingerprint on top of the frozen v2 wire format.

## Key Commands

```bash
npm install          # install dependencies
npm run build        # compile TypeScript -> dist/
npm test             # run vitest test suite
npm run test:watch   # vitest in watch mode
npm run typecheck    # type-check without emitting
npm run clean        # remove dist/
```

## Dependencies

- `@forgesworn/shamir-core`: core GF(256) and Shamir split/reconstruct arithmetic
- `@noble/hashes` v2: SHA-256 for wire format checksums and the v3 secret fingerprint
- `@scure/bip39` v2: BIP-39 wordlist and encoding utilities
- No other runtime dependencies. Do not introduce homebrew crypto.

## Repository Structure

```
src/
  index.ts           # entire library: word encoding/decoding, v3 envelope; re-exports split/reconstruct from @forgesworn/shamir-core
tests/
  index.test.ts      # comprehensive vitest suite
dist/                # build output; gitignored, not committed, built by `npm run build` for CI and for publishing
examples/            # usage examples
```

## Coding Conventions

- **British English** in all docs and code comments: licence, serialise, colour, initialise
- **ESM-only** (`"type": "module"`): no CommonJS exports
- **Strict TypeScript**: `noUncheckedIndexedAccess` and strict mode enabled
- **Error hierarchy**: throw `ShamirValidationError` for bad inputs, `ShamirCryptoError` for internal failures; both extend `ShamirError`
- **Zero secrets in memory**: buffers holding secret or share bytes are zeroed with `.fill(0)` after use (see `shareToWordsV3`, `reconstructWordsV3`); the polynomial zeroing inside `splitSecret`/`reconstructSecret` lives in the `@forgesworn/shamir-core` dependency
- **Audited dependencies only**: `@noble/hashes` v2 and `@scure/bip39` v2; never introduce homebrew crypto

## Wire Formats

- Historical v2 (`shareToWords` / `wordsToShare`) is frozen as `[data_length, threshold, share_id, ...data, checksum_1]`. The threshold is embedded in the encoding, so `wordsToShare` recovers it automatically.
- Opt-in v3 (alpha) is `[0x00, "FS", 3, payload_kind, data_length, threshold, share_id, secret_fingerprint_8, ...data, checksum_4]`. The zero sentinel cannot collide with v2's non-zero length. Prefer `splitSecretToWordsV3` / `reconstructWordsV3`, which bind and re-check the original secret so mixed split sets fail closed. `decodeWordsEnvelope` is the explicit migration decoder that reports v2 shares as `opaque`.
- Never silently change `shareToWords`; paper v2 shares are load-bearing. New ForgeSworn recovery flows should use strict v3, retain the decoded payload kind, and verify the v3 secret fingerprint through reconstruction.

Key constraints:
- Share IDs are 1-indexed (1-255): 0 is not a valid GF(256) evaluation point
- Secret max size is 255 bytes: limited by the single-byte length prefix in the wire format
- `reconstructSecret` uses only the first `threshold` shares from the array

## Working Guidelines

- Write or update tests before changing library behaviour (TDD)
- Do not add dependencies without a strong justification; prefer `@noble/*` / `@scure/*` ecosystem
- `dist/` is gitignored and not committed; do not stage it
- Commit messages use `type: description` format (e.g. `feat:`, `fix:`, `docs:`, `refactor:`)
- Do not add `Co-Authored-By` lines to commits

## Release Notes

Releases go through [`forgesworn/anvil`](https://github.com/forgesworn/anvil), not semantic-release. Version bumps and `CHANGELOG.md` entries are manual.

Release flow:

1. Bump `package.json` version by hand (e.g. `1.0.4` -> `1.1.0`)
2. Add a `CHANGELOG.md` entry under the new version heading
3. Commit (`chore: release 1.1.0`), push `main`
4. Tag the commit (`git tag v1.1.0 && git push --tags`)
5. Create a GitHub Release pointing at the tag; the workflow replaces the body from `CHANGELOG.md` and appends an artefact integrity block
6. The release workflow runs pre-publish gates (tag match, secret scan over `dist/` + `src/`, exports sanity, runtime audit) and publishes to npm with SLSA provenance via OIDC trusted publishing

Prereleases must set `publishConfig.tag` (this package currently publishes under the `alpha` tag) so they cannot move npm's `latest` tag.

Semver rules of thumb:

| Change | Bump |
|---|---|
| Bug fix, no API change | Patch (1.1.x) |
| New feature, backwards compatible | Minor (1.x.0) |
| Breaking API, wire format, or GF(256) output change | Major (x.0.0) |
| Tooling, docs, refactor with no behaviour change | Patch or none |

**Wire format is load-bearing.** A change that alters the bytes produced by `shareToWords` or accepted by `wordsToShare` must be treated as breaking: existing shares in the wild would stop reconstructing. Bump to major and document the migration path.

The runtime audit gate (`npm audit --omit=dev`) is a hard pre-publish blocker. If `@forgesworn/shamir-core`, `@noble/hashes`, or `@scure/bip39` have an open advisory at release time, the publish is refused until it is patched.
