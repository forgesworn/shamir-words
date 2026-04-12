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

## Release & Versioning

**Via [forgesworn/anvil](https://github.com/forgesworn/anvil).** Version bumps are manual; npm publishing is automatic once a GitHub Release is created for the version tag.

Release flow:

1. Bump `package.json` version by hand (e.g. `1.0.4` → `1.1.0`)
2. Add a `CHANGELOG.md` entry under the new version heading
3. Commit (`chore: release 1.1.0`), push main
4. Tag the commit (`git tag v1.1.0 && git push --tags`)
5. Create a GitHub Release pointing at the tag (placeholder body is fine — the workflow replaces it from CHANGELOG and appends an artefact integrity block)
6. The release workflow runs pre-publish gates (tag match, secret scan over `dist/` + `src/`, exports sanity, runtime audit) and publishes to npm with SLSA provenance via OIDC trusted publishing

Semver rules of thumb:

| Change | Bump |
|---|---|
| Bug fix, no API change | Patch (1.1.x) |
| New feature, backwards compatible | Minor (1.x.0) |
| Breaking API, wire format, or GF(256) output change | Major (x.0.0) |
| Tooling, docs, refactor with no behaviour change | Patch or none |

**Wire format is load-bearing.** A change that alters the bytes produced by `shareToWords` or accepted by `wordsToShare` must be treated as breaking — existing shares in the wild would stop reconstructing. Bump to major and document the migration path.

The runtime audit gate (`npm audit --omit=dev`) is a hard pre-publish blocker. If `@forgesworn/shamir-core`, `@noble/hashes`, or `@scure/bip39` have an open advisory at release time, the publish is refused until it is patched.
