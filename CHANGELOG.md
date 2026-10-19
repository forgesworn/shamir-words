## [1.2.0](https://github.com/forgesworn/shamir-words/compare/v1.1.0...v1.2.0) (2026-10-19)

Promotes `1.2.0-alpha.1` to `latest`, with the changes below. The v3 typed
envelope is still alpha: the paper-share and Heartwood hardware restore
ceremony has not run. Use v3 with test secrets and keep another backup.

### Changed

* `engines.node` is now `>=20.19.0`, the floor declared by `@noble/hashes` v2.
  It was `>=18`, which is below the floor of the `@noble/hashes` v2 dependency.

### Documentation

* say that the v3 envelope needs `1.2.0` or later; `1.1.0` and earlier have
  only the v2 functions.
* name `@forgesworn/shamir-core` among the runtime dependencies.
* define the v3 types and payload kinds (with their wire codes), and document
  that `payloadKind` is required.
* document that `reconstructSecret` uses only the first `threshold` shares, and
  list which inputs throw `ShamirValidationError` (too few shares, duplicate
  IDs, threshold mismatch, inconsistent data lengths, and every v3 rejection).
* complete the `llms.txt` API surface (`shareToWordsV3`, `wordsToShareV3`,
  `SHAMIR_WORDS_FORMAT_VERSION` and the v3 types) and correct `llms-full.txt`
  where it disagreed with the source.

## [1.2.0-alpha.1](https://github.com/forgesworn/shamir-words/compare/v1.1.0...v1.2.0-alpha.1) (2026-08-31)

### Added

* add an opt-in v3 word envelope with a collision-free sentinel, `FS` magic,
  explicit format version, recovery payload kind, eight-byte original-secret
  fingerprint, and four-byte checksum. Safe split/reconstruct helpers reject
  shares mixed across independently randomised split operations.
  `shareToWords` and `wordsToShare` retain their historical v2 wire behaviour;
  `splitSecretToWordsV3`, `reconstructWordsV3`, `shareToWordsV3`,
  `wordsToShareV3`, and `decodeWordsEnvelope` provide the new and migration
  paths without invalidating existing paper shares.

### Alpha status

* the v3 format passes automated unit and cross-repository recovery tests, but
  the complete ForgeSworn paper-share and Heartwood restore ceremony has not
  yet run on hardware. Keep historical v2 shares unchanged, use v3 with test
  secrets only, and retain an independent backup.

# [1.1.0](https://github.com/forgesworn/shamir-words/compare/v1.0.4...v1.1.0) (2026-04-11)


### Changed

* migrate release tooling from `semantic-release` to [`forgesworn/release-action`](https://github.com/forgesworn/release-action). Removes three semantic-release devDependencies and their transitive tree, replaces the classic `NPM_TOKEN` + `NPM_CONFIG_PROVENANCE=true` publish path with OIDC trusted publishing driven by `publishConfig.provenance: true` in `package.json`, and hardens the pre-publish path with gated secret scanning over `dist/` + `src/`, exports-map verification, runtime-only `npm audit`, unpinned-action audit, and per-release tarball integrity recording. No runtime, API, or wire-format changes for consumers.


### Why

`@forgesworn/shamir-words` was previously publishing via semantic-release's classic token path. The migration replaces it with pure-bash release tooling that (a) removes long-lived `NPM_TOKEN` from the repo secrets once a new OIDC trusted publisher is configured at `npmjs.com`, (b) adds hard pre-publish gates tuned for cryptography-adjacent libraries, and (c) stamps the published tarball's sha256/sha512 into the GitHub Release body so consumers can hash-compare against the registry tarball at any time.

`@forgesworn/shamir-words` is the third consumer of `forgesworn/release-action` after `nsec-tree@1.5.0` and `geohash-kit@1.6.0`, and the **first scoped-package consumer** — validating the scoped-package trusted-publisher path in the wild.

## [1.0.4](https://github.com/forgesworn/shamir-words/compare/v1.0.3...v1.0.4) (2026-03-24)


### Bug Fixes

* add semantic-release config and update CI to Node 24 ([219ec92](https://github.com/forgesworn/shamir-words/commit/219ec9232863c71a0eabd5e1619db47b182ba744))
