# [1.1.0](https://github.com/forgesworn/shamir-words/compare/v1.0.4...v1.1.0) (2026-04-11)


### Changed

* migrate release tooling from `semantic-release` to [`forgesworn/release-action`](https://github.com/forgesworn/release-action). Removes three semantic-release devDependencies and their transitive tree, replaces the classic `NPM_TOKEN` + `NPM_CONFIG_PROVENANCE=true` publish path with OIDC trusted publishing driven by `publishConfig.provenance: true` in `package.json`, and hardens the pre-publish path with gated secret scanning over `dist/` + `src/`, exports-map verification, runtime-only `npm audit`, unpinned-action audit, and per-release tarball integrity recording. No runtime, API, or wire-format changes for consumers.


### Why

`@forgesworn/shamir-words` was previously publishing via semantic-release's classic token path. The migration replaces it with pure-bash release tooling that (a) removes long-lived `NPM_TOKEN` from the repo secrets once a new OIDC trusted publisher is configured at `npmjs.com`, (b) adds hard pre-publish gates tuned for cryptography-adjacent libraries, and (c) stamps the published tarball's sha256/sha512 into the GitHub Release body so consumers can hash-compare against the registry tarball at any time.

`@forgesworn/shamir-words` is the third consumer of `forgesworn/release-action` after `nsec-tree@1.5.0` and `geohash-kit@1.6.0`, and the **first scoped-package consumer** — validating the scoped-package trusted-publisher path in the wild.

## [1.0.4](https://github.com/forgesworn/shamir-words/compare/v1.0.3...v1.0.4) (2026-03-24)


### Bug Fixes

* add semantic-release config and update CI to Node 24 ([219ec92](https://github.com/forgesworn/shamir-words/commit/219ec9232863c71a0eabd5e1619db47b182ba744))
