# Contributing to shamir-words

## Setup

```bash
git clone https://github.com/forgesworn/shamir-words.git
cd shamir-words
npm install
```

## Development

```bash
npm run build        # compile TypeScript → dist/
npm test             # run tests (vitest)
npm run test:watch   # run tests in watch mode
npm run typecheck    # type-check without emitting
```

## Making Changes

1. Create a branch from `main`
2. Make your changes in `src/index.ts`
3. Add or update tests in `tests/index.test.ts`
4. Ensure `npm test` and `npm run typecheck` pass
5. Open a pull request against `main`

## Conventions

- **British English** in docs and comments (licence, serialise, colour)
- **Strict TypeScript** — the project uses `noUncheckedIndexedAccess`
- **Commit messages** — `type: description` format (e.g. `fix:`, `feat:`, `docs:`)
- **Dependencies** — only audited cryptographic libraries (`@noble/hashes`, `@scure/bip39`); do not add new dependencies without discussion

## Releases

Releases are automated via [semantic-release](https://github.com/semantic-release/semantic-release) on push to `main`. Commit message format determines version bumps:

- `fix: ...` → patch
- `feat: ...` → minor
- `feat!: ...` or `BREAKING CHANGE:` → major
