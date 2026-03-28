# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in shamir-words, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **thecryptodonkey@proton.me** with:

1. A description of the vulnerability
2. Steps to reproduce
3. Impact assessment (what an attacker could achieve)
4. Suggested fix (if you have one)

You should receive an acknowledgement within 48 hours. We aim to release a fix within 7 days of confirmation.

## Scope

shamir-words is a cryptographic primitive library. The following are in scope:

- **Shamir reconstruction correctness** -- any input that causes incorrect secret recovery
- **GF(256) arithmetic errors** -- incorrect field operations
- **Checksum bypass** -- inputs that pass checksum validation despite corruption
- **Information leakage** -- shares revealing information about the secret below the threshold
- **Wire format parsing** -- malformed input causing crashes, hangs, or unexpected behaviour

## Dependencies

This library depends on two audited cryptographic libraries:

- `@noble/hashes` -- SHA-256 (checksum computation)
- `@scure/bip39` -- BIP-39 English wordlist

Vulnerabilities in these dependencies should be reported to their respective maintainers.

## Design Properties

- **Information-theoretic security**: fewer than `threshold` shares reveal zero information about the secret (proven property of Shamir's scheme over GF(256))
- **Integrity detection**: SHA-256 checksum byte detects transcription errors with 99.6% probability
- **Memory hygiene**: polynomial coefficients are zeroed after use; callers should zero share data when done
- **No timing-sensitive operations**: GF(256) arithmetic uses table lookups with no secret-dependent branching
