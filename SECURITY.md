# Security Policy

## Audit Status

This library has not undergone a formal security audit.

## Algorithm

This library implements Shamir's Secret Sharing over the Galois field GF(256), with BIP-39 word encoding for human-readable share representation.

A secret is split into _n_ shares such that any _t_ (threshold) shares can reconstruct the original secret via Lagrange interpolation, while fewer than _t_ shares reveal zero information about the secret. Each share is encoded as a list of BIP-39 English words for safe transcription and spoken communication.

## Academic Reference

- **Shamir, Adi (1979)** -- "How to Share a Secret". Communications of the ACM, 22(11), pp. 612-613. The foundational paper proving that polynomial-based secret sharing over a finite field achieves information-theoretic security.

## Security Properties

- **Information-theoretic security** -- fewer than _threshold_ shares reveal zero information about the secret. This is a proven mathematical property of Shamir's scheme over a finite field, not dependent on computational hardness assumptions.
- **Integrity checking** -- a SHA-256 checksum byte is embedded in each word-encoded share, detecting transcription errors before reconstruction.
- **Memory hygiene** -- polynomial coefficients are zeroed after use to reduce the window of secret exposure in memory.

## Dependencies

- [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) -- SHA-256 checksum computation (audited by Cure53)
- [`@scure/bip39`](https://github.com/paulmillr/scure-bip39) -- BIP-39 English wordlist (audited by Cure53)
- [`@forgesworn/shamir-core`](https://github.com/forgesworn/shamir-core) -- GF(256) arithmetic and Lagrange interpolation

## Known Limitations

- **Maximum 255 shares** -- constrained by the GF(256) field size (evaluation points 1-255).
- **Secret length 1-255 bytes** -- limited by the single-byte length prefix in the wire format.
- **Minimum threshold of 2** -- a threshold of 1 is not secret sharing, it is copying.

## Reporting Vulnerabilities

Please report security vulnerabilities via [GitHub Security Advisories](https://github.com/forgesworn/shamir-words/security/advisories/new).

Do not open public issues for security-sensitive reports.
