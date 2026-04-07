# shamir-words Cookbook

Common patterns and worked examples for `@forgesworn/shamir-words`.

---

## 1. Split a Nostr nsec into word shares

A Nostr private key is a 32-byte scalar. Encode it as raw bytes before splitting.

```typescript
import { splitSecret, shareToWords } from '@forgesworn/shamir-words';

// nsec as raw bytes (e.g. decoded from bech32 by @scure/base)
const nsecBytes: Uint8Array = getMyNsecBytes(); // 32 bytes

// 3-of-5: any 3 trustees can reconstruct
const shares = splitSecret(nsecBytes, 3, 5);
const wordShares = shares.map(shareToWords);

// Give each trustee their word list (e.g. print on paper, engrave on metal)
wordShares.forEach((words, i) => {
  console.log(`Trustee ${i + 1}: ${words.join(' ')}`);
});
```

---

## 2. Reconstruct from a subset of word shares

Collect threshold word shares from trustees. Each is decoded independently; if any fail, report which trustee needs to re-check their words.

```typescript
import {
  wordsToShare,
  reconstructSecret,
  ShamirValidationError,
  type ShamirShare,
} from '@forgesworn/shamir-words';

const collectedWords: string[][] = [
  trustee1Words,
  trustee3Words,
  trustee5Words,
];

const decodedShares: ShamirShare[] = [];

for (let i = 0; i < collectedWords.length; i++) {
  try {
    decodedShares.push(wordsToShare(collectedWords[i]!));
  } catch (err) {
    if (err instanceof ShamirValidationError) {
      console.error(`Share ${i + 1} failed: ${err.message}`);
      // Ask that trustee to re-read their words before proceeding
    } else {
      throw err;
    }
  }
}

if (decodedShares.length < 3) {
  throw new Error('Not enough valid shares to reconstruct');
}

const secret = reconstructSecret(decodedShares, 3);
```

---

## 3. Back up a Bitcoin BIP-32 seed

A BIP-32 seed is 64 bytes (512 bits). shamir-words handles up to 255 bytes, so this works directly.

```typescript
import { splitSecret, shareToWords } from '@forgesworn/shamir-words';

// 64-byte BIP-32 seed from BIP-39 mnemonic (via @scure/bip39)
const seed: Uint8Array = mnemonicToSeedSync('your twelve word mnemonic here'); // 64 bytes

// 2-of-3 for a simpler setup
const shares = splitSecret(seed, 2, 3);
const wordShares = shares.map(shareToWords);
// Each share is ~49 words for a 64-byte secret
```

---

## 4. Split a text passphrase

Encode the passphrase as UTF-8 bytes. Keep in mind the 255-byte limit.

```typescript
import { splitSecret, shareToWords } from '@forgesworn/shamir-words';

const passphrase = 'correct horse battery staple';
const secret = new TextEncoder().encode(passphrase);

if (secret.length > 255) {
  throw new Error('Passphrase too long — max 255 bytes encoded as UTF-8');
}

const shares = splitSecret(secret, 2, 3);
const wordShares = shares.map(shareToWords);
```

Reconstruct and decode back to string:

```typescript
import { wordsToShare, reconstructSecret } from '@forgesworn/shamir-words';

const recovered = reconstructSecret(wordShares.slice(0, 2).map(wordsToShare), 2);
const text = new TextDecoder().decode(recovered);
```

---

## 5. Verify a reconstructed secret

`reconstructSecret` does not throw when given syntactically valid but semantically wrong shares — it silently returns garbage. Always verify the result.

```typescript
import { sha256 } from '@noble/hashes/sha2.js';
import { splitSecret, reconstructSecret, shareToWords, wordsToShare } from '@forgesworn/shamir-words';

// Before distributing shares, store a hash of the original secret
const secret = crypto.getRandomValues(new Uint8Array(32));
const expectedHash = sha256(secret);

// ... later, after reconstruction ...
const recovered = reconstructSecret(decodedShares, threshold);
const recoveredHash = sha256(recovered);

const match = expectedHash.every((b, i) => b === recoveredHash[i]);
if (!match) {
  throw new Error('Reconstruction produced wrong secret — check share integrity');
}
```

---

## 6. Robustly collect word shares from user input

Word matching is case-insensitive and trims whitespace, but words must be in the BIP-39 English wordlist. This helper handles common entry mistakes.

```typescript
import { wordsToShare, ShamirValidationError, type ShamirShare } from '@forgesworn/shamir-words';

function parseUserInput(rawInput: string): ShamirShare {
  // Split on any whitespace, filter empty strings
  const words = rawInput.trim().split(/\s+/).filter(Boolean);

  try {
    return wordsToShare(words);
  } catch (err) {
    if (err instanceof ShamirValidationError) {
      throw new Error(`Invalid share: ${err.message}`);
    }
    throw err;
  }
}
```

---

## 7. nsec-tree integration — back up a master secret

When using `nsec-tree` for deterministic Nostr sub-identity derivation, the master secret is 32 bytes and can be split directly.

```typescript
import { splitSecret, reconstructSecret, shareToWords, wordsToShare } from '@forgesworn/shamir-words';

// Master secret from nsec-tree (32 bytes)
const masterSecret: Uint8Array = tree.exportMasterSecret();

// 3-of-5 for resilient backup
const shares = splitSecret(masterSecret, 3, 5);
const wordShares = shares.map(shareToWords);

// Reconstruct master secret to restore the full nsec-tree
const recovered = reconstructSecret(wordShares.slice(0, 3).map(wordsToShare), 3);
const restoredTree = NsecTree.fromMasterSecret(recovered);
```

---

## 8. Determine word count before splitting

Use the sizing formula to inform users before they write down shares.

```typescript
function wordCount(secretLength: number): number {
  // Wire format: data_length (1) + threshold (1) + share_id (1) + data (secretLength) + checksum (1)
  const totalBytes = 3 + secretLength + 1;
  return Math.ceil(totalBytes * 8 / 11);
}

console.log(`32-byte secret → ${wordCount(32)} words per share`); // 26
console.log(`64-byte secret → ${wordCount(64)} words per share`); // 49
```

---

## Error Reference

| Error class | When thrown |
|-------------|-------------|
| `ShamirValidationError` | Bad inputs: wrong types, out-of-range parameters, unknown BIP-39 words, checksum mismatch, wrong word count |
| `ShamirCryptoError` | Internal GF(256) failure (e.g. zero inverse — should not occur in normal use) |
| `ShamirError` | Base class — catch this to handle both subtypes |

All error classes are exported from `@forgesworn/shamir-words` and extend `Error`.
