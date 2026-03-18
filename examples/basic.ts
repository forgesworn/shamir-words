/**
 * Basic shamir-words example — split a secret into word shares and reconstruct.
 *
 * Run with: npx tsx examples/basic.ts
 */

import {
  splitSecret,
  reconstructSecret,
  shareToWords,
  wordsToShare,
} from '../src/index.js';

// A 16-byte secret (e.g. 128-bit key)
const secret = new TextEncoder().encode('my-secret-key!!!' /* 16 bytes */);

console.log('Original secret:', new TextDecoder().decode(secret));
console.log();

// Split into 5 shares, any 3 can reconstruct
const shares = splitSecret(secret, 3, 5);

// Convert each share to human-readable BIP-39 words
const wordShares = shares.map(shareToWords);

for (let i = 0; i < wordShares.length; i++) {
  console.log(`Share ${i + 1} (${wordShares[i]!.length} words):`);
  console.log(`  ${wordShares[i]!.join(' ')}`);
}

console.log();
console.log('--- Reconstructing from shares 1, 3, and 5 ---');
console.log();

// Pick any 3 shares, decode from words, and reconstruct
const selected = [wordShares[0]!, wordShares[2]!, wordShares[4]!];
const decoded = selected.map(wordsToShare);
const recovered = reconstructSecret(decoded, 3);

console.log('Recovered secret:', new TextDecoder().decode(recovered));
console.log('Match:', new TextDecoder().decode(recovered) === new TextDecoder().decode(secret));
