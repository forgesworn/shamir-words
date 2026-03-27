// BIP-39 word encoding for Shamir's Secret Sharing shares
// Core split/reconstruct logic is provided by @forgesworn/shamir-core

import { sha256 } from '@noble/hashes/sha2.js';
import { wordlist as BIP39_WORDLIST } from '@scure/bip39/wordlists/english.js';

// Re-export core Shamir functionality
export {
  splitSecret,
  reconstructSecret,
  ShamirError,
  ShamirValidationError,
  ShamirCryptoError,
} from '@forgesworn/shamir-core';
export type { ShamirShare } from '@forgesworn/shamir-core';

import { ShamirValidationError } from '@forgesworn/shamir-core';
import type { ShamirShare } from '@forgesworn/shamir-core';

/** O(1) word-to-index lookup, built once at module load */
const BIP39_INDEX = new Map<string, number>();
for (let i = 0; i < BIP39_WORDLIST.length; i++) {
  BIP39_INDEX.set(BIP39_WORDLIST[i]!, i);
}

// ---------------------------------------------------------------------------
// BIP-39 Word Encoding
// ---------------------------------------------------------------------------

/**
 * Encode a share as BIP-39 words.
 * Format: [data_length, threshold, share_id, ...data, checksum] → 11-bit groups → BIP-39 words.
 * The length prefix ensures exact roundtrip fidelity regardless of bit alignment.
 * The checksum (first byte of SHA-256 of the preceding bytes) detects transcription errors.
 */
export function shareToWords(share: ShamirShare): string[] {
  if (!share || typeof share !== 'object') {
    throw new ShamirValidationError('Share must be an object with id, threshold, and data properties');
  }
  if (!Number.isInteger(share.id) || share.id < 1 || share.id > 255) {
    throw new ShamirValidationError('Share ID must be an integer in [1, 255]');
  }
  if (!Number.isInteger(share.threshold) || share.threshold < 2 || share.threshold > 255) {
    throw new ShamirValidationError('Share threshold must be an integer in [2, 255]');
  }
  if (!(share.data instanceof Uint8Array) || share.data.length === 0) {
    throw new ShamirValidationError('Share data must be a non-empty Uint8Array');
  }
  if (share.data.length > 255) {
    throw new ShamirValidationError('Share data exceeds maximum length (255 bytes) for BIP-39 word encoding');
  }

  // Build payload: [data_length, threshold, share_id, ...data]
  const payloadLen = 3 + share.data.length;
  const payload = new Uint8Array(payloadLen);
  payload[0] = share.data.length;
  payload[1] = share.threshold;
  payload[2] = share.id;
  payload.set(share.data, 3);

  // Compute checksum: first byte of SHA-256 of the payload
  const checksum = sha256(payload)[0]!;

  // Final byte stream: payload + checksum
  const bytes = new Uint8Array(payloadLen + 1);
  bytes.set(payload, 0);
  bytes[payloadLen] = checksum;

  // Stream bytes into 11-bit word indices
  const words: string[] = [];
  let bits = 0;
  let accumulator = 0;

  for (const byte of bytes) {
    accumulator = ((accumulator << 8) | byte) >>> 0;
    bits += 8;
    while (bits >= 11) {
      bits -= 11;
      const index = (accumulator >>> bits) & 0x7ff;
      words.push(BIP39_WORDLIST[index]!);
      accumulator &= (1 << bits) - 1;
    }
  }

  // Pad remaining bits on the right to form a final 11-bit group
  if (bits > 0) {
    const index = ((accumulator << (11 - bits)) >>> 0) & 0x7ff;
    words.push(BIP39_WORDLIST[index]!);
  }

  return words;
}

/**
 * Decode BIP-39 words back to a share.
 * Expects format: [data_length, threshold, share_id, ...data, checksum] encoded as 11-bit groups.
 * Verifies the checksum to detect transcription errors.
 */
export function wordsToShare(words: string[]): ShamirShare {
  if (!Array.isArray(words)) {
    throw new ShamirValidationError('Words must be an array of strings');
  }
  if (words.length === 0) throw new ShamirValidationError('Cannot decode empty word list');
  if (words.length > 256) {
    throw new ShamirValidationError('Word count exceeds maximum (256)');
  }

  // Convert words to 11-bit indices using O(1) map lookup
  const indices: number[] = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (typeof w !== 'string') {
      throw new ShamirValidationError(`Word at position ${i + 1} must be a string`);
    }
    const idx = BIP39_INDEX.get(w.trim().toLowerCase());
    if (idx === undefined) {
      throw new ShamirValidationError(`Unknown BIP-39 word at position ${i + 1}`);
    }
    indices.push(idx);
  }

  // Stream 11-bit groups into bytes
  let bits = 0;
  let accumulator = 0;
  const byteList: number[] = [];

  for (const index of indices) {
    accumulator = ((accumulator << 11) | index) >>> 0;
    bits += 11;
    while (bits >= 8) {
      bits -= 8;
      byteList.push((accumulator >>> bits) & 0xff);
      accumulator &= (1 << bits) - 1;
    }
  }

  // Verify padding bits in the last word are zero
  if (bits > 0 && accumulator !== 0) {
    throw new ShamirValidationError('Non-zero padding bits detected — word list may be corrupted');
  }

  // Need at least 5 bytes: data_length + threshold + id + 1 data byte + checksum
  if (byteList.length < 5) {
    throw new ShamirValidationError('Word list too short — need at least data_length + threshold + id + 1 data byte + checksum');
  }

  // Read header
  const dataLength = byteList[0]!;
  if (dataLength === 0) {
    throw new ShamirValidationError('Encoded data length is zero');
  }

  // Total expected bytes: 3 header + dataLength + 1 checksum
  const totalExpected = 4 + dataLength;
  if (totalExpected > byteList.length) {
    throw new ShamirValidationError('Word list too short for encoded data length');
  }

  // Verify phantom bytes (decoded from padding bits) are zero — ensures canonical encoding
  for (let i = totalExpected; i < byteList.length; i++) {
    if (byteList[i] !== 0) {
      throw new ShamirValidationError('Non-zero padding bits detected — word list may be corrupted');
    }
  }

  // Enforce canonical encoding: word count must match expected
  const expectedWords = Math.ceil(totalExpected * 8 / 11);
  if (words.length !== expectedWords) {
    throw new ShamirValidationError(
      `Expected ${expectedWords} words for data length ${dataLength}, got ${words.length}`,
    );
  }

  const threshold = byteList[1]!;
  if (threshold < 2 || threshold > 255) {
    throw new ShamirValidationError('Invalid threshold: must be in [2, 255]');
  }

  const id = byteList[2]!;
  if (id === 0) {
    throw new ShamirValidationError('Invalid share ID: 0 is not a valid x-coordinate for GF(256)');
  }

  // Verify checksum
  const payload = new Uint8Array(3 + dataLength);
  for (let i = 0; i < 3 + dataLength; i++) {
    payload[i] = byteList[i]!;
  }
  const expectedChecksum = sha256(payload)[0]!;
  const actualChecksum = byteList[3 + dataLength]!;
  if (actualChecksum !== expectedChecksum) {
    throw new ShamirValidationError('Checksum mismatch — word list is corrupted or was incorrectly transcribed');
  }

  const data = new Uint8Array(dataLength);
  for (let i = 0; i < dataLength; i++) {
    data[i] = byteList[3 + i]!;
  }

  return { id, threshold, data };
}
