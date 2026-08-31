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

import { reconstructSecret, ShamirValidationError, splitSecret } from '@forgesworn/shamir-core';
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

// ---------------------------------------------------------------------------
// Versioned word envelope (v3)
// ---------------------------------------------------------------------------

/** Meaning of the secret that the share set reconstructs. The Shamir share
 * bytes themselves remain opaque; this metadata prevents a recovered byte
 * string from being silently fed into the wrong ForgeSworn derivation. */
export type WordSharePayloadKind =
  | 'opaque'
  | 'bip39-entropy'
  | 'raw-nsec-v1'
  | 'nsec-tree-root-v1'
  | 'nsec-tree-mnemonic-v1'
  | 'nsec-tree-nsec-v1'
  | 'forgesworn-recovery-words-v1';

export interface ShareToWordsV3Options {
  payloadKind: WordSharePayloadKind;
  /** Original secret for a domain-separated 64-bit recovery fingerprint.
   * It is hashed only and is never placed in a share. Requiring it lets safe
   * reconstruction reject shares from different split operations. */
  secret: Uint8Array;
}

export interface DecodedWordsEnvelope {
  /** 2 is the historical unversioned wire layout; 3 is the typed envelope. */
  formatVersion: 2 | 3;
  /** Historical v2 shares have no payload semantics and decode as opaque. */
  payloadKind: WordSharePayloadKind;
  /** Error-detection fingerprint of the original secret. Historical v2 has none. */
  secretFingerprint: string | null;
  share: ShamirShare;
}

export interface ReconstructedWordsV3 {
  payloadKind: WordSharePayloadKind;
  secretFingerprint: string;
  /** Reconstructed secret. The caller owns this buffer and MUST zero-fill it. */
  secret: Uint8Array;
}

export const SHAMIR_WORDS_FORMAT_VERSION = 3 as const;

// A zero sentinel is impossible in v2 because its first byte is a non-zero
// data length. It therefore distinguishes v3 without probabilistic magic
// collisions. "FS" makes damaged/foreign envelopes fail with a useful error.
const V3_SENTINEL = 0x00;
const V3_MAGIC_F = 0x46;
const V3_MAGIC_S = 0x53;
const V3_BASE_HEADER_BYTES = 8;
const V3_SECRET_FINGERPRINT_BYTES = 8;
const V3_HEADER_BYTES = V3_BASE_HEADER_BYTES + V3_SECRET_FINGERPRINT_BYTES;
const V3_CHECKSUM_BYTES = 4;
const V3_SECRET_FINGERPRINT_DOMAIN = new TextEncoder().encode(
  'ForgeSworn Shamir secret fingerprint v3\0',
);

const PAYLOAD_KIND_TO_CODE: Readonly<Record<WordSharePayloadKind, number>> = {
  opaque: 0,
  'bip39-entropy': 1,
  'raw-nsec-v1': 2,
  'nsec-tree-root-v1': 3,
  'forgesworn-recovery-words-v1': 4,
  'nsec-tree-mnemonic-v1': 5,
  'nsec-tree-nsec-v1': 6,
};
const CODE_TO_PAYLOAD_KIND = new Map<number, WordSharePayloadKind>(
  Object.entries(PAYLOAD_KIND_TO_CODE).map(([kind, code]) => [code, kind as WordSharePayloadKind]),
);

function validateWordShare(share: ShamirShare): void {
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
}

function secretFingerprintBytes(
  payloadKind: WordSharePayloadKind,
  secret: Uint8Array,
): Uint8Array {
  if (!(secret instanceof Uint8Array) || secret.length === 0 || secret.length > 255) {
    throw new ShamirValidationError('v3 secret must be a non-empty Uint8Array of at most 255 bytes');
  }
  const input = new Uint8Array(V3_SECRET_FINGERPRINT_DOMAIN.length + 1 + secret.length);
  input.set(V3_SECRET_FINGERPRINT_DOMAIN);
  input[V3_SECRET_FINGERPRINT_DOMAIN.length] = PAYLOAD_KIND_TO_CODE[payloadKind];
  input.set(secret, V3_SECRET_FINGERPRINT_DOMAIN.length + 1);
  const digest = sha256(input);
  const fingerprint = digest.slice(0, V3_SECRET_FINGERPRINT_BYTES);
  input.fill(0);
  digest.fill(0);
  return fingerprint;
}

function bytesToHex(bytes: ArrayLike<number>): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i]!.toString(16).padStart(2, '0');
  return hex;
}

function bytesToWords(bytes: Uint8Array): string[] {
  const words: string[] = [];
  let bits = 0;
  let accumulator = 0;
  for (const byte of bytes) {
    accumulator = ((accumulator << 8) | byte) >>> 0;
    bits += 8;
    while (bits >= 11) {
      bits -= 11;
      words.push(BIP39_WORDLIST[(accumulator >>> bits) & 0x7ff]!);
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    words.push(BIP39_WORDLIST[((accumulator << (11 - bits)) >>> 0) & 0x7ff]!);
  }
  return words;
}

function wordsToBytes(words: string[]): number[] {
  if (!Array.isArray(words)) {
    throw new ShamirValidationError('Words must be an array of strings');
  }
  if (words.length === 0) throw new ShamirValidationError('Cannot decode empty word list');
  if (words.length > 256) throw new ShamirValidationError('Word count exceeds maximum (256)');

  let bits = 0;
  let accumulator = 0;
  const byteList: number[] = [];
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    if (typeof word !== 'string') {
      throw new ShamirValidationError(`Word at position ${i + 1} must be a string`);
    }
    const index = BIP39_INDEX.get(word.trim().toLowerCase());
    if (index === undefined) {
      throw new ShamirValidationError(`Unknown BIP-39 word at position ${i + 1}`);
    }
    accumulator = ((accumulator << 11) | index) >>> 0;
    bits += 11;
    while (bits >= 8) {
      bits -= 8;
      byteList.push((accumulator >>> bits) & 0xff);
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits > 0 && accumulator !== 0) {
    throw new ShamirValidationError('Non-zero padding bits detected — word list may be corrupted');
  }
  return byteList;
}

function validateCanonicalWords(words: string[], bytes: number[], totalExpected: number): void {
  if (totalExpected > bytes.length) {
    throw new ShamirValidationError('Word list too short for encoded data length');
  }
  for (let i = totalExpected; i < bytes.length; i++) {
    if (bytes[i] !== 0) {
      throw new ShamirValidationError('Non-zero padding bits detected — word list may be corrupted');
    }
  }
  const expectedWords = Math.ceil(totalExpected * 8 / 11);
  if (words.length !== expectedWords) {
    throw new ShamirValidationError(
      `Expected ${expectedWords} words for data length ${bytes[5] ?? 0}, got ${words.length}`,
    );
  }
}

/** Encode a share in the opt-in v3 typed envelope.
 *
 * Layout before 11-bit word packing:
 * `[0x00, 'F', 'S', 3, payload_kind, data_length, threshold, share_id,
 * secret_fingerprint_8, ...data, checksum_4]`.
 * The four-byte checksum is the SHA-256 prefix over every preceding byte.
 * `shareToWords()` deliberately remains the historical v2 encoder so existing
 * paper shares and downstream callers do not change without an explicit move.
 */
export function shareToWordsV3(
  share: ShamirShare,
  options: ShareToWordsV3Options,
): string[] {
  validateWordShare(share);
  if (!options || !Object.prototype.hasOwnProperty.call(PAYLOAD_KIND_TO_CODE, options.payloadKind)) {
    throw new ShamirValidationError('A recognised v3 payloadKind is required');
  }
  if (!(options.secret instanceof Uint8Array) || options.secret.length !== share.data.length) {
    throw new ShamirValidationError('v3 options.secret must be a Uint8Array matching the share data length');
  }

  const secretFingerprint = secretFingerprintBytes(options.payloadKind, options.secret);
  const payload = new Uint8Array(V3_HEADER_BYTES + share.data.length);
  payload.set([
    V3_SENTINEL,
    V3_MAGIC_F,
    V3_MAGIC_S,
    SHAMIR_WORDS_FORMAT_VERSION,
    PAYLOAD_KIND_TO_CODE[options.payloadKind],
    share.data.length,
    share.threshold,
    share.id,
  ]);
  payload.set(secretFingerprint, V3_BASE_HEADER_BYTES);
  payload.set(share.data, V3_HEADER_BYTES);
  const digest = sha256(payload);
  const bytes = new Uint8Array(payload.length + V3_CHECKSUM_BYTES);
  bytes.set(payload);
  bytes.set(digest.subarray(0, V3_CHECKSUM_BYTES), payload.length);
  try {
    return bytesToWords(bytes);
  } finally {
    payload.fill(0);
    secretFingerprint.fill(0);
    digest.fill(0);
    bytes.fill(0);
  }
}

/** Strictly decode a v3 typed share. It never falls back to the historical
 * format, which is the safest entry point when a workflow expects v3. */
export function wordsToShareV3(words: string[]): DecodedWordsEnvelope {
  const bytes = wordsToBytes(words);
  try {
    if (bytes.length < V3_HEADER_BYTES + 1 + V3_CHECKSUM_BYTES) {
      throw new ShamirValidationError('Word list too short for a v3 share envelope');
    }
    if (bytes[0] !== V3_SENTINEL || bytes[1] !== V3_MAGIC_F || bytes[2] !== V3_MAGIC_S) {
      throw new ShamirValidationError('Not a ForgeSworn v3 share envelope');
    }
    if (bytes[3] !== SHAMIR_WORDS_FORMAT_VERSION) {
      throw new ShamirValidationError(`Unsupported share envelope version: ${bytes[3]}`);
    }
    const payloadKind = CODE_TO_PAYLOAD_KIND.get(bytes[4]!);
    if (!payloadKind) {
      throw new ShamirValidationError(`Unsupported share payload kind: ${bytes[4]}`);
    }
    const dataLength = bytes[5]!;
    if (dataLength === 0) throw new ShamirValidationError('Encoded data length is zero');
    const totalExpected = V3_HEADER_BYTES + dataLength + V3_CHECKSUM_BYTES;
    validateCanonicalWords(words, bytes, totalExpected);

    const threshold = bytes[6]!;
    if (threshold < 2) throw new ShamirValidationError('Invalid threshold: must be in [2, 255]');
    const id = bytes[7]!;
    if (id === 0) throw new ShamirValidationError('Invalid share ID: 0 is not a valid x-coordinate for GF(256)');

    const checksumAt = V3_HEADER_BYTES + dataLength;
    const payload = new Uint8Array(checksumAt);
    for (let i = 0; i < checksumAt; i++) payload[i] = bytes[i]!;
    const digest = sha256(payload);
    let checksumMatches = true;
    for (let i = 0; i < V3_CHECKSUM_BYTES; i++) {
      checksumMatches &&= bytes[checksumAt + i] === digest[i];
    }
    payload.fill(0);
    digest.fill(0);
    if (!checksumMatches) {
      throw new ShamirValidationError('Checksum mismatch — word list is corrupted or was incorrectly transcribed');
    }

    const data = new Uint8Array(dataLength);
    for (let i = 0; i < dataLength; i++) data[i] = bytes[V3_HEADER_BYTES + i]!;
    const secretFingerprint = bytesToHex(bytes.slice(
      V3_BASE_HEADER_BYTES,
      V3_HEADER_BYTES,
    ));
    return {
      formatVersion: 3,
      payloadKind,
      secretFingerprint,
      share: { id, threshold, data },
    };
  } finally {
    bytes.fill(0);
  }
}

/** Migration decoder that reports whether words used historical v2 or typed
 * v3. Existing `wordsToShare()` semantics remain unchanged. New ForgeSworn
 * recovery code should prefer strict `wordsToShareV3()`. */
export function decodeWordsEnvelope(words: string[]): DecodedWordsEnvelope {
  const bytes = wordsToBytes(words);
  const isV3 = bytes[0] === V3_SENTINEL;
  bytes.fill(0);
  if (isV3) return wordsToShareV3(words);
  return {
    formatVersion: 2,
    payloadKind: 'opaque',
    secretFingerprint: null,
    share: wordsToShare(words),
  };
}

/** Safest v3 entry point: split a secret and encode every share with the same
 * payload meaning and secret fingerprint. Intermediate share bytes are
 * scrubbed before return. */
export function splitSecretToWordsV3(
  secret: Uint8Array,
  threshold: number,
  shares: number,
  options: Pick<ShareToWordsV3Options, 'payloadKind'>,
): string[][] {
  const split = splitSecret(secret, threshold, shares);
  try {
    return split.map((share) => shareToWordsV3(share, {
      payloadKind: options.payloadKind,
      secret,
    }));
  } finally {
    for (const share of split) share.data.fill(0);
  }
}

/** Strictly decode and reconstruct typed v3 shares. Every supplied share must
 * agree on payload kind, threshold, data length, and original-secret
 * fingerprint. The fingerprint is checked again after reconstruction, which
 * catches shares mixed across independently randomised split operations. */
export function reconstructWordsV3(wordShares: string[][]): ReconstructedWordsV3 {
  if (!Array.isArray(wordShares) || wordShares.length === 0) {
    throw new ShamirValidationError('v3 word shares must be a non-empty array');
  }
  const decoded: DecodedWordsEnvelope[] = [];
  let secret: Uint8Array | undefined;
  try {
    for (const words of wordShares) decoded.push(wordsToShareV3(words));
    const first = decoded[0]!;
    const fingerprint = first.secretFingerprint!;
    for (const item of decoded.slice(1)) {
      if (item.payloadKind !== first.payloadKind) {
        throw new ShamirValidationError('v3 shares have inconsistent payload kinds');
      }
      if (item.secretFingerprint !== fingerprint) {
        throw new ShamirValidationError('v3 shares have inconsistent secret fingerprints');
      }
      if (item.share.threshold !== first.share.threshold) {
        throw new ShamirValidationError('v3 shares have inconsistent thresholds');
      }
      if (item.share.data.length !== first.share.data.length) {
        throw new ShamirValidationError('v3 shares have inconsistent data lengths');
      }
    }

    secret = reconstructSecret(decoded.map((item) => item.share), first.share.threshold);
    const actual = secretFingerprintBytes(first.payloadKind, secret);
    let mismatch = 0;
    const expected = fingerprint.toLowerCase();
    const actualHex = bytesToHex(actual);
    for (let i = 0; i < expected.length; i++) mismatch |= expected.charCodeAt(i) ^ actualHex.charCodeAt(i);
    actual.fill(0);
    if (mismatch !== 0) {
      secret.fill(0);
      secret = undefined;
      throw new ShamirValidationError('Reconstructed secret fingerprint mismatch; shares may be mixed');
    }

    return {
      payloadKind: first.payloadKind,
      secretFingerprint: fingerprint,
      secret,
    };
  } finally {
    for (const item of decoded) item.share.data.fill(0);
  }
}
