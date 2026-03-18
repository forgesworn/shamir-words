// Shamir's Secret Sharing over GF(256)
// Split secrets into threshold-of-n shares using polynomial interpolation
// Shares can be encoded as BIP-39 words for human-readable exchange

import { sha256 } from '@noble/hashes/sha2.js';
import { wordlist as BIP39_WORDLIST } from '@scure/bip39/wordlists/english.js';

/** O(1) word-to-index lookup, built once at module load */
const BIP39_INDEX = new Map<string, number>();
for (let i = 0; i < BIP39_WORDLIST.length; i++) {
  BIP39_INDEX.set(BIP39_WORDLIST[i]!, i);
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class ShamirError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ShamirError';
  }
}

export class ShamirValidationError extends ShamirError {
  constructor(message: string) {
    super(message);
    this.name = 'ShamirValidationError';
  }
}

export class ShamirCryptoError extends ShamirError {
  constructor(message: string) {
    super(message);
    this.name = 'ShamirCryptoError';
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ShamirShare {
  id: number;          // 1-255 (the x coordinate)
  threshold: number;   // 2-255 (minimum shares needed to reconstruct)
  data: Uint8Array;    // evaluated polynomial bytes
}

// ---------------------------------------------------------------------------
// GF(256) Arithmetic — irreducible polynomial 0x11b (same as AES)
// ---------------------------------------------------------------------------

const IRREDUCIBLE = 0x11b;
const GENERATOR = 0x03;

/** Log table: log_g(i) for i in [0..255]. LOG[0] is unused. */
const LOG = new Uint8Array(256);
/** Exp table: g^i for i in [0..255]. EXP[255] wraps to EXP[0]. */
const EXP = new Uint8Array(256);

/** Carryless multiplication used only during table construction */
function gf256MulSlow(a: number, b: number): number {
  let result = 0;
  let aa = a;
  let bb = b;
  while (bb > 0) {
    if (bb & 1) result ^= aa;
    aa <<= 1;
    if (aa & 0x100) aa ^= IRREDUCIBLE;
    bb >>= 1;
  }
  return result;
}

// Build log/exp tables at module load time using generator 0x03
{
  let val = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = val;
    LOG[val] = i;
    val = gf256MulSlow(val, GENERATOR);
  }
  // Wrap: makes modular indexing simpler
  EXP[255] = EXP[0]!;
}

/** Addition in GF(256) is XOR */
function gf256Add(a: number, b: number): number {
  return a ^ b;
}

/** Multiplication in GF(256) using log/exp tables */
function gf256Mul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[(LOG[a]! + LOG[b]!) % 255]!;
}

/** Multiplicative inverse in GF(256) */
function gf256Inv(a: number): number {
  if (a === 0) throw new ShamirCryptoError('No inverse for zero in GF(256)');
  return EXP[(255 - LOG[a]!) % 255]!;
}

// ---------------------------------------------------------------------------
// Shamir's Secret Sharing
// ---------------------------------------------------------------------------

/**
 * Evaluate a polynomial at x in GF(256) using Horner's method.
 * coeffs[0] is the constant term (the secret byte).
 */
function evalPoly(coeffs: Uint8Array, x: number): number {
  let result = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = gf256Add(gf256Mul(result, x), coeffs[i]!);
  }
  return result;
}

/** Zero a byte array (defence-in-depth for secret material) */
function zeroBytes(arr: Uint8Array): void {
  arr.fill(0);
}

/**
 * Split a secret into shares using Shamir's Secret Sharing over GF(256).
 *
 * @param secret    The secret bytes to split
 * @param threshold Minimum shares needed to reconstruct (>= 2)
 * @param shares    Total number of shares to create (>= threshold, <= 255)
 * @returns Array of ShamirShare objects (each includes the threshold for encoding)
 */
export function splitSecret(
  secret: Uint8Array,
  threshold: number,
  shares: number,
): ShamirShare[] {
  if (!(secret instanceof Uint8Array)) {
    throw new ShamirValidationError('Secret must be a Uint8Array');
  }
  if (secret.length === 0) {
    throw new ShamirValidationError('Secret must not be empty');
  }
  if (!Number.isSafeInteger(threshold) || !Number.isSafeInteger(shares)) {
    throw new ShamirValidationError('Threshold and shares must be safe integers');
  }
  if (threshold < 2) {
    throw new ShamirValidationError('Threshold must be at least 2');
  }
  if (shares < threshold) {
    throw new ShamirValidationError('Number of shares must be >= threshold');
  }
  if (shares > 255) {
    throw new ShamirValidationError('Number of shares must be <= 255');
  }
  if (secret.length > 255) {
    throw new ShamirValidationError('Secret must be at most 255 bytes for BIP-39 word encoding');
  }

  const secretLen = secret.length;
  const result: ShamirShare[] = [];

  // Initialize share data arrays
  for (let i = 0; i < shares; i++) {
    result.push({ id: i + 1, threshold, data: new Uint8Array(secretLen) });
  }

  // For each byte of the secret, build a random polynomial and evaluate
  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    // coeffs[0] = secret byte, coeffs[1..threshold-1] = random
    const coeffs = new Uint8Array(threshold);
    coeffs[0] = secret[byteIdx]!;

    const rand = new Uint8Array(threshold - 1);
    crypto.getRandomValues(rand);
    for (let j = 1; j < threshold; j++) {
      coeffs[j] = rand[j - 1]!;
    }

    // Evaluate at x = 1, 2, ..., shares
    for (let i = 0; i < shares; i++) {
      result[i]!.data[byteIdx] = evalPoly(coeffs, i + 1);
    }

    zeroBytes(coeffs);
    zeroBytes(rand);
  }

  return result;
}

/**
 * Reconstruct a secret from shares using Lagrange interpolation over GF(256).
 *
 * @param shares    Array of shares (at least `threshold` shares)
 * @param threshold The threshold used during splitting
 * @returns The reconstructed secret bytes
 */
export function reconstructSecret(
  shares: ShamirShare[],
  threshold: number,
): Uint8Array {
  if (!Number.isSafeInteger(threshold) || threshold < 2) {
    throw new ShamirValidationError('Threshold must be an integer >= 2');
  }
  if (!Array.isArray(shares) || shares.length < threshold) {
    throw new ShamirValidationError(`Need at least ${threshold} shares, got ${Array.isArray(shares) ? shares.length : 0}`);
  }

  // Use only the first `threshold` shares
  const used = shares.slice(0, threshold);

  // Validate share structure, IDs, and check for duplicates
  const ids = new Set<number>();
  for (const share of used) {
    if (!share || typeof share !== 'object') {
      throw new ShamirValidationError('Each share must be an object with id and data properties');
    }
    if (!Number.isInteger(share.id) || share.id < 1 || share.id > 255) {
      throw new ShamirValidationError('Invalid share ID: must be an integer in [1, 255]');
    }
    if (!(share.data instanceof Uint8Array)) {
      throw new ShamirValidationError('Share data must be a Uint8Array');
    }
    if (ids.has(share.id)) {
      throw new ShamirValidationError('Duplicate share IDs detected — each share must have a unique ID');
    }
    if (Number.isInteger(share.threshold) && share.threshold !== threshold) {
      throw new ShamirValidationError(
        `Share threshold (${share.threshold}) does not match supplied threshold (${threshold})`,
      );
    }
    ids.add(share.id);
  }

  const secretLen = used[0]!.data.length;
  if (secretLen === 0) {
    throw new ShamirValidationError('Share data must not be empty');
  }
  for (const share of used) {
    if (share.data.length !== secretLen) {
      throw new ShamirValidationError('Inconsistent share lengths — shares may be from different secrets');
    }
  }
  const result = new Uint8Array(secretLen);

  // Lagrange interpolation at x = 0 for each byte position
  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    let value = 0;

    for (let i = 0; i < threshold; i++) {
      const xi = used[i]!.id;
      const yi = used[i]!.data[byteIdx]!;

      // Lagrange basis l_i(0) = product of x_j / (x_i ^ x_j) for j != i
      // In GF(256): subtraction = addition = XOR
      let basis = 1;
      for (let j = 0; j < threshold; j++) {
        if (i === j) continue;
        const xj = used[j]!.id;
        basis = gf256Mul(basis, gf256Mul(xj, gf256Inv(gf256Add(xi, xj))));
      }

      value = gf256Add(value, gf256Mul(yi, basis));
    }

    result[byteIdx] = value;
  }

  return result;
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
    throw new ShamirValidationError('Share data exceeds maximum length (255 bytes)');
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
