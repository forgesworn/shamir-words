import { describe, it, expect } from 'vitest';
import {
  gf256Add,
  gf256Mul,
  gf256Inv,
  splitSecret,
  reconstructSecret,
  shareToWords,
  wordsToShare,
} from '../src/index.js';
import { wordlist as BIP39_WORDLIST } from '@scure/bip39/wordlists/english.js';

describe('shamir-words', () => {
  // A known 16-byte secret (128-bit, standard for 12-word mnemonic entropy)
  const secret16 = new Uint8Array([
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
  ]);

  // A 32-byte secret (256-bit)
  const secret32 = new Uint8Array([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
  ]);

  describe('GF(256) arithmetic', () => {
    it('addition is XOR', () => {
      expect(gf256Add(0x57, 0x83)).toBe(0x57 ^ 0x83);
      expect(gf256Add(0, 0xff)).toBe(0xff);
      expect(gf256Add(0xff, 0xff)).toBe(0);
    });

    it('multiplication by 1 is identity', () => {
      for (let i = 0; i < 256; i++) {
        expect(gf256Mul(i, 1)).toBe(i);
      }
    });

    it('multiplication by 0 is 0', () => {
      for (let i = 0; i < 256; i++) {
        expect(gf256Mul(i, 0)).toBe(0);
        expect(gf256Mul(0, i)).toBe(0);
      }
    });

    it('multiplication is commutative', () => {
      expect(gf256Mul(0x57, 0x83)).toBe(gf256Mul(0x83, 0x57));
    });

    it('inverse is correct: a * inv(a) = 1', () => {
      for (let i = 1; i < 256; i++) {
        expect(gf256Mul(i, gf256Inv(i))).toBe(1);
      }
    });

    it('inverse of zero throws', () => {
      expect(() => gf256Inv(0)).toThrow('No inverse for zero');
    });
  });

  describe('split and reconstruct', () => {
    it('reconstructs a 16-byte secret with 2-of-3', () => {
      const shares = splitSecret(secret16, 2, 3);
      expect(shares).toHaveLength(3);
      const recovered = reconstructSecret(shares, 2);
      expect(recovered).toEqual(secret16);
    });

    it('reconstructs a 16-byte secret with 3-of-5', () => {
      const shares = splitSecret(secret16, 3, 5);
      expect(shares).toHaveLength(5);
      const recovered = reconstructSecret(shares, 3);
      expect(recovered).toEqual(secret16);
    });

    it('any 2 of 3 shares reconstruct (all 3 combinations)', () => {
      const shares = splitSecret(secret16, 2, 3);
      expect(reconstructSecret([shares[0], shares[1]], 2)).toEqual(secret16);
      expect(reconstructSecret([shares[0], shares[2]], 2)).toEqual(secret16);
      expect(reconstructSecret([shares[1], shares[2]], 2)).toEqual(secret16);
    });

    it('any 3 of 5 shares reconstruct (all 10 combinations)', () => {
      const shares = splitSecret(secret16, 3, 5);
      const combos = [
        [0, 1, 2], [0, 1, 3], [0, 1, 4], [0, 2, 3], [0, 2, 4],
        [0, 3, 4], [1, 2, 3], [1, 2, 4], [1, 3, 4], [2, 3, 4],
      ];
      for (const [a, b, c] of combos) {
        expect(reconstructSecret([shares[a], shares[b], shares[c]], 3)).toEqual(secret16);
      }
    });

    it('fewer shares than threshold gives wrong result', () => {
      const shares = splitSecret(secret16, 2, 3);
      const singleShareData = shares[0].data;
      const matches = secret16.every((b, i) => b === singleShareData[i]);
      expect(matches).toBe(false);
    });

    it('works with 32-byte secrets (256-bit)', () => {
      const shares = splitSecret(secret32, 3, 5);
      const recovered = reconstructSecret(shares, 3);
      expect(recovered).toEqual(secret32);
    });

    it('shares are different from each other', () => {
      const shares = splitSecret(secret16, 2, 3);
      for (let i = 0; i < shares.length; i++) {
        for (let j = i + 1; j < shares.length; j++) {
          const same = shares[i].data.every((b, idx) => b === shares[j].data[idx]);
          expect(same).toBe(false);
        }
      }
    });

    it('shares are different from the original secret', () => {
      const shares = splitSecret(secret16, 2, 3);
      for (const share of shares) {
        const same = share.data.every((b, idx) => b === secret16[idx]);
        expect(same).toBe(false);
      }
    });
  });

  describe('validation', () => {
    it('throws when threshold < 2', () => {
      expect(() => splitSecret(secret16, 1, 3)).toThrow('at least 2');
    });

    it('throws when shares < threshold', () => {
      expect(() => splitSecret(secret16, 4, 3)).toThrow('>= threshold');
    });

    it('throws when shares > 255', () => {
      expect(() => splitSecret(secret16, 2, 256)).toThrow('<= 255');
    });

    it('throws when not enough shares for reconstruction', () => {
      const shares = splitSecret(secret16, 3, 5);
      expect(() => reconstructSecret([shares[0], shares[1]], 3)).toThrow('Need at least 3');
    });

    it('throws when a share has ID 0', () => {
      const shares = splitSecret(secret16, 2, 3);
      const zeroIdShare = { id: 0, data: shares[0].data };
      expect(() => reconstructSecret([zeroIdShare, shares[1]], 2)).toThrow('must be an integer in [1, 255]');
    });

    it('throws when share ID exceeds 255', () => {
      const shares = splitSecret(secret16, 2, 3);
      const badShare = { id: 256, data: shares[0].data };
      expect(() => reconstructSecret([badShare, shares[1]], 2)).toThrow('must be an integer in [1, 255]');
    });

    it('throws when shares have inconsistent data lengths', () => {
      const shares16 = splitSecret(secret16, 2, 3);
      const shares32 = splitSecret(secret32, 2, 3);
      expect(() => reconstructSecret([shares16[0], shares32[1]], 2)).toThrow('Inconsistent share lengths');
    });
  });

  describe('BIP-39 word encoding', () => {
    it('shareToWords produces words all in the BIP-39 wordlist', () => {
      const shares = splitSecret(secret16, 2, 3);
      for (const share of shares) {
        const words = shareToWords(share);
        for (const word of words) {
          expect(BIP39_WORDLIST).toContain(word);
        }
      }
    });

    it('shareToWords -> wordsToShare roundtrips', () => {
      const shares = splitSecret(secret16, 2, 3);
      for (const share of shares) {
        const words = shareToWords(share);
        const recovered = wordsToShare(words);
        expect(recovered.id).toBe(share.id);
        expect(recovered.data).toEqual(share.data);
      }
    });

    it('roundtrips with 32-byte secret shares', () => {
      const shares = splitSecret(secret32, 3, 5);
      for (const share of shares) {
        const words = shareToWords(share);
        const recovered = wordsToShare(words);
        expect(recovered.id).toBe(share.id);
        expect(recovered.data).toEqual(share.data);
      }
    });

    it('wordsToShare throws on empty word list', () => {
      expect(() => wordsToShare([])).toThrow('Cannot decode empty word list');
    });

    it('full pipeline: split -> words -> reconstruct', () => {
      const shares = splitSecret(secret16, 2, 3);
      const wordShares = shares.map(shareToWords);
      const recoveredShares = wordShares.map(wordsToShare);
      const recovered = reconstructSecret(recoveredShares, 2);
      expect(recovered).toEqual(secret16);
    });

    it('roundtrips large secrets (48 bytes) without bit overflow', () => {
      const largeSecret = new Uint8Array(48);
      for (let i = 0; i < 48; i++) largeSecret[i] = (i * 7 + 13) & 0xff;

      const shares = splitSecret(largeSecret, 3, 5);
      for (const share of shares) {
        const words = shareToWords(share);
        const recovered = wordsToShare(words);
        expect(recovered.id).toBe(share.id);
        expect(recovered.data).toEqual(share.data);
      }

      const wordShares = shares.map(shareToWords);
      const recoveredShares = wordShares.map(wordsToShare);
      const recovered = reconstructSecret(recoveredShares.slice(0, 3), 3);
      expect(recovered).toEqual(largeSecret);
    });

    it('roundtrips all previously-affected secret lengths (phantom byte regression)', () => {
      // These lengths had padding >= 8 bits in the old format, causing phantom byte injection
      const affectedLengths = [2, 6, 9, 13, 17, 20, 24, 28, 31, 35, 39, 42, 46, 50, 53, 57, 61, 64];
      for (const len of affectedLengths) {
        const secret = new Uint8Array(len);
        for (let i = 0; i < len; i++) secret[i] = (i * 13 + 7) & 0xff;

        const shares = splitSecret(secret, 2, 3);
        const wordShares = shares.map(shareToWords);
        const recoveredShares = wordShares.map(wordsToShare);
        const recovered = reconstructSecret(recoveredShares, 2);
        expect(recovered).toEqual(secret);
      }
    });

    it('roundtrips 1-byte secret through full pipeline', () => {
      const secret = new Uint8Array([0x42]);
      const shares = splitSecret(secret, 2, 3);
      const wordShares = shares.map(shareToWords);
      const recoveredShares = wordShares.map(wordsToShare);
      const recovered = reconstructSecret(recoveredShares, 2);
      expect(recovered).toEqual(secret);
    });

    it('roundtrips boundary share IDs (1, 128, 255) through words', () => {
      const shares = splitSecret(secret16, 2, 255);
      for (const id of [1, 128, 255]) {
        const share = shares[id - 1];
        expect(share.id).toBe(id);
        const words = shareToWords(share);
        const recovered = wordsToShare(words);
        expect(recovered.id).toBe(id);
        expect(recovered.data).toEqual(share.data);
      }
    });

    it('wordsToShare handles case-insensitive input', () => {
      const shares = splitSecret(secret16, 2, 3);
      const words = shareToWords(shares[0]);
      const upperWords = words.map(w => w.toUpperCase());
      const recovered = wordsToShare(upperWords);
      expect(recovered.id).toBe(shares[0].id);
      expect(recovered.data).toEqual(shares[0].data);
    });
  });

  describe('security: splitSecret input validation', () => {
    it('throws on empty secret', () => {
      expect(() => splitSecret(new Uint8Array(0), 2, 3)).toThrow('must not be empty');
    });

    it('throws on non-Uint8Array secret', () => {
      expect(() => splitSecret([0xDE, 0xAD] as unknown as Uint8Array, 2, 3)).toThrow('must be a Uint8Array');
    });

    it('throws on non-integer threshold', () => {
      expect(() => splitSecret(secret16, 2.5, 3)).toThrow('safe integers');
      expect(() => splitSecret(secret16, NaN, 3)).toThrow('safe integers');
      expect(() => splitSecret(secret16, Infinity, 3)).toThrow('safe integers');
    });

    it('throws on non-integer shares', () => {
      expect(() => splitSecret(secret16, 2, 3.5)).toThrow('safe integers');
      expect(() => splitSecret(secret16, 2, NaN)).toThrow('safe integers');
    });
  });

  describe('security: reconstructSecret input validation', () => {
    it('throws on threshold < 2', () => {
      const shares = splitSecret(secret16, 2, 3);
      expect(() => reconstructSecret(shares, 1)).toThrow('integer >= 2');
      expect(() => reconstructSecret(shares, 0)).toThrow('integer >= 2');
    });

    it('throws on non-integer threshold', () => {
      const shares = splitSecret(secret16, 2, 3);
      expect(() => reconstructSecret(shares, 2.5)).toThrow('integer >= 2');
      expect(() => reconstructSecret(shares, NaN)).toThrow('integer >= 2');
    });

    it('throws on negative threshold', () => {
      const shares = splitSecret(secret16, 2, 3);
      expect(() => reconstructSecret(shares, -1)).toThrow('integer >= 2');
    });

    it('throws on negative share ID', () => {
      const shares = splitSecret(secret16, 2, 3);
      const bad = { id: -1, data: shares[0].data };
      expect(() => reconstructSecret([bad, shares[1]], 2)).toThrow('must be an integer in [1, 255]');
    });

    it('throws on NaN share ID', () => {
      const shares = splitSecret(secret16, 2, 3);
      const bad = { id: NaN, data: shares[0].data };
      expect(() => reconstructSecret([bad, shares[1]], 2)).toThrow('must be an integer in [1, 255]');
    });

    it('throws on duplicate share IDs', () => {
      const shares = splitSecret(secret16, 2, 3);
      const dup = [shares[0], { id: shares[0].id, data: shares[1].data }];
      expect(() => reconstructSecret(dup, 2)).toThrow('Duplicate share IDs');
    });

    it('throws on share with missing data property', () => {
      const shares = splitSecret(secret16, 2, 3);
      const bad = { id: 1 } as unknown as { id: number; data: Uint8Array };
      expect(() => reconstructSecret([bad, shares[1]], 2)).toThrow('Uint8Array');
    });

    it('throws on null share in array', () => {
      const shares = splitSecret(secret16, 2, 3);
      expect(() => reconstructSecret([null as unknown as { id: number; data: Uint8Array }, shares[1]], 2)).toThrow('object');
    });
  });

  describe('security: shareToWords input validation', () => {
    it('throws on share ID 0', () => {
      const shares = splitSecret(secret16, 2, 3);
      expect(() => shareToWords({ id: 0, data: shares[0].data })).toThrow('integer in [1, 255]');
    });

    it('throws on share ID 256 (prevents silent Uint8Array truncation)', () => {
      const shares = splitSecret(secret16, 2, 3);
      expect(() => shareToWords({ id: 256, data: shares[0].data })).toThrow('integer in [1, 255]');
    });

    it('throws on negative share ID', () => {
      const shares = splitSecret(secret16, 2, 3);
      expect(() => shareToWords({ id: -1, data: shares[0].data })).toThrow('integer in [1, 255]');
    });

    it('throws on empty share data', () => {
      expect(() => shareToWords({ id: 1, data: new Uint8Array(0) })).toThrow('non-empty');
    });
  });

  describe('security: wordsToShare input validation', () => {
    it('throws on unknown BIP-39 word with position info', () => {
      expect(() => wordsToShare(['abandon', 'notaword', 'ability'])).toThrow('position 2');
    });
  });
});
