
import { describe, it, expect } from 'vitest';
import { generatePRNG, isPrime } from '../utils/cryptoUtils';

describe('PRNG Logic', () => {
    it('isPrime checks primality correctly', () => {
        expect(isPrime(2)).toBe(true);
        expect(isPrime(3)).toBe(true);
        expect(isPrime(4)).toBe(false);
        expect(isPrime(17)).toBe(true);
        expect(isPrime(25)).toBe(false);
        expect(isPrime(97)).toBe(true);
    });

    it('generatePRNG Integer returns valid number in range', () => {
        const min = 10;
        const max = 20;
        const res = generatePRNG(12345, 'Integer', min, max, 2, false);
        const val = parseInt(res, 10);
        expect(val).toBeGreaterThanOrEqual(min);
        expect(val).toBeLessThanOrEqual(max);
        expect(res).toMatch(/^\d+$/);
    });

    it('generatePRNG Float returns valid number in range with precision', () => {
        const min = 0;
        const max = 1;
        const precision = 4;
        const res = generatePRNG(12345, 'Float', min, max, precision, false);
        const val = parseFloat(res);
        expect(val).toBeGreaterThanOrEqual(min);
        expect(val).toBeLessThanOrEqual(max);
        // Check precision
        const decimals = res.split('.')[1];
        expect(decimals ? decimals.length : 0).toBe(precision);
    });

    it('generatePRNG with isPrime returns prime number', () => {
        const min = 10;
        const max = 50;
        const res = generatePRNG(12345, 'Integer', min, max, 0, true);
        const val = parseInt(res, 10);
        expect(isPrime(val)).toBe(true);
        expect(val).toBeGreaterThanOrEqual(min);
        expect(val).toBeLessThanOrEqual(max);
    });

    it('generatePRNG is deterministic with seed', () => {
        const seed = 999;
        const res1 = generatePRNG(seed, 'Integer', 0, 1000, 0, false);
        const res2 = generatePRNG(seed, 'Integer', 0, 1000, 0, false);
        // Note: My implementation creates a new SeededRandom instance each call.
        // It always grabs the FIRST number from the sequence for that seed.
        // So yes, it should be deterministic.
        expect(res1).toBe(res2);
    });
});
