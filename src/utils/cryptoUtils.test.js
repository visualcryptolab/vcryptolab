
import { describe, it, expect, vi } from 'vitest';
import {
    caesarEncrypt,
    vigenereEncryptDecrypt,
    performBitwiseXor,
    performBitShiftOperation,
    modPow,
    gcd,
    modInverse,
    splitDataIntoChunks,
    concatenateData,
    isContentCompatible,
    calculateHash,
    // Async functions are imported but testing robustly requires mocking crypto which we might skip for this unit level if complex
    generateSymmetricKey,
    symmetricEncrypt,
    symmetricDecrypt
} from './cryptoUtils';

describe('cryptoUtils', () => {

    describe('caesarEncrypt', () => {
        it('encrypts standard text correctly with positive shift', () => {
            const input = 'HELLO';
            const shift = 1;
            const result = caesarEncrypt(input, 'Text (UTF-8)', shift);
            expect(result.output).toBe('IFMMP');
        });

        it('wraps around the alphabet correctly', () => {
            const input = 'XYZ';
            const shift = 3;
            const result = caesarEncrypt(input, 'Text (UTF-8)', shift);
            expect(result.output).toBe('ABC');
        });

        it('preserves case', () => {
            const input = 'Hello World';
            const shift = 1;
            const result = caesarEncrypt(input, 'Text (UTF-8)', shift);
            expect(result.output).toBe('Ifmmp Xpsme');
        });

        it('handles negative comparisons correctly (decryption logic)', () => {
            const input = 'B';
            const shift = -1;
            const result = caesarEncrypt(input, 'Text (UTF-8)', shift);
            expect(result.output).toBe('A');
        });

        it('does not change non-alphabetic characters', () => {
            const input = '123!@#';
            const shift = 5;
            const result = caesarEncrypt(input, 'Text (UTF-8)', shift);
            expect(result.output).toBe('123!@#');
        });

        it('returns error for invalid format', () => {
            const result = caesarEncrypt('0101', 'Binary', 1);
            expect(result.output).toContain('ERROR');
        });
    });

    describe('vigenereEncryptDecrypt', () => {
        it('encrypts correctly with a keyword', () => {
            const input = 'ATTACKATDAWN';
            const keyword = 'LEMON';
            const result = vigenereEncryptDecrypt(input, keyword, 'ENCRYPT');
            expect(result.output).toBe('LXFOPVEFRNHR');
        });

        it('decrypts correctly with a keyword', () => {
            const input = 'LXFOPVEFRNHR';
            const keyword = 'LEMON';
            const result = vigenereEncryptDecrypt(input, keyword, 'DECRYPT');
            expect(result.output).toBe('ATTACKATDAWN');
        });

        it('handles mixed case and non-alpha characters', () => {
            const input = 'Hello, World!';
            const keyword = 'KEY';
            const result = vigenereEncryptDecrypt(input, keyword, 'ENCRYPT');
            expect(result.output).toBe('Rijvs, Uyvjn!');
        });

        it('returns error for empty keyword', () => {
            const result = vigenereEncryptDecrypt('HELLO', '', 'ENCRYPT');
            expect(result.output).toContain('ERROR');
        });
    });

    describe('performBitwiseXor', () => {
        it('performs XOR on Binary strings correctly', () => {
            const inputA = '1010'; // 10
            const inputB = '1100'; // 12
            // 10 ^ 12 = 6 (0110)
            const result = performBitwiseXor(inputA, 'Binary', inputB, 'Binary');
            expect(result.output).toBe('0110');
        });

        it('performs XOR on Hexadecimal strings correctly', () => {
            const inputA = 'A'; // 1010
            const inputB = 'C'; // 1100
            const result = performBitwiseXor(inputA, 'Hexadecimal', inputB, 'Hexadecimal');
            expect(result.output.toUpperCase()).toBe('6'); // 0110 -> 6
        });
    });

    describe('performBitShiftOperation', () => {
        it('performs Rotational Left Shift on Binary', () => {
            const input = '1101'; // 13
            const shift = 1;
            // Rotational: 1101 -> 1011
            const result = performBitShiftOperation(input, 'Left', shift, 'Binary');
            expect(result.output).toBe('1011');
        });

        it('performs Arithmetic shift for Decimal', () => {
            const input = '10';
            const shift = 1;
            // 10 << 1 = 20
            const result = performBitShiftOperation(input, 'Left', shift, 'Decimal');
            expect(result.output).toBe('20');
        });
    });

    describe('Math Utilities', () => {
        it('calculates GCD correctly', () => {
            expect(gcd(BigInt(12), BigInt(8))).toBe(BigInt(4));
        });

        it('calculates Modular Exponentiation correctly', () => {
            expect(modPow(BigInt(2), BigInt(3), BigInt(5))).toBe(BigInt(3));
        });

        it('calculates Modular Inverse correctly', () => {
            expect(modInverse(BigInt(3), BigInt(11))).toBe(BigInt(4));
        });
    });

    describe('splitDataIntoChunks', () => {
        it('splits string correctly', () => {
            const input = 'ABCD';
            const result = splitDataIntoChunks(input, 'Text (UTF-8)');
            expect(result.chunk1).toBe('AB');
            expect(result.chunk2).toBe('CD');
        });
    });

    describe('concatenateData', () => {
        it('concatenates two strings', () => {
            const result = concatenateData('ABC', 'Text (UTF-8)', 'DEF', 'Text (UTF-8)', true);
            expect(result.output).toBe('ABCDEF');
        });
    });

    describe('isContentCompatible', () => {
        it('validates binary content', () => {
            expect(isContentCompatible('10101', 'Binary')).toBe(true);
            expect(isContentCompatible('10201', 'Binary')).toBe(false);
        });
    });
});
