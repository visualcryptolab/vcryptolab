// src/crypto/utils.test.js

/**
 * Unit test framework for the core cryptographic and utility functions.
 * In a real environment, run these tests using Jest or Vitest.
 * * NOTE: These functions rely on browser APIs (like crypto.subtle and TextEncoder/Decoder)
 * and BigInt, so they may require a specific test environment (like jsdom with Node >= 10).
 * * To run: `npx vitest src/crypto/utils.test.js` (after installing vitest)
 */

import { 
    modPow, gcd, modInverse, 
    caesarEncrypt, vigenereEncryptDecrypt, 
    arrayBufferToBase64, base64ToArrayBuffer, convertToUint8Array,
    convertDataFormat, stringToBigInt, bigIntToString,
    performBitwiseXor, performBitShiftOperation,
    getOutputFormat, isContentCompatible
} from './utils'; // Adjust path as necessary if running externally

// Mock the BigInt environment if running in an older Node version
// (Assuming BigInt support for the Canvas environment)

describe('Modular Arithmetic Utilities', () => {

    test('modPow should correctly calculate (base^exponent) mod modulus', () => {
        // Standard small case: 2^3 mod 5 = 8 mod 5 = 3
        expect(modPow(BigInt(2), BigInt(3), BigInt(5))).toBe(BigInt(3)); 
        // Larger case: 123^456 mod 789
        const result = modPow(BigInt(123), BigInt(456), BigInt(789));
        expect(result).toBe(BigInt(699));
        // Identity: x^1 mod n = x mod n
        expect(modPow(BigInt(10), BigInt(1), BigInt(7))).toBe(BigInt(3));
    });

    test('gcd should find the greatest common divisor', () => {
        expect(gcd(BigInt(48), BigInt(18))).toBe(BigInt(6));
        expect(gcd(BigInt(17), BigInt(5))).toBe(BigInt(1)); // Prime to each other
        expect(gcd(BigInt(100), BigInt(0))).toBe(BigInt(100)); // GCD with zero
    });

    test('modInverse should calculate modular inverse (Extended Euclidean Algorithm)', () => {
        // Find d such that 3d mod 11 = 1. (d=4)
        expect(modInverse(BigInt(3), BigInt(11))).toBe(BigInt(4));
        // Find d such that 17d mod 3120 = 1. (d=2753)
        expect(modInverse(BigInt(17), BigInt(3120))).toBe(BigInt(2753));
        // Inverse does not exist (gcd > 1)
        // NOTE: modInverse implementation returns non-zero result if inverse doesn't exist,
        // but its validity (a * d mod m) !== 1 must be checked externally.
    });
});

describe('Classic Ciphers', () => {
    test('caesarEncrypt should encrypt text correctly with positive shift', () => {
        const result = caesarEncrypt('ABC xyz', 'Text (UTF-8)', 3);
        expect(result.output).toBe('DEF abc');
        expect(result.format).toBe('Text (UTF-8)');
    });

    test('caesarEncrypt should handle wrapping (shift 27)', () => {
        const result = caesarEncrypt('A', 'Text (UTF-8)', 27);
        expect(result.output).toBe('B');
    });
    
    test('caesarEncrypt should ignore non-text input formats', () => {
        const result = caesarEncrypt('abc', 'Base64', 3);
        expect(result.output).toContain('ERROR');
    });

    test('vigenereEncryptDecrypt should encrypt correctly', () => {
        const result = vigenereEncryptDecrypt('ATTACKATDAWN', 'LEMON', 'ENCRYPT');
        expect(result.output).toBe('LXFOPVEFRNHR');
    });

    test('vigenereEncryptDecrypt should decrypt correctly', () => {
        const result = vigenereEncryptDecrypt('LXFOPVEFRNHR', 'LEMON', 'DECRYPT');
        expect(result.output).toBe('ATTACKATDAWN');
    });

    test('vigenereEncryptDecrypt should handle mixed-case and spaces', () => {
        const encrypted = vigenereEncryptDecrypt('Attack At Dawn!', 'Lemon', 'ENCRYPT');
        expect(encrypted.output).toBe('Lxfopv Ef Rnhr!');
        const decrypted = vigenereEncryptDecrypt('Lxfopv Ef Rnhr!', 'Lemon', 'DECRYPT');
        expect(decrypted.output).toBe('Attack At Dawn!');
    });
});

describe('Bitwise and Shift Operations', () => {
    // Helper function to convert hex string to Uint8Array for XOR testing
    const hexToBytes = (hex) => convertToUint8Array(hex, 'Hexadecimal');

    test('performBitwiseXor should correctly XOR byte arrays', () => {
        // 0101 ^ 1100 = 1001 (Hex: 5 ^ C = 9)
        const bytesA = hexToBytes('55'); // 01010101
        const bytesB = hexToBytes('CC'); // 11001100
        const expectedBase64 = arrayBufferToBase64(hexToBytes('99').buffer);

        const result = performBitwiseXor(bytesA, bytesB);
        // Result is in Base64
        expect(result).toBe(expectedBase64);
    });

    test('performBitwiseXor should handle different lengths (truncation)', () => {
        const bytesA = hexToBytes('AA55'); // AA 55
        const bytesB = hexToBytes('FF');   // FF
        const expectedBase64 = arrayBufferToBase64(hexToBytes('55').buffer); // AA ^ FF = 55 (truncated)
        
        const result = performBitwiseXor(bytesA, bytesB);
        expect(result).toBe(expectedBase64);
    });

    test('stringToBigInt should correctly parse Decimal, Hex, and Binary strings', () => {
        expect(stringToBigInt('12345', 'Decimal')).toBe(BigInt(12345));
        expect(stringToBigInt('1A', 'Hexadecimal')).toBe(BigInt(26));
        expect(stringToBigInt('1010', 'Binary')).toBe(BigInt(10));
        // Should reject input with spaces for numeric formats
        expect(stringToBigInt('10 10', 'Decimal')).toBeNull(); 
    });

    test('performBitShiftOperation should correctly shift left (multiplication)', () => {
        // Decimal: 10 << 3 = 80
        const result = performBitShiftOperation('10', 'Left', 3, 'Decimal');
        expect(result).toBe('80');

        // Binary: 1010 << 2 = 101000 (40 decimal)
        const resultBin = performBitShiftOperation('1010', 'Left', 2, 'Binary');
        expect(resultBin).toBe('101000');
    });

    test('performBitShiftOperation should correctly shift right (division)', () => {
        // Decimal: 80 >> 3 = 10
        const result = performBitShiftOperation('80', 'Right', 3, 'Decimal');
        expect(result).toBe('10');

        // Hex: FF >> 4 = 15 (F)
        const resultHex = performBitShiftOperation('FF', 'Right', 4, 'Hexadecimal');
        expect(resultHex).toBe('F');
    });
    
    test('performBitShiftOperation should reject non-numeric input formats', () => {
        const result = performBitShiftOperation('hello', 'Left', 2, 'Text (UTF-8)');
        expect(result).toContain('ERROR');
    });
});

describe('Data Conversion Utilities', () => {

    const testString = "Hello World!";
    const testUint8 = new TextEncoder().encode(testString);
    const testBuffer = testUint8.buffer;

    test('arrayBufferToBase64 and base64ToArrayBuffer should be inverse operations', () => {
        const base64 = arrayBufferToBase64(testBuffer);
        const backToBuffer = base64ToArrayBuffer(base64);
        expect(new TextDecoder().decode(backToBuffer)).toBe(testString);
    });

    test('convertToUint8Array should handle Base64 input', () => {
        const base64 = arrayBufferToBase64(testBuffer);
        const uint8Array = convertToUint8Array(base64, 'Base64');
        expect(new TextDecoder().decode(uint8Array)).toBe(testString);
    });
    
    test('convertDataFormat from Text to Base64', () => {
        const result = convertDataFormat(testString, 'Text (UTF-8)', 'Base64');
        expect(result).toBe(arrayBufferToBase64(testBuffer));
    });

    test('convertDataFormat from Base64 to Hexadecimal (byte-separated)', () => {
        const base64 = arrayBufferToBase64(testBuffer);
        const result = convertDataFormat(base64, 'Base64', 'Hexadecimal');
        // 'Hello World!' in hex: 48 65 6C 6C 6F 20 57 6F 72 6C 64 21
        expect(result.toUpperCase()).toBe('48 65 6C 6C 6F 20 57 6F 72 6C 64 21');
    });

    test('convertDataFormat to Decimal (Single Number Mode)', () => {
        // "A" (Hex 41) -> Decimal 65
        const base64A = arrayBufferToBase64(new TextEncoder().encode("A").buffer);
        const result = convertDataFormat(base64A, 'Base64', 'Decimal', true);
        expect(result).toBe('65');
    });
});