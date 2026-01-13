
import { describe, it, expect } from 'vitest';
import { caesarEncrypt } from './cryptoUtils';

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
        // A shift of -1 on 'B' should be 'A'
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
});
