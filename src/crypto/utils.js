// src/crypto/utils.js

/**
 * All core cryptographic and data utility functions used throughout the application.
 * This file is intended for unit testing and reuse across components.
 */

const DEMO_PRIMES = [167, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283];

// --- Modular Arithmetic Utilities ---

/** Calculates (base^exponent) mod modulus using BigInt for large numbers. */
export const modPow = (base, exponent, modulus) => {
    if (modulus === BigInt(1)) return BigInt(0);
    let result = BigInt(1);
    base = base % modulus;
    while (exponent > BigInt(0)) {
        if (exponent % BigInt(2) === BigInt(1)) {
            result = (result * base) % modulus;
        }
        exponent = exponent >> BigInt(1); // exponent = exponent / 2
        base = (base * base) % modulus;
    }
    return result;
};

/** Finds the greatest common divisor of two numbers using BigInt. */
export const gcd = (a, b) => {
    while (b) {
        [a, b] = [b, a % b];
    }
    return a;
};

/** Calculates the modular multiplicative inverse (d) of 'e' modulo 'phi(n)'.
 * Uses the Extended Euclidean Algorithm, compatible with BigInt.
 */
export const modInverse = (a, m) => {
    let m0 = m;
    let x0 = BigInt(0); 
    let x1 = BigInt(1); 

    if (m === BigInt(1)) return BigInt(0); 

    while (a > BigInt(1)) { 
        let q = a / m;
        let t = m;

        m = a % m;
        a = t;
        t = x0;

        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < BigInt(0)) { 
        x1 += m0;
    }
    return x1;
};

/** Finds two random distinct prime numbers from the DEMO_PRIMES array. */
export const generateSmallPrimes = () => {
    let p = 0;
    let q = 0;
    while (p === q) {
        p = DEMO_PRIMES[Math.floor(Math.random() * DEMO_PRIMES.length)];
        q = DEMO_PRIMES[Math.floor(Math.random() * DEMO_PRIMES.length)];
    }
    return { p: BigInt(p), q: BigInt(q) };
};

/** Generates a random valid public exponent 'e' for the given phi(n). */
export const generateSmallE = (phiN) => {
    let e = BigInt(0); 
    do {
        // Choose a random number > 1 and < phiN
        e = BigInt(Math.floor(Math.random() * (Number(phiN) - 3)) + 2);
    } while (gcd(e, phiN) !== BigInt(1)); 
    return e;
};


// --- Caesar Cipher Implementation ---

/**
 * Encrypts plaintext using the Caesar cipher.
 * ONLY works on Text (UTF-8) input. Returns error otherwise.
 * @param {string} inputData The data string (or text).
 * @param {string} inputFormat The format of the inputData.
 * @param {number} k The shift value (key).
 * @returns {{output: string, format: string}} The resulting output data and its format.
 */
export const caesarEncrypt = (inputData, inputFormat, k) => {
    if (inputFormat !== 'Text (UTF-8)') {
          return { output: `ERROR: Caesar Cipher requires Text (UTF-8) input. Received: ${inputFormat}`, format: inputFormat };
    }
    
    let ciphertext = '';
    const shift = (k % 26 + 26) % 26; // Ensure shift is positive and within 0-25
    const plaintext = inputData;
    
    for (let i = 0; i < plaintext.length; i++) {
        const char = plaintext[i];
        const charCode = char.charCodeAt(0);

        if (charCode >= 65 && charCode <= 90) { // Uppercase (A=65, Z=90)
            const encryptedCode = ((charCode - 65 + shift) % 26) + 65;
            ciphertext += String.fromCharCode(encryptedCode);
        } else if (charCode >= 97 && charCode <= 122) { // Lowercase (a=97, z=122)
            const encryptedCode = ((charCode - 97 + shift) % 26) + 97;
            ciphertext += String.fromCharCode(encryptedCode);
        } else {
            ciphertext += char;
        }
    }
    return { output: ciphertext, format: 'Text (UTF-8)' };
};


// --- Vigenère Cipher Implementation ---

/**
 * Encrypts/Decrypts plaintext using the Vigenère cipher.
 * ONLY works on Text (UTF-8) input.
 * @param {string} inputData The plaintext or ciphertext.
 * @param {string} keyWord The keyword for the Vigenère cipher.
 * @param {string} mode 'ENCRYPT' or 'DECRYPT'.
 * @returns {{output: string, format: string}} The resulting output data and its format.
 */
export const vigenereEncryptDecrypt = (inputData, keyWord, mode = 'ENCRYPT') => {
    if (!keyWord || keyWord.length === 0) {
        return { output: "ERROR: Keyword cannot be empty.", format: 'Text (UTF-8)' };
    }

    if (inputData.startsWith('ERROR')) {
        return { output: inputData, format: 'Text (UTF-8)' };
    }

    let result = '';
    let keyIndex = 0;
    const plaintext = inputData;
    const alphabetSize = 26;
    const direction = mode === 'ENCRYPT' ? 1 : -1;

    for (let i = 0; i < plaintext.length; i++) {
        const char = plaintext[i];
        const charCode = char.charCodeAt(0);

        if ((charCode >= 65 && charCode <= 90) || (charCode >= 97 && charCode <= 122)) {
            const keyChar = keyWord[keyIndex % keyWord.length];
            let keyShift = keyChar.toUpperCase().charCodeAt(0) - 65;

            let base = 0;
            if (charCode >= 65 && charCode <= 90) {
                base = 65; // Uppercase
            } else {
                base = 97; // Lowercase
            }

            let charOffset = charCode - base;
            
            let encryptedOffset;
            
            if (mode === 'ENCRYPT') {
                encryptedOffset = (charOffset + keyShift) % alphabetSize;
            } else {
                encryptedOffset = (charOffset - keyShift + alphabetSize) % alphabetSize;
            }

            result += String.fromCharCode(encryptedOffset + base);
            
            keyIndex++;
        } else {
            result += char;
        }
    }

    return { output: result, format: 'Text (UTF-8)' };
};


// --- Data Format Conversion Helpers ---

/** Converts ArrayBuffer to Base64 URL-safe string. */
export const arrayBufferToBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

/** Converts Base64 URL-safe string to ArrayBuffer. */
export const base64ToArrayBuffer = (base64) => {
  const binary_string = atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
};

/** Converts ArrayBuffer to a single BigInt string (Base 10). */
const arrayBufferToBigIntString = (buffer) => {
    const hex = arrayBufferToHex(buffer);
    if (hex.length === 0) return '0';
    
    let bigInt = BigInt(0);
    try {
        bigInt = BigInt(`0x${hex}`);
    } catch (e) {
        return `ERROR: Data too large for BigInt conversion (${buffer.byteLength} bytes).`;
    }
    return bigInt.toString(10);
};

/** Converts ArrayBuffer to a single hexadecimal string (Big Number representation). */
const arrayBufferToHexBig = (buffer) => {
    const hex = arrayBufferToHex(buffer);
    return hex.toUpperCase(); 
};

/** Converts ArrayBuffer to a single binary string (Big Number representation). */
const arrayBufferToBinaryBig = (buffer) => {
    const byteArray = new Uint8Array(buffer);
    let binary = '';
    for (const byte of byteArray) {
        binary += byte.toString(2).padStart(8, '0');
    }
    return binary;
};

/** Converts ArrayBuffer to a hexadecimal string (space separated by byte). */
const arrayBufferToHex = (buffer) => {
    const byteArray = new Uint8Array(buffer);
    return Array.from(byteArray).map(byte => byte.toString(16).padStart(2, '0')).join('');
};

/** Converts ArrayBuffer to a binary string (space separated by byte). */
const arrayBufferToBinary = (buffer) => {
    const byteArray = new Uint8Array(buffer);
    return Array.from(byteArray).map(byte => byte.toString(2).padStart(8, '0')).join(' ');
};

/** Converts a hexadecimal string to ArrayBuffer. */
const hexToArrayBuffer = (hex) => {
    const cleanedHex = hex.replace(/\s/g, ''); 
    if (cleanedHex.length === 0) return new ArrayBuffer(0);

    const paddedHex = cleanedHex.length % 2 !== 0 ? '0' + cleanedHex : cleanedHex;

    const len = paddedHex.length / 2;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = parseInt(paddedHex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes.buffer;
};

/** * Converts a data string and its format into a Uint8Array. */
export const convertToUint8Array = (dataStr, sourceFormat) => {
    if (!dataStr) return new Uint8Array(0);

    try {
        if (sourceFormat === 'Text (UTF-8)') {
             return new TextEncoder().encode(dataStr);
        } else if (sourceFormat === 'Base64') {
             return new Uint8Array(base64ToArrayBuffer(dataStr));
        } else if (sourceFormat === 'Hexadecimal') {
             const cleanedHex = dataStr.replace(/\s/g, ''); 
             return new Uint8Array(hexToArrayBuffer(cleanedHex));
        } else if (sourceFormat === 'Binary') {
             const binaryArray = dataStr.replace(/\s+/g, '').match(/.{1,8}/g) || []; 
             const validBytes = binaryArray.map(s => parseInt(s, 2)).filter(b => !isNaN(b));
             return new Uint8Array(validBytes);
        } else if (sourceFormat === 'Decimal') {
             const decimalArray = dataStr.split(/\s+/).map(s => parseInt(s, 10));
             const validBytes = decimalArray.filter(b => !isNaN(b) && b >= 0 && b >= 255);
             return new Uint8Array(validBytes);
        } else {
             return new TextEncoder().encode(dataStr);
        }
    } catch (e) {
         console.error(`Conversion to Uint8Array failed for format ${sourceFormat}:`, e);
         return new Uint8Array(0);
    }
};

/** Converts a data string from a source format to a target format via ArrayBuffer. */
export const convertDataFormat = (dataStr, sourceFormat, targetFormat, toSingleNumber = false) => {
    if (!dataStr) return '';
    
    if (sourceFormat === targetFormat || dataStr.startsWith('ERROR')) return dataStr;
    
    let buffer;
    
    // 1. Convert from source format to ArrayBuffer
    try {
        if (sourceFormat === 'Text (UTF-8)') {
             buffer = new TextEncoder().encode(dataStr).buffer;
        } else if (sourceFormat === 'Base64') {
             buffer = base64ToArrayBuffer(dataStr);
        } else if (sourceFormat === 'Hexadecimal') {
             const cleanedHex = dataStr.replace(/\s/g, '');
             buffer = hexToArrayBuffer(cleanedHex);
        } else if (sourceFormat === 'Binary') {
             const binaryArray = dataStr.replace(/\s+/g, '').match(/.{1,8}/g) || [];
             const validBytes = binaryArray.map(s => parseInt(s, 2)).filter(b => !isNaN(b) && b >= 0 && b <= 255);
             buffer = new Uint8Array(validBytes).buffer;
        } else if (sourceFormat === 'Decimal') {
             const decimalArray = dataStr.split(/\s+/).map(s => parseInt(s, 10));
             const validBytes = decimalArray.filter(b => !isNaN(b) && b >= 0 && b <= 255);
             buffer = new Uint8Array(validBytes).buffer;
        } else {
             buffer = new TextEncoder().encode(dataStr).buffer;
        }
    } catch (e) {
         return `DECODING ERROR: Failed source format (${sourceFormat}).`;
    }

    // 2. Convert from ArrayBuffer to target format
    try {
        if (toSingleNumber) {
            if (targetFormat === 'Decimal') {
                return arrayBufferToBigIntString(buffer);
            }
            if (targetFormat === 'Hexadecimal') {
                return arrayBufferToHexBig(buffer);
            }
            if (targetFormat === 'Binary') {
                return arrayBufferToBinaryBig(buffer);
            }
        }

        if (targetFormat === 'Text (UTF-8)') {
            return new TextDecoder().decode(buffer);
        } else if (targetFormat === 'Base64') {
            return arrayBufferToBase64(buffer);
        } else if (targetFormat === 'Hexadecimal') {
            return arrayBufferToHex(buffer).toUpperCase().match(/.{1,2}/g)?.join(' ') || ''; 
        } else if (targetFormat === 'Binary') {
            return arrayBufferToBinary(buffer); 
        } else if (targetFormat === 'Decimal') {
             const byteArray = new Uint8Array(buffer);
             return Array.from(byteArray).join(' ');
        } else {
             return `ERROR: Unsupported target format (${targetFormat})`;
        }
    } catch (e) {
        return `ENCODING ERROR: Failed conversion to ${targetFormat}.`;
    }
};

/** Determines the output format based on the node type. */
export const getOutputFormat = (nodeType) => {
    switch (nodeType) {
        case 'DATA_INPUT':
        case 'CAESAR_CIPHER': 
        case 'VIGENERE_CIPHER': 
            return 'Text (UTF-8)'; 
        case 'KEY_GEN':
        case 'SYM_ENC':
        case 'ASYM_ENC':
        case 'SIMPLE_RSA_KEY_GEN':
        case 'RSA_KEY_GEN':
        case 'SIMPLE_RSA_PUBKEY_GEN': 
            return 'Base64';
        case 'HASH_FN':
            return 'Hexadecimal';
        case 'SYM_DEC':
        case 'ASYM_DEC':
            return 'Text (UTF-8)';
        case 'SIMPLE_RSA_ENC':
        case 'SIMPLE_RSA_DEC':
        case 'SIMPLE_RSA_SIGN': 
            return 'Decimal'; 
        case 'SIMPLE_RSA_VERIFY':
            return 'Text (UTF-8)'; 
        default:
            return 'Text (UTF-8)';
    }
}

/** Performs XOR operation on two input byte arrays. */
export const performBitwiseXor = (bytesA, bytesB) => {
    if (bytesA.length === 0 || bytesB.length === 0) {
        return "ERROR: Missing one or both inputs or inputs failed conversion to bytes.";
    }

    try {
        const len = Math.min(bytesA.length, bytesB.length);
        const result = new Uint8Array(len);

        for (let i = 0; i < len; i++) {
            result[i] = bytesA[i] ^ bytesB[i];
        }

        return arrayBufferToBase64(result.buffer);
    } catch (error) {
        console.error("XOR operation failed:", error);
        return `ERROR: XOR failed. ${error.message}`;
    }
};

/** Converts a large number represented as a string to a BigInt. */
export const stringToBigInt = (dataStr, format) => {
    if (!dataStr) return null;
    
    if (dataStr.includes(' ') && format !== 'Text (UTF-8)' && format !== 'Base64') {
        return null; 
    }
    const cleanedStr = dataStr.replace(/\s/g, '');

    try {
        if (format === 'Decimal') {
            if (!/^\d+$/.test(cleanedStr)) return null;
            return BigInt(cleanedStr);
        }
        if (format === 'Hexadecimal') {
            if (!/^[0-9a-fA-F]+$/.test(cleanedStr)) return null;
            return BigInt(`0x${cleanedStr}`);
        }
        if (format === 'Binary') {
            if (!/^[01]+$/.test(cleanedStr)) return null;
            return BigInt(`0b${cleanedStr}`);
        }
    } catch (e) {
        return null;
    }
    return null;
};

/** Converts a BigInt back to a string in the specified format (Decimal, Hex, Binary). */
export const bigIntToString = (bigIntValue, format) => {
    if (bigIntValue === null) return 'N/A';
    
    switch (format) {
        case 'Decimal':
            return bigIntValue.toString(10);
        case 'Hexadecimal':
            return bigIntValue.toString(16).toUpperCase();
        case 'Binary':
            return bigIntValue.toString(2);
        default:
            return bigIntValue.toString(10);
    }
};

/** Performs a bit shift operation on the input number (represented by a string). */
export const performBitShiftOperation = (dataStr, shiftType, shiftAmount, inputFormat) => {
    if (!dataStr) return "ERROR: Missing data input.";
    
    if (inputFormat === 'Text (UTF-8)' || inputFormat === 'Base64') {
        return "ERROR: Bit Shift requires input data to be a single number (Decimal, Hexadecimal, or Binary), not Text or Base64 byte stream.";
    }
    
    const bigIntData = stringToBigInt(dataStr, inputFormat);
    if (bigIntData === null) {
        return `ERROR: Data must represent a single, contiguous number in ${inputFormat} format. Spaces are not allowed.`;
    }
    
    const amount = BigInt(Math.max(0, parseInt(shiftAmount) || 0));
    let resultBigInt;

    try {
        if (shiftType === 'Left') {
            resultBigInt = bigIntData << amount;
        } else if (shiftType === 'Right') {
            resultBigInt = bigIntData >> amount;
        } else {
            return "ERROR: Invalid shift type.";
        }
    } catch (error) {
        console.error("Bit Shift operation failed:", error);
        return `ERROR: Bit Shift calculation failed. ${error.message}`;
    }

    return bigIntToString(resultBigInt, inputFormat);
};

/** Calculates the hash of a given string using the Web Crypto API. */
export const calculateHash = async (str, algorithm) => {
  if (!str) return 'Missing data input.';
  const webCryptoAlgorithm = algorithm.toUpperCase(); 
  
  if (!['SHA-256', 'SHA-512'].includes(algorithm)) {
      return `ERROR: Algorithm not supported (${algorithm}).`;
  }

  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest(webCryptoAlgorithm, data);
    
    return arrayBufferToHex(hashBuffer);
  } catch (error) {
    console.error(`Error calculating hash with ${algorithm}:`, error);
    return `ERROR: Calculation failed with ${algorithm}. Check console for details.`;
  }
};

/** Generates an AES-GCM Symmetric Key. */
export const generateSymmetricKey = async (algorithm) => {
    try {
        const key = await crypto.subtle.generateKey(
            { name: algorithm, length: 256 },
            true, // extractable
            ["encrypt", "decrypt"]
        );
        
        const rawKey = await crypto.subtle.exportKey('raw', key);
        const base64Key = arrayBufferToBase64(rawKey);
        
        return { keyObject: key, keyBase64: base64Key };
    } catch (error) {
        console.error("Key generation failed:", error);
        return { keyObject: null, keyBase64: `ERROR: Key generation failed. ${error.message}` };
    }
};

/** Generates an RSA Key Pair (Web Crypto API). */
export const generateAsymmetricKeyPair = async (algorithm, modulusLength, publicExponentDecimal) => {
    
    let publicExponentArray;
    publicExponentArray = new Uint8Array([0x01, 0x00, 0x01]); // 65537 (standard exponent)
    const hashAlgorithm = "SHA-256";
    const exponentValue = publicExponentDecimal || 65537;

    if (exponentValue !== 65537) {
        console.warn(`Non-standard public exponent (${exponentValue}) detected. Using standard 65537 for Web Crypto API compatibility.`);
    }

    try {
        const keyPair = await crypto.subtle.generateKey(
            {
                name: algorithm,
                modulusLength: modulusLength,
                publicExponent: publicExponentArray,
                hash: { name: hashAlgorithm },
            },
            true, 
            ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
        );
        
        const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const base64PublicKey = arrayBufferToBase64(publicKey);
        
        const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const base64PrivateKey = arrayBufferToBase64(privateKey);
        
        const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        
        const rsaParams = {
            n: privateKeyJwk.n, e: privateKeyJwk.e, d: privateKeyJwk.d, p: privateKeyJwk.p, q: privateKeyJwk.q, 
        };
        
        return { 
            publicKey: base64PublicKey, 
            privateKey: base64PrivateKey,
            keyPairObject: keyPair,
            rsaParameters: rsaParams
        };

    } catch (error) {
        console.error("RSA Key generation failed:", error);
        return { 
            publicKey: `ERROR: ${error.message}`, 
            privateKey: `ERROR: ${error.message}`,
            keyPairObject: null,
            rsaParameters: {}
        };
    }
};

/** Encrypts data using an RSA public key (Asymmetric - Web Crypto). */
export const asymmetricEncrypt = async (dataStr, base64PublicKey, algorithm) => {
    if (!dataStr) return 'Missing Data Input.';
    if (!base64PublicKey || typeof base64PublicKey !== 'string' || base64PublicKey.length === 0) {
        return 'Missing or invalid Public Key Input.'; 
    }

    try {
        const keyBuffer = base64ToArrayBuffer(base64PublicKey);
        
        const publicKey = await crypto.subtle.importKey(
            'spki', keyBuffer, { name: algorithm, hash: "SHA-256" }, true, ['encrypt']
        );
        
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(dataStr);

        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: algorithm }, publicKey, dataBuffer
        );
        
        return arrayBufferToBase64(encryptedBuffer);

    } catch (error) {
        console.error("Asymmetric Encryption failed:", error);
        return `ERROR: Asymmetric Encryption failed. ${error.message}`;
    }
};

/** Decrypts data using an RSA private key (Asymmetric - Web Crypto). */
export const asymmetricDecrypt = async (base64Ciphertext, base64PrivateKey, algorithm) => {
    if (!base64Ciphertext) return 'Missing Ciphertext Input.';
    if (!base64PrivateKey || typeof base64PrivateKey !== 'string' || base64PrivateKey.length === 0) {
        return 'Missing or invalid Private Key Input.'; 
    }

    try {
        const keyBuffer = base64ToArrayBuffer(base64PrivateKey);
        
        const privateKey = await crypto.subtle.importKey(
            'pkcs8', keyBuffer, { name: algorithm, hash: "SHA-256" }, true, ['decrypt']
        );
        
        const cipherBuffer = base64ToArrayBuffer(base64Ciphertext);

        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: algorithm },
            privateKey, 
            cipherBuffer
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decryptedBuffer);

    } catch (error) {
        console.error("Asymmetric Decryption failed:", error);
        return `ERROR: Asymmetric Decryption failed. ${error.message}. Check key/data integrity.`;
    }
};

/** Encrypts data using an AES-GCM key (Symmetric - Web Crypto). */
export const symmetricEncrypt = async (dataStr, base64Key, algorithm) => {
    if (!dataStr) return 'Missing Data Input.';
    if (!base64Key || typeof base64Key !== 'string' || base64Key.length === 0) {
        return 'Missing or invalid Key Input.'; 
    }
    
    try {
        const keyBuffer = base64ToArrayBuffer(base64Key);
        
        const key = await crypto.subtle.importKey(
            'raw', keyBuffer, { name: algorithm, length: 256 }, true, ['encrypt', 'decrypt']
        );
        
        const iv = crypto.getRandomValues(new Uint8Array(12)); 
        
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(dataStr);

        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: algorithm, iv: iv }, key, dataBuffer
        );
        
        const fullCipher = new Uint8Array(iv.byteLength + encryptedBuffer.byteLength);
        fullCipher.set(new Uint8Array(iv), 0); 
        fullCipher.set(new Uint8Array(encryptedBuffer), iv.byteLength); 

        return arrayBufferToBase64(fullCipher.buffer);

    } catch (error) {
        console.error("Encryption failed:", error);
        return `ERROR: Encryption failed. ${error.message}`;
    }
};

/** Decrypts data using an AES-GCM key (Symmetric - Web Crypto). */
export const symmetricDecrypt = async (base64Ciphertext, base64Key, algorithm) => {
    if (!base64Ciphertext) return 'Missing Ciphertext Input.';
    if (!base64Key || typeof base64Key !== 'string' || base64Key.length === 0) {
        return 'Missing or invalid Key Input.'; 
    }

    try {
        const keyBuffer = base64ToArrayBuffer(base64Key);
        
        const key = await crypto.subtle.importKey(
            'raw', keyBuffer, { name: algorithm, length: 256 }, true, ['encrypt', 'decrypt']
        );
        
        const fullCipherBuffer = base64ToArrayBuffer(base64Ciphertext);
        
        if (fullCipherBuffer.byteLength < 12) {
             throw new Error('Ciphertext is too short to contain IV and tag.');
        }

        const iv = fullCipherBuffer.slice(0, 12);
        const ciphertext = fullCipherBuffer.slice(12);

        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: algorithm, iv: new Uint8Array(iv) }, key, ciphertext
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decryptedBuffer);

    } catch (error) {
        console.error("Decryption failed:", error);
        return `ERROR: Decryption failed. ${error.message}. Check key/data integrity.`;
    }
};

/**
 * Checks content compatibility with numeric formats.
 * @param {string} content The user input string.
 * @param {string} targetFormat The format to check against.
 * @returns {boolean} True if content is compatible with the target format.
 */
export const isContentCompatible = (content, targetFormat) => {
    const cleanedContent = content.replace(/\s+/g, '');
    if (!cleanedContent) return true;

    if (targetFormat === 'Text (UTF-8)') return true;
    
    if (targetFormat === 'Binary') {
        return /^[01]*$/.test(cleanedContent);
    }
    if (targetFormat === 'Decimal') {
        return /^\d*$/.test(cleanedContent);
    }
    if (targetFormat === 'Hexadecimal') {
        return /^[0-9a-fA-F]*$/.test(cleanedContent);
    }
    if (targetFormat === 'Base64') {
        return /^[A-Za-z0-9+/=]*$/.test(cleanedContent); 
    }
    return true; 
};

// Supported Algorithms and Formats
export const HASH_ALGORITHMS = ['SHA-256', 'SHA-512'];
export const SYM_ALGORITHMS = ['AES-GCM']; 
export const ASYM_ALGORITHMS = ['RSA-OAEP']; 
export const RSA_MODULUS_LENGTHS = [1024, 2048, 4096];
export const ALL_FORMATS = ['Text (UTF-8)', 'Base64', 'Hexadecimal', 'Binary', 'Decimal'];