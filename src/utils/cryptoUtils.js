import {
    convertToUint8Array,
    arrayBufferToHex,
    arrayBufferToBase64,
    base64ToArrayBuffer,
    convertDataFormat,
    stringToBigInt,
    bigIntToString
} from './formatUtils';

import { HASH_ALGORITHMS } from '../constants/appConstants';

export const modPow = (base, exponent, modulus) => {
    if (modulus === BigInt(1)) return BigInt(0);
    let result = BigInt(1);
    base = base % modulus;
    while (exponent > BigInt(0)) {
        if (exponent % BigInt(2) === BigInt(1)) {
            result = (result * base) % modulus;
        }
        exponent = exponent >> BigInt(1);
        base = (base * base) % modulus;
    }
    return result;
};

export const gcd = (a, b) => {
    while (b) {
        [a, b] = [b, a % b];
    }
    return a;
};

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

const DEMO_PRIMES = [167, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283];

export const generateSmallPrimes = () => {
    let p = 0;
    let q = 0;
    while (p === q) {
        p = DEMO_PRIMES[Math.floor(Math.random() * DEMO_PRIMES.length)];
        q = DEMO_PRIMES[Math.floor(Math.random() * DEMO_PRIMES.length)];
    }
    return { p: BigInt(p), q: BigInt(q) };
};

export const generateSmallE = (phiN) => {
    let e = BigInt(0);
    do {
        e = BigInt(Math.floor(Math.random() * (Number(phiN) - 3)) + 2);
    } while (gcd(e, phiN) !== BigInt(1));
    return e;
};

export const caesarEncrypt = (inputData, inputFormat, k) => {
    if (inputFormat !== 'Text (UTF-8)') {
        return { output: `ERROR: Caesar Cipher requires Text (UTF-8) input. Received: ${inputFormat}`, format: inputFormat };
    }
    let ciphertext = '';
    const shift = (k % 26 + 26) % 26;
    const plaintext = inputData;
    for (let i = 0; i < plaintext.length; i++) {
        const char = plaintext[i];
        const charCode = char.charCodeAt(0);
        if (charCode >= 65 && charCode <= 90) {
            const encryptedCode = ((charCode - 65 + shift) % 26) + 65;
            ciphertext += String.fromCharCode(encryptedCode);
        } else if (charCode >= 97 && charCode <= 122) {
            const encryptedCode = ((charCode - 97 + shift) % 26) + 97;
            ciphertext += String.fromCharCode(encryptedCode);
        } else {
            ciphertext += char;
        }
    }
    return { output: ciphertext, format: 'Text (UTF-8)' };
};

export const vigenereEncryptDecrypt = (inputData, keyWord, mode = 'ENCRYPT') => {
    if (!keyWord || keyWord.length === 0) return { output: "ERROR: Keyword cannot be empty.", format: 'Text (UTF-8)' };
    if (inputData.startsWith('ERROR')) return { output: inputData, format: 'Text (UTF-8)' };

    let result = '';
    let keyIndex = 0;
    const plaintext = inputData;
    const alphabetSize = 26;

    for (let i = 0; i < plaintext.length; i++) {
        const char = plaintext[i];
        const charCode = char.charCodeAt(0);
        if ((charCode >= 65 && charCode <= 90) || (charCode >= 97 && charCode <= 122)) {
            const keyChar = keyWord[keyIndex % keyWord.length];
            let keyShift = keyChar.toUpperCase().charCodeAt(0) - 65;
            let base = (charCode >= 65 && charCode <= 90) ? 65 : 97;
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

export const getOutputFormat = (nodeType) => {
    switch (nodeType) {
        case 'DATA_INPUT': case 'CAESAR_CIPHER': case 'VIGENERE_CIPHER': return 'Text (UTF-8)';
        case 'KEY_GEN': case 'SYM_ENC': case 'DATA_SPLIT': case 'DATA_CONCAT': return 'Binary';
        case 'ASYM_ENC': case 'SIMPLE_RSA_KEY_GEN': case 'RSA_KEY_GEN': case 'SIMPLE_RSA_PUBKEY_GEN': return 'Base64';
        case 'HASH_FN': return 'Hexadecimal';
        case 'SYM_DEC': case 'ASYM_DEC': return 'Text (UTF-8)';
        case 'SIMPLE_RSA_ENC': case 'SIMPLE_RSA_DEC': case 'SIMPLE_RSA_SIGN': return 'Decimal';
        case 'SIMPLE_RSA_VERIFY': return 'Text (UTF-8)';
        default: return 'Text (UTF-8)';
    }
}

export const performRawXor = (bytesA, bytesB) => {
    const len = Math.min(bytesA.length, bytesB.length);
    const result = new Uint8Array(len);
    for (let i = 0; i < len; i++) result[i] = bytesA[i] ^ bytesB[i];
    return result;
};

export const performBitwiseXor = (dataAStr, formatA, dataBStr, formatB) => {
    if (!dataAStr || !dataBStr || dataAStr.startsWith('ERROR') || dataBStr.startsWith('ERROR')) {
        return { output: "ERROR: Missing one or both inputs or inputs failed conversion.", format: formatA };
    }
    if (formatA !== formatB || !['Binary', 'Hexadecimal'].includes(formatA)) {
        const bytesA = convertToUint8Array(dataAStr, formatA);
        const bytesB = convertToUint8Array(dataBStr, formatB);
        const combinedBytes = performRawXor(bytesA, bytesB);
        const finalFormat = formatA === 'N/A' || formatA === 'Decimal' ? 'Base64' : formatA;
        const output = convertDataFormat(arrayBufferToBase64(combinedBytes.buffer), 'Base64', finalFormat);
        return { output: output, format: finalFormat };
    }
    const cleanA = dataAStr.replace(/\s/g, '');
    const cleanB = dataBStr.replace(/\s/g, '');
    const targetLength = Math.max(cleanA.length, cleanB.length);
    const paddedA = cleanA.padStart(targetLength, '0');
    const paddedB = cleanB.padStart(targetLength, '0');
    let bigIntA, bigIntB;
    try {
        if (formatA === 'Binary') {
            bigIntA = BigInt(`0b${paddedA}`);
            bigIntB = BigInt(`0b${paddedB}`);
        } else if (formatA === 'Hexadecimal') {
            bigIntA = BigInt(`0x${paddedA}`);
            bigIntB = BigInt(`0x${paddedB}`);
        }
    } catch (e) { return { output: "ERROR: Data too large for BigInt XOR or invalid numerical input.", format: formatA }; }
    const resultBigInt = bigIntA ^ bigIntB;
    let resultStr;
    if (formatA === 'Binary') resultStr = bigIntToString(resultBigInt, 'Binary', targetLength);
    else resultStr = bigIntToString(resultBigInt, 'Hexadecimal', targetLength, true);
    return { output: resultStr, format: formatA };
};

export const performBitShiftOperation = (dataStr, shiftType, shiftAmount, inputFormat) => {
    let shiftDescription = `Arithmetic/Logical ${shiftType} Shift (${shiftAmount} bits)`;
    if (!dataStr) return { output: "ERROR: Missing data input.", description: shiftDescription };
    if (inputFormat === 'Text (UTF-8)' || inputFormat === 'Base64') return { output: `ERROR: Bit Shift requires input data to be a single number (Decimal, Hexadecimal, or Binary). Received: ${inputFormat}.`, description: shiftDescription };
    const cleanedStr = dataStr.replace(/\s/g, '');
    const bigIntData = stringToBigInt(cleanedStr, inputFormat);
    if (bigIntData === null) return { output: `ERROR: Data must represent a single, contiguous number in ${inputFormat} format. Spaces are not allowed.`, description: shiftDescription };
    const amount = BigInt(Math.max(0, parseInt(shiftAmount) || 0));
    let resultBigInt;
    let bitLength = 0;
    const isRotational = inputFormat === 'Binary' || inputFormat === 'Hexadecimal';
    if (isRotational) {
        if (inputFormat === 'Binary') bitLength = cleanedStr.length;
        else if (inputFormat === 'Hexadecimal') bitLength = cleanedStr.length * 4;
    }
    const amountMod = amount % BigInt(bitLength || 1);
    try {
        if (isRotational && bitLength > 0) {
            const L = BigInt(bitLength);
            const data = bigIntData;
            if (shiftType === 'Left') {
                const shiftedLeft = data << amountMod;
                const shiftedRight = data >> (L - amountMod);
                const mask = (BigInt(1) << L) - BigInt(1);
                resultBigInt = (shiftedLeft | shiftedRight) & mask;
                shiftDescription = `Rotational Left Shift (ROL) (${shiftAmount} bits)`;
            } else if (shiftType === 'Right') {
                const shiftedRight = data >> amountMod;
                const shiftedLeft = data << (L - amountMod);
                const mask = (BigInt(1) << L) - BigInt(1);
                resultBigInt = (shiftedRight | shiftedLeft) & mask;
                shiftDescription = `Rotational Right Shift (ROR) (${shiftAmount} bits)`;
            }
        } else {
            if (shiftType === 'Left') resultBigInt = bigIntData << amount;
            else resultBigInt = bigIntData >> amount;
        }
    } catch (error) { return { output: `ERROR: Bit Shift calculation failed. ${error.message}`, description: shiftDescription }; }
    const finalLength = isRotational ? bitLength : 0;
    return { output: bigIntToString(resultBigInt, inputFormat, finalLength, inputFormat === 'Hexadecimal'), description: shiftDescription };
};

export const splitDataIntoChunks = (dataStr, format) => {
    if (!dataStr || dataStr.startsWith('ERROR')) {
        const error = dataStr || 'Missing data input.';
        return { chunk1: `ERROR: ${error}`, chunk2: `ERROR: ${error}`, outputFormat: format };
    }

    let cleanData = dataStr.replace(/\s/g, '');
    let representation, splitUnit;
    if (format === 'Text (UTF-8)' || format === 'Base64') { representation = cleanData; splitUnit = 'char'; }
    else if (format === 'Hexadecimal') { representation = cleanData; splitUnit = 'hex'; }
    else if (format === 'Decimal') return { chunk1: `ERROR: Cannot split a single Decimal number.`, chunk2: `ERROR: Cannot split a single Decimal number.`, outputFormat: 'Text (UTF-8)' };
    else { representation = cleanData; splitUnit = 'bin'; }
    const length = representation.length;
    const midPoint = Math.ceil(length / 2);
    const chunk1 = representation.substring(0, midPoint);
    const chunk2 = representation.substring(midPoint);
    const formatChunk = (chunk, originalFormat) => {
        if (originalFormat === 'Hexadecimal' && splitUnit === 'hex') return chunk.match(/.{1,2}/g)?.join(' ')?.trim() || chunk;
        if (originalFormat === 'Binary' && splitUnit === 'bin') return chunk.match(/.{1,8}/g)?.join(' ')?.trim() || chunk;
        return chunk;
    };
    return { chunk1: formatChunk(chunk1, format), chunk2: formatChunk(chunk2, format), outputFormat: format };
};

export const concatenateData = (dataAStr, formatA, dataBStr, formatB, interpretAsText = false) => {
    if (!dataAStr || dataAStr.startsWith('ERROR')) return { output: dataBStr || "ERROR: Missing data input A and B.", format: formatB || 'Binary' };
    if (!dataBStr || dataBStr.startsWith('ERROR')) return { output: dataAStr, format: formatA || 'Binary' };

    // Strict text concatenation if checkbox is enabled
    if (interpretAsText) {
        return { output: dataAStr + dataBStr, format: 'Text (UTF-8)' };
    }

    // STRICT TYPE CHECKING
    if (formatA !== formatB) {
        return {
            output: `ERROR: Type Mismatch. Input A is ${formatA} and Input B is ${formatB}. Inputs must be of the same type.`,
            format: 'Text (UTF-8)'
        };
    }

    const cleanA = dataAStr.replace(/\s/g, '');
    const cleanB = dataBStr.replace(/\s/g, '');

    if (formatA === 'Binary') return { output: cleanA + cleanB, format: 'Binary' };

    if (formatA === 'Hexadecimal') {
        // Concatenate without spaces and ensure lower case to match visual expectation from user
        return { output: (cleanA + cleanB).toLowerCase(), format: 'Hexadecimal' };
    }

    if (formatA === 'Text (UTF-8)') {
        return { output: dataAStr + dataBStr, format: 'Text (UTF-8)' };
    }

    try {
        const bytesA = convertToUint8Array(dataAStr, formatA);
        const bytesB = convertToUint8Array(dataBStr, formatB);
        const combinedBytes = new Uint8Array(bytesA.length + bytesB.length);
        combinedBytes.set(bytesA, 0);
        combinedBytes.set(bytesB, bytesA.length);
        const output = convertDataFormat(arrayBufferToBase64(combinedBytes.buffer), 'Base64', formatA);
        return { output, format: formatA };
    } catch (e) { return { output: `ERROR: Concatenation failed. Check data formats.`, format: formatA }; }
};

export const calculateHash = async (str, format, algorithm) => {
    if (!str) return 'Missing data input.';
    if (!HASH_ALGORITHMS.includes(algorithm)) return `ERROR: Algorithm not supported (${algorithm}).`;
    try {
        // Convert based on the actual format (e.g. 'Hexadecimal' -> bytes) instead of always assuming text
        const data = convertToUint8Array(str, format);
        const hashBuffer = await crypto.subtle.digest(algorithm.toUpperCase(), data);
        return arrayBufferToHex(hashBuffer);
    } catch (error) { return `ERROR: Calculation failed with ${algorithm}.`; }
};

export const generateSymmetricKey = async (algorithm) => {
    try {
        const key = await crypto.subtle.generateKey({ name: algorithm, length: 256 }, true, ["encrypt", "decrypt"]);
        const rawKey = await crypto.subtle.exportKey('raw', key);
        return { keyObject: key, keyBase64: arrayBufferToBase64(rawKey) };
    } catch (error) { return { keyObject: null, keyBase64: `ERROR: Key generation failed. ${error.message}` }; }
};

export const generateAsymmetricKeyPair = async (algorithm, modulusLength, publicExponentDecimal) => {
    let publicExponentArray = new Uint8Array([0x01, 0x00, 0x01]);
    const exponentValue = publicExponentDecimal || 65537;
    try {
        const keyPair = await crypto.subtle.generateKey(
            { name: algorithm, modulusLength: modulusLength, publicExponent: publicExponentArray, hash: { name: "SHA-256" } },
            true, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
        );
        const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        return {
            publicKey: arrayBufferToBase64(publicKey),
            privateKey: arrayBufferToBase64(privateKey),
            keyPairObject: keyPair,
            rsaParameters: { n: privateKeyJwk.n, e: privateKeyJwk.e, d: privateKeyJwk.d, p: privateKeyJwk.p, q: privateKeyJwk.q }
        };
    } catch (error) { return { publicKey: `ERROR: ${error.message}`, privateKey: `ERROR: ${error.message}`, keyPairObject: null, rsaParameters: {} }; }
};

export const asymmetricEncrypt = async (dataStr, base64PublicKey, algorithm) => {
    if (!dataStr) return 'Missing Data Input.';
    if (!base64PublicKey || typeof base64PublicKey !== 'string') return 'Missing or invalid Public Key Input.';
    try {
        const keyBuffer = base64ToArrayBuffer(base64PublicKey);
        const publicKey = await crypto.subtle.importKey('spki', keyBuffer, { name: algorithm, hash: "SHA-256" }, true, ['encrypt']);
        const encoder = new TextEncoder();
        const encryptedBuffer = await crypto.subtle.encrypt({ name: algorithm }, publicKey, encoder.encode(dataStr));
        return arrayBufferToBase64(encryptedBuffer);
    } catch (error) { return `ERROR: Asymmetric Encryption failed. ${error.message}`; }
};

export const asymmetricDecrypt = async (base64Ciphertext, base64PrivateKey, algorithm) => {
    if (!base64Ciphertext) return 'Missing Ciphertext Input.';
    if (!base64PrivateKey || typeof base64PrivateKey !== 'string') return 'Missing or invalid Private Key Input.';
    try {
        const keyBuffer = base64ToArrayBuffer(base64PrivateKey);
        const privateKey = await crypto.subtle.importKey('pkcs8', keyBuffer, { name: algorithm, hash: "SHA-256" }, true, ['decrypt']);
        const decryptedBuffer = await crypto.subtle.decrypt({ name: algorithm }, privateKey, base64ToArrayBuffer(base64Ciphertext));
        return new TextDecoder().decode(decryptedBuffer);
    } catch (error) { return `ERROR: Asymmetric Decryption failed. ${error.message}`; }
};

export const symmetricEncrypt = async (dataStr, base64Key, algorithm) => {
    if (!dataStr) return 'Missing Data Input.';
    if (!base64Key || typeof base64Key !== 'string') return 'Missing or invalid Key Input.';
    try {
        const key = await crypto.subtle.importKey('raw', base64ToArrayBuffer(base64Key), { name: algorithm, length: 256 }, true, ['encrypt', 'decrypt']);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedBuffer = await crypto.subtle.encrypt({ name: algorithm, iv: iv }, key, new TextEncoder().encode(dataStr));
        const fullCipher = new Uint8Array(iv.byteLength + encryptedBuffer.byteLength);
        fullCipher.set(new Uint8Array(iv), 0);
        fullCipher.set(new Uint8Array(encryptedBuffer), iv.byteLength);
        return arrayBufferToBase64(fullCipher.buffer);
    } catch (error) { return `ERROR: Encryption failed. ${error.message}`; }
};

export const symmetricDecrypt = async (base64Ciphertext, base64Key, algorithm) => {
    if (!base64Ciphertext) return 'Missing Ciphertext Input.';
    if (!base64Key || typeof base64Key !== 'string') return 'Missing or invalid Key Input.';
    try {
        const key = await crypto.subtle.importKey('raw', base64ToArrayBuffer(base64Key), { name: algorithm, length: 256 }, true, ['encrypt', 'decrypt']);
        const fullCipherBuffer = base64ToArrayBuffer(base64Ciphertext);
        if (fullCipherBuffer.byteLength < 12) throw new Error('Ciphertext is too short.');
        const iv = fullCipherBuffer.slice(0, 12);
        const ciphertext = fullCipherBuffer.slice(12);
        const decryptedBuffer = await crypto.subtle.decrypt({ name: algorithm, iv: new Uint8Array(iv) }, key, ciphertext);
        return new TextDecoder().decode(decryptedBuffer);
    } catch (error) { return `ERROR: Decryption failed. ${error.message}.`; }
};

export const isContentCompatible = (content, targetFormat) => {
    const cleanedContent = content.replace(/\s+/g, '');
    if (!cleanedContent) return true;
    if (targetFormat === 'Text (UTF-8)') return true;
    if (targetFormat === 'Binary') return /^[01]*$/.test(cleanedContent);
    if (targetFormat === 'Decimal') return /^\d*$/.test(cleanedContent);
    if (targetFormat === 'Hexadecimal') return /^[0-9a-fA-F]*$/.test(cleanedContent);
    if (targetFormat === 'Base64') return /^[A-Za-z0-9+/=]*$/.test(cleanedContent);
    return true;
};
