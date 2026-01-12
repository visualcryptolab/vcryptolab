import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { LayoutGrid, Cpu, Key, Zap, Settings, Lock, Unlock, Hash, Clipboard, X, ArrowLeft, ArrowRight, Download, Upload, Camera, ChevronDown, ChevronUp, CheckCheck, Fingerprint, Signature, ZoomIn, ZoomOut, Info, Split } from 'lucide-react';

// --- Global Configuration ---
const PROJECT_SCHEMA_VERSION = '1.2';

// --- CSS Styles ---
const globalStyles = `
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

  html, body, #root {
    height: 100%;
    margin: 0;
    padding: 0;
    font-family: 'Inter', sans-serif;
  }

  @keyframes animate-pulse-slow {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
  }
  .animate-pulse-slow {
      animation: animate-pulse-slow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
  }
  
  .connection-line-visible {
      stroke: #059669; /* Emerald 600 */
      fill: none;
      pointer-events: none;
  }
  .connection-hitbox {
      stroke: transparent;
      fill: none;
      cursor: pointer;
      pointer-events: stroke;
  }
  .connection-hitbox:hover {
      stroke: rgba(248, 113, 129, 0.5);
  }
  
  /* Custom scrollbar for panels */
  ::-webkit-scrollbar {
    width: 6px;
    height: 6px;
  }
  ::-webkit-scrollbar-track {
    background: #f1f1f1; 
  }
  ::-webkit-scrollbar-thumb {
    background: #c1c1c1; 
    border-radius: 3px;
  }
  ::-webkit-scrollbar-thumb:hover {
    background: #a8a8a8; 
  }
`;

// --- Custom Icons ---

function XORIcon(props) {
  return (
    <svg 
      xmlns="http://www.w3.org/2000/svg" 
      viewBox="0 0 24 24" 
      fill="none" 
      stroke="currentColor" 
      strokeWidth="2.5" 
      strokeLinecap="round" 
      strokeLinejoin="round" 
      className="w-6 h-6"
      {...props}
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="8" x2="12" y2="16" />
      <line x1="8" y1="12" x2="16" y2="12" />
    </svg>
  );
}

function BitShiftIcon(props) {
  return (
    <svg 
      xmlns="http://www.w3.org/2000/svg" 
      viewBox="0 0 24 24" 
      fill="none" 
      stroke="currentColor" 
      strokeWidth="2.5" 
      strokeLinecap="round" 
      strokeLinejoin="round" 
      className="w-6 h-6"
      {...props}
    >
      <polyline points="15 8 19 12 15 16" />
      <line x1="19" y1="12" x2="5" y2="12" />
      <polyline points="9 16 5 12 9 8" />
    </svg>
  );
}

// --- Constants & Maps ---

const BORDER_CLASSES = {
  blue: 'border-blue-600', red: 'border-red-600', orange: 'border-orange-600', cyan: 'border-cyan-600', pink: 'border-pink-500', 
  teal: 'border-teal-600', gray: 'border-gray-600', lime: 'border-lime-600', indigo: 'border-indigo-600',
  purple: 'border-purple-600', maroon: 'border-red-800', rose: 'border-pink-700', amber: 'border-amber-500',
  yellow: 'border-yellow-400', fuchsia: 'border-fuchsia-600', green: 'border-green-600',
};

const HOVER_BORDER_CLASSES = {
  blue: 'hover:border-blue-500', red: 'hover:border-red-500', orange: 'hover:border-orange-500', cyan: 'hover:border-cyan-500', pink: 'hover:border-pink-500', 
  teal: 'hover:border-teal-500', gray: 'hover:border-gray-500', lime: 'hover:border-lime-500', indigo: 'hover:border-indigo-500',
  purple: 'hover:border-purple-500', maroon: 'hover:border-red-700', rose: 'hover:border-pink-600', amber: 'hover:border-amber-400',
  yellow: 'hover:border-yellow-300', fuchsia: 'hover:border-fuchsia-500', green: 'hover:border-green-500',
};

const TEXT_ICON_CLASSES = {
  blue: 'text-blue-600', red: 'text-red-600', orange: 'text-orange-600', cyan: 'text-cyan-600', pink: 'text-pink-500', 
  teal: 'text-teal-600', gray: 'text-gray-600', lime: 'text-lime-600', indigo: 'text-indigo-600',
  purple: 'text-purple-600', maroon: 'text-red-800', rose: 'text-pink-700', amber: 'text-amber-500',
  yellow: 'text-yellow-400', fuchsia: 'text-fuchsia-600', green: 'text-green-600',
};

const HOVER_BORDER_TOOLBAR_CLASSES = {
  blue: 'hover:border-blue-400', red: 'hover:border-red-400', orange: 'hover:border-orange-400', cyan: 'hover:border-cyan-400', 
  pink: 'hover:border-pink-400', teal: 'hover:border-teal-400', gray: 'hover:border-gray-400', lime: 'hover:border-lime-400', 
  indigo: 'hover:border-indigo-400', purple: 'hover:border-purple-400', maroon: 'hover:border-red-600', rose: 'hover:border-pink-600', 
  amber: 'hover:border-amber-400', yellow: 'hover:border-yellow-300', fuchsia: 'hover:border-fuchsia-400', green: 'hover:border-green-400',
};

const PORT_SIZE = 4;
const INPUT_PORT_COLOR = 'bg-stone-500';
const OPTIONAL_PORT_COLOR = 'bg-gray-400';
const OUTPUT_PORT_COLOR = 'bg-emerald-500';
const PUBLIC_KEY_COLOR = 'bg-lime-500';
const PRIVATE_KEY_COLOR = 'bg-red-800';
const SIGNATURE_COLOR = 'bg-fuchsia-500';

const HASH_ALGORITHMS = ['SHA-256', 'SHA-512'];
const SYM_ALGORITHMS = ['AES-GCM']; 
const ASYM_ALGORITHMS = ['RSA-OAEP']; 
const ALL_FORMATS = ['Text (UTF-8)', 'Base64', 'Hexadecimal', 'Binary', 'Decimal'];

const NODE_DEFINITIONS = {
  DATA_INPUT: { label: 'Data Input', color: 'blue', icon: LayoutGrid, inputPorts: [], outputPorts: [{ name: 'Data Output', type: 'data', keyField: 'dataOutput' }] },
  OUTPUT_VIEWER: { label: 'Output Viewer', color: 'red', icon: Zap, inputPorts: [{ name: 'Data Input', type: 'data', mandatory: true, id: 'data' }], outputPorts: [{ name: 'Viewer Data Output', type: 'data', keyField: 'dataOutput' }] },
  HASH_FN: { label: 'Hash Function', color: 'gray', icon: Hash, inputPorts: [{ name: 'Data Input', type: 'data', mandatory: true, id: 'data' }], outputPorts: [{ name: 'Hash Output', type: 'data', keyField: 'dataOutput' }] },
  XOR_OP: { label: 'XOR Operation', color: 'lime', icon: XORIcon, inputPorts: [{ name: 'Input A', type: 'data', mandatory: true, id: 'dataA' }, { name: 'Input B', type: 'data', mandatory: true, id: 'dataB' }], outputPorts: [{ name: 'Result', type: 'data', keyField: 'dataOutput' }] },
  SHIFT_OP: { label: 'Bit Shift', color: 'indigo', icon: BitShiftIcon, inputPorts: [{ name: 'Data Input', type: 'data', mandatory: true, id: 'data' }], outputPorts: [{ name: 'Result', type: 'data', keyField: 'dataOutput' }] },
  DATA_SPLIT: { label: 'Data Split', color: 'green', icon: Split, inputPorts: [{ name: 'Data Input', type: 'data', mandatory: true, id: 'data' }], outputPorts: [{ name: 'Chunk 1', type: 'data', keyField: 'chunk1' }, { name: 'Chunk 2', type: 'data', keyField: 'chunk2' }] },
  DATA_CONCAT: { label: 'Data Concatenate', color: 'teal', icon: Cpu, inputPorts: [{ name: 'Data A', type: 'data', mandatory: true, id: 'dataA' }, { name: 'Data B', type: 'data', mandatory: true, id: 'dataB' }], outputPorts: [{ name: 'Concatenated Output', type: 'data', keyField: 'dataOutput' }] },
  CAESAR_CIPHER: { label: 'Caesar Cipher', color: 'amber', icon: Lock, inputPorts: [{ name: 'Plaintext', type: 'data', mandatory: true, id: 'plaintext' }], outputPorts: [{ name: 'Ciphertext', type: 'data', keyField: 'dataOutput' }] },
  VIGENERE_CIPHER: { label: 'Vigenère Cipher', color: 'yellow', icon: Lock, inputPorts: [{ name: 'Plaintext/Ciphertext', type: 'data', mandatory: true, id: 'data' }], outputPorts: [{ name: 'Result', type: 'data', keyField: 'dataOutput' }] },
  KEY_GEN: { label: 'Sym Key Generator', color: 'orange', icon: Key, inputPorts: [], outputPorts: [{ name: 'Key Output (AES)', type: 'key', keyField: 'dataOutput' }] }, 
  SIMPLE_RSA_KEY_GEN: { label: 'Simple RSA PrivKey Gen', color: 'purple', icon: Key, inputPorts: [], outputPorts: [{ name: 'Private Key (d)', type: 'private', keyField: 'dataOutputPrivate' }] },
  SIMPLE_RSA_PUBKEY_GEN: { label: 'Simple RSA PubKey Gen', color: 'lime', icon: Unlock, inputPorts: [{ name: 'Private Key Source', type: 'private', mandatory: false, id: 'keySource' }], outputPorts: [{ name: 'Public Key (n, e)', type: 'public', keyField: 'dataOutputPublic' }] },
  SIMPLE_RSA_ENC: { label: 'Simple RSA Encrypt', color: 'maroon', icon: Lock, inputPorts: [{ name: 'Message (m)', type: 'data', mandatory: true, id: 'message' }, { name: 'Public Key (n, e)', type: 'public', mandatory: true, id: 'publicKey' }], outputPorts: [{ name: 'Ciphertext (c)', type: 'data', keyField: 'dataOutput' }] },
  SIMPLE_RSA_DEC: { label: 'Simple RSA Decrypt', color: 'rose', icon: Unlock, inputPorts: [{ name: 'Ciphertext (c)', type: 'data', mandatory: true, id: 'cipher' }, { name: 'Private Key (d)', type: 'private', mandatory: true, id: 'privateKey' }], outputPorts: [{ name: 'Plaintext (m)', type: 'data', keyField: 'dataOutput' }] },
  SIMPLE_RSA_SIGN: { label: 'Simple RSA Sign', color: 'fuchsia', icon: Signature, inputPorts: [{ name: 'Message (m)', type: 'data', mandatory: true, id: 'message' }, { name: 'Private Key (d)', type: 'private', mandatory: true, id: 'privateKey' }], outputPorts: [{ name: 'Signature (s)', type: 'data', keyField: 'dataOutput' }] },
  SIMPLE_RSA_VERIFY: { label: 'Simple RSA Verify', color: 'fuchsia', icon: CheckCheck, inputPorts: [{ name: 'Message (m)', type: 'data', mandatory: true, id: 'message' }, { name: 'Signature (s)', type: 'data', mandatory: true, id: 'signature' }, { name: 'Public Key (n, e)', type: 'public', mandatory: true, id: 'publicKey' }], outputPorts: [{ name: 'Verification Result', type: 'data', keyField: 'dataOutput' }] },
  SYM_ENC: { label: 'Sym Encrypt', color: 'red', icon: Lock, inputPorts: [{ name: 'Data Input', type: 'data', mandatory: true, id: 'data' }, { name: 'Key Input', type: 'key', mandatory: true, id: 'key' }], outputPorts: [{ name: 'Ciphertext', type: 'data', keyField: 'dataOutput' }] },
  SYM_DEC: { label: 'Sym Decrypt', color: 'pink', icon: Unlock, inputPorts: [{ name: 'Cipher Input', type: 'data', mandatory: true, id: 'cipher' }, { name: 'Key Input', type: 'key', mandatory: true, id: 'key' }], outputPorts: [{ name: 'Plaintext', type: 'data', keyField: 'dataOutput' }] },
  ASYM_ENC: { label: 'Asym Encrypt', color: 'cyan', icon: Lock, inputPorts: [{ name: 'Data Input', type: 'data', mandatory: true, id: 'data' }, { name: 'Public Key', type: 'public', mandatory: true, id: 'publicKey' }], outputPorts: [{ name: 'Ciphertext', type: 'data', keyField: 'dataOutput' }] },
  ASYM_DEC: { label: 'Asym Decrypt', color: 'teal', icon: Unlock, inputPorts: [{ name: 'Cipher Input', type: 'data', mandatory: true, id: 'cipher' }, { name: 'Private Key', type: 'private', mandatory: true, id: 'privateKey' }], outputPorts: [{ name: 'Plaintext', type: 'data', keyField: 'dataOutput' }] },
};

const ORDERED_NODE_GROUPS = [
    { name: 'CORE TOOLS', types: ['DATA_INPUT', 'OUTPUT_VIEWER', 'HASH_FN', 'XOR_OP', 'SHIFT_OP', 'DATA_SPLIT', 'DATA_CONCAT'] },
    { name: 'CLASSIC CIPHERS', types: ['CAESAR_CIPHER', 'VIGENERE_CIPHER'] }, 
    { name: 'SIMPLE RSA', types: ['SIMPLE_RSA_KEY_GEN', 'SIMPLE_RSA_PUBKEY_GEN', 'SIMPLE_RSA_ENC', 'SIMPLE_RSA_DEC', 'SIMPLE_RSA_SIGN', 'SIMPLE_RSA_VERIFY'] }, 
    { name: 'SYMMETRIC CRYPTO (AES)', types: ['KEY_GEN', 'SYM_ENC', 'SYM_DEC'] }, 
];

const INITIAL_NODES = []; 
const INITIAL_CONNECTIONS = []; 
const NODE_DIMENSIONS = { initialWidth: 300, initialHeight: 280, minWidth: 250, minHeight: 250 };

// --- Logic & Helpers ---

const modPow = (base, exponent, modulus) => {
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

const gcd = (a, b) => {
    while (b) {
        [a, b] = [b, a % b];
    }
    return a;
};

const modInverse = (a, m) => {
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

const generateSmallPrimes = () => {
    let p = 0;
    let q = 0;
    while (p === q) {
        p = DEMO_PRIMES[Math.floor(Math.random() * DEMO_PRIMES.length)];
        q = DEMO_PRIMES[Math.floor(Math.random() * DEMO_PRIMES.length)];
    }
    return { p: BigInt(p), q: BigInt(q) };
};

const generateSmallE = (phiN) => {
    let e = BigInt(0); 
    do {
        e = BigInt(Math.floor(Math.random() * (Number(phiN) - 3)) + 2);
    } while (gcd(e, phiN) !== BigInt(1)); 
    return e;
};

const caesarEncrypt = (inputData, inputFormat, k) => {
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

const vigenereEncryptDecrypt = (inputData, keyWord, mode = 'ENCRYPT') => {
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

const arrayBufferToBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

const base64ToArrayBuffer = (base64) => {
  const binary_string = atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
};

const arrayBufferToBigIntString = (buffer) => {
    const hex = arrayBufferToHex(buffer);
    if (hex.length === 0) return '0';
    try {
        return BigInt(`0x${hex}`).toString(10);
    } catch (e) {
        return `ERROR: Data too large for BigInt conversion (${buffer.byteLength} bytes).`;
    }
};

const arrayBufferToHexBig = (buffer) => {
    return arrayBufferToHex(buffer).toUpperCase();
};

const arrayBufferToBinaryBig = (buffer) => {
    const byteArray = new Uint8Array(buffer);
    let binary = '';
    for (const byte of byteArray) {
        binary += byte.toString(2).padStart(8, '0');
    }
    return binary;
};

const arrayBufferToHex = (buffer) => {
    const byteArray = new Uint8Array(buffer);
    return Array.from(byteArray).map(byte => byte.toString(16).padStart(2, '0')).join('');
};

const arrayBufferToBinary = (buffer) => {
    const byteArray = new Uint8Array(buffer);
    return Array.from(byteArray).map(byte => byte.toString(2).padStart(8, '0')).join(' ');
};

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

const convertToUint8Array = (dataStr, sourceFormat) => {
    if (!dataStr) return new Uint8Array(0);
    try {
        if (sourceFormat === 'Text (UTF-8)') return new TextEncoder().encode(dataStr);
        if (sourceFormat === 'Base64') return new Uint8Array(base64ToArrayBuffer(dataStr));
        if (sourceFormat === 'Hexadecimal') {
             const cleanedHex = dataStr.replace(/\s/g, '');
             return new Uint8Array(hexToArrayBuffer(cleanedHex));
        }
        if (sourceFormat === 'Binary') {
             const binaryArray = dataStr.replace(/\s+/g, '').match(/.{1,8}/g) || [];
             const validBytes = binaryArray.map(s => parseInt(s, 2)).filter(b => !isNaN(b));
             return new Uint8Array(validBytes);
        }
        if (sourceFormat === 'Decimal') {
             const decimalArray = dataStr.split(/\s+/).map(s => parseInt(s, 10));
             const validBytes = decimalArray.filter(b => !isNaN(b) && b >= 0 && b >= 255);
             return new Uint8Array(validBytes);
        }
        return new TextEncoder().encode(dataStr);
    } catch (e) {
         console.error(`Conversion to Uint8Array failed for format ${sourceFormat}:`, e);
         return new Uint8Array(0);
    }
};

const convertDataFormat = (dataStr, sourceFormat, targetFormat, toSingleNumber = false) => {
    if (!dataStr) return '';
    if (sourceFormat === targetFormat || dataStr.startsWith('ERROR')) return dataStr;
    let buffer;
    try {
        if (sourceFormat === 'Text (UTF-8)') buffer = new TextEncoder().encode(dataStr).buffer;
        else if (sourceFormat === 'Base64') buffer = base64ToArrayBuffer(dataStr);
        else if (sourceFormat === 'Hexadecimal') buffer = hexToArrayBuffer(dataStr.replace(/\s/g, ''));
        else if (sourceFormat === 'Binary') {
             const binaryArray = dataStr.replace(/\s+/g, '').match(/.{1,8}/g) || [];
             const validBytes = binaryArray.map(s => parseInt(s, 2)).filter(b => !isNaN(b) && b >= 0 && b <= 255);
             buffer = new Uint8Array(validBytes).buffer;
        } else if (sourceFormat === 'Decimal') {
             const decimalArray = dataStr.split(/\s+/).map(s => parseInt(s, 10));
             const validBytes = decimalArray.filter(b => !isNaN(b) && b >= 0 && b <= 255);
             buffer = new Uint8Array(validBytes).buffer;
        } else buffer = new TextEncoder().encode(dataStr).buffer;
    } catch (e) { return `DECODING ERROR: Failed source format (${sourceFormat}).`; }

    try {
        if (toSingleNumber) {
            if (targetFormat === 'Decimal') return arrayBufferToBigIntString(buffer);
            if (targetFormat === 'Hexadecimal') return arrayBufferToHexBig(buffer);
            if (targetFormat === 'Binary') return arrayBufferToBinaryBig(buffer);
        }
        if (targetFormat === 'Text (UTF-8)') return new TextDecoder().decode(buffer);
        if (targetFormat === 'Base64') return arrayBufferToBase64(buffer);
        if (targetFormat === 'Hexadecimal') return arrayBufferToHex(buffer).toUpperCase().match(/.{1,2}/g)?.join(' ') || '';
        if (targetFormat === 'Binary') return arrayBufferToBinary(buffer);
        if (targetFormat === 'Decimal') return Array.from(new Uint8Array(buffer)).join(' ');
        return `ERROR: Unsupported target format (${targetFormat})`;
    } catch (e) { return `ENCODING ERROR: Failed conversion to ${targetFormat}.`; }
};

const getOutputFormat = (nodeType) => {
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

const performBitwiseXor = (dataAStr, formatA, dataBStr, formatB) => {
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

const performRawXor = (bytesA, bytesB) => {
    const len = Math.min(bytesA.length, bytesB.length);
    const result = new Uint8Array(len);
    for (let i = 0; i < len; i++) result[i] = bytesA[i] ^ bytesB[i];
    return result;
};

const stringToBigInt = (dataStr, format) => {
    if (!dataStr) return null;
    if (dataStr.includes(' ') && format !== 'Text (UTF-8)' && format !== 'Base64') return null; 
    const cleanedStr = dataStr.replace(/\s/g, '');
    try {
        if (format === 'Decimal') { if (!/^\d+$/.test(cleanedStr)) return null; return BigInt(cleanedStr); }
        if (format === 'Hexadecimal') { if (!/^[0-9a-fA-F]+$/.test(cleanedStr)) return null; return BigInt(`0x${cleanedStr}`); }
        if (format === 'Binary') {
            if (!/^[01]+$/.test(cleanedStr)) return null;
            const paddedBinary = cleanedStr.padStart(Math.ceil(cleanedStr.length / 4) * 4, '0');
            return BigInt(`0b${paddedBinary}`);
        }
    } catch (e) { return null; }
    return null;
};

const bigIntToString = (bigIntValue, format, originalLength = 0, isHexLength = false) => {
    if (bigIntValue === null) return 'N/A';
    switch (format) {
        case 'Decimal': return bigIntValue.toString(10);
        case 'Hexadecimal':
            let hexString = bigIntValue.toString(16).toUpperCase();
            if (originalLength > 0) {
                 const hexLength = isHexLength ? originalLength : Math.ceil(originalLength / 4);
                 hexString = hexString.padStart(hexLength, '0');
                 if (hexString.length > hexLength) hexString = hexString.substring(hexString.length - hexLength);
            }
            return hexString;
        case 'Binary':
            let binaryString = bigIntValue.toString(2);
            if (originalLength > 0) {
                binaryString = binaryString.padStart(originalLength, '0');
                 if (binaryString.length > originalLength) binaryString = binaryString.substring(binaryString.length - originalLength);
            }
            return binaryString;
        default: return bigIntValue.toString(10);
    }
};

const performBitShiftOperation = (dataStr, shiftType, shiftAmount, inputFormat) => {
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

const splitDataIntoChunks = (dataStr, format) => {
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

const concatenateData = (dataAStr, formatA, dataBStr, formatB, interpretAsText = false) => {
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

// MODIFIED: calculateHash now takes format to convert input correctly
const calculateHash = async (str, format, algorithm) => {
  if (!str) return 'Missing data input.';
  if (!HASH_ALGORITHMS.includes(algorithm)) return `ERROR: Algorithm not supported (${algorithm}).`;
  try {
    // Convert based on the actual format (e.g. 'Hexadecimal' -> bytes) instead of always assuming text
    const data = convertToUint8Array(str, format);
    const hashBuffer = await crypto.subtle.digest(algorithm.toUpperCase(), data);
    return arrayBufferToHex(hashBuffer);
  } catch (error) { return `ERROR: Calculation failed with ${algorithm}.`; }
};

const generateSymmetricKey = async (algorithm) => {
    try {
        const key = await crypto.subtle.generateKey({ name: algorithm, length: 256 }, true, ["encrypt", "decrypt"]);
        const rawKey = await crypto.subtle.exportKey('raw', key);
        return { keyObject: key, keyBase64: arrayBufferToBase64(rawKey) };
    } catch (error) { return { keyObject: null, keyBase64: `ERROR: Key generation failed. ${error.message}` }; }
};

const generateAsymmetricKeyPair = async (algorithm, modulusLength, publicExponentDecimal) => {
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

const asymmetricEncrypt = async (dataStr, base64PublicKey, algorithm) => {
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

const asymmetricDecrypt = async (base64Ciphertext, base64PrivateKey, algorithm) => {
    if (!base64Ciphertext) return 'Missing Ciphertext Input.';
    if (!base64PrivateKey || typeof base64PrivateKey !== 'string') return 'Missing or invalid Private Key Input.'; 
    try {
        const keyBuffer = base64ToArrayBuffer(base64PrivateKey);
        const privateKey = await crypto.subtle.importKey('pkcs8', keyBuffer, { name: algorithm, hash: "SHA-256" }, true, ['decrypt']);
        const decryptedBuffer = await crypto.subtle.decrypt({ name: algorithm }, privateKey, base64ToArrayBuffer(base64Ciphertext));
        return new TextDecoder().decode(decryptedBuffer);
    } catch (error) { return `ERROR: Asymmetric Decryption failed. ${error.message}`; }
};

const symmetricEncrypt = async (dataStr, base64Key, algorithm) => {
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

const symmetricDecrypt = async (base64Ciphertext, base64Key, algorithm) => {
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

const isContentCompatible = (content, targetFormat) => {
    const cleanedContent = content.replace(/\s+/g, '');
    if (!cleanedContent) return true;
    if (targetFormat === 'Text (UTF-8)') return true;
    if (targetFormat === 'Binary') return /^[01]*$/.test(cleanedContent);
    if (targetFormat === 'Decimal') return /^\d*$/.test(cleanedContent);
    if (targetFormat === 'Hexadecimal') return /^[0-9a-fA-F]*$/.test(cleanedContent);
    if (targetFormat === 'Base64') return /^[A-Za-z0-9+/=]*$/.test(cleanedContent); 
    return true; 
};

const getLinePath = (sourceNode, targetNode, connection) => {
    const sourceDef = NODE_DEFINITIONS[sourceNode.type];
    const targetDef = NODE_DEFINITIONS[targetNode.type];
    const getVerticalPosition = (nodeDef, index, isInput, nodeHeight) => {
        const numPorts = isInput ? nodeDef.inputPorts.length : nodeDef.outputPorts.length;
        const step = nodeHeight / (numPorts + 1); 
        return (index + 1) * step;
    };
    const sourceVerticalPos = getVerticalPosition(sourceDef, connection.sourcePortIndex, false, sourceNode.height);
    const targetPortIndex = targetDef.inputPorts.findIndex(p => p.id === connection.targetPortId);
    const targetVerticalPos = getVerticalPosition(targetDef, targetPortIndex, true, targetNode.height);
    const p1 = { x: sourceNode.position.x + sourceNode.width, y: sourceNode.position.y + sourceVerticalPos }; 
    const p2 = { x: targetNode.position.x, y: targetNode.position.y + targetVerticalPos }; 
    const midX = (p1.x + p2.x) / 2;
    return `M${p1.x} ${p1.y} C${midX} ${p1.y}, ${midX} ${p2.y}, ${p2.x} ${p2.y}`;
};

const migrateProjectData = (projectData) => {
    const currentVersion = PROJECT_SCHEMA_VERSION;
    const importedVersion = projectData.schemaVersion || '1.0';
    if (importedVersion === currentVersion) return { migratedData: projectData, wasMigrated: false };
    let migratedData = { ...projectData };
    let wasMigrated = false;
    if (importedVersion < '1.1') {
        wasMigrated = true;
        migratedData.nodes = migratedData.nodes.map(node => {
            const newNode = { ...node };
            if (newNode.type === 'DATA_INPUT' && newNode.format && newNode.outputFormat === 'Text (UTF-8)') {
                if (['Binary', 'Hexadecimal', 'Decimal'].includes(newNode.format)) newNode.outputFormat = newNode.format;
            }
            if (!newNode.width || newNode.width < NODE_DIMENSIONS.minWidth) newNode.width = NODE_DIMENSIONS.initialWidth;
            if (!newNode.height || newNode.height < NODE_DIMENSIONS.minHeight) {
                if (newNode.type === 'XOR_OP' || newNode.type === 'SHIFT_OP' || newNode.type === 'DATA_SPLIT' || newNode.type === 'DATA_CONCAT') newNode.height = 300;
                else newNode.height = NODE_DIMENSIONS.initialHeight;
            }
            if (newNode.type === 'XOR_OP') { delete newNode.shiftType; delete newNode.shiftAmount; delete newNode.shiftDescription; }
            return newNode;
        });
    }
    migratedData.schemaVersion = currentVersion;
    return { migratedData, wasMigrated };
};

// --- Sub-Components ---

const Port = React.memo(({ nodeId, type, isConnecting, onStart, onEnd, title, isMandatory, portId, portIndex, outputType, nodes }) => {
    let interactionClasses = "";
    let clickHandler = () => {};
    let portColor = OUTPUT_PORT_COLOR;
    if (outputType === 'public' || outputType === 'private') {
        portColor = outputType === 'public' ? PUBLIC_KEY_COLOR : PRIVATE_KEY_COLOR;
    } else if (type === 'input') {
        portColor = isMandatory ? INPUT_PORT_COLOR : OPTIONAL_PORT_COLOR;
    }
    if (type === 'output' && outputType === 'key') portColor = TEXT_ICON_CLASSES['orange'].replace('text', 'bg'); 
    if (type === 'output' && outputType === 'signature') portColor = SIGNATURE_COLOR.replace('border', 'bg'); 
    
    if (type === 'output') {
        clickHandler = (e) => { e.stopPropagation(); onStart(nodeId, portIndex, outputType); };
        interactionClasses = isConnecting?.sourceId === nodeId ? 'ring-4 ring-emerald-300 animate-pulse' : 'hover:ring-4 hover:ring-emerald-300 transition duration-150';
    } else if (type === 'input') {
        const targetNode = nodes.find(n => n.id === nodeId);
        const targetNodeDef = NODE_DEFINITIONS[targetNode?.type];
        const inputPortDef = targetNodeDef.inputPorts.find(p => p.id === portId);
        const inputPortType = inputPortDef?.type;
        const isTargetCandidate = isConnecting && isConnecting.sourceId !== nodeId && isConnecting.outputType === inputPortType; 
        if (isTargetCandidate) {
            clickHandler = (e) => { e.stopPropagation(); onEnd(nodeId, portId); };
            interactionClasses = 'ring-4 ring-yellow-300 cursor-pointer animate-pulse-slow';
        } else {
             interactionClasses = 'hover:ring-4 hover:ring-stone-300 transition duration-150';
             clickHandler = (e) => { e.stopPropagation(); }; 
        }
    }
    const stopPropagation = (e) => e.stopPropagation();
    return (
        <div 
            className={`w-${PORT_SIZE} h-${PORT_SIZE} rounded-full ${portColor} absolute transform -translate-x-1/2 -translate-y-1/2 shadow-md border-2 border-white cursor-pointer ${interactionClasses}`}
            onClick={clickHandler} onMouseDown={stopPropagation} onTouchStart={stopPropagation} title={title}
        />
    );
});

const DraggableBox = ({ node, setPosition, canvasRef, handleConnectStart, handleConnectEnd, connectingPort, updateNodeContent, connections, handleDeleteNode, nodes, scale, handleResize }) => {
  const { id, label, position, type, color, content, format, dataOutput, dataOutputPublic, dataOutputPrivate, isProcessing, hashAlgorithm, keyAlgorithm, symAlgorithm, modulusLength, publicExponent, sourceFormat, rawInputData, p, q, e, d, n, phiN, shiftKey, keyword, vigenereMode, dStatus, n_pub, e_pub, isReadOnly, width, height, keyBase64, shiftDescription, chunk1, chunk2, convertedData, convertedFormat, isConversionExpanded, interpretAsText } = node; 
  const definition = NODE_DEFINITIONS[type];
  const [isDragging, setIsDragging] = useState(false);
  const [isResizing, setIsResizing] = useState(false); 
  const boxRef = useRef(null);
  const offset = useRef({ x: 0, y: 0 });
  const resizeOffset = useRef({ x: 0, y: 0 }); 
  const [copyStatus, setCopyStatus] = useState('Copy'); 

  const isDataInput = type === 'DATA_INPUT';
  const isOutputViewer = type === 'OUTPUT_VIEWER'; 
  const isHashFn = type === 'HASH_FN';
  const isKeyGen = type === 'KEY_GEN';
  const isSimpleRSAKeyGen = type === 'SIMPLE_RSA_KEY_GEN'; 
  const isSimpleRSAPubKeyGen = type === 'SIMPLE_RSA_PUBKEY_GEN'; 
  const isRSAKeyGen = type === 'RSA_KEY_GEN'; 
  const isSimpleRSAEnc = type === 'SIMPLE_RSA_ENC'; 
  const isSimpleRSADec = type === 'SIMPLE_RSA_DEC'; 
  const isSimpleRSASign = type === 'SIMPLE_RSA_SIGN'; 
  const isSimpleRSAVerify = type === 'SIMPLE_RSA_VERIFY'; 
  const isSymEnc = type === 'SYM_ENC';
  const isSymDec = type === 'SYM_DEC';
  const isAsymEnc = type === 'ASYM_ENC'; 
  const isAsymDec = type === 'ASYM_DEC'; 
  const isBitShift = type === 'SHIFT_OP'; 
  const isCaesarCipher = type === 'CAESAR_CIPHER'; 
  const isVigenereCipher = type === 'VIGENERE_CIPHER'; 
  const isDataSplit = type === 'DATA_SPLIT'; 
  const isDataConcat = type === 'DATA_CONCAT'; 
  
  const FORMATS = ALL_FORMATS;
  const isPortSource = connectingPort?.sourceId === id;
  const iconTextColorClass = TEXT_ICON_CLASSES[color] || 'text-gray-600';
  let specificClasses = '';
  if (isPortSource) specificClasses = `border-emerald-500 ring-4 ring-emerald-300 cursor-pointer animate-pulse transition duration-200`; 
  else specificClasses = `${BORDER_CLASSES[color]} ${HOVER_BORDER_CLASSES[color]} ${isDragging ? 'cursor-grabbing' : 'cursor-pointer hover:border-blue-500'}`;
  if (isProcessing) specificClasses = `border-yellow-500 ring-4 ring-yellow-300 animate-pulse transition duration-200`; 
  
  let requiredMinHeight = NODE_DIMENSIONS.minHeight;
  if (isOutputViewer) requiredMinHeight = isConversionExpanded ? 280 : 250;
  if (isBitShift || type === 'XOR_OP' || isDataSplit || isDataConcat) requiredMinHeight = 300; 
  const effectiveMinHeight = requiredMinHeight;
  const baseClasses = `h-auto flex flex-col justify-start items-center p-3 bg-white shadow-xl rounded-xl border-4 transition duration-150 ease-in-out hover:shadow-2xl absolute select-none z-10`;
  const boxStyle = { left: `${position.x}px`, top: `${position.y}px`, width: `${width}px`, minHeight: `${effectiveMinHeight}px`, height: `${height}px` };
  const contentHeightExcludingHeader = height - 50; 

  const handleDragStart = useCallback((e) => {
    if (connectingPort || isResizing) return; 
    const interactiveTags = ['TEXTAREA', 'SELECT', 'OPTION', 'BUTTON', 'INPUT']; 
    if (e.target.tagName === 'DIV' && e.target.classList.contains('w-4') && e.target.classList.contains('h-4')) return; 
    if (interactiveTags.includes(e.target.tagName)) return; 
    const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
    const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);
    const canvas = canvasRef.current;
    if (boxRef.current && canvas) {
      const canvasRect = canvas.getBoundingClientRect();
      const unscaledMouseX = (clientX - canvasRect.left) / scale;
      const unscaledMouseY = (clientY - canvasRect.y) / scale;
      offset.current = { x: unscaledMouseX - position.x, y: unscaledMouseY - position.y };
      setIsDragging(true);
      e.preventDefault(); 
    }
  }, [canvasRef, position.x, position.y, connectingPort, isResizing, scale]);

  const handleDragMove = useCallback((e) => {
    if (!isDragging) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
    const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);
    const canvasRect = canvas.getBoundingClientRect();
    const unscaledMouseX = (clientX - canvasRect.left) / scale;
    const unscaledMouseY = (clientY - canvasRect.y) / scale;
    let newX = unscaledMouseX - offset.current.x;
    let newY = unscaledMouseY - offset.current.y;
    newX = Math.max(0, newX);
    newY = Math.max(0, newY);
    setPosition(id, { x: newX, y: newY });
  }, [isDragging, id, setPosition, canvasRef, scale]);

  const handleDragEnd = useCallback(() => setIsDragging(false), []);
  
  const handleResizeStart = useCallback((e) => {
    e.stopPropagation(); setIsResizing(true);
    const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
    const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);
    const canvas = canvasRef.current.getBoundingClientRect();
    const unscaledMouseX = (clientX - canvas.left) / scale;
    const unscaledMouseY = (clientY - canvas.y) / scale;
    resizeOffset.current = { x: unscaledMouseX - (node.position.x + node.width), y: unscaledMouseY - (node.position.y + node.height) };
  }, [node.position.x, node.position.y, node.width, node.height, scale, canvasRef]);

  const handleResizeMove = useCallback((e) => {
    if (!isResizing) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
    const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);
    const canvasRect = canvas.getBoundingClientRect();
    const unscaledMouseX = (clientX - canvasRect.left) / scale;
    const unscaledMouseY = (clientY - canvasRect.y) / scale;
    let newWidth = unscaledMouseX - node.position.x - resizeOffset.current.x;
    let newHeight = unscaledMouseY - node.position.y - resizeOffset.current.y;
    handleResize(id, newWidth, newHeight);
    e.preventDefault(); 
  }, [isResizing, id, handleResize, node.position.x, node.position.y, scale]);

  const handleResizeEnd = useCallback(() => setIsResizing(false), []);
  
  useEffect(() => {
    const globalHandleMove = (e) => { if (isDragging) handleDragMove(e); else if (isResizing) handleResizeMove(e); };
    const globalHandleUp = (e) => { if (isDragging) handleDragEnd(e); else if (isResizing) handleResizeEnd(e); };
    if (isDragging || isResizing) {
      document.addEventListener('mousemove', globalHandleMove);
      document.addEventListener('mouseup', globalHandleUp);
      document.addEventListener('touchmove', globalHandleMove, { passive: false });
      document.addEventListener('touchend', globalHandleUp);
    } 
    return () => {
      document.removeEventListener('mousemove', globalHandleMove);
      document.removeEventListener('mouseup', globalHandleUp);
      document.removeEventListener('touchmove', globalHandleMove);
      document.removeEventListener('touchend', globalHandleUp);
    };
  }, [isDragging, isResizing, handleDragMove, handleDragEnd, handleResizeMove, handleResizeEnd]);
  
  const handleBoxClick = useCallback((e) => {
    if (isDragging || isResizing) return; 
    if (connectingPort) handleConnectEnd(null); 
    e.stopPropagation();
  }, [connectingPort, handleConnectEnd, isDragging, isResizing]);

  const handleCopyToClipboard = useCallback((e, textToCopy) => {
    e.stopPropagation();
    if (!textToCopy || textToCopy.startsWith('ERROR')) return;
    try {
        const tempTextArea = document.createElement('textarea');
        tempTextArea.value = textToCopy;
        tempTextArea.style.position = 'fixed';
        tempTextArea.style.left = '-9999px';
        document.body.appendChild(tempTextArea);
        tempTextArea.select();
        document.execCommand('copy');
        document.body.removeChild(tempTextArea);
        setCopyStatus('Copied!'); 
        setTimeout(() => setCopyStatus('Copy'), 1500); 
    } catch (err) { console.error('Failed to copy text:', err); setCopyStatus('Error'); setTimeout(() => setCopyStatus('Copy'), 2000); }
  }, [setCopyStatus]);

  const renderInputPorts = () => {
    if (!definition.inputPorts || definition.inputPorts.length === 0) return null;
    const step = height / (definition.inputPorts.length + 1); 
    return definition.inputPorts.map((portDef, index) => {
        const topPosition = (index + 1) * step;
        const isInputConnected = connections.some(c => c.target === id && c.targetPortId === portDef.id);
        return (
            <div key={portDef.id} className="absolute -left-2 transform -translate-y-1/2 z-20" style={{ top: `${topPosition}px` }}>
                <Port nodeId={id} type="input" portId={portDef.id} isConnecting={connectingPort} onStart={handleConnectStart} onEnd={handleConnectEnd} title={`${portDef.name} (${portDef.mandatory ? 'Mandatory' : 'Optional'}) - Type: ${portDef.type}`} isMandatory={portDef.mandatory} isInputConnected={isInputConnected} nodes={nodes} />
            </div>
        );
    });
  };

  const renderOutputPorts = () => {
    if (!definition.outputPorts || definition.outputPorts.length === 0) return null;
    const step = height / (definition.outputPorts.length + 1); 
    return definition.outputPorts.map((portDef, index) => {
        const topPosition = (index + 1) * step;
        return (
            <div key={portDef.name} className="absolute -right-2 transform -translate-y-1/2 z-20" style={{ top: `${topPosition}px` }}>
                <Port nodeId={id} type="output" portId={`${portDef.type}-${index}`} portIndex={index} outputType={portDef.type} isConnecting={connectingPort} onStart={handleConnectStart} onEnd={handleConnectEnd} title={`${portDef.name} - Type: ${portDef.type}`} isMandatory={true} nodes={nodes} />
            </div>
        );
    });
  };

  return (
    <div ref={boxRef} id={id} className={`${baseClasses} ${specificClasses}`} style={boxStyle} onMouseDown={handleDragStart} onTouchStart={handleDragStart} onClick={handleBoxClick}>
      <div className="absolute bottom-0 right-0 w-4 h-4 rounded-tl-lg bg-gray-200 opacity-60 hover:opacity-100 transition duration-150 cursor-nwse-resize z-30" onMouseDown={handleResizeStart} onTouchStart={handleResizeStart} onClick={(e) => e.stopPropagation()} title="Resize">
        <div className="w-1 h-1 bg-gray-600 absolute bottom-1 right-1"></div>
      </div>
      <button className="absolute top-1 right-1 p-1 rounded-full bg-gray-100 hover:bg-gray-200 text-gray-400 hover:text-gray-600 z-30 transition duration-150" onClick={(e) => { e.stopPropagation(); handleDeleteNode(id); }} title="Delete Node"><X className="w-3 h-3" /></button>
      {renderInputPorts()} {renderOutputPorts()} 
      <div className="flex flex-col w-full justify-start items-center overflow-hidden" style={{ height: `${contentHeightExcludingHeader}px` }}>
        <div className="flex flex-col justify-start items-center w-full flex-shrink-0 mb-2">
          {definition.icon && (<definition.icon className={`w-6 h-6 ${iconTextColorClass} mb-1`} />)}
          <span className={`text-${isDataInput ? 'base' : 'lg'} font-bold text-gray-800 text-center leading-tight`}>{label}</span>
          {isCaesarCipher && <span className={`text-xs text-gray-500 mt-1`}>k = {node.shiftKey || 0}</span>}
          {isVigenereCipher && <span className={`text-xs text-gray-500 mt-1`}>Keyword: {node.keyword || 'None'}</span>}
          {isSimpleRSASign && <span className={`text-xs text-gray-500 mt-1`}>Signing (m^d mod n)</span>}
          {isSimpleRSAVerify && <span className={`text-xs text-gray-500 mt-1`}>Verifying (s^e mod n)</span>}
          {isSimpleRSAEnc && <span className={`text-xs text-gray-500 mt-1`}>Encryption: (c = m^e mod n)</span>}
          {isSimpleRSADec && <span className={`text-xs text-gray-500 mt-1`}>Decryption: (m = c^d mod n)</span>}
          {isHashFn && (
              <div className="text-xs w-full text-center flex flex-col items-center">
                <span className={`text-[10px] font-semibold text-gray-600 mb-1`}>ALGORITHM</span>
                <select className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 bg-white appearance-none cursor-pointer text-gray-700 focus:ring-2 focus:ring-gray-500 focus:border-gray-500 outline-none transition duration-200" value={hashAlgorithm || 'SHA-256'} onChange={(e) => updateNodeContent(id, 'hashAlgorithm', e.target.value)} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()}>
                    {HASH_ALGORITHMS.map(alg => (<option key={alg} value={alg}>{alg}</option>))}
                </select>
              </div>
          )}
          {isKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({keyAlgorithm})</span>}
          {isSimpleRSAKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({modulusLength} bits)</span>}
          {type === 'XOR_OP' && <span className={`text-xs text-gray-500 mt-1`}>({isProcessing ? 'Processing' : 'Bitwise XOR'})</span>}
          {isBitShift && <span className={`text-xs text-gray-500 mt-1`}>({isProcessing ? 'Processing' : (shiftDescription || 'Bit Shift')})</span>}
          {isSimpleRSAPubKeyGen && <span className={`text-xs text-gray-500 mt-1`}>Public Key Output</span>} 
          {isDataSplit && <span className={`text-xs text-gray-500 mt-1`}>Split by: Character/Hex/Bit</span>}
          {isDataConcat && <span className={`text-xs text-gray-500 mt-1`}>Concatenation: Data A + Data B</span>}
        </div>
        
        {isDataInput && (
          <div className="w-full flex flex-col items-center flex-grow">
            <textarea className="w-full text-xs p-2 border border-gray-200 rounded-lg shadow-md resize-y flex-grow mb-2 placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200" placeholder="Enter data here..." value={content || ''} onChange={(e) => {
                  const newContent = e.target.value;
                  const currentFormat = node.format;
                  let newFormat = currentFormat;
                  const formatsByRestrictiveness = ['Binary', 'Decimal', 'Hexadecimal', 'Base64', 'Text (UTF-8)'];
                  if (!isContentCompatible(newContent, currentFormat)) {
                      for (const formatCheck of formatsByRestrictiveness) {
                          if (isContentCompatible(newContent, formatCheck)) { newFormat = formatCheck; break; }
                      }
                  }
                  if (newFormat !== currentFormat) updateNodeContent(id, 'format', newFormat);
                  updateNodeContent(id, 'content', newContent);
              }} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} />
            <select className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm flex-shrink-0 bg-white appearance-none cursor-pointer text-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200" value={format || 'Text (UTF-8)'} onChange={(e) => {
                e.stopPropagation();
                const selectedFormat = e.target.value;
                const currentContent = content || '';
                let finalFormat = selectedFormat;
                if (!isContentCompatible(currentContent, selectedFormat)) {
                    const formatsByRestrictiveness = ['Binary', 'Decimal', 'Hexadecimal', 'Base64', 'Text (UTF-8)'];
                    for (const formatCheck of formatsByRestrictiveness) {
                        if (isContentCompatible(currentContent, formatCheck)) { finalFormat = formatCheck; break; }
                    }
                }
                updateNodeContent(id, 'format', finalFormat);
              }} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()}>
              {FORMATS.map(f => (<option key={f} value={f}>{f}</option>))}
            </select>
          </div>
        )}
        
        {isOutputViewer && (
            <div className="w-full mt-1 flex flex-col items-center flex-grow text-xs text-gray-700 bg-gray-50 p-2 border border-gray-200 rounded-lg shadow-inner overflow-y-auto">
                <span className="text-center font-bold text-red-600 mb-1 flex-shrink-0">RAW INPUT DATA</span>
                <div className="w-full mb-1 flex-shrink-0">
                    <label className="block text-left text-[10px] font-semibold text-gray-600 mb-0.5">Source Data Type</label>
                    <div className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm bg-gray-100 text-gray-700 truncate">{sourceFormat || 'N/A'}</div>
                </div>
                <div className={`relative w-full break-all text-[10px] leading-tight text-gray-800 bg-white p-1 rounded-md mb-2 overflow-y-auto border border-gray-200`} style={{ flexGrow: isConversionExpanded ? 0.5 : 1.2, minHeight: '40px' }}>
                    <p>{rawInputData || 'Not connected or no data.'}</p>
                    <button onClick={(e) => handleCopyToClipboard(e, rawInputData)} disabled={!rawInputData || rawInputData.startsWith('ERROR')} className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm ${rawInputData && !rawInputData.startsWith('ERROR') ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500' : 'bg-gray-300 cursor-not-allowed'}`} title="Copy to Clipboard"><Clipboard className="w-3 h-3" /></button>
                </div>
                <button onClick={(e) => { e.stopPropagation(); updateNodeContent(id, 'isConversionExpanded', !isConversionExpanded); }} className={`mt-1 w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md bg-red-500 hover:bg-red-600 flex-shrink-0`}><span>{isConversionExpanded ? 'Hide Conversion' : 'Convert Type'}</span></button>
                {isConversionExpanded && (
                    <div className="w-full mt-2 pt-2 border-t border-gray-200 flex flex-col space-y-2 flex-grow">
                        <span className="text-center font-bold text-red-600 text-[10px] flex-shrink-0">CONVERTED VIEW</span>
                        <div className="relative w-full break-all text-[10px] leading-tight text-gray-800 bg-white p-1 rounded-md mb-2 overflow-y-auto border border-gray-200" style={{ flexGrow: 1, minHeight: '40px' }}>
                            <p>{convertedData || 'Select conversion type...'}</p>
                            <button onClick={(e) => handleCopyToClipboard(e, convertedData)} disabled={!convertedData || convertedData.startsWith('ERROR')} className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm ${convertedData && !convertedData.startsWith('ERROR') ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500' : 'bg-gray-300 cursor-not-allowed'}`} title="Copy to Clipboard"><Clipboard className="w-3 h-3" /></button>
                        </div>
                        <select className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm flex-shrink-0 bg-white appearance-none cursor-pointer text-gray-700 focus:ring-2 focus:ring-red-500 focus:border-red-500 outline-none transition duration-200" value={convertedFormat || 'Base64'} onChange={(e) => updateNodeContent(id, 'convertedFormat', e.target.value)} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()}>
                            {FORMATS.map(f => (<option key={f} value={f}>{f}</option>))}
                        </select>
                    </div>
                )}
            </div>
        )}

        {isCaesarCipher && (
            <div className="text-xs w-full text-center flex flex-col items-center flex-grow">
                <span className={`text-[10px] font-semibold text-gray-600 mb-1 flex-shrink-0`}>SHIFT KEY (k)</span>
                <input type="number" min="0" max="25" step="1" className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 flex-shrink-0 text-gray-700 focus:ring-2 focus:ring-amber-500 focus:border-amber-500 outline-none transition duration-200" value={node.shiftKey || 0} onChange={(e) => updateNodeContent(id, 'shiftKey', parseInt(e.target.value) || 0)} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} />
                <span className={`font-semibold mt-2 ${isProcessing ? 'text-yellow-600' : 'text-amber-600'} flex-shrink-0`}>{isProcessing ? 'Encrypting...' : 'Active'}</span>
                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                    <p className={`text-left text-[10px] break-all p-2 bg-gray-100 rounded overflow-auto h-full ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>{dataOutput ? `Result (${node.outputFormat}): ${dataOutput}` : 'Waiting for Plaintext...'}</p>
                    <button onClick={(e) => handleCopyToClipboard(e, dataOutput)} disabled={!dataOutput || dataOutput.startsWith('ERROR')} className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm ${dataOutput && !dataOutput.startsWith('ERROR') ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500' : 'bg-gray-300 cursor-not-allowed'}`} title="Copy to Clipboard"><Clipboard className="w-3 h-3" /></button>
                </div>
            </div>
        )}

        {isSimpleRSAKeyGen && (
             <div className="text-xs w-full flex flex-col items-center flex-grow space-y-2">
                <div className="w-full grid grid-cols-2 gap-2 flex-shrink-0">
                    <label className="block"><span className="block text-[10px] font-semibold text-gray-600 mb-0.5">P (Prime 1)</span><input type="text" placeholder="Auto" className="w-full text-[10px] p-1 border border-gray-200 rounded-lg shadow-sm text-gray-700 focus:ring-2 focus:ring-purple-500 outline-none transition" value={p || ''} onChange={(e) => updateNodeContent(id, 'p', e.target.value.replace(/[^0-9]/g, ''))} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} /></label>
                    <label className="block"><span className="block text-[10px] font-semibold text-gray-600 mb-0.5">Q (Prime 2)</span><input type="text" placeholder="Auto" className="w-full text-[10px] p-1 border border-gray-200 rounded-lg shadow-sm text-gray-700 focus:ring-2 focus:ring-purple-500 outline-none transition" value={q || ''} onChange={(e) => updateNodeContent(id, 'q', e.target.value.replace(/[^0-9]/g, ''))} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} /></label>
                </div>
                <div className="w-full grid grid-cols-2 gap-2 flex-shrink-0">
                    <label className="block"><span className="block text-[10px] font-semibold text-gray-600 mb-0.5">N (Modulus)</span><div className="text-[10px] p-1.5 border border-gray-200 rounded-lg bg-gray-100 overflow-hidden break-all h-6">{n || 'N/A'}</div></label>
                    <label className="block"><span className="block text-[10px] font-semibold text-gray-600 mb-0.5">Phi(N)</span><div className="text-[10px] p-1.5 border border-gray-200 rounded-lg bg-gray-100 overflow-hidden break-all h-6">{phiN || 'N/A'}</div></label>
                </div>
                <div className="w-full grid grid-cols-2 gap-2 flex-shrink-0">
                    <label className="block"><span className="block text-[10px] font-semibold text-gray-600 mb-0.5">E (Public Exp)</span><input type="text" placeholder="Auto" className="w-full text-[10px] p-1 border border-gray-200 rounded-lg shadow-sm text-gray-700 focus:ring-2 focus:ring-purple-500 outline-none transition" value={e || ''} onChange={(e) => updateNodeContent(id, 'e', e.target.value.replace(/[^0-9]/g, ''))} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} /></label>
                    <label className="block"><span className="block text-[10px] font-semibold text-red-800 mb-0.5">D (Private Key)</span><input type="text" placeholder="Calculated D" className="w-full text-[10px] p-1 border border-gray-200 rounded-lg shadow-sm text-gray-700 focus:ring-2 focus:ring-red-800 outline-none transition" value={d || ''} onChange={(e) => updateNodeContent(id, 'd', e.target.value.replace(/[^0-9]/g, ''))} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} /></label>
                </div>
                <button onClick={(e) => { e.stopPropagation(); updateNodeContent(id, 'generateKey', true); }} className={`w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md ${isProcessing ? 'bg-yellow-500 animate-pulse' : 'bg-purple-600 hover:bg-purple-700'} flex-shrink-0`} disabled={isProcessing}><Key className="w-4 h-4" /><span>{isProcessing ? 'Generating...' : 'Generate Keys'}</span></button>
                <div className="relative w-full text-left flex-grow">
                    <span className={`block text-[10px] font-semibold text-red-800 mb-0.5`}>PRIVATE KEY D OUTPUT (d)</span>
                    <div className={`text-[10px] p-1 bg-gray-100 rounded border h-full overflow-y-auto break-all ${dStatus?.startsWith('INCORRECT') || dStatus?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                        <p>D: {dataOutputPrivate || 'N/A'}</p>
                        <p className="mt-1 font-bold italic text-gray-700">Status: {dStatus || 'Idle'}</p>
                    </div>
                </div>
            </div>
        )}
        
        {/* Simplified renders for other nodes to save space in the component - core logic is identical to original app */}
        {!isDataInput && !isOutputViewer && !isCaesarCipher && !isSimpleRSAKeyGen && (
            <div className="text-xs w-full text-center flex flex-col items-center flex-grow">
                 {/* Specific Controls per node type */}
                 {isVigenereCipher && (
                    <>
                        <input type="text" placeholder="Keyword" className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-1 flex-shrink-0 text-gray-700 focus:ring-2 focus:ring-yellow-500 outline-none transition" value={keyword || ''} onChange={(e) => updateNodeContent(id, 'keyword', e.target.value.toUpperCase().replace(/[^A-Z]/g, ''))} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} />
                        <select className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm bg-white cursor-pointer text-gray-700 focus:ring-2 focus:ring-yellow-500 outline-none transition" value={vigenereMode || 'ENCRYPT'} onChange={(e) => updateNodeContent(id, 'vigenereMode', e.target.value)} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()}>
                            <option value="ENCRYPT">Encrypt (C = P + K)</option>
                            <option value="DECRYPT">Decrypt (P = C - K)</option>
                        </select>
                    </>
                 )}
                 {isBitShift && (
                    <>
                        <input type="number" min="0" className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 flex-shrink-0 text-gray-700 focus:ring-2 focus:ring-indigo-500 outline-none transition" value={node.shiftAmount || 0} onChange={(e) => updateNodeContent(id, 'shiftAmount', parseInt(e.target.value) || 0)} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} />
                        <select className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 bg-white cursor-pointer text-gray-700 focus:ring-2 focus:ring-indigo-500 outline-none transition" value={node.shiftType || 'Left'} onChange={(e) => updateNodeContent(id, 'shiftType', e.target.value)} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()}>
                            <option value="Left">Left Shift (ROL)</option>
                            <option value="Right">Right Shift (ROR)</option>
                        </select>
                    </>
                 )}
                 {isKeyGen && (
                    <button onClick={(e) => { e.stopPropagation(); updateNodeContent(id, 'generateKey', true); }} className={`w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md ${isProcessing ? 'bg-yellow-500 animate-pulse' : 'bg-orange-500 hover:bg-orange-600'} flex-shrink-0`} disabled={isProcessing}><Key className="w-4 h-4" /><span>{isProcessing ? 'Generating...' : 'Generate Key'}</span></button>
                 )}
                 {isSimpleRSAPubKeyGen && (
                    <div className="w-full space-y-2">
                        <label className="block w-full flex-shrink-0">
                            <span className="block text-[10px] font-semibold text-gray-600 mb-0.5">N (Modulus)</span>
                            <input type="text" className={`w-full text-[10px] p-1 border rounded ${isReadOnly ? 'bg-gray-100' : 'bg-white'}`} value={n_pub || ''} onChange={(e) => updateNodeContent(id, 'n_pub', e.target.value.replace(/[^0-9]/g, ''))} readOnly={isReadOnly} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} />
                        </label>
                        <label className="block w-full flex-shrink-0">
                            <span className="block text-[10px] font-semibold text-gray-600 mb-0.5">E (Public Exponent)</span>
                            <input type="text" className={`w-full text-[10px] p-1 border rounded ${isReadOnly ? 'bg-gray-100' : 'bg-white'}`} value={e_pub || ''} onChange={(e) => updateNodeContent(id, 'e_pub', e.target.value.replace(/[^0-9]/g, ''))} readOnly={isReadOnly} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} />
                        </label>
                        <div className="relative w-full text-left flex-grow">
                            <span className={`block text-[10px] font-semibold text-lime-600 mb-0.5`}>PUBLIC KEY (N, E) OUTPUT</span>
                            <div className={`text-[10px] p-1 bg-gray-100 rounded border h-full overflow-y-auto break-all text-gray-800`}>
                                <p>{dataOutputPublic || 'N/A'}</p>
                            </div>
                        </div>
                    </div>
                 )}
                 {isDataConcat && (
                    <div className="w-full flex flex-col items-center">
                        <label className="flex items-center space-x-2 cursor-pointer mb-2">
                            <input 
                                type="checkbox" 
                                className="form-checkbox h-3 w-3 text-teal-600 transition duration-150 ease-in-out"
                                checked={interpretAsText || false}
                                onChange={(e) => updateNodeContent(id, 'interpretAsText', e.target.checked)}
                            />
                            <span className="text-[10px] text-gray-600">Interpret inputs as Text</span>
                        </label>
                    </div>
                 )}

                 {/* Generic Output Area - for nodes NOT using custom output display logic above */}
                 {!isSimpleRSAPubKeyGen && (
                     <>
                        <span className={`font-semibold mt-2 ${isProcessing ? 'text-yellow-600' : 'text-gray-600'} flex-shrink-0`}>{isProcessing ? 'Processing...' : 'Active'}</span>
                        <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                            <p className={`text-left text-[10px] break-all p-1 bg-gray-100 rounded overflow-auto h-full ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                                {dataOutput ? (dataOutput.length > 200 ? dataOutput.substring(0, 200) + '...' : dataOutput) : (chunk1 ? `Chunk 1: ${chunk1}\nChunk 2: ${chunk2}` : 'Waiting for input...')}
                            </p>
                            <button onClick={(e) => handleCopyToClipboard(e, dataOutput || chunk1)} disabled={!dataOutput && !chunk1} className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm bg-gray-400 hover:bg-gray-500`} title="Copy"><Clipboard className="w-3 h-3" /></button>
                        </div>
                     </>
                 )}
            </div>
        )}
      </div>
    </div>
  );
};

const ToolbarButton = ({ icon: Icon, label, color, onClick, onChange, isFileInput }) => {
    const hoverBorderClass = HOVER_BORDER_TOOLBAR_CLASSES[color] || 'hover:border-gray-400';
    const iconTextColorClass = TEXT_ICON_CLASSES[color] || 'text-gray-600';
    const inputRef = useRef(null);
    const handleClick = () => { if (isFileInput) inputRef.current.click(); else if (onClick) onClick(); };
    return (
        <div className="relative flex-shrink">
            <button onClick={handleClick} className={`w-full p-2 flex items-center justify-center bg-white hover:bg-gray-100 border-2 border-transparent ${hoverBorderClass} transition duration-150 text-gray-700 rounded-lg shadow-sm`} title={label}>
                {Icon && <Icon className={`w-5 h-5 ${iconTextColorClass} flex-shrink-0`} />}
            </button>
            {isFileInput && <input type="file" ref={inputRef} onChange={(e) => { if (e.target.files.length > 0) onChange(e.target); e.target.value = null; }} accept=".json" className="hidden" />}
        </div>
    );
};

const Toolbar = ({ addNode, onDownloadProject, onUploadProject, onZoomIn, onZoomOut }) => {
    const [collapsedGroups, setCollapsedGroups] = useState(() => ORDERED_NODE_GROUPS.reduce((acc, group) => { acc[group.name] = false; return acc; }, {}));
    const toggleGroup = useCallback((groupName) => setCollapsedGroups(prev => ({ ...prev, [groupName]: !prev[groupName] })), []);
    const handleInfoClick = (url) => window.open(url, '_blank');

    return (
        <div className="w-64 bg-gray-50 flex-shrink-0 border-r border-gray-200 shadow-lg flex flex-col h-full">
            <div className="p-4 pt-6 pb-4 border-b border-gray-200 flex flex-col justify-center items-center bg-white">
                <img 
                  src="public/VCL - Horizonal logo + name.png"
                  alt="VisualCryptoLab" 
                  className="w-full h-auto max-w-[180px]"
                  onError={(e) => { e.target.onerror = null; e.target.src = 'https://placehold.co/180x40/999/fff?text=VCL'; }}
                />
            </div>
            <div className="flex flex-col space-y-3 p-3 overflow-y-auto pt-4 flex-grow">
                {ORDERED_NODE_GROUPS.map((group) => (
                    <React.Fragment key={group.name}>
                        <div className="flex justify-between items-center text-xs font-bold uppercase text-gray-500 pt-2 pb-1 border-b border-gray-200 cursor-pointer hover:text-gray-700 transition" onClick={() => toggleGroup(group.name)}>
                            <span className="flex items-center space-x-1">
                                <span>{group.name}</span>
                                {group.name === 'SIMPLE RSA' && <button onClick={(e) => { e.stopPropagation(); handleInfoClick('https://github.com/visualcryptolab/vcryptolab/blob/main/docs/SimpleRSA.md'); }} className="p-0.5 rounded-full text-gray-400 hover:text-blue-500 transition duration-150 focus:outline-none" title="Docs"><Info className="w-3.5 h-3.5" /></button>}
                            </span>
                            <ChevronDown className={`w-4 h-4 transition-transform duration-200 ${collapsedGroups[group.name] ? 'rotate-180' : ''}`} />
                        </div>
                        {!collapsedGroups[group.name] && (
                            <div className="space-y-1">
                                {group.types.map((type) => {
                                    const def = NODE_DEFINITIONS[type];
                                    if (!def) return null;
                                    const hoverBorderClass = HOVER_BORDER_TOOLBAR_CLASSES[def.color] || 'hover:border-gray-400';
                                    const iconTextColorClass = TEXT_ICON_CLASSES[def.color] || 'text-gray-600';
                                    return (
                                        <button key={type} onClick={() => addNode(type, def.label, def.color)} className={`w-full py-3 px-4 flex items-center justify-start space-x-3 bg-white hover:bg-gray-100 border-2 border-transparent ${hoverBorderClass} transition duration-150 text-gray-700 rounded-lg shadow-sm`}>
                                            {def.icon && <def.icon className={`w-5 h-5 ${iconTextColorClass} flex-shrink-0`} />}
                                            <span className="font-medium text-left">{def.label}</span>
                                        </button>
                                    );
                                })}
                            </div>
                        )}
                    </React.Fragment>
                ))}
            </div>
            <div className="flex justify-around space-x-1 p-3 pt-4 border-t border-gray-200 flex-shrink-0 bg-white shadow-inner">
                <ToolbarButton icon={Download} label="Export JSON" color="blue" onClick={onDownloadProject} />
                <ToolbarButton icon={Upload} label="Import JSON" color="orange" onChange={onUploadProject} isFileInput={true} />
                <ToolbarButton icon={ZoomOut} label="Zoom Out" color="teal" onClick={onZoomOut} />
                <ToolbarButton icon={ZoomIn} label="Zoom In" color="teal" onClick={onZoomIn} />
            </div>
        </div>
    );
}

const StatusNotification = ({ status, message, onClose }) => {
    let bgColor;
    let IconComponent;
    switch (status) {
        case 'success': bgColor = 'bg-green-500'; IconComponent = CheckCheck; break;
        case 'warning': bgColor = 'bg-yellow-600'; IconComponent = Info; break;
        case 'error': default: bgColor = 'bg-red-500'; IconComponent = X; break;
    }
    return (
        <div className={`fixed bottom-4 right-4 p-4 rounded-lg shadow-xl text-white max-w-sm z-50 flex items-start space-x-3 transition-opacity duration-300 ${bgColor}`}>
            <IconComponent className="w-5 h-5 flex-shrink-0 mt-0.5" />
            <div className="flex-grow"><p className="font-semibold text-sm">{status.toUpperCase()}</p><p className="text-sm">{message}</p></div>
            <button onClick={onClose} className="p-1 -mr-2 -mt-2 opacity-75 hover:opacity-100 transition"><X className="w-4 h-4" /></button>
        </div>
    );
};

// --- Main Application ---

const App = () => {
  const [nodes, setNodes] = useState(INITIAL_NODES);
  const [connections, setConnections] = useState(INITIAL_CONNECTIONS); 
  const [connectingPort, setConnectingPort] = useState(null); 
  const [scale, setScale] = useState(1.0); 
  const [statusMessage, setStatusMessage] = useState(null); 
  const canvasRef = useRef(null);

  // Inject html2canvas for image export feature
  useEffect(() => {
      const script = document.createElement('script');
      script.src = "https://html2canvas.hertzen.com/dist/html2canvas.min.js";
      script.async = true;
      document.body.appendChild(script);
      return () => { document.body.removeChild(script); };
  }, []);

  const handleZoomIn = useCallback(() => setScale(s => Math.min(2.0, s + 0.1)), []);
  const handleZoomOut = useCallback(() => setScale(s => Math.max(0.5, s - 0.1)), []);
  const clearStatusMessage = useCallback(() => setStatusMessage(null), []);

  const downloadFile = (data, filename, type) => {
    const blob = new Blob([data], { type: type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadProject = useCallback(() => {
    const projectData = { schemaVersion: PROJECT_SCHEMA_VERSION, nodes: nodes, connections: connections };
    downloadFile(JSON.stringify(projectData, null, 2), `visual_crypto_project_v${PROJECT_SCHEMA_VERSION}.json`, 'application/json');
    setStatusMessage({ type: 'success', message: 'Project exported successfully!' });
    setTimeout(clearStatusMessage, 3000);
  }, [nodes, connections, clearStatusMessage]);

  const handleUploadProject = useCallback((fileInput) => {
      clearStatusMessage();
      const file = fileInput.files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (e) => {
          try {
              const projectData = JSON.parse(e.target.result);
              if (!projectData || !Array.isArray(projectData.nodes)) throw new Error("Invalid JSON");
              const { migratedData, wasMigrated } = migrateProjectData(projectData);
              setNodes(migratedData.nodes);
              setConnections(migratedData.connections);
              setStatusMessage({ type: 'success', message: wasMigrated ? 'Project migrated & loaded!' : 'Project loaded successfully!' });
          } catch (error) { setStatusMessage({ type: 'error', message: 'Import failed: Invalid file.' }); }
          setTimeout(clearStatusMessage, 3000);
      };
      reader.readAsText(file);
      fileInput.value = ''; 
  }, [clearStatusMessage]);

  const recalculateGraph = useCallback((currentNodes, currentConnections, changedNodeId = null) => {
    const newNodesMap = new Map(currentNodes.map(n => {
        const newNode = { ...n, isProcessing: false };
        if (newNode.type === 'OUTPUT_VIEWER') {
             newNode.convertedData = newNode.convertedData || ''; 
             newNode.convertedFormat = newNode.convertedFormat || 'Base64';
             newNode.isConversionExpanded = newNode.isConversionExpanded || false;
             newNode.sourceFormat = newNode.sourceFormat || ''; 
             newNode.rawInputData = newNode.rawInputData || ''; 
        }
        return [n.id, newNode];
    })); 
    
    let initialQueue = new Set(currentNodes.filter(n => NODE_DEFINITIONS[n.type]?.inputPorts.length === 0).map(n => n.id));
    if (changedNodeId) initialQueue.add(changedNodeId);
    let nodesToProcess = Array.from(initialQueue);
    const processed = new Set();
    const findAllTargets = (sourceId) => currentConnections.filter(c => c.source === sourceId).map(c => c.target).filter(targetId => !processed.has(targetId));

    while (nodesToProcess.length > 0) {
        const sourceId = nodesToProcess.shift();
        if (processed.has(sourceId) || !newNodesMap.has(sourceId)) continue; 
        const sourceNode = newNodesMap.get(sourceId);
        const sourceNodeDef = NODE_DEFINITIONS[sourceNode.type];
        let outputData = sourceNode.dataOutput || '';
        let isProcessing = false;
        
        if (sourceNodeDef.inputPorts.length === 0) {
            if (sourceNode.type === 'DATA_INPUT') outputData = sourceNode.content || ''; 
            else if (sourceNode.type === 'KEY_GEN') {
                if (sourceNode.generateKey || !sourceNode.keyBase64) {
                    isProcessing = true;
                    generateSymmetricKey(sourceNode.keyAlgorithm || 'AES-GCM').then(({ keyBase64 }) => {
                        setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: keyBase64, keyBase64: keyBase64, isProcessing: false, generateKey: false } : n));
                    });
                    processed.add(sourceId); nodesToProcess.push(...findAllTargets(sourceId)); continue; 
                } else outputData = sourceNode.keyBase64;
            } else if (sourceNode.type === 'SIMPLE_RSA_KEY_GEN' && sourceNode.generateKey) {
                 isProcessing = true;
                 const rawP = sourceNode.p; const rawQ = sourceNode.q; const rawE = sourceNode.e;
                 let p_val, q_val, e_val, d_val, n_val, phiN_val;
                 let error = null;
                 try {
                     const userP = rawP && !isNaN(Number(rawP)) ? BigInt(rawP) : null;
                     const userQ = rawQ && !isNaN(Number(rawQ)) ? BigInt(rawQ) : null;
                     if (userP && userQ) { p_val = userP; q_val = userQ; } else { ({ p: p_val, q: q_val } = generateSmallPrimes()); }
                     n_val = p_val * q_val;
                     phiN_val = (p_val - BigInt(1)) * (q_val - BigInt(1)); 
                     const userE = rawE && !isNaN(Number(rawE)) ? BigInt(rawE) : null;
                     if (userE && userE > BigInt(1) && userE < phiN_val && gcd(userE, phiN_val) === BigInt(1)) e_val = userE;
                     else e_val = generateSmallE(phiN_val);
                     d_val = modInverse(e_val, phiN_val);
                 } catch (err) { error = `ERROR: Calculation failed.`; }
                 if (!error) {
                      sourceNode.dataOutputPublic = `${n_val},${e_val}`; sourceNode.dataOutputPrivate = d_val.toString();
                      sourceNode.n = n_val.toString(); sourceNode.phiN = phiN_val.toString(); sourceNode.d = d_val.toString();
                      sourceNode.p = p_val.toString(); sourceNode.q = q_val.toString(); sourceNode.e = e_val.toString();
                      outputData = sourceNode.dataOutputPrivate; 
                 } else { outputData = error; sourceNode.dStatus = error; }
                 sourceNode.isProcessing = false; sourceNode.generateKey = false; 
                 newNodesMap.set(sourceId, sourceNode); processed.add(sourceId); nodesToProcess.push(...findAllTargets(sourceId)); continue;
            }
        } else {
            const incomingConns = currentConnections.filter(c => c.target === sourceId);
            let inputs = {};
            incomingConns.forEach(conn => {
                const srcNode = newNodesMap.get(conn.source);
                if (!srcNode) return;
                let dataToUse;
                const srcDef = NODE_DEFINITIONS[srcNode.type];
                if (srcDef && srcDef.outputPorts.length > conn.sourcePortIndex) {
                    const keyField = srcDef.outputPorts[conn.sourcePortIndex].keyField;
                    dataToUse = srcNode.type === 'DATA_SPLIT' && (keyField === 'chunk1' || keyField === 'chunk2') ? srcNode[keyField] : srcNode[keyField];
                } else dataToUse = srcNode.dataOutput;
                inputs[conn.targetPortId] = { data: dataToUse, format: srcNode.type === 'DATA_INPUT' ? srcNode.format : (srcNode.outputFormat || getOutputFormat(srcNode.type)) };
            });
            
            switch (sourceNode.type) {
                case 'OUTPUT_VIEWER':
                    const rawInput = inputs['data']?.data; 
                    let converted = '';
                    let srcFormat = inputs['data']?.format || 'N/A';
                    if (rawInput && !rawInput.startsWith('ERROR')) {
                        const isBinary = ['Hexadecimal', 'Binary', 'Decimal', 'Base64'].includes(srcFormat);
                        const isSLNTarget = ['Decimal', 'Hexadecimal', 'Binary'].includes(sourceNode.convertedFormat);
                        if (sourceNode.isConversionExpanded) converted = convertDataFormat(rawInput, srcFormat, sourceNode.convertedFormat || 'Base64', isSLNTarget && isBinary);
                        outputData = (sourceNode.isConversionExpanded && converted && !converted.startsWith('ERROR')) ? converted : rawInput;
                        sourceNode.outputFormat = sourceNode.isConversionExpanded ? sourceNode.convertedFormat : (srcFormat === 'N/A' ? 'Text (UTF-8)' : srcFormat);
                    } else outputData = 'Not connected or no data.';
                    sourceNode.convertedData = converted; sourceNode.sourceFormat = srcFormat; sourceNode.rawInputData = rawInput || outputData;
                    break;
                case 'CAESAR_CIPHER':
                    const plain = inputs['plaintext']?.data;
                    if (plain) {
                        const { output, format } = caesarEncrypt(plain, inputs['plaintext']?.format, parseInt(sourceNode.shiftKey) || 0);
                        outputData = output; sourceNode.outputFormat = format;
                    } else outputData = 'Waiting for plaintext input.';
                    break;
                case 'VIGENERE_CIPHER':
                    const vInput = inputs['data']?.data;
                    if (vInput) {
                        if (inputs['data']?.format !== 'Text (UTF-8)') outputData = "ERROR: Needs Text (UTF-8)";
                        else { const { output, format } = vigenereEncryptDecrypt(vInput, sourceNode.keyword, sourceNode.vigenereMode); outputData = output; sourceNode.outputFormat = format; }
                    } else outputData = 'Waiting for data.';
                    break;
                case 'HASH_FN':
                    if (inputs['data']?.data && !inputs['data'].data.startsWith('ERROR')) { 
                        isProcessing = true; 
                        calculateHash(inputs['data'].data, inputs['data'].format, sourceNode.hashAlgorithm || 'SHA-256').then(res => setNodes(prev => prev.map(n => n.id === sourceId ? { ...n, dataOutput: res, isProcessing: false } : n)));
                        processed.add(sourceId); nodesToProcess.push(...findAllTargets(sourceId)); continue; 
                    } else outputData = 'Waiting for data.';
                    break;
                case 'XOR_OP':
                    const xA = inputs['dataA']?.data; const xB = inputs['dataB']?.data;
                    if (xA && xB && !xA.startsWith('ERROR') && !xB.startsWith('ERROR')) {
                        const res = performBitwiseXor(xA, inputs['dataA'].format, xB, inputs['dataB'].format);
                        outputData = res.output; sourceNode.outputFormat = res.format;
                    } else outputData = 'Waiting for inputs.';
                    break;
                case 'SIMPLE_RSA_ENC':
                    try {
                        const mStr = inputs['message']?.data; const pkStr = inputs['publicKey']?.data;
                        let n, e;
                        const pkSourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'publicKey');
                        const sourceNodeKeyGen = newNodesMap.get(pkSourceConn?.source);
                        if (sourceNodeKeyGen?.n_pub) { n = BigInt(sourceNodeKeyGen.n_pub); e = BigInt(sourceNodeKeyGen.e_pub); }
                        else if (pkStr) { const [nStr, eStr] = pkStr.split(','); n = BigInt(nStr); e = BigInt(eStr); }
                        if (mStr && n) {
                             const m = BigInt(mStr.replace(/\s+/g, ''));
                             outputData = (m >= n) ? "ERROR: m >= n" : modPow(m, e, n).toString();
                        } else outputData = 'Waiting for input.';
                    } catch(err) { outputData = "ERROR"; }
                    break;
                case 'SIMPLE_RSA_DEC':
                    try {
                        const cStr = inputs['cipher']?.data; const dStr = inputs['privateKey']?.data;
                        const privConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'privateKey');
                        const privSource = newNodesMap.get(privConn?.source);
                        if (cStr && dStr && privSource?.n) {
                            outputData = modPow(BigInt(cStr), BigInt(dStr), BigInt(privSource.n)).toString();
                        } else outputData = 'Waiting for input.';
                    } catch(err) { outputData = "ERROR"; }
                    break;
                case 'SHIFT_OP':
                    if (inputs['data']?.data && !inputs['data'].data.startsWith('ERROR')) {
                        const res = performBitShiftOperation(inputs['data'].data, sourceNode.shiftType, sourceNode.shiftAmount, inputs['data'].format);
                        outputData = res.output; sourceNode.shiftDescription = res.description; sourceNode.outputFormat = inputs['data'].format;
                    } else outputData = 'Waiting for input.';
                    break;
                case 'DATA_SPLIT':
                    if (inputs['data']?.data && !inputs['data'].data.startsWith('ERROR')) {
                        const splitRes = splitDataIntoChunks(inputs['data'].data, inputs['data'].format);
                        sourceNode.chunk1 = splitRes.chunk1; sourceNode.chunk2 = splitRes.chunk2; sourceNode.outputFormat = splitRes.outputFormat;
                    } else { sourceNode.chunk1 = 'Waiting...'; sourceNode.chunk2 = 'Waiting...'; }
                    outputData = '';
                    break;
                case 'DATA_CONCAT':
                    const inputsA = inputs['dataA'];
                    const inputsB = inputs['dataB'];
                    if (inputsA && inputsB) {
                        const concatRes = concatenateData(inputsA.data, inputsA.format, inputsB.data, inputsB.format, sourceNode.interpretAsText);
                        outputData = concatRes.output;
                        sourceNode.outputFormat = concatRes.format;
                    } else {
                        outputData = 'Waiting for inputs.';
                    }
                    break;
                case 'SIMPLE_RSA_PUBKEY_GEN':
                    const kSourceConn = incomingConns.find(c => c.targetPortId === 'keySource');
                    const kSource = newNodesMap.get(kSourceConn?.source);
                    if (kSource?.n) { sourceNode.n_pub = kSource.n; sourceNode.e_pub = kSource.e; sourceNode.isReadOnly = true; }
                    sourceNode.dataOutputPublic = (sourceNode.n_pub && sourceNode.e_pub) ? `${sourceNode.n_pub},${sourceNode.e_pub}` : 'N/A';
                    outputData = sourceNode.dataOutputPublic;
                    break;
                case 'SIMPLE_RSA_SIGN':
                    try {
                        const mS = inputs['message']?.data; const dS = inputs['privateKey']?.data;
                        const pC = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'privateKey');
                        const pS = newNodesMap.get(pC?.source);
                        if (mS && dS && pS?.n) outputData = modPow(BigInt(mS.replace(/\s+/g, '')), BigInt(dS), BigInt(pS.n)).toString();
                        else outputData = 'Waiting...';
                    } catch(err) { outputData = "ERROR"; }
                    break;
                case 'SIMPLE_RSA_VERIFY':
                    try {
                        const mV = inputs['message']?.data; const sV = inputs['signature']?.data;
                        const pkC = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'publicKey');
                        const pkS = newNodesMap.get(pkC?.source);
                        let nV, eV;
                        if (pkS?.n_pub) { nV = BigInt(pkS.n_pub); eV = BigInt(pkS.e_pub); }
                        if (mV && sV && nV) {
                            const dec = modPow(BigInt(sV.replace(/\s+/g, '')), eV, nV);
                            outputData = (dec === BigInt(mV.replace(/\s+/g, ''))) ? "SUCCESS: Signature Valid" : "FAILURE: Signature Invalid";
                        } else outputData = 'Waiting...';
                    } catch (err) { outputData = "ERROR"; }
                    break;
                case 'SYM_ENC':
                    if (inputs['data']?.data && inputs['key']?.data && !inputs['data'].data.startsWith('ERROR')) {
                        isProcessing = true;
                        symmetricEncrypt(inputs['data'].data, inputs['key'].data, sourceNode.symAlgorithm || 'AES-GCM').then(res => setNodes(prev => prev.map(n => n.id === sourceId ? { ...n, dataOutput: res, isProcessing: false } : n)));
                        processed.add(sourceId); nodesToProcess.push(...findAllTargets(sourceId)); continue;
                    } else outputData = 'Waiting...';
                    break;
                case 'SYM_DEC':
                    if (inputs['cipher']?.data && inputs['key']?.data && !inputs['cipher'].data.startsWith('ERROR')) {
                        isProcessing = true;
                        symmetricDecrypt(inputs['cipher'].data, inputs['key'].data, sourceNode.symAlgorithm || 'AES-GCM').then(res => setNodes(prev => prev.map(n => n.id === sourceId ? { ...n, dataOutput: res, isProcessing: false } : n)));
                        processed.add(sourceId); nodesToProcess.push(...findAllTargets(sourceId)); continue;
                    } else outputData = 'Waiting...';
                    break;
            }
        }
        if (sourceNode.type === 'DATA_SPLIT') {} 
        else {
             const primOut = sourceNodeDef.outputPorts?.[0];
             if (primOut && primOut.keyField === 'dataOutput') sourceNode.dataOutput = outputData;
             else if (!primOut && sourceNode.type !== 'OUTPUT_VIEWER') sourceNode.dataOutput = outputData;
        }
        sourceNode.isProcessing = isProcessing;
        newNodesMap.set(sourceId, sourceNode);
        processed.add(sourceId);
        nodesToProcess.push(...findAllTargets(sourceId));
    }
    return Array.from(newNodesMap.values());
  }, [setNodes]);

  useEffect(() => { setNodes(prevNodes => recalculateGraph(prevNodes, connections)); }, [connections, recalculateGraph]); 

  const updateNodeContent = useCallback((id, field, value) => {
    setNodes(prevNodes => {
        const nextNodes = prevNodes.map(node => node.id === id ? { ...node, [field]: value } : node);
        return recalculateGraph(nextNodes, connections, id);
    });
  }, [connections, recalculateGraph]);

  const setPosition = useCallback((id, newPos) => setNodes(prev => prev.map(n => n.id === id ? { ...n, position: newPos } : n)), []);
  const handleNodeResize = useCallback((id, w, h) => setNodes(prev => prev.map(n => n.id === id ? { ...n, width: Math.max(250, w), height: Math.max(250, h) } : n)), []);
  const addNode = useCallback((type, label, color) => {
    const newId = `${type}_${Date.now()}`;
    const def = NODE_DEFINITIONS[type];
    const initialContent = { dataOutput: '', isProcessing: false, outputFormat: getOutputFormat(type), width: (['SHIFT_OP','XOR_OP','DATA_SPLIT','DATA_CONCAT'].includes(type) ? 300 : 300), height: (['SHIFT_OP','XOR_OP','DATA_SPLIT','DATA_CONCAT'].includes(type) ? 300 : 280) };
    const cv = canvasRef.current;
    let x = ((cv?.clientWidth || 800) / 2) - 150 + (Math.random() * 200 - 100);
    let y = ((cv?.clientHeight || 600) / 2) - 140 + (Math.random() * 200 - 100);
    if (type === 'DATA_INPUT') { initialContent.content = ''; initialContent.format = 'Binary'; }
    else if (type === 'OUTPUT_VIEWER') { initialContent.isConversionExpanded = false; initialContent.convertedFormat = 'Base64'; }
    else if (type === 'CAESAR_CIPHER') initialContent.shiftKey = 3;
    else if (type === 'VIGENERE_CIPHER') { initialContent.keyword = 'HELLO'; initialContent.vigenereMode = 'ENCRYPT'; }
    else if (type === 'SIMPLE_RSA_KEY_GEN') { initialContent.generateKey = true; initialContent.modulusLength = 0; }
    else if (type === 'SHIFT_OP') { initialContent.shiftType = 'Left'; initialContent.shiftAmount = 1; }
    setNodes(prev => [...prev, { id: newId, label: def.label, position: { x: Math.max(20, x), y: Math.max(20, y) }, type, color, ...initialContent }]);
  }, []);

  const handleDeleteNode = useCallback((id) => {
      setNodes(prev => prev.filter(n => n.id !== id));
      setConnections(prev => prev.filter(c => c.source !== id && c.target !== id));
  }, []);

  const handleConnectStart = useCallback((nodeId, portIndex, outputType) => setConnectingPort({ sourceId: nodeId, sourcePortIndex: portIndex, outputType }), []);
  const handleConnectEnd = useCallback((targetId, targetPortId) => {
    if (connectingPort && targetId && connectingPort.sourceId !== targetId) {
      const { sourceId, sourcePortIndex } = connectingPort;
      const targetNode = nodes.find(n => n.id === targetId);
      const targetNodeDef = NODE_DEFINITIONS[targetNode?.type];
      if (targetNodeDef && targetNodeDef.inputPorts.some(p => p.id === targetPortId)) {
           setConnections(prev => [...prev, { source: sourceId, sourcePortIndex, target: targetId, targetPortId }]);
      }
    }
    setConnectingPort(null); 
  }, [connectingPort, nodes]);

  const handleRemoveConnection = useCallback((s, t, sIdx, tId) => setConnections(prev => prev.filter(c => !(c.source === s && c.target === t && c.sourcePortIndex === sIdx && c.targetPortId === tId))), []);
  
  const connectionPaths = useMemo(() => {
    let maxX = 0; let maxY = 0; const padding = 50;
    nodes.forEach(node => { maxX = Math.max(maxX, node.position.x + node.width); maxY = Math.max(maxY, node.position.y + node.height); });
    const svgWidth = Math.max(maxX + padding, (canvasRef.current?.clientWidth || 0) / scale);
    const svgHeight = Math.max(maxY + padding, (canvasRef.current?.clientHeight || 0) / scale);
    return {
        size: { width: svgWidth, height: svgHeight },
        paths: connections.map(conn => {
            const sN = nodes.find(n => n.id === conn.source);
            const tN = nodes.find(n => n.id === conn.target);
            return (sN && tN) ? { path: getLinePath(sN, tN, conn), source: conn.source, target: conn.target, sourcePortIndex: conn.sourcePortIndex, targetPortId: conn.targetPortId } : null;
        }).filter(Boolean)
    };
  }, [connections, nodes, scale]);

  const handleCanvasClick = useCallback(() => { if (connectingPort) handleConnectEnd(null); }, [connectingPort, handleConnectEnd]);

  return (
    <div className="h-screen w-screen flex bg-gray-100 font-inter overflow-hidden">
      <style dangerouslySetInnerHTML={{ __html: globalStyles }} />
      <Toolbar addNode={addNode} onDownloadProject={handleDownloadProject} onUploadProject={handleUploadProject} onZoomIn={handleZoomIn} onZoomOut={handleZoomOut} />
      <div className="flex-grow flex flex-col p-4">
        <div ref={canvasRef} className="canvas-container relative w-full flex-grow border-4 border-dashed border-gray-300 rounded-2xl bg-white shadow-inner overflow-auto" onClick={handleCanvasClick}>
          <div style={{ transform: `scale(${scale})`, transformOrigin: 'top left', width: `${connectionPaths.size.width}px`, height: `${connectionPaths.size.height}px`, minWidth: `100%`, minHeight: `100%` }} className="absolute top-0 left-0">
              <svg className="absolute top-0 left-0 pointer-events-auto z-0" style={{ width: `${connectionPaths.size.width}px`, height: `${connectionPaths.size.height}px` }}>
                {connectionPaths.paths.map((conn) => (
                  <g key={`${conn.source}-${conn.target}-${conn.sourcePortIndex}-${conn.targetPortId}`} onClick={(e) => { e.stopPropagation(); handleRemoveConnection(conn.source, conn.target, conn.sourcePortIndex, conn.targetPortId); }} className="cursor-pointer">
                    <path d={conn.path} className="connection-hitbox" style={{ strokeWidth: `${15 / scale}px` }} />
                    <path d={conn.path} className="connection-line-visible" style={{ strokeWidth: `${4 / scale}px` }} />
                  </g>
                ))}
              </svg>
              {nodes.map(node => (
                <DraggableBox key={node.id} node={node} setPosition={setPosition} updateNodeContent={updateNodeContent} canvasRef={canvasRef} handleConnectStart={handleConnectStart} handleConnectEnd={handleConnectEnd} connectingPort={connectingPort} connections={connections} handleDeleteNode={handleDeleteNode} nodes={nodes} scale={scale} handleResize={handleNodeResize} />
              ))}
          </div>
        </div>
        {statusMessage && <StatusNotification status={statusMessage.type} message={statusMessage.message} onClose={clearStatusMessage} />}
      </div>
    </div>
  );
};

export default App;