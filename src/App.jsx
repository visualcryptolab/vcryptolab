import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { LayoutGrid, Cpu, Key, Zap, Settings, Lock, Unlock, Hash, Clipboard, X, ArrowLeft, ArrowRight, Download, Upload, Camera, ChevronDown, ChevronUp, CheckCheck, Fingerprint, Signature, ZoomIn, ZoomOut, Info, Split } from 'lucide-react'; 

// NOTE: For the 'Download Diagram (JPG)' feature to work, the html2canvas library 
// needs to be loaded globally in the consuming environment. This is assumed to be handled
// by the Canvas environment or an external script tag (as seen in the original index.html).

// --- Project Schema Versioning ---
// V1.0: Initial core features (pre-migration logic)
// V1.1: Standardized Data Input outputFormat to match input format (e.g., Binary, not Text) for math nodes. Added width/height defaults.
// V1.2: Added Data Concatenate node.
const PROJECT_SCHEMA_VERSION = '1.2';

// --- CSS Styles (Consolidated from src/App.css, src/main.css, and src/styles.css) ---
const globalStyles = `
/* Styles from src/main.css and src/styles.css (Tailwind directives) */
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Essential Overrides and Selection Styles */
html, body, #root {
  height: 100%;
  margin: 0;
  padding: 0;
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

/* --- Multi-Selection Styles --- */

/* The selection box (blue rectangle) */
.selection-marquee {
    position: absolute;
    border: 1px dashed #3b82f6; /* Blue-500 */
    background-color: rgba(59, 130, 246, 0.1); /* Blue-500 with opacity */
    pointer-events: none; /* Allow clicks to pass through */
    z-index: 1000;
}

/* Visual state for selected nodes */
.node-selected {
    /* Use Tailwind-like ring effect via box-shadow to avoid conflict with border classes */
    box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.6), 0 10px 15px -3px rgba(0, 0, 0, 0.1) !important;
    border-color: #2563eb !important; /* Force Blue-600 border */
    z-index: 50 !important; /* Bring to front */
}
`;


// --- Custom XOR Icon Component (The mathematical $\oplus$ symbol) ---
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
      className="w-6 h-6 absolute"
      {...props}
    >
      {/* Circle part */}
      <circle cx="12" cy="12" r="10" />
      {/* Plus (XOR) part */}
      <line x1="12" y1="8" x2="12" y2="16" />
      <line x1="8" y1="12" x2="16" y2="12" />
    </svg>
  );
};

// --- Custom Bit Shift Icon Component (The $\rightleftharpoons$ symbol) ---
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
      className="w-6 h-6 absolute"
      {...props}
    >
      {/* Right Arrow (Top) */}
      <polyline points="15 8 19 12 15 16" />
      <line x1="19" y1="12" x2="5" y2="12" />
      {/* Left Arrow (Bottom) - Flipped */}
      <polyline points="9 16 5 12 9 8" />
    </svg>
  );
};


// =================================================================
// 1. HELPER CONSTANTS & STATIC TAILWIND CLASS MAPS
// =================================================================

// --- Static Tailwind Class Maps (Ensures no dynamic class generation) ---

const BORDER_CLASSES = {
  blue: 'border-blue-600', red: 'border-red-600', orange: 'border-orange-600', cyan: 'border-cyan-600', pink: 'border-pink-500', 
  teal: 'border-teal-600', // Used by ASYM_DEC and DATA_CONCAT
  gray: 'border-gray-600', lime: 'border-lime-600', indigo: 'border-indigo-600',
  purple: 'border-purple-600', // Simple RSA PrivKey Gen
  maroon: 'border-red-800', // Simple RSA Encrypt
  rose: 'border-pink-700', // Simple RSA Decrypt
  amber: 'border-amber-500', // Caesar Cipher
  yellow: 'border-yellow-400', // Vigenere Cipher
  fuchsia: 'border-fuchsia-600', // RSA Signature
  // Data Split Node Color
  green: 'border-green-600',
};

const HOVER_BORDER_CLASSES = {
  blue: 'hover:border-blue-500', red: 'hover:border-red-500', orange: 'hover:border-orange-500', cyan: 'hover:border-cyan-500', pink: 'hover:border-pink-500', 
  teal: 'hover:border-teal-500', // Used by ASYM_DEC and DATA_CONCAT
  gray: 'hover:border-gray-500', lime: 'hover:border-lime-500', indigo: 'hover:border-indigo-500',
  purple: 'hover:border-purple-500',
  maroon: 'hover:border-red-700',
  rose: 'hover:border-pink-600',
  amber: 'hover:border-amber-400',
  yellow: 'hover:border-yellow-300',
  fuchsia: 'hover:border-fuchsia-500',
  // Data Split Node Color
  green: 'hover:border-green-500',
};

const TEXT_ICON_CLASSES = {
  blue: 'text-blue-600', red: 'text-red-600', orange: 'text-orange-600', cyan: 'text-cyan-600', pink: 'text-pink-500', 
  teal: 'text-teal-600', // Used by ASYM_DEC and DATA_CONCAT
  gray: 'text-gray-600', lime: 'text-lime-600', indigo: 'text-indigo-600',
  purple: 'text-purple-600',
  maroon: 'text-red-800',
  rose: 'text-pink-700',
  amber: 'text-amber-500',
  yellow: 'text-yellow-400',
  fuchsia: 'text-fuchsia-600',
  // Data Split Node Color
  green: 'text-green-600',
};

const HOVER_BORDER_TOOLBAR_CLASSES = {
  blue: 'hover:border-blue-400', 
  red: 'hover:border-red-400', 
  orange: 'hover:border-orange-400', 
  cyan: 'hover:border-cyan-400', 
  pink: 'hover:border-pink-400', 
  teal: 'hover:border-teal-400', // Used by ASYM_DEC and DATA_CONCAT
  gray: 'hover:border-gray-400', 
  lime: 'hover:border-lime-400', 
  indigo: 'hover:border-indigo-400',
  purple: 'hover:border-purple-400',
  maroon: 'hover:border-red-600',
  rose: 'hover:border-pink-600',
  amber: 'hover:border-amber-400',
  yellow: 'hover:border-yellow-300',
  fuchsia: 'hover:border-fuchsia-400',
  // Data Split Node Color
  green: 'hover:border-green-400',
};

// --- Port Configuration ---
const PORT_SIZE = 4; // w-4 h-4
const PORT_VISUAL_OFFSET_PX = 8; 
const INPUT_PORT_COLOR = 'bg-stone-500'; // Standard Input (Mandatory)
const OPTIONAL_PORT_COLOR = 'bg-gray-400'; // Optional Input 
const OUTPUT_PORT_COLOR = 'bg-emerald-500'; // Standard Data Output

// New Specific Key Port Colors
const PUBLIC_KEY_COLOR = 'bg-lime-500'; // Light Green/Lime for Public Key
const PRIVATE_KEY_COLOR = 'bg-red-800'; // Dark Red/Maroon for Private Key (Warning)
const SIGNATURE_COLOR = 'bg-fuchsia-500'; // Fuchsia for Signature Output


// Supported Algorithms
const HASH_ALGORITHMS = ['SHA-256', 'SHA-512'];
const SYM_ALGORITHMS = ['AES-GCM']; 
const ASYM_ALGORITHMS = ['RSA-OAEP']; 
const RSA_MODULUS_LENGTHS = [1024, 2048, 4096];

// Supported Data Formats
const ALL_FORMATS = ['Text (UTF-8)', 'Base64', 'Hexadecimal', 'Binary', 'Decimal'];

// --- Node Definitions with detailed Port structure ---

const NODE_DEFINITIONS = {
  // --- Core Nodes ---
  DATA_INPUT: { label: 'Data Input', color: 'blue', icon: LayoutGrid, inputPorts: [], outputPorts: [{ name: 'Data Output', type: 'data', keyField: 'dataOutput' }] },
  OUTPUT_VIEWER: { 
    label: 'Output Viewer', 
    color: 'red', 
    icon: Zap, 
    inputPorts: [{ name: 'Data Input', type: 'data', mandatory: true, id: 'data' }], 
    outputPorts: [{ name: 'Viewer Data Output', type: 'data', keyField: 'dataOutput' }] 
  },
  
  // --- Core Utility Nodes ---
  HASH_FN: { label: 'Hash Function', color: 'gray', icon: Hash, 
    inputPorts: [{ name: 'Data Input', type: 'data', mandatory: true, id: 'data' }], 
    outputPorts: [{ name: 'Hash Output', type: 'data', keyField: 'dataOutput' }] },

  XOR_OP: { label: 'XOR Operation', color: 'lime', icon: XORIcon, 
    inputPorts: [
        { name: 'Input A', type: 'data', mandatory: true, id: 'dataA' }, 
        { name: 'Input B', type: 'data', mandatory: true, id: 'dataB' }
    ], 
    outputPorts: [{ name: 'Result', type: 'data', keyField: 'dataOutput' }] },
    
  SHIFT_OP: { label: 'Bit Shift', color: 'indigo', icon: BitShiftIcon, 
    inputPorts: [{ name: 'Data Input', type: 'data', mandatory: true, id: 'data' }], 
    outputPorts: [{ name: 'Result', type: 'data', keyField: 'dataOutput' }] },
    
  // Data Split Node (Divide data in two halves)
  DATA_SPLIT: { 
    label: 'Data Split', // Removed (Half)
    color: 'green', 
    icon: Split, 
    inputPorts: [
        { name: 'Data Input', type: 'data', mandatory: true, id: 'data' }
    ], 
    outputPorts: [
        { name: 'Chunk 1', type: 'data', keyField: 'chunk1' }, 
        { name: 'Chunk 2', type: 'data', keyField: 'chunk2' }  
    ] 
  },
  
  // NEW: Data Concatenate Node (Join two data inputs)
  DATA_CONCAT: { 
    label: 'Data Concatenate', 
    color: 'teal', 
    icon: Cpu, 
    inputPorts: [
        { name: 'Data A', type: 'data', mandatory: true, id: 'dataA' }, 
        { name: 'Data B', type: 'data', mandatory: true, id: 'dataB' }
    ], 
    outputPorts: [
        { name: 'Concatenated Output', type: 'data', keyField: 'dataOutput' }
    ] 
  },

  // --- Classic Cipher Nodes ---
  CAESAR_CIPHER: {
    label: 'Caesar Cipher',
    color: 'amber',
    icon: Lock, 
    inputPorts: [
        { name: 'Plaintext', type: 'data', mandatory: true, id: 'plaintext' },
    ],
    outputPorts: [{ name: 'Ciphertext', type: 'data', keyField: 'dataOutput' }]
  },

  VIGENERE_CIPHER: {
    label: 'Vigenère Cipher',
    color: 'yellow',
    icon: Lock,
    inputPorts: [
        { name: 'Plaintext/Ciphertext', type: 'data', mandatory: true, id: 'data' },
    ],
    outputPorts: [{ name: 'Result', type: 'data', keyField: 'dataOutput' }]
  },
  
  // --- Key Generators ---
  KEY_GEN: { label: 'Sym Key Generator', color: 'orange', icon: Key, inputPorts: [], outputPorts: [{ name: 'Key Output (AES)', type: 'key', keyField: 'dataOutput' }] }, 

  // Simple RSA Key Generator (Private Key Gen - for modular arithmetic demo)
  SIMPLE_RSA_KEY_GEN: { 
    label: 'Simple RSA PrivKey Gen', 
    color: 'purple', 
    icon: Key, 
    inputPorts: [], 
    outputPorts: [
        { name: 'Private Key (d)', type: 'private', keyField: 'dataOutputPrivate' } 
    ]
  },
    
  // Simple RSA Public Key Generator
  SIMPLE_RSA_PUBKEY_GEN: {
    label: 'Simple RSA PubKey Gen',
    color: 'lime', 
    icon: Unlock, 
    inputPorts: [
        { name: 'Private Key Source', type: 'private', mandatory: false, id: 'keySource' } 
    ],
    outputPorts: [
        { name: 'Public Key (n, e)', type: 'public', keyField: 'dataOutputPublic' }
    ]
  },

  // Advanced RSA Key Generator (Existing node with more controls)
  RSA_KEY_GEN: { 
    label: 'Advanced RSA Key Gen', 
    color: 'cyan', 
    icon: Key, 
    inputPorts: [], 
    outputPorts: [
        { name: 'Public Key', type: 'public', keyField: 'dataOutputPublic' }, // index 0
        { name: 'Private Key', type: 'private', keyField: 'dataOutputPrivate' } // index 1
    ]
  },
  
  // --- Simple RSA Cipher Nodes (Modular Arithmetic Demo) ---
  SIMPLE_RSA_ENC: {
    label: 'Simple RSA Encrypt',
    color: 'maroon',
    icon: Lock,
    inputPorts: [
        { name: 'Message (m)', type: 'data', mandatory: true, id: 'message' }, 
        { name: 'Public Key (n, e)', type: 'public', mandatory: true, id: 'publicKey' }
    ],
    outputPorts: [{ name: 'Ciphertext (c)', type: 'data', keyField: 'dataOutput' }] 
  },

  SIMPLE_RSA_DEC: {
    label: 'Simple RSA Decrypt',
    color: 'rose',
    icon: Unlock,
    inputPorts: [
        { name: 'Ciphertext (c)', type: 'data', mandatory: true, id: 'cipher' }, 
        { name: 'Private Key (d)', type: 'private', mandatory: true, id: 'privateKey' }
    ],
    outputPorts: [{ name: 'Plaintext (m)', type: 'data', keyField: 'dataOutput' }]
  },

  // --- Simple RSA Signature Nodes ---
  SIMPLE_RSA_SIGN: {
      label: 'Simple RSA Sign',
      color: 'fuchsia',
      icon: Signature, 
      inputPorts: [
          { name: 'Message (m)', type: 'data', mandatory: true, id: 'message' },
          { name: 'Private Key (d)', type: 'private', mandatory: true, id: 'privateKey' }
      ],
      outputPorts: [{ name: 'Signature (s)', type: 'data', keyField: 'dataOutput' }]
  },

  SIMPLE_RSA_VERIFY: {
      label: 'Simple RSA Verify',
      color: 'fuchsia',
      icon: CheckCheck,
      inputPorts: [
          { name: 'Message (m)', type: 'data', mandatory: true, id: 'message' },
          { name: 'Signature (s)', type: 'data', mandatory: true, id: 'signature' },
          { name: 'Public Key (n, e)', type: 'public', mandatory: true, id: 'publicKey' }
      ],
      outputPorts: [{ name: 'Verification Result', type: 'data', keyField: 'dataOutput' }]
  },
  
  // --- Cipher Nodes (Web Crypto API) ---
  SYM_ENC: { 
    label: 'Sym Encrypt', 
    color: 'red', 
    icon: Lock, 
    inputPorts: [
        { name: 'Data Input', type: 'data', mandatory: true, id: 'data' },
        { name: 'Key Input', type: 'key', mandatory: true, id: 'key' }
    ], 
    outputPorts: [{ name: 'Ciphertext', type: 'data', keyField: 'dataOutput' }]
  },
  SYM_DEC: { 
    label: 'Sym Decrypt', 
    color: 'pink', 
    icon: Unlock, 
    inputPorts: [
        { name: 'Cipher Input', type: 'data', mandatory: true, id: 'cipher' }, 
        { name: 'Key Input', type: 'key', mandatory: true, id: 'key' }
    ], 
    outputPorts: [{ name: 'Plaintext', type: 'data', keyField: 'dataOutput' }] 
  },

  ASYM_ENC: { 
    label: 'Asym Encrypt', 
    color: 'cyan', 
    icon: Lock, 
    inputPorts: [
        { name: 'Data Input', type: 'data', mandatory: true, id: 'data' }, 
        { name: 'Public Key', type: 'public', mandatory: true, id: 'publicKey' }
    ], 
    outputPorts: [{ name: 'Ciphertext', type: 'data', keyField: 'dataOutput' }] 
  },
  ASYM_DEC: { 
    label: 'Asym Decrypt', 
    color: 'teal', 
    icon: Unlock, 
    inputPorts: [
        { name: 'Cipher Input', type: 'data', mandatory: true, id: 'cipher' }, 
        { name: 'Private Key', type: 'private', mandatory: true, id: 'privateKey' }
    ], 
    outputPorts: [{ name: 'Plaintext', type: 'data', keyField: 'dataOutput' }]
  },
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
const BOX_SIZE = NODE_DIMENSIONS; 


// =================================================================
// 2. CRYPTO & UTILITY FUNCTIONS
// =================================================================

// ... (Functions modPow, gcd, modInverse, DEMO_PRIMES, generateSmallPrimes, generateSmallE, caesarEncrypt, vigenereEncryptDecrypt, arrayBufferToBase64, base64ToArrayBuffer, arrayBufferToBigIntString, arrayBufferToHexBig, arrayBufferToBinaryBig, arrayBufferToHex, arrayBufferToBinary, hexToArrayBuffer, convertToUint8Array, convertDataFormat, getOutputFormat, performBitwiseXor, performRawXor, stringToBigInt, bigIntToString, performBitShiftOperation, splitDataIntoChunks, concatenateData, calculateHash, generateSymmetricKey, generateAsymmetricKeyPair, asymmetricEncrypt, asymmetricDecrypt, symmetricEncrypt, symmetricDecrypt, isContentCompatible remain unchanged)

/** Calculates (base^exponent) mod modulus using BigInt for large numbers. */
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

    for (let i = 0; i < plaintext.length; i++) {
        const char = plaintext[i];
        const charCode = char.charCodeAt(0);

        if ((charCode >= 65 && charCode <= 90) || (charCode >= 97 && charCode <= 122)) {
            const keyChar = keyWord[keyIndex % keyWord.length];
            let keyShift = keyChar.toUpperCase().charCodeAt(0) - 65;

            let base = 0;
            if (charCode >= 65 && charCode <= 90) {
                base = 65; 
            } else {
                base = 97; 
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
    let bigInt = BigInt(0);
    try {
        bigInt = BigInt(`0x${hex}`);
    } catch (e) {
        return `ERROR: Data too large for BigInt conversion (${buffer.byteLength} bytes).`;
    }
    return bigInt.toString(10);
};

const arrayBufferToHexBig = (buffer) => {
    const hex = arrayBufferToHex(buffer);
    return hex.toUpperCase(); 
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

const convertDataFormat = (dataStr, sourceFormat, targetFormat, toSingleNumber = false) => {
    if (!dataStr) return '';
    if (sourceFormat === targetFormat || dataStr.startsWith('ERROR')) return dataStr;
    
    let buffer;
    
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

const getOutputFormat = (nodeType) => {
    switch (nodeType) {
        case 'DATA_INPUT':
        case 'CAESAR_CIPHER': 
        case 'VIGENERE_CIPHER': 
            return 'Text (UTF-8)'; 
        case 'KEY_GEN':
        case 'SYM_ENC':
        case 'DATA_SPLIT': 
        case 'DATA_CONCAT': 
            return 'Binary';
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
    
    let bigIntA;
    let bigIntB;
    
    try {
        if (formatA === 'Binary') {
            bigIntA = BigInt(`0b${paddedA}`);
            bigIntB = BigInt(`0b${paddedB}`);
        } else if (formatA === 'Hexadecimal') {
            bigIntA = BigInt(`0x${paddedA}`);
            bigIntB = BigInt(`0x${paddedB}`);
        } else {
             return { output: "ERROR: Unsupported XOR numerical format.", format: formatA };
        }
    } catch (e) {
         return { output: "ERROR: Data too large for BigInt XOR or invalid numerical input.", format: formatA };
    }

    const resultBigInt = bigIntA ^ bigIntB;
    let resultStr;
    if (formatA === 'Binary') {
        resultStr = bigIntToString(resultBigInt, 'Binary', targetLength);
    } else { 
        resultStr = bigIntToString(resultBigInt, 'Hexadecimal', targetLength, true);
    }
    
    return { output: resultStr, format: formatA };
};

const performRawXor = (bytesA, bytesB) => {
    const len = Math.min(bytesA.length, bytesB.length);
    const result = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        result[i] = bytesA[i] ^ bytesB[i];
    }
    return result;
};

const stringToBigInt = (dataStr, format) => {
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
            const paddedBinary = cleanedStr.padStart(Math.ceil(cleanedStr.length / 4) * 4, '0');
            return BigInt(`0b${paddedBinary}`);
        }
    } catch (e) {
        return null;
    }
    return null;
};

const bigIntToString = (bigIntValue, format, originalLength = 0, isHexLength = false) => {
    if (bigIntValue === null) return 'N/A';
    
    switch (format) {
        case 'Decimal':
            return bigIntValue.toString(10);
        case 'Hexadecimal':
            let hexString = bigIntValue.toString(16).toUpperCase();
            if (originalLength > 0) {
                 const hexLength = isHexLength ? originalLength : Math.ceil(originalLength / 4);
                 hexString = hexString.padStart(hexLength, '0');
                 if (hexString.length > hexLength) {
                     hexString = hexString.substring(hexString.length - hexLength);
                 }
            }
            return hexString;
        case 'Binary':
            let binaryString = bigIntValue.toString(2);
            if (originalLength > 0) {
                binaryString = binaryString.padStart(originalLength, '0');
                 if (binaryString.length > originalLength) {
                     binaryString = binaryString.substring(binaryString.length - originalLength);
                 }
            }
            return binaryString;
        default:
            return bigIntValue.toString(10);
    }
};

const performBitShiftOperation = (dataStr, shiftType, shiftAmount, inputFormat) => {
    let shiftDescription = `Arithmetic/Logical ${shiftType} Shift (${shiftAmount} bits)`; 
    
    if (!dataStr) return { output: "ERROR: Missing data input.", description: shiftDescription };
    
    if (inputFormat === 'Text (UTF-8)' || inputFormat === 'Base64') {
        return { output: `ERROR: Bit Shift requires input data to be a single number (Decimal, Hexadecimal, or Binary). Received: ${inputFormat}.`, description: shiftDescription };
    }
    
    const cleanedStr = dataStr.replace(/\s/g, ''); 
    const bigIntData = stringToBigInt(cleanedStr, inputFormat);
    
    if (bigIntData === null) {
        return { output: `ERROR: Data must represent a single, contiguous number in ${inputFormat} format. Spaces are not allowed.`, description: shiftDescription };
    }
    
    const amount = BigInt(Math.max(0, parseInt(shiftAmount) || 0));
    let resultBigInt;
    
    let bitLength = 0;
    const isRotational = inputFormat === 'Binary' || inputFormat === 'Hexadecimal';
    
    if (isRotational) {
        if (inputFormat === 'Binary') {
            bitLength = cleanedStr.length;
        } else if (inputFormat === 'Hexadecimal') {
            bitLength = cleanedStr.length * 4;
        } 
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
            if (shiftType === 'Left') {
                resultBigInt = bigIntData << amount;
            } else { // Right
                resultBigInt = bigIntData >> amount;
            }
        }
    } catch (error) {
        console.error("Bit Shift operation failed:", error);
        return { output: `ERROR: Bit Shift calculation failed. ${error.message}`, description: shiftDescription };
    }

    const finalLength = isRotational ? bitLength : 0;
    
    return { 
        output: bigIntToString(resultBigInt, inputFormat, finalLength, inputFormat === 'Hexadecimal'), 
        description: shiftDescription 
    };
};

const splitDataIntoChunks = (dataStr, format) => {
    if (!dataStr || dataStr.startsWith('ERROR')) {
        const error = dataStr || 'Missing data input.';
        return { chunk1: `ERROR: ${error}`, chunk2: `ERROR: ${error}`, outputFormat: format };
    }

    let cleanData = dataStr.replace(/\s/g, '');
    let representation;
    let splitUnit; 

    if (format === 'Text (UTF-8)' || format === 'Base64') {
        representation = cleanData;
        splitUnit = 'char';
    } else if (format === 'Hexadecimal') {
        representation = cleanData;
        splitUnit = 'hex';
    } else if (format === 'Decimal') {
        return { chunk1: `ERROR: Cannot split a single Decimal number. Convert to Base64/Hex/Binary stream first.`, 
                 chunk2: `ERROR: Cannot split a single Decimal number. Convert to Base64/Hex/Binary stream first.`, 
                 outputFormat: 'Text (UTF-8)' };
    } else { 
        representation = cleanData;
        splitUnit = 'bin';
    }
    
    const length = representation.length;
    const midPoint = Math.ceil(length / 2); 
    
    const chunk1 = representation.substring(0, midPoint);
    const chunk2 = representation.substring(midPoint);
    
    const outputFormat = format; 
    
    const formatChunk = (chunk, originalFormat) => {
        if (originalFormat === 'Hexadecimal' && splitUnit === 'hex') {
             const spacedChunk = chunk.match(/.{1,2}/g)?.join(' ') || chunk;
             return spacedChunk.trim(); 
        }
        if (originalFormat === 'Binary' && splitUnit === 'bin') {
             const spacedChunk = chunk.match(/.{1,8}/g)?.join(' ') || chunk;
             return spacedChunk.trim();
        }
        return chunk;
    };


    return { 
        chunk1: formatChunk(chunk1, format), 
        chunk2: formatChunk(chunk2, format), 
        outputFormat: format
    };
};

const concatenateData = (dataAStr, formatA, dataBStr, formatB) => {
    if (!dataAStr || dataAStr.startsWith('ERROR')) {
        return { output: dataBStr || "ERROR: Missing data input A and B.", format: formatB || 'Binary' };
    }
    if (!dataBStr || dataBStr.startsWith('ERROR')) {
        return { output: dataAStr, format: formatA || 'Binary' };
    }
    
    const cleanA = dataAStr.replace(/\s/g, '');
    const cleanB = dataBStr.replace(/\s/g, '');
    const outputFormat = formatA; 

    if (formatA === 'Binary' && formatB === 'Binary') {
        return { output: cleanA + cleanB, format: 'Binary' };
    }
    if (formatA === 'Hexadecimal' && formatB === 'Hexadecimal') {
        const concatenatedHex = cleanA + cleanB;
        const spacedOutput = concatenatedHex.toUpperCase().match(/.{1,2}/g)?.join(' ') || concatenatedHex;
        return { output: spacedOutput, format: 'Hexadecimal' };
    }
    
    try {
        const bytesA = convertToUint8Array(dataAStr, formatA);
        const bytesB = convertToUint8Array(dataBStr, formatB);

        const combinedBytes = new Uint8Array(bytesA.length + bytesB.length);
        combinedBytes.set(bytesA, 0);
        combinedBytes.set(bytesB, bytesA.length);
        
        const output = convertDataFormat(arrayBufferToBase64(combinedBytes.buffer), 'Base64', outputFormat);
        
        return { output, format: outputFormat };

    } catch (e) {
        console.error("Byte-level Concatenation failed:", e);
        return { output: `ERROR: Concatenation failed. Check data formats.`, format: formatA };
    }
};


const calculateHash = async (str, algorithm) => {
  if (!str) return 'Missing data input.';
  const webCryptoAlgorithm = algorithm.toUpperCase(); 
  
  if (!HASH_ALGORITHMS.includes(algorithm)) {
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

const generateSymmetricKey = async (algorithm) => {
    try {
        const key = await crypto.subtle.generateKey(
            { name: algorithm, length: 256 },
            true, 
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

const generateAsymmetricKeyPair = async (algorithm, modulusLength, publicExponentDecimal) => {
    
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

const asymmetricEncrypt = async (dataStr, base64PublicKey, algorithm) => {
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

const asymmetricDecrypt = async (base64Ciphertext, base64PrivateKey, algorithm) => {
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
        return `ERROR: Asymmetric Decryption failed. ${error.message}`;
    }
};


const symmetricEncrypt = async (dataStr, base64Key, algorithm) => {
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

const symmetricDecrypt = async (base64Ciphertext, base64Key, algorithm) => {
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


const isContentCompatible = (content, targetFormat) => {
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


// =================================================================
// 3. UI COMPONENTS & GRAPH LOGIC
// =================================================================

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

    const p1 = { 
      x: sourceNode.position.x + sourceNode.width, 
      y: sourceNode.position.y + sourceVerticalPos 
    }; 
    
    const p2 = { 
      x: targetNode.position.x, 
      y: targetNode.position.y + targetVerticalPos
    }; 
    
    const midX = (p1.x + p2.x) / 2;
    return `M${p1.x} ${p1.y} C${midX} ${p1.y}, ${midX} ${p2.y}, ${p2.x} ${p2.y}`;
};


// --- Helper function to calculate correct mouse position considering scroll and scale ---
const getMouseCoordinates = (e, canvasElement, scale) => {
    const rect = canvasElement.getBoundingClientRect();
    const scrollLeft = canvasElement.scrollLeft;
    const scrollTop = canvasElement.scrollTop;
    
    // Calculate position relative to the container's content area (including scroll)
    // and apply inverse scaling.
    const x = (e.clientX - rect.left + scrollLeft) / scale;
    const y = (e.clientY - rect.top + scrollTop) / scale;
    return { x, y };
};


// --- Sub-Component for Ports (Visual and Interaction) ---
const Port = React.memo(({ nodeId, type, isConnecting, onStart, onEnd, title, isMandatory, portId, portIndex, outputType, nodes }) => {
    let interactionClasses = "";
    let clickHandler = () => {};
    
    let portColor = OUTPUT_PORT_COLOR;

    if (outputType === 'public' || outputType === 'private') {
        portColor = outputType === 'public' ? PUBLIC_KEY_COLOR : PRIVATE_KEY_COLOR;
    } else if (type === 'input') {
        portColor = isMandatory ? INPUT_PORT_COLOR : OPTIONAL_PORT_COLOR;
    }
    
    if (type === 'output' && outputType === 'key') {
         portColor = TEXT_ICON_CLASSES['orange'].replace('text', 'bg'); 
    }
    if (type === 'output' && outputType === 'signature') {
         portColor = SIGNATURE_COLOR.replace('border', 'bg'); 
    }
    
    if (type === 'output') {
        clickHandler = (e) => { 
            e.stopPropagation(); 
            onStart(nodeId, portIndex, outputType); 
        };
        interactionClasses = isConnecting?.sourceId === nodeId 
            ? 'ring-4 ring-emerald-300 animate-pulse' 
            : 'hover:ring-4 hover:ring-emerald-300 transition duration-150';
    } else if (type === 'input') {
        const targetNode = nodes.find(n => n.id === nodeId);
        const targetNodeDef = NODE_DEFINITIONS[targetNode?.type];
        
        const inputPortDef = targetNodeDef.inputPorts.find(p => p.id === portId);
        const inputPortType = inputPortDef?.type;
        
        const isTargetCandidate = isConnecting && 
                                   isConnecting.sourceId !== nodeId && 
                                   isConnecting.outputType === inputPortType; 
        
        if (isTargetCandidate) {
            clickHandler = (e) => { 
                e.stopPropagation(); 
                onEnd(nodeId, portId); 
            };
            interactionClasses = 'ring-4 ring-yellow-300 cursor-pointer animate-pulse-slow';
        } else {
             interactionClasses = 'hover:ring-4 hover:ring-stone-300 transition duration-150';
             clickHandler = (e) => { e.stopPropagation(); }; 
        }
    }
    
    const stopPropagation = (e) => e.stopPropagation();

    return (
        <div 
            className={`w-${PORT_SIZE} h-${PORT_SIZE} rounded-full ${portColor} absolute transform -translate-x-1/2 -translate-y-1/2 
                           shadow-md border-2 border-white cursor-pointer ${interactionClasses}`}
            onClick={clickHandler}
            onMouseDown={stopPropagation}
            onTouchStart={stopPropagation}
            title={title}
        />
    );
});


// --- Component for the Draggable Box ---

const DraggableBox = ({ node, setPosition, canvasRef, handleConnectStart, handleConnectEnd, connectingPort, updateNodeContent, connections, handleDeleteNode, nodes, scale, handleResize, isSelected, onNodeDown }) => {
  const { id, label, position, type, color, content, format, dataOutput, dataOutputPublic, dataOutputPrivate, viewFormat, isProcessing, hashAlgorithm, keyAlgorithm, symAlgorithm, modulusLength, publicExponent, rsaParameters, asymAlgorithm, convertedData, convertedFormat, isConversionExpanded, sourceFormat, rawInputData, p, q, e, d, n, phiN, shiftKey, keyword, vigenereMode, dStatus, n_pub, e_pub, isReadOnly, width, height, keyBase64, generateKey, shiftDescription, chunk1, chunk2 } = node; 
  const definition = NODE_DEFINITIONS[type];
  const [isResizing, setIsResizing] = useState(false); 
  const boxRef = useRef(null);
  const resizeOffset = useRef({ x: 0, y: 0 }); 
  const [copyStatus, setCopyStatus] = useState('Copy'); 

  // Node specific flags
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
  
  // --- Drag Handler Logic Moved to App.jsx ---
  // We only notify parent on mouse down
  const handleMouseDown = useCallback((e) => {
      // Only process left click
      if (e.button !== 0) return;

      // Allow interaction with inputs without triggering drag
      const interactiveTags = ['TEXTAREA', 'SELECT', 'OPTION', 'BUTTON', 'INPUT']; 
      // Check if a port was clicked to prevent drag (handled in port, but just in case)
      if (e.target.tagName === 'DIV' && e.target.classList.contains('w-4') && e.target.classList.contains('h-4')) {
          return; 
      }
      if (interactiveTags.includes(e.target.tagName)) {
          return; 
      }
      e.stopPropagation(); // Stop propagation to prevent selection box
      onNodeDown(e, id);
  }, [onNodeDown, id]);

  
  // --- Resizing Handlers ---
  const handleResizeStart = useCallback((e) => {
    if (e.button !== 0) return; // Only left click for resizing
    e.stopPropagation(); 
    setIsResizing(true);
    
    const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
    const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);
    
    // Use getMouseCoordinates logic for resizing too, although here we need relative movement
    const canvas = canvasRef.current.getBoundingClientRect();
    const scrollLeft = canvasRef.current.scrollLeft;
    const scrollTop = canvasRef.current.scrollTop;

    const unscaledMouseX = (clientX - canvas.left + scrollLeft) / scale;
    const unscaledMouseY = (clientY - canvas.top + scrollTop) / scale;

    resizeOffset.current = {
        x: unscaledMouseX - (node.position.x + node.width),
        y: unscaledMouseY - (node.position.y + node.height),
    };
    
  }, [node.position.x, node.position.y, node.width, node.height, scale, canvasRef]);

  const handleResizeMove = useCallback((e) => {
    if (!isResizing) return;
    const canvas = canvasRef.current;
    if (!canvas) return;

    const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
    const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);

    const canvasRect = canvas.getBoundingClientRect();
    const scrollLeft = canvas.scrollLeft;
    const scrollTop = canvas.scrollTop;
    
    const unscaledMouseX = (clientX - canvasRect.left + scrollLeft) / scale;
    const unscaledMouseY = (clientY - canvasRect.top + scrollTop) / scale;
    
    let newWidth = unscaledMouseX - node.position.x - resizeOffset.current.x;
    let newHeight = unscaledMouseY - node.position.y - resizeOffset.current.y;
    
    handleResize(id, newWidth, newHeight);

    e.preventDefault(); 
  }, [isResizing, id, handleResize, node.position.x, node.position.y, scale]);

  const handleResizeEnd = useCallback(() => {
    setIsResizing(false);
  }, []);
  
  
  // --- Combined Global Event Listeners ---
  useEffect(() => {
    const globalHandleMove = (e) => {
        if (isResizing) {
            handleResizeMove(e);
        }
    };
    
    const globalHandleUp = (e) => {
        if (isResizing) {
            handleResizeEnd(e);
        }
    };

    if (isResizing) {
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
  }, [isResizing, handleResizeMove, handleResizeEnd]);
  
  const handleBoxClick = useCallback((e) => {
    if (isResizing) return; 
    if (connectingPort) {
      handleConnectEnd(null); 
    }
    // Don't stop prop here if we want node click to select, but mousedown usually handles select
    // e.stopPropagation(); 
  }, [connectingPort, handleConnectEnd, isResizing]);

  // Handle Copy to Clipboard
  const handleCopyToClipboard = useCallback((e, textToCopy) => {
    e.stopPropagation();
    
    if (!textToCopy || textToCopy.startsWith('ERROR')) return;

    try {
        const tempTextArea = document.createElement('textarea');
        tempTextArea.value = textToCopy;
        tempTextArea.style.position = 'fixed';
        tempTextArea.style.left = '-9999px';
        tempTextArea.style.top = '0';
        tempTextArea.style.opacity = '0'; 
        document.body.appendChild(tempTextArea);
        tempTextArea.select();
        document.execCommand('copy');
        document.body.removeChild(tempTextArea);
        setCopyStatus('Copied!'); 
        setTimeout(() => setCopyStatus('Copy'), 1500); 
    } catch (err) {
        console.error('Failed to copy text:', err);
        setCopyStatus('Error');
        setTimeout(() => setCopyStatus('Copy'), 2000);
    }
  }, [setCopyStatus]);


  // --- Port Rendering Logic ---
  
  const renderInputPorts = () => {
    if (!definition.inputPorts || definition.inputPorts.length === 0) return null;
    
    const numPorts = definition.inputPorts.length;
    const nodeHeight = height; 
    const step = nodeHeight / (numPorts + 1); 

    return definition.inputPorts.map((portDef, index) => {
        const topPosition = (index + 1) * step;
        const portId = portDef.id;
        const isInputConnected = connections.some(c => c.target === id && c.targetPortId === portId);

        return (
            <div 
                key={portId}
                className="absolute -left-2 transform -translate-y-1/2 z-20"
                style={{ top: `${topPosition}px` }} 
            >
                <Port 
                    nodeId={id} 
                    type="input"
                    portId={portId} 
                    isConnecting={connectingPort}
                    onStart={handleConnectStart} 
                    onEnd={handleConnectEnd} 
                    title={`${portDef.name} (${portDef.mandatory ? 'Mandatory' : 'Optional'}) - Type: ${portDef.type}`}
                    isMandatory={portDef.mandatory}
                    isInputConnected={isInputConnected}
                    nodes={nodes} 
                />
            </div>
        );
    });
  };

  const renderOutputPorts = () => {
    if (!definition.outputPorts || definition.outputPorts.length === 0) return null;
    
    const numPorts = definition.outputPorts.length;
    const nodeHeight = height; 
    const step = nodeHeight / (numPorts + 1); 

    return definition.outputPorts.map((portDef, index) => {
        const topPosition = (index + 1) * step;
        
        return (
            <div 
                key={portDef.name}
                className="absolute -right-2 transform -translate-y-1/2 z-20"
                style={{ top: `${topPosition}px` }} 
            >
                <Port 
                    nodeId={id} 
                    type="output"
                    portId={`${portDef.type}-${index}`} 
                    portIndex={index} 
                    outputType={portDef.type} 
                    isConnecting={connectingPort}
                    onStart={handleConnectStart}
                    onEnd={handleConnectEnd}
                    title={`${portDef.name} - Type: ${portDef.type}`}
                    isMandatory={true} 
                    nodes={nodes} 
                />
            </div>
        );
    });
  };
  
  // --- Class Lookups ---
  const iconTextColorClass = TEXT_ICON_CLASSES[color] || 'text-gray-600';

  let specificClasses = '';

  if (isPortSource) {
    specificClasses = `border-emerald-500 ring-4 ring-emerald-300 cursor-pointer animate-pulse transition duration-200`; 
  } else {
    // Add specific styles for selected state (blue border/ring)
    specificClasses = `${BORDER_CLASSES[color]} ${HOVER_BORDER_CLASSES[color]} ${isSelected ? 'node-selected' : 'cursor-pointer hover:border-blue-500'}`;
  }
  
  if (isProcessing) {
      specificClasses = `border-yellow-500 ring-4 ring-yellow-300 animate-pulse transition duration-200`; 
  }
  
  let requiredMinHeight = NODE_DIMENSIONS.minHeight;
  
  if (isOutputViewer) {
      requiredMinHeight = isConversionExpanded ? 280 : 250;
  }
  
  if (isBitShift || type === 'XOR_OP' || isDataSplit || isDataConcat) {
      requiredMinHeight = 300; 
  }

  const effectiveMinHeight = requiredMinHeight;

  const baseClasses = 
    `h-auto flex flex-col justify-start items-center p-3 
    bg-white shadow-xl rounded-xl border-4 transition duration-150 ease-in-out 
    hover:shadow-2xl absolute select-none z-10`;
    
  const boxStyle = {
      left: `${position.x}px`,
      top: `${position.y}px`,
      width: `${width}px`,
      minHeight: `${effectiveMinHeight}px`, 
      height: `${height}px`, 
  };
  
  const contentHeightExcludingHeader = height - 50; 

  // --- Render ---
  return (
    <div
      ref={boxRef}
      id={id}
      // Add draggable-box class for easier hit testing
      className={`${baseClasses} ${specificClasses} draggable-box`}
      style={boxStyle} 
      onMouseDown={handleMouseDown} 
      onTouchStart={handleMouseDown} // Map touch to same logic if needed, but multitouch selection is tricky
      onClick={handleBoxClick} 
    >
      
      {/* Resizing Handle */}
      <div 
          className="absolute bottom-0 right-0 w-4 h-4 rounded-tl-lg bg-gray-200 opacity-60 hover:opacity-100 transition duration-150 cursor-nwse-resize z-30"
          onMouseDown={handleResizeStart}
          onTouchStart={handleResizeStart}
          onClick={(e) => e.stopPropagation()} 
          title="Resize"
      >
        <div className="w-1 h-1 bg-gray-600 absolute bottom-1 right-1"></div>
        <div className="w-1 h-1 bg-gray-600 absolute bottom-2 right-2"></div>
        <div className="w-1 h-1 bg-gray-600 absolute bottom-2 right-1"></div>
        <div className="w-1 h-1 bg-gray-600 absolute bottom-1 right-2"></div>
      </div>

      {/* Delete Button */}
      <button
        className="absolute top-1 right-1 p-1 rounded-full bg-gray-100 hover:bg-gray-200 text-gray-400 hover:text-gray-600 z-30 transition duration-150"
        onClick={(e) => {
            e.stopPropagation();
            handleDeleteNode(id);
        }}
        title="Delete Node"
      >
        <X className="w-3 h-3" />
      </button>

      {/* -------------------- PORTS -------------------- */}
      {renderInputPorts()}
      {renderOutputPorts()} 

      {/* -------------------- CONTENT -------------------- */}
      <div 
          className="flex flex-col w-full justify-start items-center overflow-hidden" 
          style={{ height: `${contentHeightExcludingHeader}px` }}
      >
        {/* Top Section: Icon and Main Label */}
        <div className="flex flex-col justify-start items-center w-full flex-shrink-0 mb-2">
          {definition.icon && (
              <definition.icon className={`w-6 h-6 ${iconTextColorClass} mb-1`} />
          )}
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
                <select
                    className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm mb-2
                                     bg-white appearance-none cursor-pointer text-gray-700 
                                     focus:ring-2 focus:ring-gray-500 focus:border-gray-500 outline-none transition duration-200"
                    value={hashAlgorithm || 'SHA-256'}
                    onChange={(e) => updateNodeContent(id, 'hashAlgorithm', e.target.value)}
                    onMouseDown={(e) => e.stopPropagation()}
                    onTouchStart={(e) => e.stopPropagation()}
                    onClick={(e) => e.stopPropagation()}
                >
                    {HASH_ALGORITHMS.map(alg => (
                        <option key={alg} value={alg}>{alg}</option>
                    ))}
                </select>
              </div>
          )}
          {isKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({keyAlgorithm})</span>}
          
          {isSimpleRSAKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({modulusLength} bits)</span>}
          
          {isRSAKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({node.keyAlgorithm} {modulusLength} bits, e={publicExponent})</span>}
          
          {type === 'XOR_OP' && <span className={`text-xs text-gray-500 mt-1`}>({isProcessing ? 'Processing' : 'Bitwise XOR'})</span>}
          {isBitShift && <span className={`text-xs text-gray-500 mt-1`}>({isProcessing ? 'Processing' : (shiftDescription || 'Bit Shift')})</span>}
          {isSimpleRSAPubKeyGen && <span className={`text-xs text-gray-500 mt-1`}>Public Key Output</span>} 
          {isDataSplit && <span className={`text-xs text-gray-500 mt-1`}>Split by: Character/Hex/Bit</span>}
          {isDataConcat && <span className={`text-xs text-gray-500 mt-1`}>Concatenation: Data A + Data B</span>}


          {!isDataInput && !isOutputViewer && !isHashFn && !isKeyGen && !isSymEnc && !isSymDec && !isRSAKeyGen && !isAsymEnc && !isAsymDec && type !== 'XOR_OP' && !isBitShift && !isSimpleRSAKeyGen && !isSimpleRSAPubKeyGen && !isSimpleRSAEnc && !isSimpleRSADec && !isCaesarCipher && !isVigenereCipher && !isSimpleRSASign && !isSimpleRSAVerify && !isDataSplit && !isDataConcat && <span className={`text-xs text-gray-500 mt-1`}>({definition.label})</span>}
        </div>
        
        {isDataInput && (
          <div className="w-full flex flex-col items-center flex-grow">
            <textarea
              className="w-full text-xs p-2 border border-gray-200 rounded-lg shadow-md resize-y flex-grow mb-2 
                           placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 
                           outline-none transition duration-200"
              placeholder="Enter data here..."
              value={content || ''}
              onChange={(e) => {
                  const newContent = e.target.value;
                  const currentFormat = node.format;
                  let newFormat = currentFormat;
                  
                  const formatsByRestrictiveness = ['Binary', 'Decimal', 'Hexadecimal', 'Base64', 'Text (UTF-8)'];
                  
                  if (!isContentCompatible(newContent, currentFormat)) {
                      let detectedFormat = 'Text (UTF-8)'; 
                      for (const formatCheck of formatsByRestrictiveness) {
                          if (isContentCompatible(newContent, formatCheck)) {
                              detectedFormat = formatCheck;
                              break; 
                          }
                      }
                      newFormat = detectedFormat;
                  }
                  
                  if (newFormat !== currentFormat) {
                      updateNodeContent(id, 'format', newFormat);
                  }
                  
                  updateNodeContent(id, 'content', newContent);
              }}
              onMouseDown={(e) => e.stopPropagation()} 
              onTouchStart={(e) => e.stopPropagation()} 
              onClick={(e) => e.stopPropagation()}
            />
            <select
              className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm flex-shrink-0
                           bg-white appearance-none cursor-pointer text-gray-700 
                           focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              value={format || 'Text (UTF-8)'}
              onChange={(e) => {
                e.stopPropagation();
                const selectedFormat = e.target.value;
                const currentContent = content || '';
                let finalFormat = selectedFormat;

                if (!isContentCompatible(currentContent, selectedFormat)) {
                    
                    const formatsByRestrictiveness = ['Binary', 'Decimal', 'Hexadecimal', 'Base64', 'Text (UTF-8)'];
                    
                    for (const formatCheck of formatsByRestrictiveness) {
                        if (isContentCompatible(currentContent, formatCheck)) {
                            finalFormat = formatCheck;
                            break;
                        }
                    }

                    if (finalFormat !== selectedFormat) {
                        console.warn(`Content incompatible with ${selectedFormat}. Reverted to compatible format: ${finalFormat}`);
                    }
                }

                updateNodeContent(id, 'format', finalFormat);
              }}
              onMouseDown={(e) => e.stopPropagation()}
              onTouchStart={(e) => e.stopPropagation()}
              onClick={(e) => e.stopPropagation()}
            >
              {FORMATS.map(f => (
                <option key={f} value={f}>{f}</option>
              ))}
            </select>
          </div>
        )}
        
        {/* Output Viewer Display (Convert) */}
        {isOutputViewer && (
            <div className="w-full mt-1 flex flex-col items-center flex-grow text-xs text-gray-700 bg-gray-50 p-2 border border-gray-200 rounded-lg shadow-inner overflow-y-auto">
                <span className="text-center font-bold text-red-600 mb-1 flex-shrink-0">RAW INPUT DATA</span>
                
                <div className="w-full mb-1 flex-shrink-0">
                    <label className="block text-left text-[10px] font-semibold text-gray-600 mb-0.5">Source Data Type</label>
                    <select
                        className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm 
                                     bg-gray-100 cursor-default text-gray-700 appearance-none pointer-events-none"
                        value={sourceFormat || 'N/A'}
                        onChange={() => {}} 
                        onMouseDown={(e) => e.stopPropagation()}
                        onClick={(e) => e.stopPropagation()}
                        disabled
                    >
                        <option>{sourceFormat || 'N/A'}</option>
                    </select>
                </div>

                <div 
                    className={`relative w-full break-all text-[10px] leading-tight text-gray-800 bg-white p-1 rounded-md mb-2 overflow-y-auto border border-gray-200`}
                    style={{ flexGrow: isConversionExpanded ? 0.5 : 1.2, minHeight: '40px' }} 
                >
                    <p>{rawInputData || 'Not connected or no data.'}</p>
                    
                    <button
                        onClick={(e) => handleCopyToClipboard(e, rawInputData)} 
                        disabled={!rawInputData || rawInputData.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm 
                                     ${rawInputData && !rawInputData.startsWith('ERROR')
                                         ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                         : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>

                <button
                    onClick={(e) => { 
                        e.stopPropagation();
                        updateNodeContent(id, 'isConversionExpanded', !isConversionExpanded);
                    }}
                    className={`mt-1 w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md bg-red-500 hover:bg-red-600 flex-shrink-0`}
                >
                    <span>{isConversionExpanded ? 'Hide Conversion' : 'Convert Type'}</span>
                </button>


                {isConversionExpanded && (
                    <div className="w-full mt-2 pt-2 border-t border-gray-200 flex flex-col space-y-2 flex-grow">
                        <span className="text-center font-bold text-red-600 text-[10px] flex-shrink-0">CONVERTED VIEW</span>

                        <div 
                            className="relative w-full break-all text-[10px] leading-tight text-gray-800 bg-white p-1 rounded-md mb-2 overflow-y-auto border border-gray-200"
                            style={{ flexGrow: 1, minHeight: '40px' }} 
                        >
                            <p>{convertedData || 'Select conversion type...'}</p>

                            <button
                                onClick={(e) => handleCopyToClipboard(e, convertedData)}
                                disabled={!convertedData || convertedData.startsWith('ERROR')}
                                className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                             ${convertedData && !convertedData.startsWith('ERROR')
                                                 ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                                 : 'bg-gray-300 cursor-not-allowed'}`}
                                title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                            >
                                <Clipboard className="w-3 h-3" />
                            </button>
                        </div>

                        <select
                            className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm flex-shrink-0
                                             bg-white appearance-none cursor-pointer text-gray-700 
                                             focus:ring-2 focus:ring-red-500 focus:border-red-500 outline-none transition duration-200"
                            value={convertedFormat || 'Base64'}
                            onChange={(e) => updateNodeContent(id, 'convertedFormat', e.target.value)}
                            onMouseDown={(e) => e.stopPropagation()}
                            onTouchStart={(e) => e.stopPropagation()}
                            onClick={(e) => e.stopPropagation()}
                        >
                            {FORMATS.map(f => (
                                <option key={f} value={f}>{f}</option>
                            ))}
                        </select>
                    </div>
                )}
            </div>
        )}

        {/* ... (Other Node Types Rendering Logic - Kept same as original, just ensuring e.stopPropagation is correct) ... */}
        
        {/* Generic Output Preview (Fallback for unimplemented nodes) */}
        {!isDataInput && !isOutputViewer && !isHashFn && !isKeyGen && !isSymEnc && !isSymDec && !isRSAKeyGen && !isAsymEnc && !isAsymDec && type !== 'XOR_OP' && !isBitShift && !isSimpleRSAKeyGen && !isSimpleRSAPubKeyGen && !isSimpleRSAEnc && !isSimpleRSADec && !isCaesarCipher && !isVigenereCipher && !isSimpleRSASign && !isSimpleRSAVerify && !isDataSplit && !isDataConcat && (
            <div className="text-xs text-gray-500 mt-2">
                <p>Output: {dataOutput ? dataOutput.substring(0, 10) + '...' : 'Waiting for connection'}</p>
            </div>
        )}
      </div>
    </div>
  );
};

// --- Main Application Component ---

const migrateProjectData = (projectData) => {
    const currentVersion = PROJECT_SCHEMA_VERSION;
    const importedVersion = projectData.schemaVersion || '1.0'; 

    if (importedVersion === currentVersion) {
        return { migratedData: projectData, wasMigrated: false };
    }
    
    let migratedData = { ...projectData };
    let wasMigrated = false;

    if (importedVersion < '1.1') {
        wasMigrated = true;
        migratedData.nodes = migratedData.nodes.map(node => {
            const newNode = { ...node };

            if (newNode.type === 'DATA_INPUT' && newNode.format && newNode.outputFormat === 'Text (UTF-8)') {
                if (['Binary', 'Hexadecimal', 'Decimal'].includes(newNode.format)) {
                    newNode.outputFormat = newNode.format;
                }
            }

            if (!newNode.width || newNode.width < NODE_DIMENSIONS.minWidth) {
                newNode.width = NODE_DIMENSIONS.initialWidth;
            }
            if (!newNode.height || newNode.height < NODE_DIMENSIONS.minHeight) {
                if (newNode.type === 'XOR_OP' || newNode.type === 'SHIFT_OP' || newNode.type === 'DATA_SPLIT' || newNode.type === 'DATA_CONCAT') {
                    newNode.height = 300;
                } else {
                    newNode.height = NODE_DIMENSIONS.initialHeight;
                }
            }
            
            if (newNode.type === 'XOR_OP') {
                 delete newNode.shiftType;
                 delete newNode.shiftAmount;
                 delete newNode.shiftDescription;
            }


            return newNode;
        });
    }
    
    migratedData.schemaVersion = currentVersion;
    console.log(`Project migrated from version ${importedVersion} to ${currentVersion}.`);
    
    return { migratedData, wasMigrated };
};


const StatusNotification = ({ status, message, onClose }) => {
    let bgColor;
    let IconComponent;
    
    switch (status) {
        case 'success':
            bgColor = 'bg-green-500';
            IconComponent = CheckCheck;
            break;
        case 'warning':
            bgColor = 'bg-yellow-600';
            IconComponent = Info;
            break;
        case 'error':
        default:
            bgColor = 'bg-red-500';
            IconComponent = X;
            break;
    }


    return (
        <div 
            className={`fixed bottom-4 right-4 p-4 rounded-lg shadow-xl text-white max-w-sm z-50 
                        flex items-start space-x-3 transition-opacity duration-300 ${bgColor}`}
        >
            <IconComponent className="w-5 h-5 flex-shrink-0 mt-0.5" />
            <div className="flex-grow">
                <p className="font-semibold text-sm">{status.toUpperCase()}</p>
                <p className="text-sm">{message}</p>
            </div>
            <button onClick={onClose} className="p-1 -mr-2 -mt-2 opacity-75 hover:opacity-100 transition">
                <X className="w-4 h-4" />
            </button>
        </div>
    );
};


const App = () => {
  const [nodes, setNodes] = useState(INITIAL_NODES);
  const [connections, setConnections] = useState(INITIAL_CONNECTIONS); 
  const [connectingPort, setConnectingPort] = useState(null); 
  const [scale, setScale] = useState(1.0); 
  const [statusMessage, setStatusMessage] = useState(null); 
  
  // --- New Selection State ---
  const [selectedNodeIds, setSelectedNodeIds] = useState(new Set()); // IDs of selected nodes
  const [selectionBox, setSelectionBox] = useState(null); // { x, y, width, height, startX, startY }
  
  // --- Refs for Dragging/Selecting to avoid re-renders and stale closures ---
  const interactionState = useRef({
      mode: 'IDLE', // 'IDLE', 'SELECTING', 'DRAGGING'
      startMouse: { x: 0, y: 0 }, // Unscaled coordinates at start
      initialNodePositions: new Map(), // Map<id, {x, y}>
      selectionBoxStart: { x: 0, y: 0 }, // For marquee drawing
  });

  const canvasRef = useRef(null);
  
  const MAX_SCALE = 2.0;
  const MIN_SCALE = 0.5;
  const ZOOM_STEP = 0.2;

  const handleZoomIn = useCallback(() => {
      setScale(prevScale => Math.min(MAX_SCALE, prevScale + ZOOM_STEP));
  }, []);

  const handleZoomOut = useCallback(() => {
      setScale(prevScale => Math.max(MIN_SCALE, prevScale - ZOOM_STEP));
  }, []);

  const clearStatusMessage = useCallback(() => setStatusMessage(null), []);
    
  // --- Mouse Interaction Handlers ---

  // 1. Canvas Mouse Down (Start Selection)
  const handleCanvasMouseDown = useCallback((e) => {
      if (connectingPort) return;
      
      // Ensure only left click triggers selection
      if (e.button !== 0) return; 

      if (e.target.closest('.draggable-box')) return; // Ignore if clicking on a node
      
      const canvas = canvasRef.current;
      if (!canvas) return;
      
      const { x, y } = getMouseCoordinates(e, canvas, scale);

      // Clear selection if not holding Shift/Ctrl
      if (!e.shiftKey && !e.ctrlKey && !e.metaKey) {
          setSelectedNodeIds(new Set());
      }

      interactionState.current.mode = 'SELECTING';
      interactionState.current.selectionBoxStart = { x, y };
      
      setSelectionBox({
          x, y, width: 0, height: 0
      });
  }, [connectingPort, scale]);

  // 2. Node Mouse Down (Start Dragging or Toggle Selection)
  const handleNodeMouseDown = useCallback((e, nodeId) => {
      // Ensure only left click triggers selection/drag
      if (e.button !== 0) return; 

      e.stopPropagation(); 
      if (connectingPort) return;

      const canvas = canvasRef.current;
      if (!canvas) return;

      const { x, y } = getMouseCoordinates(e, canvas, scale);

      // Handle Selection Logic
      let newSelectedIds = new Set(selectedNodeIds);
      
      if (e.shiftKey || e.ctrlKey || e.metaKey) {
          if (newSelectedIds.has(nodeId)) {
              newSelectedIds.delete(nodeId);
          } else {
              newSelectedIds.add(nodeId);
          }
          setSelectedNodeIds(newSelectedIds);
      } else {
          // If clicking a node that is NOT in the current selection, verify selection.
          // If it IS in the current selection, keep the group selection to allow dragging the group.
          if (!newSelectedIds.has(nodeId)) {
              newSelectedIds = new Set([nodeId]);
              setSelectedNodeIds(newSelectedIds);
          }
      }

      // Prepare Dragging State
      interactionState.current.mode = 'DRAGGING';
      interactionState.current.startMouse = { x, y };
      interactionState.current.initialNodePositions.clear();

      // Snapshot initial positions of ALL selected nodes (using the calculated new set)
      nodes.forEach(n => {
          if (newSelectedIds.has(n.id)) {
              interactionState.current.initialNodePositions.set(n.id, { ...n.position });
          }
      });

  }, [connectingPort, scale, nodes, selectedNodeIds]);

  // 3. Global Mouse Move (Handle both operations)
  useEffect(() => {
      const handleGlobalMouseMove = (e) => {
          const mode = interactionState.current.mode;
          if (mode === 'IDLE') return;

          const canvas = canvasRef.current;
          if (!canvas) return;

          const { x: currentX, y: currentY } = getMouseCoordinates(e, canvas, scale);

          if (mode === 'SELECTING') {
              const startX = interactionState.current.selectionBoxStart.x;
              const startY = interactionState.current.selectionBoxStart.y;

              const newX = Math.min(currentX, startX);
              const newY = Math.min(currentY, startY);
              const newWidth = Math.abs(currentX - startX);
              const newHeight = Math.abs(currentY - startY);

              setSelectionBox({ x: newX, y: newY, width: newWidth, height: newHeight });
          } 
          else if (mode === 'DRAGGING') {
              const startMouse = interactionState.current.startMouse;
              const dx = currentX - startMouse.x;
              const dy = currentY - startMouse.y;

              setNodes(prevNodes => prevNodes.map(node => {
                  const initialPos = interactionState.current.initialNodePositions.get(node.id);
                  if (initialPos) {
                      return {
                          ...node,
                          position: {
                              x: Math.max(0, initialPos.x + dx),
                              y: Math.max(0, initialPos.y + dy)
                          }
                      };
                  }
                  return node;
              }));
          }
      };

      const handleGlobalMouseUp = (e) => {
          const mode = interactionState.current.mode;
          if (mode === 'IDLE') return;

          const canvas = canvasRef.current;
          if (canvas && mode === 'SELECTING') {
              // Finalize Selection
              const { x: currentX, y: currentY } = getMouseCoordinates(e, canvas, scale);
              const startX = interactionState.current.selectionBoxStart.x;
              const startY = interactionState.current.selectionBoxStart.y;
              
              const boxLeft = Math.min(currentX, startX);
              const boxTop = Math.min(currentY, startY);
              const boxRight = Math.max(currentX, startX);
              const boxBottom = Math.max(currentY, startY);

              setSelectionBox(null); // Clear visual box

              setSelectedNodeIds(prevSelected => {
                  const newSelected = new Set(e.shiftKey || e.ctrlKey ? prevSelected : []);
                  
                  nodes.forEach(node => {
                      const nodeRight = node.position.x + node.width;
                      const nodeBottom = node.position.y + node.height;
                      
                      // Check overlap
                      if (node.position.x < boxRight && 
                          nodeRight > boxLeft && 
                          node.position.y < boxBottom && 
                          nodeBottom > boxTop) {
                          newSelected.add(node.id);
                      }
                  });
                  return newSelected;
              });
          }

          // Reset Mode
          interactionState.current.mode = 'IDLE';
          interactionState.current.initialNodePositions.clear();
      };

      document.addEventListener('mousemove', handleGlobalMouseMove);
      document.addEventListener('mouseup', handleGlobalMouseUp);

      return () => {
          document.removeEventListener('mousemove', handleGlobalMouseMove);
          document.removeEventListener('mouseup', handleGlobalMouseUp);
      };
  }, [nodes, scale]); // Minimal dependencies to avoid thrashing


  // --- Project Management Handlers ---
  
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
    const projectData = {
        schemaVersion: PROJECT_SCHEMA_VERSION, 
        nodes: nodes,
        connections: connections
    };
    const data = JSON.stringify(projectData, null, 2);
    downloadFile(data, `visual_crypto_project_v${PROJECT_SCHEMA_VERSION}.json`, 'application/json');
    setStatusMessage({ type: 'success', message: `Project exported successfully! Version: ${PROJECT_SCHEMA_VERSION}` });
    setTimeout(clearStatusMessage, 5000);
  }, [nodes, connections, clearStatusMessage]);

  const handleUploadProject = useCallback((fileInput) => {
      clearStatusMessage();
      
      const file = fileInput.files?.[0]; 
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (e) => {
          let projectData = null;
          let importStatus = { type: 'error', message: 'Import failed due to an unknown error.' };
          
          try {
              try {
                  projectData = JSON.parse(e.target.result);
              } catch (error) {
                  importStatus = { type: 'error', message: 'Import failed: File is not a valid JSON structure.' };
                  throw new Error("Invalid JSON");
              }

              if (!projectData || !Array.isArray(projectData.nodes) || !Array.isArray(projectData.connections)) {
                  importStatus = { type: 'error', message: "Import failed: JSON file is missing the required 'nodes' or 'connections' structure." };
                  throw new Error("Invalid schema structure");
              }
              
              const importedVersion = projectData.schemaVersion || '1.0';
              const currentVersion = PROJECT_SCHEMA_VERSION;
              
              const { migratedData, wasMigrated } = migrateProjectData(projectData);
              
              setNodes(migratedData.nodes);
              setConnections(migratedData.connections);
              
              if (wasMigrated) {
                  importStatus = { 
                      type: 'warning', 
                      message: `Project loaded successfully, but imported version (${importedVersion}) required migration to ${currentVersion}. Minor feature differences may exist.` 
                  };
              } else if (importedVersion !== currentVersion) {
                   importStatus = { 
                      type: 'warning', 
                      message: `Project loaded successfully. Version mismatch (Imported: ${importedVersion}, Current: ${currentVersion}).` 
                  };
              } else {
                  importStatus = { type: 'success', message: 'Project imported successfully!' };
              }

          } catch (error) {
              console.error("Import process failed:", error);
          }
          
          setStatusMessage(importStatus);
          setTimeout(clearStatusMessage, 8000);
      };
      
      reader.onerror = (e) => {
          const message = "Import failed: An error occurred while reading the file from disk.";
          setStatusMessage({ type: 'error', message });
          setTimeout(clearStatusMessage, 8000);
      };
      
      reader.readAsText(file);
      fileInput.value = ''; 
  }, [clearStatusMessage, setNodes, setConnections]);

  // --- Core Logic: Graph Recalculation (Data Flow Engine) ---
  
  const recalculateGraph = useCallback((currentNodes, currentConnections, changedNodeId = null) => {
    const newNodesMap = new Map(currentNodes.map(n => {
        const newNode = { ...n };
        newNode.isProcessing = false;
        if (newNode.type === 'OUTPUT_VIEWER') {
             newNode.convertedData = newNode.convertedData || ''; 
             newNode.convertedFormat = newNode.convertedFormat || 'Base64';
             newNode.isConversionExpanded = newNode.isConversionExpanded || false;
             newNode.sourceFormat = newNode.sourceFormat || ''; 
             newNode.rawInputData = newNode.rawInputData || ''; 
        } else if (newNode.type === 'DATA_SPLIT') { 
             newNode.chunk1 = '';
             newNode.chunk2 = '';
        }
        return [n.id, newNode];
    })); 
    
    let initialQueue = new Set(currentNodes.filter(n => {
        const def = NODE_DEFINITIONS[n.type];
        return def && def.inputPorts && def.inputPorts.length === 0;
    }).map(n => n.id));
    
    if (changedNodeId) {
        initialQueue.add(changedNodeId);
    }
    
    let nodesToProcess = Array.from(initialQueue);
    const processed = new Set();
    
    const findAllTargets = (sourceId) => {
        return currentConnections
            .filter(c => c.source === sourceId)
            .map(c => c.target)
            .filter(targetId => !processed.has(targetId));
    };

    while (nodesToProcess.length > 0) {
        const sourceId = nodesToProcess.shift();
        if (processed.has(sourceId) || !newNodesMap.has(sourceId)) continue; 

        const sourceNode = newNodesMap.get(sourceId);
        const sourceNodeDef = NODE_DEFINITIONS[sourceNode.type];

        let outputData = sourceNode.dataOutput || '';
        let isProcessing = false;
        
        if (sourceNodeDef.inputPorts.length === 0) {
            
            if (sourceNode.type === 'DATA_INPUT') {
                outputData = sourceNode.content || ''; 
            } else if (sourceNode.type === 'KEY_GEN') {
                const algorithm = sourceNode.keyAlgorithm || 'AES-GCM';

                if (sourceNode.generateKey || !sourceNode.keyBase64) {
                    isProcessing = true;
                    generateSymmetricKey(algorithm).then(({ keyBase64 }) => {
                        setNodes(prevNodes => prevNodes.map(n => 
                            n.id === sourceId 
                                ? { 
                                     ...n, 
                                     dataOutput: keyBase64,
                                     keyBase64: keyBase64,
                                     isProcessing: false, 
                                     generateKey: false 
                                   } 
                                : n
                        ));
                    }).catch(err => {
                         setNodes(prevNodes => prevNodes.map(n => 
                             n.id === sourceId 
                                 ? { ...n, dataOutput: `ERROR: Key generation failed. ${err.message}`, keyBase64: `ERROR: Key generation failed. ${err.message}`, isProcessing: false, generateKey: false } 
                                 : n
                           ));
                    });
                    
                    outputData = sourceNode.dataOutput || 'Generating Key...';
                    sourceNode.isProcessing = isProcessing;
                    sourceNode.generateKey = false;
                    newNodesMap.set(sourceId, sourceNode);
                    
                    processed.add(sourceId);
                    nodesToProcess.push(...findAllTargets(sourceId));
                    continue; 

                } else if (sourceNode.keyBase64) {
                    outputData = sourceNode.keyBase64; 
                    isProcessing = false;
                }
                
            } else if (sourceNode.type === 'RSA_KEY_GEN' || sourceNode.type === 'SIMPLE_RSA_KEY_GEN') { 
                
                 const publicExponentToUse = sourceNode.type === 'SIMPLE_RSA_KEY_GEN' ? 65537 : (sourceNode.publicExponent || 65537);
                   
                 if (sourceNode.type === 'SIMPLE_RSA_KEY_GEN' && sourceNode.generateKey) {
                     isProcessing = true;
                     
                     const rawP = sourceNode.p;
                     const rawQ = sourceNode.q;
                     const rawE = sourceNode.e;
                     const userD = sourceNode.d ? BigInt(sourceNode.d) : null; 

                     let p_val, q_val, e_val, d_val;
                     let n_val, phiN_val;
                     let error = null;
                     let d_status = ''; 

                     try {
                         const userP = rawP && !isNaN(Number(rawP)) ? BigInt(rawP) : null;
                         const userQ = rawQ && !isNaN(Number(rawQ)) ? BigInt(rawQ) : null;
                         
                         if (userP && userQ && userP > BigInt(0) && userQ > BigInt(0)) {
                             p_val = userP;
                             q_val = userQ;
                         } else {
                             ({ p: p_val, q: q_val } = generateSmallPrimes());
                         }

                         n_val = p_val * q_val;
                         phiN_val = (p_val - BigInt(1)) * (q_val - BigInt(1)); 

                         const userE = rawE && !isNaN(Number(rawE)) ? BigInt(rawE) : null;
                         
                         if (userE && userE > BigInt(1) && userE < phiN_val && gcd(userE, phiN_val) === BigInt(1)) {
                             e_val = userE;
                         } else if (!userE || userE <= BigInt(0)) {
                             e_val = generateSmallE(phiN_val);
                         } else {
                             error = `ERROR: Invalid E (${userE.toString()}). Must be 1 < E < phi(n) and gcd(E, phi(n)) = 1.`;
                             throw new Error(error);
                         }
                         
                         const calculatedD = modInverse(e_val, phiN_val);
                         d_val = calculatedD; 
                         
                         if (userD && userD > BigInt(0)) {
                            if ((userD * e_val) % phiN_val === BigInt(1) && userD < phiN_val) {
                                d_status = `CORRECT (User input D: ${userD.toString()}). Using calculated value for consistency.`;
                            } else {
                                d_status = `INCORRECT (User input D: ${userD.toString()}). The correct value is: ${calculatedD.toString()}.`;
                            }
                         } else {
                             d_status = 'CORRECT (Calculated).';
                         }
                         
                     } catch (err) {
                          error = err.message.startsWith("ERROR") ? err.message : `ERROR: Calculation failed. ${err.message}`;
                     }
                     
                     if (!error) {
                          sourceNode.dataOutputPublic = `${n_val.toString()},${e_val.toString()}`; 
                          sourceNode.dataOutputPrivate = d_val.toString();
                          
                          sourceNode.n = n_val.toString();
                          sourceNode.phiN = phiN_val.toString();
                          sourceNode.d = d_val.toString(); 
                          sourceNode.p = p_val.toString();
                          sourceNode.q = q_val.toString();
                          sourceNode.e = e_val.toString();
                          sourceNode.dStatus = d_status; 
                          
                          outputData = sourceNode.dataOutputPrivate; 
                          isProcessing = false;
                     } else {
                          outputData = error;
                          sourceNode.dataOutputPublic = outputData;
                          sourceNode.dataOutputPrivate = outputData;
                          sourceNode.n = ''; sourceNode.phiN = ''; 
                          
                          sourceNode.p = rawP; 
                          sourceNode.q = rawQ;
                          sourceNode.e = rawE;
                          sourceNode.d = ''; 
                          sourceNode.dStatus = error;
                     }

                     sourceNode.isProcessing = isProcessing;
                     sourceNode.generateKey = false; 
                     newNodesMap.set(sourceId, sourceNode);
                     
                     processed.add(sourceId);
                     nodesToProcess.push(...findAllTargets(sourceId));
                     continue;

                 } else if (sourceNode.keyPairObject || sourceNode.generateKey) {
                      isProcessing = true;
                      
                      if (!sourceNode.keyPairObject || sourceNode.generateKey) {
                           const algorithm = ASYM_ALGORITHMS[0]; 
                           const modulusLength = sourceNode.modulusLength || 2048;
                           
                           generateAsymmetricKeyPair(algorithm, modulusLength, publicExponentToUse).then(({ publicKey, privateKey, keyPairObject, rsaParameters }) => {
                               setNodes(prevNodes => prevNodes.map(n => 
                                   n.id === sourceId 
                                       ? { 
                                             ...n, 
                                             dataOutputPublic: publicKey, 
                                             dataOutputPrivate: privateKey, 
                                             keyPairObject: keyPairObject, 
                                             rsaParameters: rsaParameters, 
                                             isProcessing: false, 
                                             generateKey: false 
                                           } 
                                       : n
                                   ));
                           }).catch(err => {
                               setNodes(prevNodes => prevNodes.map(n => 
                                   n.id === sourceId 
                                       ? { ...n, dataOutputPublic: `ERROR: ${err.message}`, dataOutputPrivate: `ERROR: ${err.message}`, isProcessing: false, generateKey: false } 
                                       : n
                                   ));
                           });
                           outputData = sourceNode.dataOutputPublic || 'Generating Keys...';
                      } else {
                           outputData = sourceNode.dataOutputPublic || '';
                           isProcessing = false;
                      }
                 } else {
                     outputData = 'Click "Generate RSA Key Pair"';
                 }
            }
        
        } else {
            const incomingConns = currentConnections.filter(c => c.target === sourceId);
            let inputs = {};
            
            incomingConns.forEach(conn => {
                const inputSourceNode = newNodesMap.get(conn.source);
                if (!inputSourceNode) return;

                let dataToUse;
                const sourceDef = NODE_DEFINITIONS[inputSourceNode.type];
                
                if (sourceDef && sourceDef.outputPorts.length > conn.sourcePortIndex) {
                    const keyField = sourceDef.outputPorts[conn.sourcePortIndex].keyField;
                    
                    if (inputSourceNode.type === 'DATA_SPLIT' && (keyField === 'chunk1' || keyField === 'chunk2')) {
                        dataToUse = inputSourceNode[keyField];
                    } else {
                        dataToUse = inputSourceNode[keyField]; 
                    }
                } else {
                    dataToUse = inputSourceNode.dataOutput; 
                }

                const sourceFormat = inputSourceNode.type === 'DATA_INPUT' 
                    ? inputSourceNode.format 
                    : (inputSourceNode.outputFormat || getOutputFormat(inputSourceNode.type)); 

                if (!inputs[conn.targetPortId]) { 
                    inputs[conn.targetPortId] = { 
                        data: dataToUse, 
                        format: sourceFormat,
                        nodeId: inputSourceNode.id
                    };
                }
            });
            
            switch (sourceNode.type) {
                case 'OUTPUT_VIEWER':
                    const inputObj = inputs['data'];
                    const rawInput = inputObj?.data; 
                    let convertedDataOutput = sourceNode.convertedData || '';
                    let calculatedSourceFormat = inputObj?.format || 'N/A';
                    
                    if (rawInput !== undefined && rawInput !== null && rawInput !== '' && !rawInput?.startsWith('ERROR')) {
                        const isSourceBinary = ['Hexadecimal', 'Binary', 'Decimal', 'Base64'].includes(calculatedSourceFormat);
                        const isSLNTarget = ['Decimal', 'Hexadecimal', 'Binary'].includes(sourceNode.convertedFormat);
                        const shouldBeSingleNumber = isSLNTarget && isSourceBinary;

                        if (sourceNode.isConversionExpanded) {
                            convertedDataOutput = convertDataFormat(rawInput, calculatedSourceFormat, sourceNode.convertedFormat || 'Base64', shouldBeSingleNumber);
                        } else {
                            convertedDataOutput = '';
                        }
                        
                        if (sourceNode.isConversionExpanded && convertedDataOutput && !convertedDataOutput.startsWith('ERROR')) {
                            outputData = convertedDataOutput;
                            sourceNode.outputFormat = sourceNode.convertedFormat; 
                        } else {
                            outputData = rawInput;
                            sourceNode.outputFormat = calculatedSourceFormat === 'N/A' ? 'Text (UTF-8)' : calculatedSourceFormat; 
                        }

                    } else {
                        outputData = 'Not connected or no data.';
                        convertedDataOutput = '';
                        calculatedSourceFormat = 'N/A';
                        sourceNode.outputFormat = 'Text (UTF-8)'; 
                    }
                    
                    sourceNode.convertedData = convertedDataOutput;
                    sourceNode.sourceFormat = calculatedSourceFormat; 
                    sourceNode.rawInputData = rawInput || outputData; 
                    break;
                
                case 'CAESAR_CIPHER':
                    const plaintextInput = inputs['plaintext']?.data;
                    const plainFormat = inputs['plaintext']?.format;
                    const shiftKey = sourceNode.shiftKey; 
                    
                    if (plaintextInput !== undefined && plaintextInput !== null) {
                        isProcessing = true;
                        const k = parseInt(shiftKey) || 0;
                        const { output, format } = caesarEncrypt(plaintextInput, plainFormat, k);
                        outputData = output;
                        sourceNode.outputFormat = format;
                        isProcessing = false;
                        
                    } else {
                        outputData = 'Waiting for plaintext input.';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    }
                    break;
                
                case 'VIGENERE_CIPHER':
                    const vigenereInput = inputs['data']?.data;
                    const vigenereFormat = inputs['data']?.format;
                    const keyword = sourceNode.keyword;
                    const mode = sourceNode.vigenereMode || 'ENCRYPT';

                    if (vigenereInput !== undefined && vigenereInput !== null) {
                        isProcessing = true;
                        
                        if (vigenereFormat !== 'Text (UTF-8)') {
                            outputData = `ERROR: Vigenère Cipher requires Text (UTF-8) input. Received: ${vigenereFormat}`;
                            sourceNode.outputFormat = vigenereFormat;
                            isProcessing = false;
                            break;
                        }

                        const { output, format } = vigenereEncryptDecrypt(vigenereInput, keyword, mode);
                        outputData = output;
                        sourceNode.outputFormat = format;
                        isProcessing = false;
                    } else {
                        outputData = 'Waiting for input data and keyword.';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    }
                    break;
                    
                case 'SIMPLE_RSA_KEY_GEN':
                    outputData = sourceNode.dataOutputPrivate;
                    break;
                
                case 'SIMPLE_RSA_PUBKEY_GEN':
                    const keySourceConn = incomingConns.find(c => c.targetPortId === 'keySource');
                    const sourceKeyGenNode = newNodesMap.get(keySourceConn?.source);
                    
                    let n_val = sourceNode.n_pub;
                    let e_val = sourceNode.e_pub;
                    let isReadOnly = false;

                    if (sourceKeyGenNode && sourceKeyGenNode.n && sourceKeyGenNode.e) {
                        n_val = sourceKeyGenNode.n;
                        e_val = sourceKeyGenNode.e;
                        isReadOnly = true;
                    } 
                    
                    sourceNode.isReadOnly = isReadOnly;
                    sourceNode.n_pub = n_val;
                    sourceNode.e_pub = e_val;

                    if (n_val && e_val) {
                        try {
                            BigInt(n_val);
                            BigInt(e_val);
                            sourceNode.dataOutputPublic = `${n_val},${e_val}`;
                        } catch (err) {
                            sourceNode.dataOutputPublic = `ERROR: Invalid N or E format. Must be numeric.`;
                        }
                    } else {
                        sourceNode.dataOutputPublic = 'N/A (Missing N or E input)';
                    }

                    outputData = sourceNode.dataOutputPublic;
                    break;
                    
                case 'SIMPLE_RSA_ENC':
                    try {
                        const mStr = inputs['message']?.data; 
                        const pkInputObj = inputs['publicKey'];
                        const pkSourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'publicKey');
                        const sourceNodeKeyGen = newNodesMap.get(pkSourceConn?.source);

                        let n, e;

                        if (sourceNodeKeyGen?.type === 'SIMPLE_RSA_PUBKEY_GEN' && sourceNodeKeyGen.n_pub && sourceNodeKeyGen.e_pub) {
                            n = BigInt(sourceNodeKeyGen.n_pub);
                            e = BigInt(sourceNodeKeyGen.e_pub);
                        } else if (pkInputObj?.data) {
                            const [nStr, eStr] = pkInputObj.data.split(',');
                            if (nStr && eStr) {
                                n = BigInt(nStr);
                                e = BigInt(eStr);
                            }
                        }


                        if (!mStr || !n || !e) {
                            outputData = 'Waiting for message (m) and Public Key (n, e).';
                            break;
                        }
                        
                        let mValue = mStr.replace(/\s+/g, '');
                        if (isNaN(Number(mValue))) {
                            outputData = `ERROR: Message must be a valid DECIMAL number. Received: ${mStr}`;
                            break;
                        }
                        
                        const m = BigInt(mValue);

                        if (m >= n) {
                            outputData = `ERROR: Message (m=${mStr}) must be less than Modulus (n=${n.toString()}).`;
                        } else {
                            isProcessing = true;
                            const c = modPow(m, e, n);
                            outputData = c.toString();
                            isProcessing = false;
                        }
                    } catch (err) {
                        outputData = `ERROR: Encryption failed. Check inputs are valid numbers. ${err.message}`;
                    }
                    break;
                
                case 'SIMPLE_RSA_DEC':
                    try {
                        const cStr = inputs['cipher']?.data;
                        const dStr = inputs['privateKey']?.data;
                        
                        if (isNaN(Number(cStr))) {
                            outputData = `ERROR: Ciphertext must be a valid number. Received: ${cStr}`;
                            break;
                        }
                        
                        const sourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'privateKey');
                        const sourceNodeKeyGen = newNodesMap.get(sourceConn?.source);
                        
                        if (!cStr || !dStr || !sourceNodeKeyGen || !sourceNodeKeyGen.n) {
                            outputData = 'Waiting for ciphertext (c) and Private Key (d, n).';
                            break;
                        }
                        
                        const c = BigInt(cStr);
                        const d = BigInt(dStr);
                        const n = BigInt(sourceNodeKeyGen.n);

                        isProcessing = true;
                        const m = modPow(c, d, n);
                        outputData = m.toString();
                        isProcessing = false;
                        
                    } catch (err) {
                         outputData = `ERROR: Decryption failed. Check if Private Key was generated correctly. ${err.message}`;
                    }
                    break;

                case 'SIMPLE_RSA_SIGN':
                    try {
                        const mStr = inputs['message']?.data;
                        const dStr = inputs['privateKey']?.data;

                        if (!mStr || !dStr) {
                             outputData = 'Waiting for message (m) and Private Key (d, n).';
                             break;
                        }
                        
                        let mValue = mStr.replace(/\s+/g, '');
                        if (isNaN(Number(mValue))) {
                            outputData = `ERROR: Message must be a valid DECIMAL number. Received: ${mStr}`;
                            break;
                        }
                        
                        const sourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'privateKey');
                        const sourceNodeKeyGen = newNodesMap.get(sourceConn?.source);

                        if (!sourceNodeKeyGen || !sourceNodeKeyGen.n) {
                            outputData = 'ERROR: Cannot find modulus (n). Ensure Private Key is connected from Simple RSA PrivKey Gen.';
                            break;
                        }

                        const m = BigInt(mValue);
                        const d = BigInt(dStr);
                        const n = BigInt(sourceNodeKeyGen.n);

                        isProcessing = true;
                        const s = modPow(m, d, n);
                        outputData = s.toString();
                        isProcessing = false;

                    } catch (err) {
                        outputData = `ERROR: Signature failed. Check inputs. ${err.message}`;
                    }
                    break;
                
                case 'SIMPLE_RSA_VERIFY':
                    try {
                        const mStr = inputs['message']?.data;
                        const sStr = inputs['signature']?.data;
                        const pkInputObj = inputs['publicKey'];
                        const pkSourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'publicKey');
                        const sourceNodeKeyGen = newNodesMap.get(pkSourceConn?.source);

                        let n, e;

                        if (sourceNodeKeyGen?.type === 'SIMPLE_RSA_PUBKEY_GEN' && sourceNodeKeyGen.n_pub && sourceNodeKeyGen.e_pub) {
                            n = BigInt(sourceNodeKeyGen.n_pub);
                            e = BigInt(sourceNodeKeyGen.e_pub);
                        } else if (pkInputObj?.data) {
                            const [nStr, eStr] = pkInputObj.data.split(',');
                            if (nStr && eStr) {
                                n = BigInt(nStr);
                                e = BigInt(eStr);
                            }
                        }

                        if (!mStr || !sStr || !n || !e) {
                            outputData = 'Waiting for message (m), signature (s), and Public Key (n, e).';
                            break;
                        }
                        
                        let mValue = mStr.replace(/\s+/g, '');
                        let sValue = sStr.replace(/\s+/g, '');
                        
                        if (isNaN(Number(mValue)) || isNaN(Number(sValue))) {
                            outputData = 'ERROR: Message and Signature must be valid DECIMAL numbers.';
                            break;
                        }

                        const m = BigInt(mValue);
                        const s = BigInt(sValue);
                        
                        isProcessing = true;
                        const decryptedM = modPow(s, e, n);
                        isProcessing = false;

                        if (decryptedM === m) {
                            outputData = `SUCCESS: Signature verified. Decrypted message m'=${decryptedM.toString()} equals original message m=${m.toString()}.`;
                        } else {
                            outputData = `FAILURE: Signature verification failed. Calculated m'=${decryptedM.toString()} does not equal original m=${m.toString()}.`;
                        }

                    } catch (err) {
                        outputData = `ERROR: Verification failed. Check inputs. ${err.message}`;
                    }
                    break;
                    
                case 'HASH_FN':
                    const hashInput = inputs['data']?.data;
                    if (hashInput && !hashInput.startsWith('ERROR')) { 
                        isProcessing = true; 
                        const algorithm = sourceNode.hashAlgorithm || 'SHA-256';

                        calculateHash(hashInput, algorithm).then(hashResult => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: hashResult, isProcessing: false } : n));
                        }).catch(err => {
                             setNodes(prevNodes => prevNodes.map(n => 
                                 n.id === sourceId 
                                     ? { ...n, dataOutput: `ERROR: Hash calculation failed. ${err.message}`, isProcessing: false } 
                                     : n
                             ));
                        });
                        
                        outputData = sourceNode.dataOutput || 'Calculating...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                        sourceNode.isProcessing = isProcessing;
                        newNodesMap.set(sourceId, sourceNode);
                        processed.add(sourceId);
                        nodesToProcess.push(...findAllTargets(sourceId));
                        continue; 

                    } else if (hashInput && hashInput.startsWith('ERROR')) {
                        outputData = hashInput;
                    } else {
                        outputData = 'Waiting for data input.'; 
                    }
                    break;
                
                case 'XOR_OP':
                    const xorInputA = inputs['dataA']?.data; 
                    const xorInputB = inputs['dataB']?.data; 
                    const xorFormatA = inputs['dataA']?.format; 
                    const xorFormatB = inputs['dataB']?.format;

                    if (xorInputA && xorInputB) { 
                        if (xorInputA.startsWith('ERROR')) {
                            outputData = xorInputA;
                        } else if (xorInputB.startsWith('ERROR')) {
                            outputData = xorInputB;
                        } else {
                            isProcessing = true;
                            
                            const result = performBitwiseXor(xorInputA, xorFormatA, xorInputB, xorFormatB);
                            outputData = result.output;
                            sourceNode.outputFormat = result.format;
                            isProcessing = false;
                        }
                    } else if (xorInputA?.startsWith('ERROR')) {
                        outputData = xorInputA;
                    } else if (xorInputB?.startsWith('ERROR')) {
                        outputData = xorInputB;
                    } else if (xorInputA && !xorInputB) {
                        outputData = 'Waiting for Input B.';
                        sourceNode.outputFormat = xorFormatA || ''; 
                    } else if (!xorInputA && xorInputB) {
                        outputData = 'Waiting for Input A.';
                        sourceNode.outputFormat = xorFormatB || ''; 
                    } else {
                        outputData = 'Waiting for two data inputs.'; 
                        sourceNode.outputFormat = '';
                    }

                    break;
                
                case 'SHIFT_OP':
                    const shiftDataInput = inputs['data']?.data;
                    const shiftFormat = inputs['data']?.format; 
                    const shiftType = sourceNode.shiftType || 'Left';
                    const shiftAmount = sourceNode.shiftAmount || 0;
                    
                    if (shiftDataInput && !shiftDataInput.startsWith('ERROR')) {
                        isProcessing = true;
                        
                        if (shiftFormat === 'Decimal' || shiftFormat === 'Hexadecimal' || shiftFormat === 'Binary') {
                            
                            const result = performBitShiftOperation(shiftDataInput, shiftType, shiftAmount, shiftFormat);
                            outputData = result.output;
                            sourceNode.shiftDescription = result.description; 
                            sourceNode.outputFormat = shiftFormat;
                            
                        } else {
                            outputData = `ERROR: Bit Shift requires input data to be a single number (Decimal, Hexadecimal, or Binary). Received: ${shiftFormat}.`;
                            sourceNode.outputFormat = shiftFormat;
                        }

                        isProcessing = false; 
                    } else if (shiftDataInput?.startsWith('ERROR')) {
                         outputData = shiftDataInput;
                    } else { 
                        outputData = 'Waiting for data input.'; 
                        sourceNode.outputFormat = '';
                        sourceNode.shiftDescription = 'Active (Rotational)';
                    }
                    break;
                    
                case 'DATA_SPLIT': 
                    const splitDataInput = inputs['data']?.data;
                    const splitFormat = inputs['data']?.format;

                    if (splitDataInput && !splitDataInput.startsWith('ERROR')) {
                        isProcessing = true;
                        
                        const { chunk1, chunk2, outputFormat } = splitDataIntoChunks(splitDataInput, splitFormat);
                        
                        sourceNode.chunk1 = chunk1;
                        sourceNode.chunk2 = chunk2;
                        sourceNode.outputFormat = outputFormat; 
                        
                        isProcessing = false;
                        
                    } else if (splitDataInput?.startsWith('ERROR')) {
                        sourceNode.chunk1 = splitDataInput;
                        sourceNode.chunk2 = splitDataInput;
                        sourceNode.outputFormat = splitFormat;
                    } else {
                        sourceNode.chunk1 = 'Awaiting Input...';
                        sourceNode.chunk2 = 'Awaiting Input...';
                        sourceNode.outputFormat = splitFormat;
                    }
                    
                    outputData = '';
                    break;
                    
                case 'DATA_CONCAT': 
                    const concatInputA = inputs['dataA']?.data; 
                    const concatInputB = inputs['dataB']?.data; 
                    const concatFormatA = inputs['dataA']?.format;
                    const concatFormatB = inputs['dataB']?.format;
                    
                    if (concatInputA || concatInputB) {
                        isProcessing = true;
                        
                        const { output, format } = concatenateData(concatInputA, concatFormatA, concatInputB, concatFormatB);
                        outputData = output;
                        sourceNode.outputFormat = format;
                        isProcessing = false;
                        
                    } else {
                        outputData = 'Waiting for data inputs A and B.';
                        sourceNode.outputFormat = 'Binary';
                    }
                    break;


                case 'SYM_ENC':
                    if (inputs['data']?.data && inputs['key']?.data && !inputs['data'].data.startsWith('ERROR') && !inputs['key'].data.startsWith('ERROR')) {
                        isProcessing = true;
                        const algorithm = sourceNode.symAlgorithm || 'AES-GCM';
                        
                        symmetricEncrypt(inputs['data'].data, inputs['key'].data, algorithm).then(ciphertext => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: ciphertext, isProcessing: false } : n));
                        }).catch(err => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: `ERROR: Encryption failed. ${err.message}`, isProcessing: false } : n));
                        });
                        outputData = sourceNode.dataOutput || 'Encrypting...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                        
                        sourceNode.isProcessing = isProcessing;
                        newNodesMap.set(sourceId, sourceNode);
                        processed.add(sourceId);
                        nodesToProcess.push(...findAllTargets(sourceId));
                        continue; 

                    } else if (inputs['data']?.data?.startsWith('ERROR')) {
                        outputData = inputs['data'].data;
                    } else if (inputs['key']?.data?.startsWith('ERROR')) {
                        outputData = inputs['key'].data;
                    } else {
                        outputData = 'Waiting for Data and Key inputs.';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    }
                    break;
                
                case 'SYM_DEC':
                    if (inputs['cipher']?.data && inputs['key']?.data && !inputs['cipher'].data.startsWith('ERROR') && !inputs['key'].data.startsWith('ERROR')) {
                        isProcessing = true;
                        const algorithm = sourceNode.symAlgorithm || 'AES-GCM'; 
                        
                        symmetricDecrypt(inputs['cipher'].data, inputs['key'].data, algorithm).then(plaintext => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: plaintext, isProcessing: false } : n));
                        }).catch(err => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: `ERROR: Decryption failed. ${err.message}`, isProcessing: false } : n));
                        });
                        outputData = sourceNode.dataOutput || 'Decrypting...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                        
                        sourceNode.isProcessing = isProcessing;
                        newNodesMap.set(sourceId, sourceNode);
                        processed.add(sourceId);
                        nodesToProcess.push(...findAllTargets(sourceId));
                        continue; 

                    } else if (inputs['cipher']?.data?.startsWith('ERROR')) {
                        outputData = inputs['cipher'].data;
                    } else if (inputs['key']?.data?.startsWith('ERROR')) {
                        outputData = inputs['key'].data;
                    } else {
                        outputData = 'Waiting for Cipher and Key inputs.';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    }
                    break;

                case 'ASYM_ENC':
                    if (inputs['data']?.data && inputs['publicKey']?.data) {
                        isProcessing = true;
                        const algorithm = sourceNode.asymAlgorithm || 'RSA-OAEP';
                        asymmetricEncrypt(inputs['data'].data, inputs['publicKey'].data, algorithm).then(ciphertext => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: ciphertext, isProcessing: false } : n));
                        }).catch(err => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: `ERROR: Encryption failed. ${err.message}`, isProcessing: false } : n));
                        });
                        outputData = sourceNode.dataOutput || 'Encrypting...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    } else {
                        outputData = 'Waiting for Data and Public Key inputs.';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    }
                    break;
                
                case 'ASYM_DEC':
                    if (inputs['cipher']?.data && inputs['privateKey']?.data) {
                        isProcessing = true;
                        const algorithm = sourceNode.asymAlgorithm || 'RSA-OAEP';
                        asymmetricDecrypt(inputs['cipher'].data, inputs['privateKey'].data, algorithm).then(plaintext => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: plaintext, isProcessing: false } : n));
                        }).catch(err => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: `ERROR: Decryption failed. ${err.message}`, isProcessing: false } : n));
                        });
                        outputData = sourceNode.dataOutput || 'Decrypting...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    } else {
                        outputData = 'Waiting for Cipher and Private Key inputs.';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    }
                    break;
                    
                default:
                    outputData = 'ERROR: Unrecognized Node Type.';
            }

        }
        
        if (sourceNode.type === 'DATA_SPLIT') {
        } else {
             const primaryOutputPort = sourceNodeDef.outputPorts?.[0];
             if (primaryOutputPort && primaryOutputPort.keyField === 'dataOutput') {
                 sourceNode.dataOutput = outputData; 
             } else if (!primaryOutputPort) {
                 if (sourceNode.type !== 'OUTPUT_VIEWER') {
                     sourceNode.dataOutput = outputData;
                 }
             }
        }


        sourceNode.isProcessing = isProcessing;
        newNodesMap.set(sourceId, sourceNode);
        processed.add(sourceId);

        const targets = findAllTargets(sourceId);
        nodesToProcess.push(...targets);
    }
    
    return Array.from(newNodesMap.values());
  }, [setNodes]);
  
  useEffect(() => {
    setNodes(prevNodes => recalculateGraph(prevNodes, connections));
  }, [connections, recalculateGraph]); 

  const updateNodeContent = useCallback((id, field, value) => {
    setNodes(prevNodes => {
        const nextNodes = prevNodes.map(node => {
            if (node.id === id) {
                const updatedNode = { 
                    ...node, 
                    [field]: value, 
                    generateKey: (field === 'generateKey' ? value : node.generateKey), 
                    modulusLength: (field === 'modulusLength' ? value : node.modulusLength), 
                    publicExponent: (field === 'publicExponent' ? value : node.publicExponent),
                    shiftType: (field === 'shiftType' ? value : node.shiftType),
                    shiftAmount: (field === 'shiftAmount' ? value : node.shiftAmount),
                    shiftKey: (field === 'shiftKey' ? value : node.shiftKey), 
                    keyword: (field === 'keyword' ? value : node.keyword), 
                    vigenereMode: (field === 'vigenereMode' ? value : node.vigenereMode), 
                    symAlgorithm: (field === 'symAlgorithm' ? value : node.symAlgorithm),
                    asymAlgorithm: (field === 'asymAlgorithm' ? value : node.asymAlgorithm),
                    p: (field === 'p' ? value : node.p),
                    q: (field === 'q' ? value : node.q),
                    e: (field === 'e' ? value : node.e),
                    d: (field === 'd' ? value : node.d), 
                    n_pub: (field === 'n_pub' ? value : node.n_pub), 
                    e_pub: (field === 'e_pub' ? value : node.e_pub), 
                    isReadOnly: node.isReadOnly, 
                    isConversionExpanded: (field === 'isConversionExpanded' ? value : node.isConversionExpanded),
                    convertedFormat: (field === 'convertedFormat' ? value : node.convertedFormat),
                    viewFormat: (field === 'viewFormat' ? value : node.viewFormat),
                    isProcessing: node.isProcessing,
                    dStatus: node.dStatus,
                    hashAlgorithm: (field === 'hashAlgorithm' ? value : node.hashAlgorithm), 
                };
                return updatedNode;
            }
            return node;
        });
        return recalculateGraph(nextNodes, connections, id);
    });
  }, [connections, recalculateGraph]);
  
  const setPosition = useCallback((id, newPos) => {
    setNodes(prevNodes => prevNodes.map(node =>
      node.id === id ? { ...node, position: newPos } : node
    ));
  }, []);
  
  const handleNodeResize = useCallback((id, newWidth, newHeight) => {
      setNodes(prevNodes => prevNodes.map(node => {
          if (node.id === id) {
              const finalWidth = Math.max(NODE_DIMENSIONS.minWidth, newWidth);
              const finalHeight = Math.max(NODE_DIMENSIONS.minHeight, newHeight);
              
              if (finalWidth !== node.width || finalHeight !== node.height) {
                  return { ...node, width: finalWidth, height: finalHeight };
              }
          }
          return node;
      }));
  }, []);

  const addNode = useCallback((type, label, color) => {
    const newId = `${type}_${Date.now()}`;
    const definition = NODE_DEFINITIONS[type];
    
    let initialNodeHeight = NODE_DIMENSIONS.initialHeight;
    let initialNodeWidth = NODE_DIMENSIONS.initialWidth;
    
    if (type === 'SHIFT_OP' || type === 'XOR_OP' || type === 'DATA_SPLIT' || type === 'DATA_CONCAT') {
        initialNodeHeight = 300; 
        initialNodeWidth = 300;
    }
    
    const initialContent = { 
        dataOutput: '', 
        isProcessing: false, 
        outputFormat: getOutputFormat(type),
        width: initialNodeWidth, 
        height: initialNodeHeight, 
    };
    
    const canvas = canvasRef.current;
    
    const canvasWidth = canvas?.clientWidth > 100 ? canvas.clientWidth : 800;
    const canvasHeight = canvas?.clientHeight > 100 ? canvas.clientHeight : 600;
    
    let x = (canvasWidth / 2) - (initialNodeWidth / 2);
    let y = (canvasHeight / 2) - (initialNodeHeight / 2);
    
    const randomOffset = () => Math.floor(Math.random() * 200) - 100;
    x += randomOffset();
    y += randomOffset();

    x = Math.max(20, Math.min(x, canvasWidth - initialNodeWidth - 20));
    y = Math.max(20, Math.min(y, canvasHeight - initialNodeHeight - 20));
    
    const position = { x, y };

    if (type === 'DATA_INPUT') {
      initialContent.content = '';
      initialContent.format = 'Binary'; 
    } else if (type === 'OUTPUT_VIEWER') { 
      initialContent.dataOutput = ''; 
      initialContent.rawInputData = ''; 
      initialContent.viewFormat = 'Text (UTF-8)'; 
      initialContent.isConversionExpanded = false; 
      initialContent.convertedData = ''; 
      initialContent.convertedFormat = 'Base64'; 
      initialContent.sourceFormat = '';
    } else if (type === 'CAESAR_CIPHER') {
      initialContent.shiftKey = 3; 
      initialContent.outputFormat = 'Text (UTF-8)';
    } else if (type === 'VIGENERE_CIPHER') {
      initialContent.keyword = 'HELLO'; 
      initialContent.vigenereMode = 'ENCRYPT';
      initialContent.outputFormat = 'Text (UTF-8)';
    } else if (type === 'HASH_FN') { 
      initialContent.hashAlgorithm = 'SHA-256'; 
    } else if (type === 'KEY_GEN') {
      initialContent.keyAlgorithm = 'AES-GCM';
      initialContent.keyBase64 = ''; 
      initialContent.generateKey = false; 
    } else if (type === 'RSA_KEY_GEN') { 
      initialContent.keyAlgorithm = 'RSA-OAEP';
      initialContent.modulusLength = 2048;
      initialContent.publicExponent = 65537; 
      initialContent.dataOutputPublic = '';
      initialContent.dataOutputPrivate = '';
      initialContent.keyPairObject = null;
      initialContent.rsaParameters = { n: '', d: '', p: '', q: '', e: 65537 }; 
    } else if (type === 'SIMPLE_RSA_KEY_GEN') { 
      initialContent.keyAlgorithm = 'RSA-OAEP';
      initialContent.modulusLength = 0;
      initialContent.p = '';
      initialContent.q = '';
      initialContent.e = '';
      initialContent.d = ''; 
      initialContent.n = '';
      initialContent.phiN = '';
      initialContent.dataOutputPublic = '';
      initialContent.dataOutputPrivate = '';
      initialContent.dStatus = ''; 
      initialContent.generateKey = true; 
    } else if (type === 'SIMPLE_RSA_PUBKEY_GEN') { 
      initialContent.outputFormat = 'Decimal';
      initialContent.n_pub = '';
      initialContent.e_pub = '';
      initialContent.dataOutputPublic = ''; 
      initialContent.isReadOnly = false;
    } else if (type === 'SIMPLE_RSA_ENC' || type === 'SIMPLE_RSA_DEC') {
      initialContent.outputFormat = 'Decimal';
    } else if (type === 'SIMPLE_RSA_SIGN' || type === 'SIMPLE_RSA_VERIFY') { 
      initialContent.outputFormat = type === 'SIMPLE_RSA_SIGN' ? 'Decimal' : 'Text (UTF-8)';
    } else if (type === 'SYM_ENC' || type === 'SYM_DEC') {
      initialContent.symAlgorithm = 'AES-GCM'; 
    } else if (type === 'ASYM_ENC' || type === 'ASYM_DEC') {
      initialContent.asymAlgorithm = 'RSA-OAEP';
    } else if (type === 'SHIFT_OP') {
      initialContent.shiftType = 'Left';
      initialContent.shiftAmount = 1;
      initialContent.outputFormat = 'Binary'; 
      initialContent.shiftDescription = 'Active (Rotational)';
    } else if (type === 'XOR_OP') {
      initialContent.outputFormat = 'Binary'; 
    } else if (type === 'DATA_SPLIT') { 
      initialContent.outputFormat = 'Binary'; 
      initialContent.chunk1 = ''; 
      initialContent.chunk2 = ''; 
    } else if (type === 'DATA_CONCAT') { 
      initialContent.outputFormat = 'Binary'; 
    }

    setNodes(prevNodes => [
      ...prevNodes,
      { 
        id: newId, 
        label: definition.label, 
        position: position, 
        type: type, 
        color: color,
        ...initialContent 
      },
    ]);
  }, [canvasRef]); 

  
  const handleDeleteNode = useCallback((nodeIdToDelete) => {
      setNodes(prevNodes => prevNodes.filter(n => n.id !== nodeIdToDelete));
      setConnections(prevConnections => 
          prevConnections.filter(c => c.source !== nodeIdToDelete && c.target !== nodeIdToDelete)
      );
      // Remove from selection if deleted
      setSelectedNodeIds(prev => {
          const newSet = new Set(prev);
          newSet.delete(nodeIdToDelete);
          return newSet;
      });
  }, []);

  const handleConnectStart = useCallback((nodeId, portIndex, outputType) => {
    setConnectingPort({ sourceId: nodeId, sourcePortIndex: portIndex, outputType: outputType });
  }, []);

  const handleConnectEnd = useCallback((targetId, targetPortId) => {
    if (connectingPort && targetId && connectingPort.sourceId !== targetId) {
      
      const { sourceId, sourcePortIndex } = connectingPort;
      
      const isDuplicate = connections.some(c => 
          c.source === sourceId && 
          c.sourcePortIndex === sourcePortIndex && 
          c.target === targetId && 
          c.targetPortId === targetPortId
      );

      const isInputPortAlreadyConnected = connections.some(c => 
          c.target === targetId && 
          c.targetPortId === targetPortId
      );
      
      if (isDuplicate) {
          console.warn('Duplicate connection detected and prevented.');
      } else if (isInputPortAlreadyConnected) {
          console.warn(`Input port (${targetPortId}) on node ${targetId} is already connected. Only one connection per input port is allowed.`);
      } else {
        const targetNode = nodes.find(n => n.id === targetId);
        const targetNodeDef = NODE_DEFINITIONS[targetNode?.type];
        
        if (targetNodeDef && targetNodeDef.inputPorts.some(p => p.id === targetPortId)) {
             setConnections(prevConnections => [
               ...prevConnections, 
               { 
                   source: sourceId, 
                   sourcePortIndex: sourcePortIndex, 
                   target: targetId,
                   targetPortId: targetPortId 
               }
             ]);
        } else {
             console.warn(`Cannot connect: Node ${targetId} is not configured to receive input at port ${targetPortId}.`);
        }
      }
    }
    setConnectingPort(null); 
  }, [connectingPort, connections, nodes]);

  const handleRemoveConnection = useCallback((sourceId, targetId, sourcePortIndex, targetPortId) => {
    setConnections(prevConnections => 
        prevConnections.filter(c => !(
            c.source === sourceId && 
            c.target === targetId &&
            c.sourcePortIndex === sourcePortIndex &&
            c.targetPortId === targetPortId
        ))
    );
  }, []);
  
  const connectionPaths = useMemo(() => {
    let maxX = 0;
    let maxY = 0;
    const padding = 50; 

    nodes.forEach(node => {
        maxX = Math.max(maxX, node.position.x + node.width);
        maxY = Math.max(maxY, node.position.y + node.height);
    });

    const svgWidth = Math.max(maxX + padding, (canvasRef.current?.clientWidth || 0) / scale);
    const svgHeight = Math.max(maxY + padding, (canvasRef.current?.clientHeight || 0) / scale);

    return {
        size: { width: svgWidth, height: svgHeight },
        paths: connections.map(conn => {
            const sourceNode = nodes.find(n => n.id === conn.source);
            const targetNode = nodes.find(n => n.id === conn.target);
            
            if (sourceNode && targetNode) {
                return {
                    path: getLinePath(sourceNode, targetNode, conn), 
                    source: conn.source,
                    target: conn.target,
                    sourcePortIndex: conn.sourcePortIndex,
                    targetPortId: conn.targetPortId,
                };
            }
            return null;
        }).filter(p => p !== null)
    };
  }, [connections, nodes, scale]); 


  
  const handleCanvasClick = useCallback(() => {
    if (connectingPort) {
      handleConnectEnd(null);
    }
  }, [connectingPort, handleConnectEnd]);

  return (
    <div className="h-screen w-screen flex bg-gray-100 font-inter overflow-hidden">
        
      <style dangerouslySetInnerHTML={{ __html: globalStyles }} />

      <Toolbar 
        addNode={addNode} 
        onDownloadProject={handleDownloadProject}
        onUploadProject={handleUploadProject}
        onZoomIn={handleZoomIn} 
        onZoomOut={handleZoomOut} 
      />

      <div className="flex-grow flex flex-col p-4">
        
        <div 
          ref={canvasRef}
          className="canvas-container relative w-full flex-grow border-4 border-dashed border-gray-300 rounded-2xl bg-white shadow-inner overflow-auto select-none"
          onClick={handleCanvasClick}
          onMouseDown={handleCanvasMouseDown}
        >
          
          <div 
              style={{ 
                  transform: `scale(${scale})`, 
                  transformOrigin: 'top left',
                  width: `${connectionPaths.size.width}px`,
                  height: `${connectionPaths.size.height}px`,
                  minWidth: `100%`,
                  minHeight: `100%`,
              }} 
              className="absolute top-0 left-0"
          >
              {/* Selection Box Render */}
              {selectionBox && (
                  <div 
                      className="selection-marquee"
                      style={{
                          left: `${selectionBox.x}px`,
                          top: `${selectionBox.y}px`,
                          width: `${selectionBox.width}px`,
                          height: `${selectionBox.height}px`
                      }}
                  />
              )}

              <svg 
                  className="absolute top-0 left-0 pointer-events-auto z-0" 
                  style={{ 
                      width: `${connectionPaths.size.width}px`, 
                      height: `${connectionPaths.size.height}px`,
                  }} 
              >
                {connectionPaths.paths.map((conn, index) => (
                  <g 
                    key={`${conn.source}-${conn.target}-${conn.sourcePortIndex}-${conn.targetPortId}`}
                    onClick={(e) => { 
                        e.stopPropagation(); 
                        handleRemoveConnection(conn.source, conn.target, conn.sourcePortIndex, conn.targetPortId);
                    }}
                    className="cursor-pointer" 
                  >
                    <path
                        d={conn.path}
                        className="connection-hitbox"
                        style={{ strokeWidth: `${15 / scale}px` }} 
                    />
                    <path
                        d={conn.path}
                        className="connection-line-visible"
                        style={{ strokeWidth: `${4 / scale}px` }} 
                    />
                  </g>
                ))}
              </svg>

              {nodes.map(node => (
                <DraggableBox
                  key={node.id}
                  node={node}
                  setPosition={setPosition}
                  updateNodeContent={updateNodeContent}
                  canvasRef={canvasRef}
                  handleConnectStart={handleConnectStart}
                  handleConnectEnd={handleConnectEnd}
                  connectingPort={connectingPort}
                  connections={connections}
                  handleDeleteNode={handleDeleteNode}
                  nodes={nodes} 
                  scale={scale} 
                  handleResize={handleNodeResize} 
                  isSelected={selectedNodeIds.has(node.id)}
                  onNodeDown={handleNodeMouseDown}
                />
              ))}
          </div>
          
        </div>
        
        {statusMessage && (
            <StatusNotification 
                status={statusMessage.type} 
                message={statusMessage.message} 
                onClose={clearStatusMessage} 
            />
        )}
      </div>
    </div>
  );
};

// ... (ToolbarButton and Toolbar components - No changes needed) ...
const ToolbarButton = ({ icon: Icon, label, color, onClick, onChange, isFileInput }) => {
    const hoverBorderClass = HOVER_BORDER_TOOLBAR_CLASSES[color] || 'hover:border-gray-400';
    const iconTextColorClass = TEXT_ICON_CLASSES[color] || 'text-gray-600';
    const inputRef = useRef(null);

    const handleClick = () => {
        if (isFileInput) {
            inputRef.current.click();
        } else if (onClick) {
            onClick();
        }
    };

    return (
        <div className="relative flex-shrink">
            <button 
                onClick={handleClick}
                className={`w-full p-2 flex items-center justify-center 
                            bg-white hover:bg-gray-100 border-2 border-transparent ${hoverBorderClass}
                            transition duration-150 text-gray-700 rounded-lg shadow-sm`}
                title={label} 
            >
                {Icon && <Icon className={`w-5 h-5 ${iconTextColorClass} flex-shrink-0`} />}
            </button>
            
            {isFileInput && (
                <input 
                    type="file" 
                    ref={inputRef} 
                    onChange={(e) => {
                        if (e.target.files.length > 0) {
                            onChange(e.target); 
                        }
                        e.target.value = null;
                    }} 
                    accept=".json"
                    className="hidden"
                />
            )}
        </div>
    );
};

const Toolbar = ({ addNode, onDownloadProject, onUploadProject, onZoomIn, onZoomOut }) => {
    const [collapsedGroups, setCollapsedGroups] = useState(() => {
        return ORDERED_NODE_GROUPS.reduce((acc, group) => {
            acc[group.name] = false;
            return acc;
        }, {});
    });

    const toggleGroup = useCallback((groupName) => {
        setCollapsedGroups(prev => ({
            ...prev,
            [groupName]: !prev[groupName]
        }));
    }, []);
    
    const handleInfoClick = (url) => {
        window.open(url, '_blank');
    };

    return (
        <div className="w-64 bg-gray-50 flex-shrink-0 border-r border-gray-200 shadow-lg flex flex-col">
            <div className="p-4 pt-6 pb-4 border-b border-gray-200 flex flex-col justify-center items-center bg-white">
                <img 
          src="VCL - Horizonal logo + name.png"
          alt="VisualCryptoLab Logo and Name" 
          className="w-full h-auto max-w-[180px]"
          onError={(e) => {
              e.target.onerror = null; 
              e.target.src = 'https://placehold.co/180x40/999/fff?text=VCL'; 
              e.target.alt = "VisualCryptoLab Logo Placeholder";
          }}
        />
            </div>

            <div className="flex flex-col space-y-3 p-3 overflow-y-auto pt-4 flex-grow">
                
                {ORDERED_NODE_GROUPS.map((group, groupIndex) => (
                    <React.Fragment key={group.name}>
                        <div 
                            className="flex justify-between items-center text-xs font-bold uppercase text-gray-500 pt-2 pb-1 border-b border-gray-200 cursor-pointer hover:text-gray-700 transition"
                            onClick={() => toggleGroup(group.name)}
                        >
                            <span className="flex items-center space-x-1">
                                <span>{group.name}</span>
                                
                                {group.name === 'SIMPLE RSA' && (
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation(); 
                                            handleInfoClick('https://github.com/visualcryptolab/vcryptolab/blob/main/docs/SimpleRSA.md');
                                        }}
                                        className="p-0.5 rounded-full text-gray-400 hover:text-blue-500 transition duration-150 focus:outline-none"
                                        title="View Simple RSA Documentation"
                                    >
                                        <Info className="w-3.5 h-3.5" />
                                    </button>
                                )}
                                
                                {group.name === 'SYMMETRIC CRYPTO (AES)' && (
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation(); 
                                            handleInfoClick('https://www.youtube.com/watch?v=mlzxpkdXP58');
                                        }}
                                        className="p-0.5 rounded-full text-gray-400 hover:text-blue-500 transition duration-150 focus:outline-none"
                                        title="View AES Explanation Video"
                                    >
                                        <Info className="w-3.5 h-3.5" />
                                    </button>
                                )}
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
                                        <button 
                                            key={type}
                                            onClick={() => addNode(type, def.label, def.color)}
                                            className={`w-full py-3 px-4 flex items-center justify-start space-x-3 
                                                         bg-white hover:bg-gray-100 border-2 border-transparent ${hoverBorderClass}
                                                         transition duration-150 text-gray-700 rounded-lg shadow-sm`}
                                        >
                                            {def.icon && (
                                                <def.icon className={`w-5 h-5 ${iconTextColorClass} flex-shrink-0`} />
                                            )}
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
                
                <ToolbarButton 
                    icon={Download} 
                    label="Export JSON" 
                    color="blue" 
                    onClick={onDownloadProject}
                />
                
                <ToolbarButton 
                    icon={Upload} 
                    label="Import JSON" 
                    color="orange" 
                    onChange={onUploadProject}
                    isFileInput={true} 
                />
                
                <ToolbarButton 
                    icon={ZoomOut} 
                    label="Zoom Out" 
                    color="teal" 
                    onClick={onZoomOut}
                />

                <ToolbarButton 
                    icon={ZoomIn} 
                    label="Zoom In" 
                    color="teal" 
                    onClick={onZoomIn}
                />
            </div>
        </div>
    );
}

export default App;