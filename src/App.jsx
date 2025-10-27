import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { LayoutGrid, Cpu, Key, Zap, Settings, Lock, Unlock, Hash, Clipboard, X, ArrowLeft, ArrowRight, Download, Upload, Camera, ChevronDown, ChevronUp, CheckCheck, Fingerprint, Signature, ZoomIn, ZoomOut } from 'lucide-react'; 

// NOTE: For the 'Download Diagram (JPG)' feature to work, the html2canvas library 
// needs to be loaded globally in the consuming environment. This is included in index.html.


// --- Custom XOR Icon Component (The mathematical $\oplus$ symbol) ---
const XORIcon = (props) => (
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

// --- Custom Bit Shift Icon Component (The $\rightleftharpoons$ symbol) ---
const BitShiftIcon = (props) => (
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


// =================================================================
// 1. HELPER CONSTANTS & STATIC TAILWIND CLASS MAPS
// =================================================================

// --- Static Tailwind Class Maps (Ensures no dynamic class generation) ---

const BORDER_CLASSES = {
  blue: 'border-blue-600', red: 'border-red-600', orange: 'border-orange-600', cyan: 'border-cyan-600', pink: 'border-pink-500', 
  teal: 'border-teal-600', gray: 'border-gray-600', lime: 'border-lime-600', indigo: 'border-indigo-600',
  purple: 'border-purple-600', // Simple RSA PrivKey Gen
  maroon: 'border-red-800', // Simple RSA Encrypt
  rose: 'border-pink-700', // Simple RSA Decrypt
  amber: 'border-amber-500', // Caesar Cipher
  yellow: 'border-yellow-400', // Vigenere Cipher
  fuchsia: 'border-fuchsia-600', // RSA Signature
};

const HOVER_BORDER_CLASSES = {
  blue: 'hover:border-blue-500', red: 'hover:border-red-500', orange: 'hover:border-orange-500', cyan: 'hover:border-cyan-500', pink: 'hover:border-pink-500', 
  teal: 'hover:border-teal-500', gray: 'hover:border-gray-500', lime: 'hover:border-lime-500', indigo: 'hover:border-indigo-500',
  purple: 'hover:border-purple-500',
  maroon: 'hover:border-red-700',
  rose: 'hover:border-pink-600',
  amber: 'hover:border-amber-400',
  yellow: 'hover:border-yellow-300',
  fuchsia: 'hover:border-fuchsia-500',
};

const TEXT_ICON_CLASSES = {
  blue: 'text-blue-600', red: 'text-red-600', orange: 'text-orange-600', cyan: 'text-cyan-600', pink: 'text-pink-500', 
  teal: 'text-teal-600', gray: 'text-gray-600', lime: 'text-lime-600', indigo: 'text-indigo-600',
  purple: 'text-purple-600',
  maroon: 'text-red-800',
  rose: 'text-pink-700',
  amber: 'text-amber-500',
  yellow: 'text-yellow-400',
  fuchsia: 'text-fuchsia-600',
  // REMOVED DUPLICATE 'lime' KEY: lime: 'text-lime-600',
};

const HOVER_BORDER_TOOLBAR_CLASSES = {
  blue: 'hover:border-blue-400', red: 'hover:border-red-400', orange: 'hover:border-orange-400', cyan: 'hover:border-cyan-400', pink: 'hover:border-pink-400', 
  teal: 'hover:border-teal-400', gray: 'hover:border-gray-400', lime: 'hover:border-lime-400', indigo: 'hover:border-indigo-400',
  purple: 'hover:border-purple-400',
  maroon: 'hover:border-red-600',
  rose: 'hover:border-pink-600',
  amber: 'hover:border-amber-400',
  yellow: 'hover:border-yellow-300',
  fuchsia: 'hover:border-fuchsia-400',
};

// --- Port Configuration ---
const PORT_SIZE = 4; // w-4 h-4
const PORT_VISUAL_OFFSET_PX = 8; // Half port width in pixels
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
    // ADDED: Output port to send data (converted or raw) downstream
    outputPorts: [{ name: 'Viewer Data Output', type: 'data', keyField: 'dataOutput' }] 
  },
  
  // --- Classic Cipher Nodes ---
  CAESAR_CIPHER: {
    label: 'Caesar Cipher',
    color: 'amber',
    icon: Lock, // Using Lock icon as it is a cipher
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
        // The output stores the D value, but the node itself internally stores N and E for the PubKey Gen node
        { name: 'Private Key (d)', type: 'private', keyField: 'dataOutputPrivate' } 
    ]
  },
    
  // NEW: Simple RSA Public Key Generator
  SIMPLE_RSA_PUBKEY_GEN: {
    label: 'Simple RSA PubKey Gen',
    color: 'lime', 
    icon: Unlock, 
    inputPorts: [
        // This port is optional. If connected, it sources N and E from the Private Key Gen node
        { name: 'Private Key Source', type: 'private', mandatory: false, id: 'keySource' } 
    ],
    outputPorts: [
        // This output is the (n, e) combination for downstream encryption/verification
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
        // Changed to 'data' for BigInt string message compatibility
        { name: 'Message (m)', type: 'data', mandatory: true, id: 'message' }, 
        // MODIFIED PORT TYPE: Public key input uses 'public' type port
        { name: 'Public Key (n, e)', type: 'public', mandatory: true, id: 'publicKey' }
    ],
    // CHANGED OUTPUT TYPE: from 'number' to 'data' to connect to Output Viewer
    outputPorts: [{ name: 'Ciphertext (c)', type: 'data', keyField: 'dataOutput' }] 
  },

  SIMPLE_RSA_DEC: {
    label: 'Simple RSA Decrypt',
    color: 'rose',
    icon: Unlock,
    inputPorts: [
        // CHANGED INPUT TYPE: from 'number' to 'data' to connect from Encrypt or Data Input
        { name: 'Ciphertext (c)', type: 'data', mandatory: true, id: 'cipher' }, 
        { name: 'Private Key (d)', type: 'private', mandatory: true, id: 'privateKey' }
    ],
    // CHANGED OUTPUT TYPE: from 'number' to 'data' to connect to Output Viewer
    outputPorts: [{ name: 'Plaintext (m)', type: 'data', keyField: 'dataOutput' }]
  },

  // --- Simple RSA Signature Nodes ---
  SIMPLE_RSA_SIGN: {
      label: 'Simple RSA Sign',
      color: 'fuchsia',
      icon: Signature, // Changed to Signature icon
      inputPorts: [
          // CHANGED INPUT TYPE: from 'number' to 'data' for consistency
          { name: 'Message (m)', type: 'data', mandatory: true, id: 'message' },
          { name: 'Private Key (d)', type: 'private', mandatory: true, id: 'privateKey' }
      ],
      // CHANGED OUTPUT TYPE: from 'signature' to 'data' to connect to Output Viewer
      outputPorts: [{ name: 'Signature (s)', type: 'data', keyField: 'dataOutput' }]
  },

  SIMPLE_RSA_VERIFY: {
      label: 'Simple RSA Verify',
      color: 'fuchsia',
      icon: CheckCheck,
      inputPorts: [
          // CHANGED INPUT TYPE: from 'number' to 'data' for consistency
          { name: 'Message (m)', type: 'data', mandatory: true, id: 'message' },
          // CHANGED INPUT TYPE: from 'signature' to 'data' to connect from Sign output
          { name: 'Signature (s)', type: 'data', mandatory: true, id: 'signature' },
          // MODIFIED PORT TYPE: Public key input uses 'public' type port
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

  // --- Utility Nodes ---
  HASH_FN: { label: 'Hash Function', color: 'gray', icon: Hash, 
    inputPorts: [{ name: 'Data Input', type: 'data', mandatory: true, id: 'data' }], 
    outputPorts: [{ name: 'Hash Output', type: 'data', keyField: 'dataOutput' }] },

  XOR_OP: { label: 'XOR Operation', color: 'lime', icon: XORIcon, // Updated icon
    inputPorts: [
        { name: 'Input A', type: 'data', mandatory: true, id: 'dataA' }, 
        { name: 'Input B', type: 'data', mandatory: true, id: 'dataB' }
    ], 
    outputPorts: [{ name: 'Result', type: 'data', keyField: 'dataOutput' }] },
    
  SHIFT_OP: { label: 'Bit Shift', color: 'indigo', icon: BitShiftIcon, // Updated icon
    inputPorts: [{ name: 'Data Input', type: 'data', mandatory: true, id: 'data' }], 
    outputPorts: [{ name: 'Result', type: 'data', keyField: 'dataOutput' }] },
};

// --- Defines the desired rendering order for the toolbar ---
const ORDERED_NODE_GROUPS = [
    // Consolidated 'DATA_INPUT', 'OUTPUT_VIEWER', 'HASH_FN', 'XOR_OP', 'SHIFT_OP' into CORE TOOLS
    { name: 'CORE TOOLS', types: ['DATA_INPUT', 'OUTPUT_VIEWER', 'HASH_FN', 'XOR_OP', 'SHIFT_OP'] },
    { name: 'CLASSIC CIPHERS', types: ['CAESAR_CIPHER', 'VIGENERE_CIPHER'] }, 
    // MODIFIED: Changed name from 'SIMPLE RSA (MODULAR)' to 'SIMPLE RSA'
    { name: 'SIMPLE RSA', types: ['SIMPLE_RSA_KEY_GEN', 'SIMPLE_RSA_PUBKEY_GEN', 'SIMPLE_RSA_ENC', 'SIMPLE_RSA_DEC', 'SIMPLE_RSA_SIGN', 'SIMPLE_RSA_VERIFY'] }, 
    { name: 'SYMMETRIC (AES)', types: ['KEY_GEN', 'SYM_ENC', 'SYM_DEC'] },
    { name: 'ADVANCED ASYMMETRIC (WEB CRYPTO)', types: ['RSA_KEY_GEN', 'ASYM_ENC', 'ASYM_DEC'] },
    // Removed old 'BITWISE & HASH' category
];

// Initial nodes on the canvas
const INITIAL_NODES = []; // Set to empty array to start clean

const INITIAL_CONNECTIONS = []; // No initial connections

const BOX_SIZE = { width: 192, minHeight: 144 }; // w-48 is 192px

// =================================================================
// 2. CRYPTO & UTILITY FUNCTIONS
// =================================================================

/** Calculates (base^exponent) mod modulus using BigInt for large numbers. */
const modPow = (base, exponent, modulus) => {
    // Uses BigInt for large numbers.
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
const gcd = (a, b) => {
    while (b) {
        [a, b] = [b, a % b];
    }
    return a;
};

/** Calculates the modular multiplicative inverse (d) of 'e' modulo 'phi(n)'.
 * Uses the Extended Euclidean Algorithm, compatible with BigInt.
 */
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

// --- Simple RSA Key Generation Functions ---

// Simple primes for demo purposes to avoid huge BigInts and slow arithmetic
const DEMO_PRIMES = [167, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283];

/** Finds two random distinct prime numbers from the DEMO_PRIMES array. */
const generateSmallPrimes = () => {
    let p = 0;
    let q = 0;
    while (p === q) {
        p = DEMO_PRIMES[Math.floor(Math.random() * DEMO_PRIMES.length)];
        q = DEMO_PRIMES[Math.floor(Math.random() * DEMO_PRIMES.length)];
    }
    return { p: BigInt(p), q: BigInt(q) };
};

/** Generates a random valid public exponent 'e' for the given phi(n). */
const generateSmallE = (phiN) => {
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
const caesarEncrypt = (inputData, inputFormat, k) => {
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
            // (charCode - 65 + shift) mod 26 + 65
            const encryptedCode = ((charCode - 65 + shift) % 26) + 65;
            ciphertext += String.fromCharCode(encryptedCode);
        } else if (charCode >= 97 && charCode <= 122) { // Lowercase (a=97, z=122)
            // (charCode - 97 + shift) mod 26 + 97
            const encryptedCode = ((charCode - 97 + shift) % 26) + 97;
            ciphertext += String.fromCharCode(encryptedCode);
        } else {
            // Non-alphabetic characters are left unchanged
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
    const direction = mode === 'ENCRYPT' ? 1 : -1;

    for (let i = 0; i < plaintext.length; i++) {
        const char = plaintext[i];
        const charCode = char.charCodeAt(0);

        if ((charCode >= 65 && charCode <= 90) || (charCode >= 97 && charCode <= 122)) {
            // 1. Get the shift value (k_i) from the keyword
            const keyChar = keyWord[keyIndex % keyWord.length];
            let keyShift = keyChar.toUpperCase().charCodeAt(0) - 65;

            // 2. Determine base (A=65 or a=97)
            let base = 0;
            if (charCode >= 65 && charCode <= 90) {
                base = 65; // Uppercase
            } else {
                base = 97; // Lowercase
            }

            // 3. Calculate new position: (m_i + k_i) mod 26 or (c_i - k_i) mod 26
            let charOffset = charCode - base;
            
            let encryptedOffset;
            
            if (mode === 'ENCRYPT') {
                encryptedOffset = (charOffset + keyShift) % alphabetSize;
            } else {
                // Decryption: (charOffset - keyShift + 26) mod 26
                encryptedOffset = (charOffset - keyShift + alphabetSize) % alphabetSize;
            }

            // 4. Convert back to character
            result += String.fromCharCode(encryptedOffset + base);
            
            // 5. Advance key index only if an alphabetic character was processed
            keyIndex++;
        } else {
            // Non-alphabetic characters are left unchanged and do not advance the key
            result += char;
        }
    }

    return { output: result, format: 'Text (UTF-8)' };
};


// --- Standard Data Conversion Functions ---

/** Converts ArrayBuffer to Base64 URL-safe string. */
const arrayBufferToBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

/** Converts Base64 URL-safe string to ArrayBuffer. */
const base64ToArrayBuffer = (base64) => {
  const binary_string = atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
};

// --- Single Big Number Conversion Helpers ---

/** Converts ArrayBuffer to a single BigInt string (Base 10). */
const arrayBufferToBigIntString = (buffer) => {
    const hex = arrayBufferToHex(buffer);
    if (hex.length === 0) return '0';
    
    let bigInt = BigInt(0);
    // Convert hex string to BigInt
    // Note: This relies on the browser supporting BigInt from hex literal '0x'
    try {
        bigInt = BigInt(`0x${hex}`);
    } catch (e) {
        // Fallback for extremely large numbers or environments lacking full BigInt support
        return `ERROR: Data too large for BigInt conversion (${buffer.byteLength} bytes).`;
    }
    return bigInt.toString(10);
};

/** Converts ArrayBuffer to a single hexadecimal string (Big Number representation). */
const arrayBufferToHexBig = (buffer) => {
    const hex = arrayBufferToHex(buffer);
    return hex.toUpperCase(); // Display as one single number
};

/** Converts ArrayBuffer to a single binary string (Big Number representation). */
const arrayBufferToBinaryBig = (buffer) => {
    const byteArray = new Uint8Array(buffer);
    let binary = '';
    // Concatenate all 8-bit binary strings
    for (const byte of byteArray) {
        binary += byte.toString(2).padStart(8, '0');
    }
    return binary;
};

// --- Other Data Format Conversion Functions ---

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
    // Clean the hex string from spaces or non-hex characters
    const cleanedHex = hex.replace(/\s/g, ''); // Remove all spaces
    if (cleanedHex.length === 0) return new ArrayBuffer(0);

    // Ensure it has an even length, padding with 0 if necessary
    const paddedHex = cleanedHex.length % 2 !== 0 ? '0' + cleanedHex : cleanedHex;

    const len = paddedHex.length / 2;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = parseInt(paddedHex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes.buffer;
};

/** * Converts a data string and its format into a Uint8Array. */
const convertToUint8Array = (dataStr, sourceFormat) => {
    if (!dataStr) return new Uint8Array(0);

    try {
        if (sourceFormat === 'Text (UTF-8)') {
             return new TextEncoder().encode(dataStr);
        } else if (sourceFormat === 'Base64') {
             return new Uint8Array(base64ToArrayBuffer(dataStr));
        } else if (sourceFormat === 'Hexadecimal') {
             // Handle both single big number hex and byte-separated hex if needed.
             // For consistency in binary operation inputs, we interpret input hex as raw byte data.
             const cleanedHex = dataStr.replace(/\s/g, ''); // Assume contiguous hex stream
             return new Uint8Array(hexToArrayBuffer(cleanedHex));
        } else if (sourceFormat === 'Binary') {
             // Convert space-separated binary string to bytes
             const binaryArray = dataStr.replace(/\s+/g, '').match(/.{1,8}/g) || []; // Group into 8-bit chunks
             const validBytes = binaryArray.map(s => parseInt(s, 2)).filter(b => !isNaN(b));
             return new Uint8Array(validBytes);
        } else if (sourceFormat === 'Decimal') {
             // Convert space-separated decimal string to bytes
             const decimalArray = dataStr.split(/\s+/).map(s => parseInt(s, 10));
             const validBytes = decimalArray.filter(b => !isNaN(b) && b >= 0 && b <= 255);
             return new Uint8Array(validBytes);
        } else {
             // Default to UTF-8 encoding for safety
             return new TextEncoder().encode(dataStr);
        }
    } catch (e) {
         console.error(`Conversion to Uint8Array failed for format ${sourceFormat}:`, e);
         return new Uint8Array(0);
    }
};

/** Converts a data string from a source format to a target format via ArrayBuffer. */
const convertDataFormat = (dataStr, sourceFormat, targetFormat, toSingleNumber = false) => {
    if (!dataStr) return '';
    
    // Skip conversion if formats are the same OR if the source data is an error message
    if (sourceFormat === targetFormat || dataStr.startsWith('ERROR')) return dataStr;
    
    let buffer;
    
    // 1. Convert from source format to ArrayBuffer
    try {
        if (sourceFormat === 'Text (UTF-8)') {
             buffer = new TextEncoder().encode(dataStr).buffer;
        } else if (sourceFormat === 'Base64') {
             buffer = base64ToArrayBuffer(dataStr);
        } else if (sourceFormat === 'Hexadecimal') {
             // Handle hex input (assumed to be a stream of bytes, possibly a large number if crypto output)
             const cleanedHex = dataStr.replace(/\s/g, '');
             buffer = hexToArrayBuffer(cleanedHex);
        } else if (sourceFormat === 'Binary') {
             // Convert binary string (space separated or contiguous) to ArrayBuffer
             const binaryArray = dataStr.replace(/\s+/g, '').match(/.{1,8}/g) || [];
             const validBytes = binaryArray.map(s => parseInt(s, 2)).filter(b => !isNaN(b) && b >= 0 && b <= 255);
             buffer = new Uint8Array(validBytes).buffer;
        } else if (sourceFormat === 'Decimal') {
             // NOTE: Assuming space-separated bytes for now. True BigInt parsing requires more complex input logic.
             const decimalArray = dataStr.split(/\s+/).map(s => parseInt(s, 10));
             const validBytes = decimalArray.filter(b => !isNaN(b) && b >= 0 && b <= 255);
             buffer = new Uint8Array(validBytes).buffer;
        } else {
             // Treat other source formats as raw text for simplicity and encode as UTF-8
             buffer = new TextEncoder().encode(dataStr).buffer;
        }
    } catch (e) {
         return `DECODING ERROR: Failed source format (${sourceFormat}).`;
    }

    // 2. Convert from ArrayBuffer to target format
    try {
        // --- Single Number Representation ---
        if (toSingleNumber) {
            if (targetFormat === 'Decimal') {
                return arrayBufferToBigIntString(buffer);
            }
            if (targetFormat === 'Hexadecimal') {
                return arrayBufferToHexBig(buffer);
            }
            // If target format is Binary in SLN mode, we output contiguous binary string
            if (targetFormat === 'Binary') {
                return arrayBufferToBinaryBig(buffer);
            }
        }

        // --- Byte-by-Byte Representation ---
        if (targetFormat === 'Text (UTF-8)') {
            return new TextDecoder().decode(buffer);
        } else if (targetFormat === 'Base64') {
            return arrayBufferToBase64(buffer);
        } else if (targetFormat === 'Hexadecimal') {
            return arrayBufferToHex(buffer).toUpperCase().match(/.{1,2}/g)?.join(' ') || ''; // Space-separated Hex bytes
        } else if (targetFormat === 'Binary') {
            return arrayBufferToBinary(buffer); // Space-separated Binary bytes
        } else if (targetFormat === 'Decimal') {
             // Convert to decimal byte representation (space separated)
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
const getOutputFormat = (nodeType) => {
    switch (nodeType) {
        case 'DATA_INPUT':
        case 'CAESAR_CIPHER': // Caesar outputs Text
        case 'VIGENERE_CIPHER': // Vigenere outputs Text
            return 'Text (UTF-8)'; 
        case 'KEY_GEN':
        case 'SYM_ENC':
        // REMOVED XOR_OP, SHIFT_OP from here as they are dynamic
        case 'ASYM_ENC':
        case 'SIMPLE_RSA_KEY_GEN':
        case 'RSA_KEY_GEN':
        case 'SIMPLE_RSA_PUBKEY_GEN': // NEW NODE
            return 'Base64';
        case 'HASH_FN':
            return 'Hexadecimal';
        case 'SYM_DEC':
        case 'ASYM_DEC':
            return 'Text (UTF-8)';
        // Simple RSA operations output single large decimal numbers
        case 'SIMPLE_RSA_ENC':
        case 'SIMPLE_RSA_DEC':
        case 'SIMPLE_RSA_SIGN': // Signature is a large decimal number
            return 'Decimal'; 
        case 'SIMPLE_RSA_VERIFY':
            return 'Text (UTF-8)'; // Verification result is always a status message
        default:
            return 'Text (UTF-8)';
    }
}

/** * Performs XOR operation on two input byte arrays.
 * Returns the result as a Base64 string (standard output format for operations).
 */
const performBitwiseXor = (bytesA, bytesB) => {
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

/** Converts a large number represented as a string (Decimal, Hex, or Binary) to a BigInt.
 * Returns BigInt or null if conversion fails.
 */
const stringToBigInt = (dataStr, format) => {
    if (!dataStr) return null;
    
    // ** MODIFICATION: Check for spaces to enforce single number constraint **
    if (dataStr.includes(' ')) {
        return null; 
    }
    const cleanedStr = dataStr.replace(/\s/g, ''); // Remove spaces (should be empty now if spaces were present)

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
        // BigInt parsing failure
        return null;
    }
    return null;
};

/** Converts a BigInt back to a string in the specified format (Decimal, Hex, Binary). */
const bigIntToString = (bigIntValue, format) => {
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

/** * Performs a bit shift operation on the input number (represented by a string).
 * This function now specifically expects the input data to represent a SINGLE large number.
 */
const performBitShiftOperation = (dataStr, shiftType, shiftAmount, inputFormat) => {
    if (!dataStr) return "ERROR: Missing data input.";
    
    // 1. **REJECT TEXT INPUT** (from previous requirement)
    if (inputFormat === 'Text (UTF-8)' || inputFormat === 'Base64') {
        return "ERROR: Bit Shift requires input data to be a single number (Decimal, Hexadecimal, or Binary), not Text or Base64 byte stream.";
    }
    
    // 2. **VALIDATE AND CONVERT TO BIGINT**
    const bigIntData = stringToBigInt(dataStr, inputFormat);
    if (bigIntData === null) {
        // Now, this check will correctly catch inputs like "10 20" because of the space check added to stringToBigInt
        return `ERROR: Data must represent a single, contiguous number in ${inputFormat} format. Spaces are not allowed.`;
    }
    
    const amount = BigInt(Math.max(0, parseInt(shiftAmount) || 0));
    let resultBigInt;

    // 3. **PERFORM BIT SHIFT**
    try {
        if (shiftType === 'Left') {
            // Shift Left: multiplication by 2^amount
            resultBigInt = bigIntData << amount;
        } else if (shiftType === 'Right') {
            // Shift Right: division by 2^amount (integer division)
            resultBigInt = bigIntData >> amount;
        } else {
            return "ERROR: Invalid shift type.";
        }
    } catch (error) {
        console.error("Bit Shift operation failed:", error);
        return `ERROR: Bit Shift calculation failed. ${error.message}`;
    }

    // 4. **CONVERT BACK** to the original input format
    return bigIntToString(resultBigInt, inputFormat);
};

/** Calculates the hash of a given string using the Web Crypto API. */
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
    
    // Returns Hexadecimal
    return arrayBufferToHex(hashBuffer);
  } catch (error) {
    console.error(`Error calculating hash with ${algorithm}:`, error);
    return `ERROR: Calculation failed with ${algorithm}. Check console for details.`;
  }
};

/** Generates an AES-GCM Symmetric Key. */
const generateSymmetricKey = async (algorithm) => {
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

/** Generates an RSA Key Pair.
 * The standard version (used by both SIMPLE and ADVANCED generator).
 */
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
            true, // extractable
            ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
        );
        
        // Export public key to SPKI format (Base64)
        const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const base64PublicKey = arrayBufferToBase64(publicKey);
        
        // Export private key to PKCS#8 format (Base64)
        const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const base64PrivateKey = arrayBufferToBase64(privateKey);
        
        // Export PRIVATE key in JWK format to extract internal parameters (p, q, d, n) for visualization (only used by ADVANCED node)
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

/** Encrypts data using an RSA public key (Asymmetric). */
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

/** Decrypts data using an RSA private key (Asymmetric). */
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
            { name: algorithm }, // Corrected for RSA-OAEP
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


/** Encrypts data using an AES-GCM key (Symmetric). */
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

/** Decrypts data using an AES-GCM key (Symmetric). */
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
             throw new Error('Ciphertext is too short to contain IV.');
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


// --- Input Validation and Auto-Conversion Helper ---

/**
 * Checks content compatibility with numeric formats.
 * @param {string} content The user input string.
 * @param {string} targetFormat The format to check against ('Binary', 'Decimal', 'Hexadecimal', 'Text (UTF-8)').
 * @returns {boolean} True if content is compatible with the target format.
 */
const isContentCompatible = (content, targetFormat) => {
    if (targetFormat === 'Text (UTF-8)') return true;
    
    // Remove spaces for robust numeric/hex checking
    const cleanedContent = content.replace(/\s+/g, '');
    if (!cleanedContent) return true; // Empty content is always compatible

    if (targetFormat === 'Binary') {
        // Must only contain 0s and 1s
        return /^[01]*$/.test(cleanedContent);
    }
    if (targetFormat === 'Decimal') {
        // Must only contain 0-9 digits
        return /^\d*$/.test(cleanedContent);
    }
    if (targetFormat === 'Hexadecimal') {
        // Must only contain 0-9, a-f, A-F
        return /^[0-9a-fA-F]*$/.test(cleanedContent);
    }
    return true;
};


// =================================================================
// 3. UI COMPONENTS & GRAPH LOGIC
// =================================================================

/**
 * Calculates the SVG path for the line connecting two specific ports.
 * The connection is calculated to go from the center of the source port to the center of the target port.
 */
const getLinePath = (sourceNode, targetNode, connection) => {
    const sourceDef = NODE_DEFINITIONS[sourceNode.type];
    const targetDef = NODE_DEFINITIONS[targetNode.type];
    
    // 1. Calculate vertical position based on port index and node height
    const getVerticalPosition = (nodeDef, index, isInput) => {
        const numPorts = isInput ? nodeDef.inputPorts.length : nodeDef.outputPorts.length;
        const step = BOX_SIZE.minHeight / (numPorts + 1); 
        return (index + 1) * step;
    };

    // Calculate vertical position for Source Output Port
    const sourceVerticalPos = getVerticalPosition(sourceDef, connection.sourcePortIndex, false);
    
    // Find the index of the targetPortId in the target node's inputPorts array
    const targetPortIndex = targetDef.inputPorts.findIndex(p => p.id === connection.targetPortId);
    // Calculate vertical position for Target Input Port
    const targetVerticalPos = getVerticalPosition(targetDef, targetPortIndex, true);

    // P1: Source connection point (Node right edge + visual offset for the port center)
    const p1 = { 
      x: sourceNode.position.x + BOX_SIZE.width + PORT_VISUAL_OFFSET_PX, 
      y: sourceNode.position.y + sourceVerticalPos 
    }; 
    
    // P2: Target connection point (Node left edge - visual offset for the port center)
    const p2 = { 
      x: targetNode.position.x - PORT_VISUAL_OFFSET_PX, 
      y: targetNode.position.y + targetVerticalPos
    }; 
    
    // Use a smooth Bezier curve that flows horizontally
    const midX = (p1.x + p2.x) / 2;
    
    // Control points pull horizontally towards the center for a smooth arc
    return `M${p1.x} ${p1.y} C${midX} ${p1.y}, ${midX} ${p2.y}, ${p2.x} ${p2.y}`;
};


// --- Sub-Component for Ports (Visual and Interaction) ---
const Port = React.memo(({ nodeId, type, isConnecting, onStart, onEnd, title, isMandatory, portId, portIndex, outputType, nodes }) => {
    let interactionClasses = "";
    let clickHandler = () => {};
    
    let portColor = OUTPUT_PORT_COLOR;

    // Determine specific color for Key ports
    if (outputType === 'public' || outputType === 'private') {
        portColor = outputType === 'public' ? PUBLIC_KEY_COLOR : PRIVATE_KEY_COLOR;
    } else if (type === 'input') {
        portColor = isMandatory ? INPUT_PORT_COLOR : OPTIONAL_PORT_COLOR;
    }
    
    // Change Output Port Color for 'key' type (Symmetric)
    if (type === 'output' && outputType === 'key') {
         portColor = TEXT_ICON_CLASSES['orange'].replace('text', 'bg'); // Use orange background for symmetric key output
    }
    // Change Output Port Color for 'signature' type
    if (type === 'output' && outputType === 'signature') {
         portColor = SIGNATURE_COLOR.replace('border', 'bg'); 
    }
    
    if (type === 'output') {
        clickHandler = (e) => { 
            e.stopPropagation(); 
            // Pass the node ID, port index, and output data type
            onStart(nodeId, portIndex, outputType); 
        };
        interactionClasses = isConnecting?.sourceId === nodeId 
            ? 'ring-4 ring-emerald-300 animate-pulse' 
            : 'hover:ring-4 hover:ring-emerald-300 transition duration-150';
    } else if (type === 'input') {
        // --- FIX: Ensure validation works for multi-input nodes like XOR ---
        
        // Find the full node definition
        const targetNode = nodes.find(n => n.id === nodeId);
        const targetNodeDef = NODE_DEFINITIONS[targetNode?.type];
        
        // Find the specific port definition by ID to get its type (e.g., 'data', 'key')
        const inputPortDef = targetNodeDef.inputPorts.find(p => p.id === portId);
        const inputPortType = inputPortDef?.type;
        
        // A port is a target candidate if an output port is active AND port types match
        const isTargetCandidate = isConnecting && 
                                     isConnecting.sourceId !== nodeId && 
                                     isConnecting.outputType === inputPortType; 
        
        if (isTargetCandidate) {
            clickHandler = (e) => { 
                e.stopPropagation(); 
                // Pass the node ID and the input port ID
                onEnd(nodeId, portId); 
            };
            interactionClasses = 'ring-4 ring-yellow-300 cursor-pointer animate-pulse-slow';
        } else {
             interactionClasses = 'hover:ring-4 hover:ring-stone-300 transition duration-150';
             clickHandler = (e) => { e.stopPropagation(); }; 
        }
    }
    
    const stopPropagation = (e) => e.stopPropagation();

    // Port styles rely on absolute positioning determined by the parent DraggableBox
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

const DraggableBox = ({ node, setPosition, canvasRef, handleConnectStart, handleConnectEnd, connectingPort, updateNodeContent, connections, handleDeleteNode, nodes, scale }) => {
  // Destructure node props and look up definition
  const { id, label, position, type, color, content, format, dataOutput, dataOutputPublic, dataOutputPrivate, viewFormat, isProcessing, hashAlgorithm, keyAlgorithm, symAlgorithm, modulusLength, publicExponent, rsaParameters, asymAlgorithm, convertedData, convertedFormat, isConversionExpanded, sourceFormat, rawInputData, p, q, e, d, n, phiN, shiftKey, keyword, vigenereMode, dStatus, n_pub, e_pub, isReadOnly } = node; 
  const definition = NODE_DEFINITIONS[type];
  const [isDragging, setIsDragging] = useState(false);
  const boxRef = useRef(null);
  const offset = useRef({ x: 0, y: 0 });
  const [copyStatus, setCopyStatus] = useState('Copy'); // English for Copy

  // Node specific flags
  const isDataInput = type === 'DATA_INPUT';
  const isOutputViewer = type === 'OUTPUT_VIEWER'; 
  const isHashFn = type === 'HASH_FN';
  const isKeyGen = type === 'KEY_GEN';
  const isSimpleRSAKeyGen = type === 'SIMPLE_RSA_KEY_GEN'; // Private Key Gen
  const isSimpleRSAPubKeyGen = type === 'SIMPLE_RSA_PUBKEY_GEN'; // Public Key Gen
  const isRSAKeyGen = type === 'RSA_KEY_GEN'; 
  const isSimpleRSAEnc = type === 'SIMPLE_RSA_ENC'; // New Flag
  const isSimpleRSADec = type === 'SIMPLE_RSA_DEC'; // New Flag
  const isSimpleRSASign = type === 'SIMPLE_RSA_SIGN'; // New Flag
  const isSimpleRSAVerify = type === 'SIMPLE_RSA_VERIFY'; // New Flag
  const isSymEnc = type === 'SYM_ENC';
  const isSymDec = type === 'SYM_DEC';
  const isAsymEnc = type === 'ASYM_ENC'; 
  const isAsymDec = type === 'ASYM_DEC'; 
  const isBitShift = type === 'SHIFT_OP'; 
  const isCaesarCipher = type === 'CAESAR_CIPHER'; // New Flag
  const isVigenereCipher = type === 'VIGENERE_CIPHER'; // New Flag
  
  const FORMATS = ALL_FORMATS;
  
  const isPortSource = connectingPort?.sourceId === id;
  
  
  // --- Drag Handlers (standard) ---
  const handleDragStart = useCallback((e) => {
    if (connectingPort) return; 
    const interactiveTags = ['TEXTAREA', 'SELECT', 'OPTION', 'BUTTON', 'INPUT']; 
    // Check if a port was clicked to prevent drag
    if (e.target.tagName === 'DIV' && e.target.classList.contains('w-4') && e.target.classList.contains('h-4')) {
        return; 
    }
    // Allow interaction inside form elements
    if (interactiveTags.includes(e.target.tagName)) {
        return; 
    }

    const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
    const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);
    const canvas = canvasRef.current;
    
    if (boxRef.current && canvas) {
      const canvasRect = canvas.getBoundingClientRect();

      // Calculate mouse position relative to the unscaled coordinate system
      const unscaledMouseX = (clientX - canvasRect.left) / scale;
      const unscaledMouseY = (clientY - canvasRect.y) / scale;

      offset.current = {
        x: unscaledMouseX - position.x,
        y: unscaledMouseY - position.y,
      };
      
      setIsDragging(true);
      e.preventDefault(); 
    }
  }, [canvasRef, position.x, position.y, connectingPort, scale]);

  const handleDragMove = useCallback((e) => {
    if (!isDragging) return;
    const canvas = canvasRef.current;
    if (!canvas) return;

    const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
    const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);

    const canvasRect = canvas.getBoundingClientRect();
    
    // Mouse coordinates relative to the unscaled coordinate system (scaled back up)
    const unscaledMouseX = (clientX - canvasRect.left) / scale;
    const unscaledMouseY = (clientY - canvasRect.y) / scale;
    
    let newX = unscaledMouseX - offset.current.x;
    let newY = unscaledMouseY - offset.current.y;
    
    // BOUNDS CHECKING (Unscaled dimensions)
    // NOTE: For simplicity and to allow content to pan/scroll naturally when zoomed, 
    // we use the actual scrollable area boundaries for max X/Y. 
    // If we limit based on canvasRect.width/scale, we prevent dragging outside the initial visible area.
    // For now, we revert to simple bounds check to prevent nodes from disappearing off the edge.
    const canvasWidth = canvasRect.width / scale;
    const canvasHeight = canvasRect.height / scale;

    newX = Math.max(0, newX);
    newY = Math.max(0, newY);
    // Note: Max bounds check is complex with dynamic canvas size and scale, leaving it open-ended 
    // to allow the diagram to grow beyond initial viewport when zoomed in.

    setPosition(id, { x: newX, y: newY });
  }, [isDragging, id, setPosition, canvasRef, scale]);

  const handleDragEnd = useCallback(() => {
    setIsDragging(false);
  }, []);
  
  const handleBoxClick = useCallback((e) => {
    if (isDragging) return; 
    if (connectingPort) {
      handleConnectEnd(null); // Cancel connection if canvas clicked
    }
    e.stopPropagation();
  }, [connectingPort, handleConnectEnd, isDragging]);

  // Handle Copy to Clipboard for Output Viewer
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
        
        // FIX: Select and execute copy command
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


  // Attach global event listeners for dragging
  useEffect(() => {
    const handleUp = handleDragEnd;
    const handleMove = handleDragMove;
    
    if (isDragging) {
      document.addEventListener('mousemove', handleMove);
      document.addEventListener('mouseup', handleUp);
      document.addEventListener('touchmove', handleMove, { passive: false });
      document.addEventListener('touchend', handleUp);
    } else {
      document.removeEventListener('mousemove', handleMove);
      document.removeEventListener('mouseup', handleUp);
      document.removeEventListener('touchmove', handleMove);
      document.removeEventListener('touchend', handleUp);
    };
    return () => {
      document.removeEventListener('mousemove', handleMove);
      document.removeEventListener('mouseup', handleUp);
      document.removeEventListener('touchmove', handleMove);
      document.removeEventListener('touchend', handleUp);
    };
  }, [isDragging, handleDragMove, handleDragEnd]);


  // --- Port Rendering Logic ---
  
  const renderInputPorts = () => {
    if (!definition.inputPorts || definition.inputPorts.length === 0) return null;
    
    const numPorts = definition.inputPorts.length;
    // Calculate vertical offset for even distribution
    const step = 100 / (numPorts + 1); 

    return definition.inputPorts.map((portDef, index) => {
        const topPosition = (index + 1) * step;
        const portId = portDef.id;
        
        const isInputConnected = connections.some(c => c.target === id && c.targetPortId === portId);

        return (
            <div 
                key={portId}
                className="absolute -left-2 transform -translate-y-1/2 z-20"
                style={{ top: `${topPosition}%` }}
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
                    nodes={nodes} // PASSING NODES PROP TO PORT FOR VALIDATION
                />
            </div>
        );
    });
  };

  const renderOutputPorts = () => {
    if (!definition.outputPorts || definition.outputPorts.length === 0) return null;
    
    const numPorts = definition.outputPorts.length;
    // Calculate vertical offset for even distribution
    const step = 100 / (numPorts + 1); 

    return definition.outputPorts.map((portDef, index) => {
        const topPosition = (index + 1) * step;
        
        return (
            <div 
                key={portDef.name}
                className="absolute -right-2 transform -translate-y-1/2 z-20"
                style={{ top: `${topPosition}%` }}
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
                    nodes={nodes} // PASSING NODES PROP TO PORT FOR VALIDATION
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
    specificClasses = `${BORDER_CLASSES[color]} ${HOVER_BORDER_CLASSES[color]} ${isDragging ? 'cursor-grabbing' : 'cursor-pointer hover:border-blue-500'}`;
  }
  
  if (isProcessing) {
     specificClasses = `border-yellow-500 ring-4 ring-yellow-300 animate-pulse transition duration-200`; 
  }

  const baseClasses = 
    `w-[${BOX_SIZE.width}px] min-h-[${BOX_SIZE.minHeight}px] h-auto flex flex-col justify-start items-center p-3 
    bg-white shadow-xl rounded-xl border-4 transition duration-150 ease-in-out 
    hover:shadow-2xl absolute select-none z-10`;

  // --- Render ---
  return (
    <div
      ref={boxRef}
      id={id}
      className={`${baseClasses} ${specificClasses}`}
      style={{ 
        left: `${position.x}px`, 
        top: `${position.y}px`,
        // Dynamic height adjustment for expanded viewer
        minHeight: isOutputViewer && isConversionExpanded ? '280px' : `${BOX_SIZE.minHeight}px` 
      }} 
      onMouseDown={handleDragStart} 
      onTouchStart={handleDragStart} 
      onClick={handleBoxClick} 
    >
      
      {/* Removed Information Button (for Simple RSA Nodes) */}

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
      <div className="flex flex-col h-full w-full justify-start items-center overflow-hidden">
        {/* Top Section: Icon and Main Label */}
        <div className="flex flex-col justify-start items-center w-full flex-shrink-0 mb-2">
          {/* Custom icons need size and color applied to the container/SVG itself */}
          {definition.icon && typeof definition.icon === 'function' ? (
              <definition.icon className={`w-6 h-6 ${iconTextColorClass} mb-1`} />
          ) : (
              definition.icon && <definition.icon className={`w-6 h-6 ${iconTextColorClass} mb-1`} />
          )}
          <span className={`text-${isDataInput ? 'base' : 'lg'} font-bold text-gray-800 text-center leading-tight`}>{label}</span>
          {/* Show algorithm name for functional nodes */}
          
          {isCaesarCipher && <span className={`text-xs text-gray-500 mt-1`}>k = {node.shiftKey || 0}</span>}
          {isVigenereCipher && <span className={`text-xs text-gray-500 mt-1`}>Keyword: {node.keyword || 'None'}</span>}
          {isSimpleRSASign && <span className={`text-xs text-gray-500 mt-1`}>Signing (m^d mod n)</span>}
          {isSimpleRSAVerify && <span className={`text-xs text-gray-500 mt-1`}>Verifying (s^e mod n)</span>}


          {isHashFn && <span className={`text-xs text-gray-500 mt-1`}>({hashAlgorithm})</span>}
          {isKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({keyAlgorithm})</span>}
          
          {/* Simple RSA Key Gen */}
          {isSimpleRSAKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({modulusLength} bits)</span>}
          
          {/* Advanced RSA Key Gen */}
          {isRSAKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({node.keyAlgorithm} {modulusLength} bits, e={publicExponent})</span>}
          
          {/* Simple RSA Encrypt/Decrypt */}
          {(isSimpleRSAEnc || isSimpleRSADec) && <span className={`text-xs text-gray-500 mt-1`}>Modular Arithmetic Demo</span>}
          
          {/* Show status/algorithm for XOR and Bit Shift */}
          {type === 'XOR_OP' && <span className={`text-xs text-gray-500 mt-1`}>({isProcessing ? 'Processing' : 'Bitwise XOR'})</span>}
          {isBitShift && <span className={`text-xs text-gray-500 mt-1`}>({isProcessing ? 'Processing' : 'Bit Shift'})</span>}
          {isSimpleRSAPubKeyGen && <span className={`text-xs text-gray-500 mt-1`}>Public Key Output</span>} 


          {!isDataInput && !isOutputViewer && type !== 'HASH_FN' && !isKeyGen && !isSymEnc && !isSymDec && !isRSAKeyGen && !isAsymEnc && !isAsymDec && type !== 'XOR_OP' && !isBitShift && !isSimpleRSAKeyGen && !isSimpleRSAPubKeyGen && !isSimpleRSAEnc && !isSimpleRSADec && !isCaesarCipher && !isVigenereCipher && !isSimpleRSASign && !isSimpleRSAVerify && <span className={`text-xs text-gray-500 mt-1`}>({definition.label})</span>}
        </div>
        
        {isDataInput && (
          /* Data Input Specific Controls */
          <div className="w-full flex flex-col items-center flex-grow">
            <textarea
              className="w-full text-xs p-2 border border-gray-200 rounded-lg shadow-md resize-none mb-2 
                           placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 
                           outline-none transition duration-200"
              rows="4" 
              placeholder="Enter data here..."
              value={content || ''}
              // FIX: Handle content change with format detection
              onChange={(e) => {
                  const newContent = e.target.value;
                  let newFormat = format;
                  
                  // --- Auto-switch logic (only if current format is restrictive) ---
                  if (format !== 'Text (UTF-8)') {
                      
                      if (format === 'Binary' && !isContentCompatible(newContent, 'Binary')) {
                          if (isContentCompatible(newContent, 'Decimal')) {
                              newFormat = 'Decimal';
                          } else if (isContentCompatible(newContent, 'Hexadecimal')) {
                              newFormat = 'Hexadecimal';
                          } else {
                              newFormat = 'Text (UTF-8)';
                          }
                      } else if (format === 'Decimal' && !isContentCompatible(newContent, 'Decimal')) {
                          if (isContentCompatible(newContent, 'Hexadecimal')) {
                              newFormat = 'Hexadecimal';
                          } else {
                              newFormat = 'Text (UTF-8)';
                          }
                      } else if (format === 'Hexadecimal' && !isContentCompatible(newContent, 'Hexadecimal')) {
                          newFormat = 'Text (UTF-8)';
                      }
                  }
                  // If format is 'Text (UTF-8)', it is preserved, meeting the user's requirement.

                  // Apply changes
                  if (newFormat !== format) {
                      updateNodeContent(id, 'format', newFormat);
                  }
                  updateNodeContent(id, 'content', newContent);
              }}
              onMouseDown={(e) => e.stopPropagation()} 
              onTouchStart={(e) => e.stopPropagation()} 
              onClick={(e) => e.stopPropagation()}
            />
            <select
              className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm 
                           bg-white appearance-none cursor-pointer text-gray-700 
                           focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              value={format || 'Text (UTF-8)'}
              // FIX: Add auto-correction logic when user manually selects an incompatible format
              onChange={(e) => {
                e.stopPropagation();
                const selectedFormat = e.target.value;
                const currentContent = content || '';
                let finalFormat = selectedFormat;

                if (!isContentCompatible(currentContent, selectedFormat)) {
                    // If the selected format is NOT compatible with the current content,
                    // calculate the safest compatible format based on the content.
                    
                    if (isContentCompatible(currentContent, 'Binary')) {
                        finalFormat = 'Binary';
                    } else if (isContentCompatible(currentContent, 'Decimal')) {
                        finalFormat = 'Decimal';
                    } else if (isContentCompatible(currentContent, 'Hexadecimal')) {
                        finalFormat = 'Hexadecimal';
                    } else {
                        // Safest fallback
                        finalFormat = 'Text (UTF-8)';
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
                
                {/* Source Data Type Selector (Read-only representation of input data type) */}
                <div className="w-full mb-1">
                    <label className="block text-left text-[10px] font-semibold text-gray-600 mb-0.5">Source Data Type</label>
                    <select
                        className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm 
                                    bg-gray-100 cursor-default text-gray-700 appearance-none pointer-events-none"
                        value={sourceFormat || 'N/A'}
                        onChange={() => {}} // Disabled but functional selector
                        onMouseDown={(e) => e.stopPropagation()}
                        onClick={(e) => e.stopPropagation()}
                        disabled
                    >
                        <option>{sourceFormat || 'N/A'}</option>
                    </select>
                </div>

                {/* Primary Output Box (RAW UNCONVERTED Input Data - now using rawInputData state) */}
                <div className="relative w-full flex-grow break-all text-[10px] leading-tight text-gray-800 bg-white p-1 rounded-md mb-2 overflow-y-auto border border-gray-200 min-h-[4rem]">
                    <p>{rawInputData || 'Not connected or no data.'}</p>
                    
                    {/* Copy Button for Primary Output */}
                    <button
                        onClick={(e) => handleCopyToClipboard(e, rawInputData)} // Copying raw input data
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

                {/* Conversion Button */}
                <button
                    onClick={(e) => { 
                        e.stopPropagation();
                        updateNodeContent(id, 'isConversionExpanded', !isConversionExpanded);
                    }}
                    className={`mt-1 w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md bg-red-500 hover:bg-red-600`}
                >
                    <span>{isConversionExpanded ? 'Hide Conversion' : 'Convert Type'}</span>
                </button>


                {/* Secondary Output/Conversion Section (Conditionally rendered) */}
                {isConversionExpanded && (
                    <div className="w-full mt-2 pt-2 border-t border-gray-200 flex flex-col space-y-2">
                        <span className="text-center font-bold text-red-600 text-[10px] flex-shrink-0">CONVERTED VIEW</span>

                        {/* Converted Output Box */}
                        <div className="relative w-full break-all text-[10px] leading-tight text-gray-800 bg-white p-1 rounded-md mb-2 overflow-y-auto border border-gray-200 min-h-[4rem]">
                            <p>{convertedData || 'Select conversion type...'}</p>

                            {/* Copy Button for Converted Output */}
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

                        {/* Converted Format Selector */}
                        <select
                            className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm 
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

        {isCaesarCipher && (
            <div className="text-xs w-full text-center flex flex-col items-center">
                <span className={`text-[10px] font-semibold text-gray-600 mb-1`}>SHIFT KEY (k)</span>
                {/* Input for k, must be 0-25 */}
                <input
                    type="number"
                    min="0"
                    max="25"
                    step="1"
                    className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 
                               text-gray-700 focus:ring-2 focus:ring-amber-500 focus:border-amber-500 
                               outline-none transition duration-200"
                    value={node.shiftKey || 0}
                    // Only update shiftKey. Recalc is triggered by updateNodeContent.
                    onChange={(e) => updateNodeContent(id, 'shiftKey', parseInt(e.target.value) || 0)}
                    onMouseDown={(e) => e.stopPropagation()} 
                    onTouchStart={(e) => e.stopPropagation()} 
                    onClick={(e) => e.stopPropagation()}
                />
                
                <span className={`font-semibold mt-2 ${isProcessing ? 'text-yellow-600' : 'text-amber-600'}`}>
                    {isProcessing ? 'Encrypting...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    {/* Increased padding and removed substring for full error visibility */}
                    <p className={`text-left text-[10px] break-all p-2 bg-gray-100 rounded min-h-[3rem] overflow-auto ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                        {dataOutput ? `Result (${node.outputFormat}): ${dataOutput}` : 'Waiting for Plaintext...'}
                    </p>
                    {/* Copy Button for Caesar Output */}
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR') && node.outputFormat === 'Text (UTF-8)' 
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
            </div>
        )}

        {isVigenereCipher && (
             <div className="text-xs w-full text-center flex flex-col items-center">
                <span className={`text-[10px] font-semibold text-gray-600 mb-1`}>KEYWORD (A-Z only)</span>
                {/* Keyword Input */}
                <input
                    type="text"
                    placeholder="Keyword"
                    className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-1 
                               text-gray-700 focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 outline-none transition duration-200"
                    value={keyword || ''}
                    // Only update keyword. Recalc is triggered by updateNodeContent.
                    onChange={(e) => updateNodeContent(id, 'keyword', e.target.value.toUpperCase().replace(/[^A-Z]/g, ''))} // Force uppercase letters only
                    onMouseDown={(e) => e.stopPropagation()} 
                    onTouchStart={(e) => e.stopPropagation()} 
                    onClick={(e) => e.stopPropagation()}
                />

                {/* Mode Selector */}
                <div className="w-full mb-2">
                    <label className="block text-left text-[10px] font-semibold text-gray-600 mb-0.5">OPERATION MODE</label>
                    <select
                        className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm 
                                    bg-white appearance-none cursor-pointer text-gray-700 
                                    focus:ring-2 focus:ring-yellow-500 outline-none transition duration-200"
                        value={vigenereMode || 'ENCRYPT'}
                        onChange={(e) => updateNodeContent(id, 'vigenereMode', e.target.value)}
                        onMouseDown={(e) => e.stopPropagation()} 
                        onClick={(e) => e.stopPropagation()}
                    >
                        <option value="ENCRYPT">Encrypt (C = P + K)</option>
                        <option value="DECRYPT">Decrypt (P = C - K)</option>
                    </select>
                </div>
                
                <span className={`font-semibold mt-2 ${isProcessing ? 'text-yellow-600' : 'text-yellow-600'}`}>
                    {isProcessing ? 'Processing...' : `Active (${vigenereMode})`}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className={`text-left text-[10px] break-all p-2 bg-gray-100 rounded min-h-[3rem] overflow-auto ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                        {dataOutput ? `Result (${node.outputFormat}): ${dataOutput}` : 'Waiting for Data and Keyword...'}
                    </p>
                    {/* Copy Button */}
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR') && node.outputFormat === 'Text (UTF-8)' 
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
            </div>
        )}

        {/* Hash Function Implementation */}
        {isHashFn && (
            <div className="text-xs w-full text-center flex flex-col items-center">
                <span className={`text-[10px] font-semibold text-gray-600 mb-1`}>ALGORITHM</span>
                {/* Hash Algorithm Selector */}
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

                <span className={`font-semibold mt-2 ${isProcessing ? 'text-yellow-600' : 'text-gray-600'}`}>
                    {isProcessing ? 'Calculating Hash...' : 'Active'}
                </span>
                
                {/* Output Display Box */}
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className={`text-left text-[10px] break-all p-1 bg-gray-100 rounded min-h-[3rem] overflow-auto ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                        {dataOutput ? `Hash (${node.outputFormat}): ${dataOutput}` : 'Waiting for Data Input...'}
                    </p>
                    {/* Copy Button for Hash Output */}
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
            </div>
        )}


        {/* Simple RSA Private Key Generator (Modular Arithmetic Demo) */}
        {isSimpleRSAKeyGen && (
            <div className="text-xs w-full text-center flex flex-col items-center">
                <span className="text-[10px] font-semibold text-gray-600 mb-1">KEY INPUTS (P, Q, E, D)</span>
                
                {/* P Input */}
                <input
                    type="number"
                    placeholder="Prime P (Autogenerates if empty)"
                    className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-1 
                               text-gray-700 focus:ring-2 focus:ring-purple-500 outline-none transition duration-200"
                    value={p || ''}
                    onChange={(e) => updateNodeContent(id, 'p', e.target.value)}
                    onMouseDown={(e) => e.stopPropagation()} 
                    onClick={(e) => e.stopPropagation()}
                />
                {/* Q Input */}
                <input
                    type="number"
                    placeholder="Prime Q (Autogenerates if empty)"
                    className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-1 
                               text-gray-700 focus:ring-2 focus:ring-purple-500 outline-none transition duration-200"
                    value={q || ''}
                    onChange={(e) => updateNodeContent(id, 'q', e.target.value)}
                    onMouseDown={(e) => e.stopPropagation()} 
                    onClick={(e) => e.stopPropagation()}
                />
                 {/* E Input */}
                <input
                    type="number"
                    placeholder="Exponent E (Autogenerates if empty)"
                    className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-1
                               text-gray-700 focus:ring-2 focus:ring-purple-500 outline-none transition duration-200"
                    value={e || ''}
                    onChange={(e) => updateNodeContent(id, 'e', e.target.value)}
                    onMouseDown={(e) => e.stopPropagation()} 
                    onClick={(e) => e.stopPropagation()}
                />
                 {/* D Input (MODIFICADO) */}
                <input
                    type="number"
                    placeholder="Private Exponent D (Optional: Checked, then calculated)"
                    className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-3
                               text-gray-700 focus:ring-2 focus:ring-purple-500 outline-none transition duration-200"
                    value={d || ''}
                    // BIND d to the input field
                    onChange={(e) => updateNodeContent(id, 'd', e.target.value)}
                    onMouseDown={(e) => e.stopPropagation()} 
                    onClick={(e) => e.stopPropagation()}
                />


                <button
                    onClick={(e) => { e.stopPropagation(); updateNodeContent(id, 'generateKey', true); }}
                    className={`mt-1 w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md bg-purple-500 hover:bg-purple-600`}
                >
                    <Key className="w-4 h-4" />
                    <span>Calculate/Generate Keys</span>
                </button>
                
                <span className={`font-semibold mt-2 ${n ? 'text-purple-600' : 'text-gray-500'}`}>
                    {isProcessing ? 'Calculating...' : n ? 'Keys Ready' : 'Enter or Generate Primes'}
                </span>

                <div className="w-full mt-2 p-1 text-gray-500 break-all text-left border-t border-gray-200 pt-1 space-y-1">
                    <label className="block text-[10px] font-semibold text-gray-600">Calculated Parameters:</label>
                    <p className="text-[10px]">n (Modulus): <span className="font-mono text-gray-800">{n || 'N/A'}</span></p>
                    <p className="text-[10px]">&phi;(n): <span className="font-mono text-gray-800">{phiN || 'N/A'}</span></p>
                    <p className="text-[10px]">d (Private Exp.): <span className="font-mono text-gray-800">{d || 'N/A'}</span></p>
                    {dStatus && (
                        <p className={`text-[10px] font-bold ${dStatus.includes('CORRECT') ? 'text-green-600' : dStatus.includes('INCORRECT') || dStatus.includes('ERROR') ? 'text-red-600' : 'text-gray-600'}`}>
                            D Status: {dStatus}
                        </p>
                    )}
                </div>
            </div>
        )}
        
        {/* NEW Simple RSA Public Key Generator */}
        {isSimpleRSAPubKeyGen && (
            <div className="text-xs w-full text-center flex flex-col items-center">
                <span className="text-[10px] font-semibold text-gray-600 mb-1">PUBLIC KEY INPUTS (N, E)</span>
                
                {/* N Input */}
                <input
                    type="number"
                    placeholder="Modulus N"
                    className={`w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-1 
                               text-gray-700 focus:ring-2 focus:ring-lime-500 outline-none transition duration-200 ${isReadOnly ? 'bg-gray-100 cursor-default' : ''}`}
                    value={n_pub || ''}
                    onChange={(e) => updateNodeContent(id, 'n_pub', e.target.value)}
                    onMouseDown={(e) => e.stopPropagation()} 
                    onClick={(e) => e.stopPropagation()}
                    readOnly={isReadOnly}
                />
                {/* E Input */}
                <input
                    type="number"
                    placeholder="Exponent E"
                    className={`w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-3
                               text-gray-700 focus:ring-2 focus:ring-lime-500 outline-none transition duration-200 ${isReadOnly ? 'bg-gray-100 cursor-default' : ''}`}
                    value={e_pub || ''}
                    onChange={(e) => updateNodeContent(id, 'e_pub', e.target.value)}
                    onMouseDown={(e) => e.stopPropagation()} 
                    onClick={(e) => e.stopPropagation()}
                    readOnly={isReadOnly}
                />

                <span className={`font-semibold mt-2 ${dataOutputPublic ? 'text-lime-600' : 'text-gray-500'}`}>
                    {dataOutputPublic ? 'Key Pair Ready' : 'Enter or Connect Key Source'}
                </span>
                <div className="w-full mt-2 p-1 text-gray-500 break-all text-left border-t border-gray-200 pt-1 space-y-1">
                    <label className="block text-[10px] font-semibold text-gray-600">Public Key Output (n, e):</label>
                    <p className="text-[10px] font-mono text-gray-800 break-all overflow-hidden">
                        {dataOutputPublic || 'N/A'}
                    </p>
                </div>
            </div>
        )}
        
        {/* Simple RSA Encrypt */}
        {isSimpleRSAEnc && (
             <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-gray-600'}`}>
                    {isProcessing ? 'Encrypting (m^e mod n)...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded">
                        {dataOutput ? `Ciphertext (c): ${dataOutput}` : 'Waiting for m and Public Key...'}
                    </p>
                    {/* Copy Button for Ciphertext Output */}
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
                <span className="text-[10px] text-gray-500 mt-2">Input/Output are Decimal Numbers.</span>
            </div>
        )}

        {/* Simple RSA Decrypt */}
        {isSimpleRSADec && (
             <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-gray-600'}`}>
                    {isProcessing ? 'Decrypting (c^d mod n)...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded">
                        {dataOutput ? `Plaintext (m): ${dataOutput}` : 'Waiting for c and Private Key...'}
                    </p>
                    {/* Copy Button for Plaintext Output */}
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
                <span className="text-[10px] text-gray-500 mt-2">Input/Output are Decimal Numbers.</span>
            </div>
        )}

        {/* Simple RSA Sign */}
        {isSimpleRSASign && (
             <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-fuchsia-600'}`}>
                    {isProcessing ? 'Signing...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded">
                        {dataOutput ? `Signature (s): ${dataOutput}` : 'Waiting for m and Private Key...'}
                    </p>
                    {/* Copy Button for Signature Output */}
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
                <span className="text-[10px] text-gray-500 mt-2">Input/Output are Decimal Numbers.</span>
            </div>
        )}

        {/* Simple RSA Verify */}
        {isSimpleRSAVerify && (
             <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-fuchsia-600'}`}>
                    {isProcessing ? 'Verifying...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className={`text-left text-[10px] break-all p-1 rounded min-h-[3rem] overflow-auto 
                                     ${dataOutput?.includes('SUCCESS') ? 'bg-green-100 text-green-700 font-bold' : dataOutput?.includes('FAILURE') || dataOutput?.startsWith('ERROR') ? 'bg-red-100 text-red-700 font-bold' : 'bg-gray-100 text-gray-800'}`}>
                        {dataOutput || 'Waiting for m, s, and Public Key...'}
                    </p>
                </div>
            </div>
        )}
        
        {/* XOR Operation (Skipped for brevity) */}
        {type === 'XOR_OP' && (
             <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-lime-600'}`}>
                    {isProcessing ? 'Calculating XOR...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded">
                        {dataOutput ? `Result (${node.outputFormat || 'Base64'}): ${dataOutput?.substring(0, 15)}...` : 'Waiting for two data inputs...'}
                    </p>
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
            </div>
        )}

        {/* Bit Shift (Single Large Number) */}
        {isBitShift && (
             <div className="text-xs w-full text-center">
                <span className={`text-[10px] font-semibold text-gray-600 mb-1`}>SHIFT AMOUNT (BITS)</span>
                <input
                    type="number"
                    min="0"
                    className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 
                               text-gray-700 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition duration-200"
                    value={node.shiftAmount || 0}
                    onChange={(e) => updateNodeContent(id, 'shiftAmount', parseInt(e.target.value) || 0)}
                    onMouseDown={(e) => e.stopPropagation()} 
                    onTouchStart={(e) => e.stopPropagation()} 
                    onClick={(e) => e.stopPropagation()}
                />
                
                <span className={`text-[10px] font-semibold text-gray-600 mb-1`}>SHIFT DIRECTION</span>
                <select
                    className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm mb-2
                                 bg-white appearance-none cursor-pointer text-gray-700 
                                 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition duration-200"
                    value={node.shiftType || 'Left'}
                    onChange={(e) => updateNodeContent(id, 'shiftType', e.target.value)}
                    onMouseDown={(e) => e.stopPropagation()}
                    onTouchStart={(e) => e.stopPropagation()}
                    onClick={(e) => e.stopPropagation()}
                >
                    <option value="Left">Left (&lt;&lt;)</option>
                    <option value="Right">Right (&gt;&gt;)</option>
                </select>

                <span className={`font-semibold mt-2 ${isProcessing ? 'text-yellow-600' : 'text-indigo-600'}`}>
                    {isProcessing ? 'Shifting...' : 'Active (Single Number Mode)'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className={`text-left text-[10px] break-all p-1 bg-gray-100 rounded ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                        {dataOutput ? `Result (${node.outputFormat || 'N/A'}): ${dataOutput?.substring(0, 15)}...` : 'Waiting for single numeric input...'}
                    </p>
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
            </div>
        )}

        {/* Generic Output Preview */}
        {!isDataInput && !isOutputViewer && type !== 'HASH_FN' && !isKeyGen && !isSymEnc && !isSymDec && !isRSAKeyGen && !isAsymEnc && !isAsymDec && type !== 'XOR_OP' && !isBitShift && !isSimpleRSAKeyGen && !isSimpleRSAPubKeyGen && !isSimpleRSAEnc && !isSimpleRSADec && !isCaesarCipher && !isVigenereCipher && !isSimpleRSASign && !isSimpleRSAVerify && (
            <div className="text-xs text-gray-500 mt-2">
                <p>Output: {dataOutput ? dataOutput.substring(0, 10) + '...' : 'Waiting for connection'}</p>
            </div>
        )}
      </div>
    </div>
  );
};

// --- Helper Component for Toolbar Actions ---
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
                className={`w-full p-2 flex items-center justify-center // Simplified size and layout
                            bg-white hover:bg-gray-100 border-2 border-transparent ${hoverBorderClass}
                            transition duration-150 text-gray-700 rounded-lg shadow-sm`}
                title={label} // Use label as tooltip
            >
                {Icon && <Icon className={`w-5 h-5 ${iconTextColorClass} flex-shrink-0`} />}
            </button>
            
            {isFileInput && (
                <input 
                    type="file" 
                    ref={inputRef} 
                    onChange={onChange} 
                    accept=".json"
                    className="hidden"
                />
            )}
        </div>
    );
};

// --- Toolbar Component ---

const Toolbar = ({ addNode, onDownloadProject, onUploadProject, onZoomIn, onZoomOut }) => {
    const [collapsedGroups, setCollapsedGroups] = useState(() => {
        // Initialize all groups to open (false)
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

    return (
        <div className="w-64 bg-gray-50 flex-shrink-0 border-r border-gray-200 shadow-lg flex flex-col">
            {/* Title/Logo Container */}
            <div className="p-4 pt-6 pb-4 border-b border-gray-200 flex flex-col justify-center items-center bg-white">
                <img 
          src="VCL - Horizonal logo + name.png"
          alt="VisualCryptoLab Logo and Name" 
          className="w-full h-auto max-w-[180px]"
          // Fallback if image fails to load
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
                        {/* Group Header (Clickable) */}
                        <div 
                            className="flex justify-between items-center text-xs font-bold uppercase text-gray-500 pt-2 pb-1 border-b border-gray-200 cursor-pointer hover:text-gray-700 transition"
                            onClick={() => toggleGroup(group.name)}
                        >
                            <span>{group.name}</span>
                            <ChevronDown className={`w-4 h-4 transition-transform duration-200 ${collapsedGroups[group.name] ? 'rotate-180' : ''}`} />
                        </div>
                        
                        {/* Group Content (Conditionally Rendered/Collapsed) */}
                        {!collapsedGroups[group.name] && (
                            <div className="space-y-1">
                                {group.types.map((type) => {
                                    const def = NODE_DEFINITIONS[type];
                                    if (!def) return null; // Safety check
                                    
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
                                            {/* Render the custom icon component or the default Lucide icon */}
                                            {def.icon && typeof def.icon === 'function' ? (
                                                <def.icon className={`w-5 h-5 ${iconTextColorClass} flex-shrink-0`} />
                                            ) : (
                                                def.icon && <def.icon className={`w-5 h-5 ${iconTextColorClass} flex-shrink-0`} />
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
            
            {/* Action Buttons Section at the bottom */}
            <div className="flex justify-around space-x-1 p-3 pt-4 border-t border-gray-200 flex-shrink-0 bg-white shadow-inner">
                
                <ToolbarButton 
                    icon={Download} 
                    label="Download Project (JSON)" 
                    color="blue" 
                    onClick={onDownloadProject}
                />
                
                <ToolbarButton 
                    icon={Upload} 
                    label="Upload Project (JSON)" 
                    color="orange" 
                    onChange={onUploadProject}
                    isFileInput={true} 
                />
                
                {/* NEW: Zoom Out Button */}
                <ToolbarButton 
                    icon={ZoomOut} 
                    label="Zoom Out" 
                    color="teal" 
                    onClick={onZoomOut}
                />

                {/* NEW: Zoom In Button */}
                <ToolbarButton 
                    icon={ZoomIn} 
                    label="Zoom In" 
                    color="teal" 
                    onClick={onZoomIn}
                />
                
                {/* Removed 'Download Diagram (JPG)' button as per previous request.
                <ToolbarButton 
                    icon={Camera} 
                    label="Download Diagram (JPG)" 
                    color="teal" 
                    onClick={onDownloadImage}
                />
                */}
            </div>
        </div>
    );
}

// --- Main Application Component ---

const App = () => {
  const [nodes, setNodes] = useState(INITIAL_NODES);
  const [connections, setConnections] = useState(INITIAL_CONNECTIONS); 
  const [connectingPort, setConnectingPort] = useState(null); 
  const [scale, setScale] = useState(1.0); // New state for zoom level
  
  const MAX_SCALE = 2.0;
  const MIN_SCALE = 0.5;
  const ZOOM_STEP = 0.2;

  // Zoom handlers
  const handleZoomIn = useCallback(() => {
      setScale(prevScale => Math.min(MAX_SCALE, prevScale + ZOOM_STEP));
  }, []);

  const handleZoomOut = useCallback(() => {
      setScale(prevScale => Math.max(MIN_SCALE, prevScale - ZOOM_STEP));
  }, []);

    
  const canvasRef = useRef(null);
  
  // --- Project Management Handlers (Skipped for brevity) ---
  
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
        nodes: nodes,
        connections: connections
    };
    const data = JSON.stringify(projectData, null, 2);
    downloadFile(data, 'visual_crypto_project.json', 'application/json');
  }, [nodes, connections]);

  const handleUploadProject = useCallback((event) => {
      const file = event.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (e) => {
          try {
              const projectData = JSON.parse(e.target.result);
              if (projectData.nodes && projectData.connections) {
                  setNodes(projectData.nodes);
                  setConnections(projectData.connections);
                  // Recalculation is triggered by the useEffect hook watching nodes/connections
              } else {
                  console.error("Invalid project file format.");
                  // Non-blocking user feedback needed here, but for now, console log.
              }
          } catch (error) {
              console.error("Error parsing project file:", error);
          }
      };
      reader.readAsText(file);
      // Clear file input value after reading
      event.target.value = ''; 
  }, []);

  const handleDownloadImage = useCallback(() => {
      // NOTE: This feature requires the 'html2canvas' library to be loaded externally (e.g., via a <script> tag).
      // This function will now rely on external configuration in index.html to load html2canvas.
      
      if (typeof window.html2canvas !== 'function') {
          console.error("Image download failed: html2canvas library is required for canvas capture. Please ensure the <script> tag for html2canvas is loaded globally in your index.html file.");
          return;
      }
      
      const element = canvasRef.current;
      if (element) {
          window.html2canvas(element, { 
              useCORS: true, 
              allowTaint: true, 
              backgroundColor: '#ffffff'
          }).then(canvas => {
              const imageURL = canvas.toDataURL('image/jpeg', 0.9);
              
              const a = document.createElement('a');
              a.href = imageURL;
              a.download = 'visual_crypto_diagram.jpg';
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
          }).catch(err => {
              console.error("Error capturing canvas image:", err);
          });
      }
  }, []);
  
  // --- Core Logic: Graph Recalculation (Data Flow Engine) ---
  
  const recalculateGraph = useCallback((currentNodes, currentConnections, changedNodeId = null) => {
    // Re-initialize newNodesMap correctly to ensure integrity and reset calculation fields.
    const newNodesMap = new Map(currentNodes.map(n => {
        const newNode = { ...n };
        // Reset fields relevant to calculation output/status
        newNode.isProcessing = false;
        if (newNode.type === 'OUTPUT_VIEWER') {
             // Keep state of conversion feature
             newNode.convertedData = newNode.convertedData || ''; 
             newNode.convertedFormat = newNode.convertedFormat || 'Base64';
             newNode.isConversionExpanded = newNode.isConversionExpanded || false;
             newNode.sourceFormat = newNode.sourceFormat || ''; // New field for source format
             newNode.rawInputData = newNode.rawInputData || ''; // New field to store UNCONVERTED input
        }
        return [n.id, newNode];
    })); 
    
    let initialQueue = new Set(currentNodes.filter(n => {
        const def = NODE_DEFINITIONS[n.type];
        return def && def.inputPorts && def.inputPorts.length === 0;
    }).map(n => n.id));
    
    if (changedNodeId) {
        initialQueue.add(changedNodeId);
        currentConnections
            .filter(c => c.source === changedNodeId)
            .forEach(c => initialQueue.add(c.target));
    }
    
    const nodesToProcess = Array.from(initialQueue);
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
        
        // --- Source Nodes (No input ports) ---
        if (sourceNodeDef.inputPorts.length === 0) {
            
            if (sourceNode.type === 'DATA_INPUT') {
                outputData = sourceNode.content || ''; 
            } else if (sourceNode.type === 'KEY_GEN') {
                
                if (sourceNode.key || sourceNode.generateKey) {
                    isProcessing = true;
                    if (!sourceNode.key || sourceNode.generateKey) {
                         const algorithm = sourceNode.keyAlgorithm || 'AES-GCM';
                         
                         generateSymmetricKey(algorithm).then(({ keyObject, keyBase64 }) => {
                            setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId 
                                     ? { ...n, dataOutput: keyBase64, key: keyObject, isProcessing: false, generateKey: false } 
                                     : n
                            ));
                         }).catch(err => {
                             setNodes(prevNodes => prevNodes.map(n => 
                                 n.id === sourceId 
                                     ? { ...n, dataOutput: `ERROR: Key generation failed.`, isProcessing: false, generateKey: false } 
                                     : n
                             ));
                         });
                         outputData = sourceNode.dataOutput || 'Generating Key...';
                    } else {
                        outputData = sourceNode.dataOutput || '';
                        isProcessing = false;
                    }

                } else {
                    outputData = 'Click "Generate New Key"';
                }
            } else if (sourceNode.type === 'RSA_KEY_GEN' || sourceNode.type === 'SIMPLE_RSA_KEY_GEN') { 
                
                 const publicExponentToUse = sourceNode.type === 'SIMPLE_RSA_KEY_GEN' ? 65537 : (sourceNode.publicExponent || 65537);
                 
                 // --- Simple RSA Key Gen Logic ---
                 if (sourceNode.type === 'SIMPLE_RSA_KEY_GEN' && sourceNode.generateKey) {
                     isProcessing = true;
                     
                     // Read P, Q, E from input fields
                     const rawP = sourceNode.p;
                     const rawQ = sourceNode.q;
                     const rawE = sourceNode.e;
                     const userD = sourceNode.d ? BigInt(sourceNode.d) : null; 

                     let p_val, q_val, e_val, d_val;
                     let n_val, phiN_val;
                     let error = null;
                     let d_status = ''; // New status field

                     
                     try {
                        
                        // 1. Determine P and Q (Generate if missing or invalid)
                        const userP = rawP && !isNaN(Number(rawP)) ? BigInt(rawP) : null;
                        const userQ = rawQ && !isNaN(Number(rawQ)) ? BigInt(rawQ) : null;
                        
                        if (userP && userQ && userP > BigInt(0) && userQ > BigInt(0)) {
                            p_val = userP;
                            q_val = userQ;
                        } else {
                            // Autogenerate if P or Q are missing/invalid
                            ({ p: p_val, q: q_val } = generateSmallPrimes());
                        }

                        // 2. Calculate n and phi(n)
                        n_val = p_val * q_val;
                        phiN_val = (p_val - BigInt(1)) * (q_val - BigInt(1)); 

                        // 3. Determine E (Generate if missing, validate if provided)
                        const userE = rawE && !isNaN(Number(rawE)) ? BigInt(rawE) : null;
                        
                        if (userE && userE > BigInt(1) && userE < phiN_val && gcd(userE, phiN_val) === BigInt(1)) {
                            e_val = userE;
                        } else if (!userE || userE <= BigInt(0)) {
                            // Autogenerate if E is missing/invalid or 0
                            e_val = generateSmallE(phiN_val);
                        } else {
                            error = `ERROR: Invalid E (${userE.toString()}). Must be 1 < E < phi(n) and gcd(E, phi(n)) = 1.`;
                            throw new Error(error);
                        }
                         
                        // 4. Determine D (Always calculate the correct D)
                        const calculatedD = modInverse(e_val, phiN_val);
                        d_val = calculatedD; 
                         
                        // 5. Provide feedback on the user's D input
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
                         // Catches validation errors and modular inverse errors
                         error = err.message.startsWith("ERROR") ? err.message : `ERROR: Calculation failed. ${err.message}`;
                     }
                     
                     // 6. Update Node State
                     if (!error) {
                         // Key data output for downstream nodes
                         sourceNode.dataOutputPublic = `${n_val.toString()},${e_val.toString()}`; 
                         sourceNode.dataOutputPrivate = d_val.toString();
                         
                         // Internal display parameters (P, Q, E are now saved back to fill empty fields)
                         sourceNode.n = n_val.toString();
                         sourceNode.phiN = phiN_val.toString();
                         sourceNode.d = d_val.toString(); // OVERWRITE: Ensure D field shows the correct calculated key
                         sourceNode.p = p_val.toString();
                         sourceNode.q = q_val.toString();
                         sourceNode.e = e_val.toString();
                         sourceNode.dStatus = d_status; 
                         
                         outputData = sourceNode.dataOutputPrivate; // Only outputting Private Key
                         isProcessing = false;
                     } else {
                         // Handle error: reset output fields and display the error
                         outputData = error;
                         sourceNode.dataOutputPublic = outputData;
                         sourceNode.dataOutputPrivate = outputData;
                         sourceNode.n = ''; sourceNode.phiN = ''; 
                         
                         // Keep user-entered P, Q, E but set calculated fields to error state
                         sourceNode.p = rawP; 
                         sourceNode.q = rawQ;
                         sourceNode.e = rawE;
                         sourceNode.d = ''; // CLEAR D FIELD ON ERROR
                         sourceNode.dStatus = error;
                     }

                     // Since Simple RSA calculation is synchronous, we update the map directly
                     sourceNode.isProcessing = isProcessing;
                     sourceNode.generateKey = false; // Reset trigger
                     newNodesMap.set(sourceId, sourceNode);
                     
                     // Jump to next loop iteration
                     processed.add(sourceId);
                     nodesToProcess.push(...findAllTargets(sourceId));
                     continue;

                 } else if (sourceNode.keyPairObject || sourceNode.generateKey) {
                     // --- Web Crypto RSA Key Gen Logic (Advanced) ---
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
        
        // --- Processing/Sink Nodes (Have input ports) ---
        } else {
            // Collect all incoming connections to this target node
            const incomingConns = currentConnections.filter(c => c.target === sourceId);
            let inputs = {};
            
            // Step 1: Gather inputs and their formats from all upstream nodes
            incomingConns.forEach(conn => {
                const inputSourceNode = newNodesMap.get(conn.source);
                if (!inputSourceNode) return;

                let dataToUse;
                const sourceDef = NODE_DEFINITIONS[inputSourceNode.type];
                
                // Determine which data field to use from the source node
                if (sourceDef && sourceDef.outputPorts.length > conn.sourcePortIndex) {
                    const keyField = sourceDef.outputPorts[conn.sourcePortIndex].keyField;
                    dataToUse = inputSourceNode[keyField];
                } else {
                    dataToUse = inputSourceNode.dataOutput; // Fallback for simple nodes
                }

                // Determine the format of the output data
                const sourceFormat = inputSourceNode.type === 'DATA_INPUT' 
                    ? inputSourceNode.format 
                    : (inputSourceNode.outputFormat || getOutputFormat(inputSourceNode.type)); // FIX: Use node.outputFormat if set

                // Store the data and format using the input port ID
                if (!inputs[conn.targetPortId]) { 
                    inputs[conn.targetPortId] = { 
                        data: dataToUse, 
                        format: sourceFormat,
                        nodeId: inputSourceNode.id
                    };
                }
            });
            
            // Step 2: Execute node logic (using direct inputs lookup)
            switch (sourceNode.type) {
                case 'OUTPUT_VIEWER':
                    const inputObj = inputs['data'];
                    const rawInput = inputObj?.data; 
                    let convertedDataOutput = sourceNode.convertedData || '';
                    let calculatedSourceFormat = inputObj?.format || 'N/A';
                    
                    if (rawInput !== undefined && rawInput !== null && rawInput !== '' && !rawInput?.startsWith('ERROR')) {
                        
                        // Check if the source format suggests binary data (i.e., not a simple text node)
                        const isSourceBinary = ['Base64', 'Hexadecimal', 'Binary'].includes(calculatedSourceFormat) && !rawInput.match(/^[0-9\s]*$/);
                        
                        // Decide if we should treat the data as a single large number (SLN)
                        const isSLNTarget = ['Decimal', 'Hexadecimal', 'Binary'].includes(sourceNode.convertedFormat);
                        const shouldBeSingleNumber = isSLNTarget && isSourceBinary;

                        // 1. Calculate Secondary (Converted) Output if Expanded
                        if (sourceNode.isConversionExpanded) {
                            // Pass the flag to the converter
                            convertedDataOutput = convertDataFormat(rawInput, calculatedSourceFormat, sourceNode.convertedFormat || 'Base64', shouldBeSingleNumber);
                        } else {
                            convertedDataOutput = '';
                        }
                        
                        // 2. Set the data for the OUTPUT PORT (dataOutput)
                        if (sourceNode.isConversionExpanded && convertedDataOutput && !convertedDataOutput.startsWith('ERROR')) {
                            // Output converted data if expansion is active AND conversion was successful
                            outputData = convertedDataOutput;
                            // FIX: Set the advertised output format to the converted format
                            sourceNode.outputFormat = sourceNode.convertedFormat; 
                        } else {
                            // Otherwise, output the raw input (as raw input format)
                            outputData = rawInput;
                            // Set the advertised output format to the raw input format
                            sourceNode.outputFormat = calculatedSourceFormat === 'N/A' ? 'Text (UTF-8)' : calculatedSourceFormat; 
                        }

                    } else {
                        outputData = 'Not connected or no data.';
                        convertedDataOutput = '';
                        calculatedSourceFormat = 'N/A';
                        sourceNode.outputFormat = 'Text (UTF-8)'; // Default fallback format
                    }
                    
                    // 3. Update the node's state fields for UI display
                    sourceNode.convertedData = convertedDataOutput;
                    sourceNode.sourceFormat = calculatedSourceFormat; 
                    sourceNode.rawInputData = rawInput || outputData; // Raw input for internal viewer display
                    break;
                
                case 'CAESAR_CIPHER':
                    // FIX: Key input is now taken from node's internal state (shiftKey), not a port
                    const plaintextInput = inputs['plaintext']?.data;
                    const plainFormat = inputs['plaintext']?.format;
                    const shiftKey = sourceNode.shiftKey; // Read key from internal state
                    
                    if (plaintextInput !== undefined && plaintextInput !== null) {
                        isProcessing = true;
                        
                        // Handle Text (Latin alphabet shift) or Numeric (Byte shift)
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
                        
                        // Vigenere only operates on Text (UTF-8)
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
                    // Handled in the initial (no input ports) block. Skip here.
                    outputData = sourceNode.dataOutputPrivate;
                    break;
                
                case 'SIMPLE_RSA_PUBKEY_GEN':
                    const keySourceConn = incomingConns.find(c => c.targetPortId === 'keySource');
                    const sourceKeyGenNode = keySourceConn ? newNodesMap.get(keySourceConn.source) : null;
                    
                    let n_val = sourceNode.n_pub;
                    let e_val = sourceNode.e_pub;
                    let isReadOnly = false;

                    if (sourceKeyGenNode && sourceKeyGenNode.n && sourceKeyGenNode.e) {
                        // Connected to Simple RSA PrivKey Gen: pull values and set read-only
                        n_val = sourceKeyGenNode.n;
                        e_val = sourceNodeKeyGen.e;
                        isReadOnly = true;
                    } 
                    
                    // Update node state immediately (will be used in the UI)
                    sourceNode.isReadOnly = isReadOnly;
                    sourceNode.n_pub = n_val;
                    sourceNode.e_pub = e_val;

                    if (n_val && e_val) {
                        try {
                            // Simple validation that values are convertible to BigInt (numbers)
                            BigInt(n_val);
                            BigInt(e_val);
                            // Output is the concatenated string (n,e)
                            sourceNode.dataOutputPublic = `${n_val},${e_val}`;
                        } catch (err) {
                            sourceNode.dataOutputPublic = `ERROR: Invalid N or E format. Must be numeric.`;
                        }
                    } else {
                        sourceNode.dataOutputPublic = 'N/A (Missing N or E input)';
                    }

                    // Set the main output field (dataOutputPublic is already set above)
                    outputData = sourceNode.dataOutputPublic;
                    break;
                    
                case 'SIMPLE_RSA_ENC':
                    try {
                        const mStr = inputs['message']?.data; // FIX: Now accepts data type
                        // NEW LOGIC: Use 'publicKey' port to find the source node and extract N and E.
                        const pkInputObj = inputs['publicKey'];
                        const pkSourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'publicKey');
                        const sourceNodeKeyGen = newNodesMap.get(pkSourceConn?.source);

                        let n, e;

                        if (sourceNodeKeyGen?.type === 'SIMPLE_RSA_PUBKEY_GEN') {
                            n = sourceNodeKeyGen.n_pub ? BigInt(sourceNodeKeyGen.n_pub) : null;
                            e = sourceNodeKeyGen.e_pub ? BigInt(sourceNodeKeyGen.e_pub) : null;
                        } else if (pkInputObj?.data) {
                            // Fallback: if data came from a public type port, try to parse it
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
                        
                        // Ensure m is a number (if not, attempt to parse as decimal string)
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
                            // c = m^e mod n
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
                        
                        // Ensure c is a number
                        if (isNaN(Number(cStr))) {
                            outputData = `ERROR: Ciphertext must be a valid number. Received: ${cStr}`;
                            break;
                        }
                        
                        // We need to look up the source of the private key to get 'n'.
                        const sourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'privateKey');
                        const sourceNodeKeyGen = newNodesMap.get(sourceConn?.source);
                        
                        if (!cStr || !dStr || !sourceNodeKeyGen || !sourceNodeKeyGen.n) {
                            outputData = 'Waiting for ciphertext (c) and Private Key (d, n).';
                            break;
                        }
                        
                        const c = BigInt(cStr);
                        const d = BigInt(dStr);
                        // Get N from the original private key generator node
                        const n = BigInt(sourceNodeKeyGen.n);

                        isProcessing = true;
                        // m = c^d mod n
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
                        
                        // We need n from the key generator node (source of dStr)
                        const sourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'privateKey');
                        const sourceNodeKeyGen = newNodesMap.get(sourceConn?.source);

                        if (!sourceNodeKeyGen || !sourceNodeKeyGen.n) {
                            outputData = 'ERROR: Cannot find modulus (n). Ensure Private Key is connected from Simple RSA PrivKey Gen.';
                            break;
                        }

                        const m = BigInt(mValue);
                        const d = BigInt(dStr);
                        const n = BigInt(sourceNodeKeyGen.n);

                        // Signature: s = m^d mod n
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
                        // NEW LOGIC: Use 'publicKey' port to find the source node and extract N and E.
                        const pkInputObj = inputs['publicKey'];
                        const pkSourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'publicKey');
                        const sourceNodeKeyGen = newNodesMap.get(pkSourceConn?.source);

                        let n, e;

                        if (sourceNodeKeyGen?.type === 'SIMPLE_RSA_PUBKEY_GEN') {
                            n = sourceNodeKeyGen.n_pub ? BigInt(sourceNodeKeyGen.n_pub) : null;
                            e = sourceNodeKeyGen.e_pub ? BigInt(sourceNodeKeyGen.e_pub) : null;
                        } else if (pkInputObj?.data) {
                            // Fallback: if data came from a public type port, try to parse it
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

                        // Get n and e from the key generator node properties
                        const m = BigInt(mValue);
                        const s = BigInt(sValue);
                        
                        isProcessing = true;
                        // Verification: m' = s^e mod n
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
                    if (hashInput) { 
                        isProcessing = true; 
                        const algorithm = sourceNode.hashAlgorithm || 'SHA-256';

                        // Calculate hash using async function
                        const hashPromise = calculateHash(hashInput, algorithm).then(hashResult => {
                            // Update node state after successful calculation
                            setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId 
                                     ? { ...n, dataOutput: hashResult, isProcessing: false } 
                                     : n
                            ));
                        }).catch(err => {
                             // Handle error during calculation
                             setNodes(prevNodes => prevNodes.map(n => 
                                 n.id === sourceId 
                                      ? { ...n, dataOutput: `ERROR: Hash calculation failed. ${err.message}`, isProcessing: false } 
                                      : n
                             ));
                        });
                        
                        // Output placeholder while processing
                        outputData = sourceNode.dataOutput || 'Calculating...';
                    } else { 
                        outputData = 'Waiting for data input.'; 
                    }
                    break;
                
                case 'XOR_OP':
                    const dataInputA = inputs['dataA']?.data; 
                    const dataInputB = inputs['dataB']?.data; 
                    const formatA = inputs['dataA']?.format; // Primary input format
                    const formatB = inputs['dataB']?.format;

                    if (dataInputA && dataInputB) { 
                        // Note: XOR is a byte-wise operation, so conversion to Uint8Array is appropriate.
                        const bytesA = convertToUint8Array(dataInputA, formatA);
                        const bytesB = convertToUint8Array(dataInputB, formatB);

                        isProcessing = true; 
                        const base64Result = performBitwiseXor(bytesA, bytesB); 
                        outputData = convertDataFormat(base64Result, 'Base64', formatA);
                        sourceNode.outputFormat = formatA; 
                        isProcessing = false; 
                    } else if (dataInputA && !dataInputB) {
                        outputData = 'Waiting for Input B.';
                        sourceNode.outputFormat = formatA || ''; 
                    } else if (!dataInputA && dataInputB) {
                        outputData = 'Waiting for Input A.';
                        sourceNode.outputFormat = formatB || ''; 
                    } else {
                        outputData = 'Waiting for two data inputs.'; 
                        sourceNode.outputFormat = '';
                    }
                    break;
                
                case 'SHIFT_OP':
                    const shiftDataInput = inputs['data']?.data;
                    const shiftFormat = inputs['data']?.format; // Primary input format
                    const shiftType = sourceNode.shiftType || 'Left';
                    const shiftAmount = sourceNode.shiftAmount || 0;
                    
                    if (shiftDataInput) {
                        isProcessing = true;
                        
                        // Data formats considered single numbers: Decimal, Hexadecimal, Binary
                        if (shiftFormat === 'Decimal' || shiftFormat === 'Hexadecimal' || shiftFormat === 'Binary') {
                            
                            outputData = performBitShiftOperation(shiftDataInput, shiftType, shiftAmount, shiftFormat);
                            sourceNode.outputFormat = shiftFormat;
                            
                        } else {
                             // This covers Text (UTF-8) and Base64 (which is byte stream)
                            outputData = `ERROR: Bit Shift requires input data to be a single number (Decimal, Hexadecimal, or Binary). Received: ${shiftFormat}.`;
                            sourceNode.outputFormat = shiftFormat;
                        }

                        isProcessing = false; 
                    } else { 
                        outputData = 'Waiting for data input.'; 
                        sourceNode.outputFormat = '';
                    }
                    break;

                // --- Web Crypto API Cipher Nodes (Skipped for brevity) ---
                case 'SYM_ENC':
                case 'SYM_DEC':
                case 'ASYM_ENC':
                case 'ASYM_DEC':
                    // These nodes remain asynchronous or simple pass-through/error states
                    // Logic remains as in previous version
                    if (sourceNode.type === 'SYM_ENC' && inputs['data']?.data && inputs['key']?.data) {
                        isProcessing = true;
                        const algorithm = sourceNode.symAlgorithm || 'AES-GCM';
                        symmetricEncrypt(inputs['data'].data, inputs['key'].data, algorithm).then(ciphertext => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: ciphertext, isProcessing: false } : n));
                        });
                        outputData = sourceNode.dataOutput || 'Encrypting...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    } else if (sourceNode.type === 'SYM_DEC' && inputs['cipher']?.data && inputs['key']?.data) {
                        isProcessing = true;
                        const algorithm = sourceNode.symAlgorithm || 'AES-GCM'; 
                        symmetricDecrypt(inputs['cipher'].data, inputs['key'].data, algorithm).then(plaintext => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: plaintext, isProcessing: false } : n));
                        });
                        outputData = sourceNode.dataOutput || 'Decrypting...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    } else if (sourceNode.type === 'ASYM_ENC' && inputs['data']?.data && inputs['publicKey']?.data) {
                        isProcessing = true;
                        const algorithm = sourceNode.asymAlgorithm || 'RSA-OAEP';
                        asymmetricEncrypt(inputs['data'].data, inputs['publicKey'].data, algorithm).then(ciphertext => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: ciphertext, isProcessing: false } : n));
                        });
                        outputData = sourceNode.dataOutput || 'Encrypting...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    } else if (sourceNode.type === 'ASYM_DEC' && inputs['cipher']?.data && inputs['privateKey']?.data) {
                        isProcessing = true;
                        const algorithm = sourceNode.asymAlgorithm || 'RSA-OAEP';
                        asymmetricDecrypt(inputs['cipher'].data, inputs['privateKey'].data, algorithm).then(plaintext => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: plaintext, isProcessing: false } : n));
                        });
                        outputData = sourceNode.dataOutput || 'Decrypting...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    } else {
                        outputData = 'Waiting for inputs.';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    }
                    break;
                    
                default:
                    outputData = 'ERROR: Unrecognized Node Type.';
            }

        }
        
        // Update the node's output field(s) and processing status
        
        const primaryOutputPort = sourceNodeDef.outputPorts?.[0];
        if (primaryOutputPort && primaryOutputPort.keyField === 'dataOutput') {
            sourceNode.dataOutput = outputData; 
        } else if (!primaryOutputPort) {
            // Manually set dataOutput for SINK nodes (viewers)
            if (sourceNode.type !== 'OUTPUT_VIEWER') {
                sourceNode.dataOutput = outputData;
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
  
  // --- Effects for Recalculation ---
  
  useEffect(() => {
    // Initial calculation or on connection change
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
                    shiftKey: (field === 'shiftKey' ? value : node.shiftKey), // New Caesar Key
                    keyword: (field === 'keyword' ? value : node.keyword), // New Vigenere Keyword
                    vigenereMode: (field === 'vigenereMode' ? value : node.vigenereMode), // New Vigenere Mode
                    // Simple RSA specific
                    p: (field === 'p' ? value : node.p),
                    q: (field === 'q' ? value : node.q),
                    e: (field === 'e' ? value : node.e),
                    d: (field === 'd' ? value : node.d), // PRESERVE D BEFORE RECALC
                    n_pub: (field === 'n_pub' ? value : node.n_pub), // NEW PUBKEY FIELD
                    e_pub: (field === 'e_pub' ? value : node.e_pub), // NEW PUBKEY FIELD
                    isReadOnly: node.isReadOnly, // NEW PUBKEY FIELD
                    // Conversion Feature State:
                    isConversionExpanded: (field === 'isConversionExpanded' ? value : node.isConversionExpanded),
                    convertedFormat: (field === 'convertedFormat' ? value : node.convertedFormat),
                    viewFormat: (field === 'viewFormat' ? value : node.viewFormat),
                    isProcessing: node.isProcessing,
                    dStatus: node.dStatus,
                    hashAlgorithm: (field === 'hashAlgorithm' ? value : node.hashAlgorithm), // Added hashAlgorithm update
                };
                return updatedNode;
            }
            return node;
        });
        // Recalculate immediately after content update
        return recalculateGraph(nextNodes, connections, id);
    });
  }, [connections, recalculateGraph]);
  
  // --- Standard App Handlers ---

  const setPosition = useCallback((id, newPos) => {
    setNodes(prevNodes => prevNodes.map(node =>
      node.id === id ? { ...node, position: newPos } : node
    ));
  }, []);
  
  const addNode = useCallback((type, label, color) => {
    const newId = `${type}_${Date.now()}`;
    const definition = NODE_DEFINITIONS[type];
    
    const initialContent = { dataOutput: '', isProcessing: false, outputFormat: getOutputFormat(type) };
    
    // --- Determine a sensible starting position near the center/previous nodes ---
    // Calculate canvas size (approximate center, assuming CanvasRef exists later)
    const canvas = canvasRef.current;
    
    // Use fallback dimensions if ref is not yet active, or bounds are zero
    const canvasWidth = canvas?.clientWidth > 100 ? canvas.clientWidth : 800;
    const canvasHeight = canvas?.clientHeight > 100 ? canvas.clientHeight : 600;
    
    // Base position near the center
    let x = (canvasWidth / 2) - (BOX_SIZE.width / 2);
    let y = (canvasHeight / 2) - (BOX_SIZE.minHeight / 2);
    
    // Add small random offset (max 100px) to prevent direct overlap
    // Range is -100 to 100
    const randomOffset = () => Math.floor(Math.random() * 200) - 100;
    x += randomOffset();
    y += randomOffset();

    // Ensure bounds are not violated by the random offset
    x = Math.max(20, Math.min(x, canvasWidth - BOX_SIZE.width - 20));
    y = Math.max(20, Math.min(y, canvasHeight - BOX_SIZE.minHeight - 20));
    
    const position = { x, y };
    // --------------------------------------------------------------------------

    if (type === 'DATA_INPUT') {
      initialContent.content = '';
      initialContent.format = 'Text (UTF-8)';
    } else if (type === 'OUTPUT_VIEWER') { 
      initialContent.dataOutput = ''; // Will hold the final data (raw or converted)
      initialContent.rawInputData = ''; // New field to hold the raw input string
      initialContent.viewFormat = 'Text (UTF-8)'; 
      initialContent.isConversionExpanded = false; // New state
      initialContent.convertedData = ''; // New state
      initialContent.convertedFormat = 'Base64'; // New state
      initialContent.sourceFormat = '';
    } else if (type === 'CAESAR_CIPHER') {
      initialContent.shiftKey = 3; // Default shift key
      initialContent.outputFormat = 'Text (UTF-8)';
    } else if (type === 'VIGENERE_CIPHER') {
      initialContent.keyword = 'HELLO'; // Default keyword
      initialContent.vigenereMode = 'ENCRYPT';
      initialContent.outputFormat = 'Text (UTF-8)';
    } else if (type === 'HASH_FN') { 
      initialContent.hashAlgorithm = 'SHA-256'; // Default value
    } else if (type === 'KEY_GEN') {
      initialContent.keyAlgorithm = 'AES-GCM';
      initialContent.key = null; 
    } else if (type === 'RSA_KEY_GEN') { 
      initialContent.keyAlgorithm = 'RSA-OAEP';
      initialContent.modulusLength = 2048;
      initialContent.publicExponent = 65537; 
      initialContent.dataOutputPublic = '';
      initialContent.dataOutputPrivate = '';
      initialContent.keyPairObject = null;
      initialContent.rsaParameters = { n: '', d: '', p: '', q: '', e: 65537 }; 
    } else if (type === 'SIMPLE_RSA_KEY_GEN') { // Private Key Gen initialization
      initialContent.keyAlgorithm = 'RSA-OAEP';
      initialContent.modulusLength = 0;
      initialContent.p = '';
      initialContent.q = '';
      initialContent.e = '';
      initialContent.d = ''; // MODIFICADO: Initialize d as empty string to allow input
      initialContent.n = '';
      initialContent.phiN = '';
      initialContent.dataOutputPublic = '';
      initialContent.dataOutputPrivate = '';
      initialContent.dStatus = ''; // New status field
    } else if (type === 'SIMPLE_RSA_PUBKEY_GEN') { // Public Key Gen initialization (NEW)
      initialContent.outputFormat = 'Decimal';
      initialContent.n_pub = '';
      initialContent.e_pub = '';
      initialContent.dataOutputPublic = ''; 
      initialContent.isReadOnly = false;
    } else if (type === 'SIMPLE_RSA_ENC' || type === 'SIMPLE_RSA_DEC') {
      initialContent.outputFormat = 'Decimal';
    } else if (type === 'SIMPLE_RSA_SIGN' || type === 'SIMPLE_RSA_VERIFY') { // New Signature nodes
      initialContent.outputFormat = type === 'SIMPLE_RSA_SIGN' ? 'Decimal' : 'Text (UTF-8)';
    } else if (type === 'SYM_ENC' || type === 'SYM_DEC') {
      initialContent.symAlgorithm = 'AES-GCM';
    } else if (type === 'ASYM_ENC' || type === 'ASYM_DEC') {
      initialContent.asymAlgorithm = 'RSA-OAEP';
    } else if (type === 'SHIFT_OP') {
      initialContent.shiftType = 'Left';
      initialContent.shiftAmount = 1;
      initialContent.outputFormat = ''; // Dynamic output format
    } else if (type === 'XOR_OP') {
      initialContent.outputFormat = ''; // Dynamic output format
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
    return connections.map(conn => {
      const sourceNode = nodes.find(n => n.id === conn.source);
      const targetNode = nodes.find(n => n.id === conn.target);
      
      if (sourceNode && targetNode) {
        return {
            path: getLinePath(sourceNode, targetNode, conn), // Passes connection object for precise path calculation
            source: conn.source,
            target: conn.target,
            sourcePortIndex: conn.sourcePortIndex,
            targetPortId: conn.targetPortId,
        };
      }
      return null;
    }).filter(p => p !== null);
  }, [connections, nodes]);


  // Define the CSS for the line animation (removed dashed animation)
  const animatedLineStyle = `
    @keyframes animate-pulse-slow {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    .animate-pulse-slow {
      animation: animate-pulse-slow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    }
    .connection-line-visible {
        stroke: #059669; /* Emerald 600 */
        stroke-width: 4;
        fill: none;
        pointer-events: none; /* Invisible to mouse, only the hitbox is active */
    }
    .connection-hitbox {
        stroke: transparent;
        stroke-width: 15; /* Large clickable area */
        fill: none;
        cursor: pointer;
        pointer-events: stroke; /* Only sensitive to stroke clicks */
    }
    .connection-hitbox:hover {
        stroke: rgba(248, 113, 129, 0.5); /* Semi-transparent red on hover */
    }
  `;
  
  const handleCanvasClick = useCallback(() => {
    if (connectingPort) {
      handleConnectEnd(null);
    }
  }, [connectingPort, handleConnectEnd]);

  return (
    <div className="h-screen w-screen flex bg-gray-100 font-inter overflow-hidden">
        
      {/* Removed SimpleInfoModal component */}
        
      <style dangerouslySetInnerHTML={{ __html: animatedLineStyle }} />

      <Toolbar 
        addNode={addNode} 
        onDownloadProject={handleDownloadProject}
        onUploadProject={handleUploadProject}
        onDownloadImage={handleDownloadImage}
        onZoomIn={handleZoomIn} // Passed new zoom handler
        onZoomOut={handleZoomOut} // Passed new zoom handler
      />

      <div className="flex-grow flex flex-col p-4">
        
        <div 
          ref={canvasRef}
          className="canvas-container relative w-full flex-grow border-4 border-dashed border-gray-300 rounded-2xl bg-white shadow-inner" // Removed overflow-hidden here, added overflow:auto to style
          onClick={handleCanvasClick}
        >
          
          {/* New wrapper for scaling nodes and lines */}
          <div 
              style={{ 
                  transform: `scale(${scale})`, 
                  transformOrigin: 'top left',
              }} 
              className="absolute top-0 left-0 w-full h-full"
          >
              <svg className="absolute top-0 left-0 w-full h-full pointer-events-auto z-0">
                {connectionPaths.map((conn, index) => (
                  <g 
                    key={`${conn.source}-${conn.target}-${conn.sourcePortIndex}-${conn.targetPortId}`}
                    onClick={(e) => { 
                        e.stopPropagation(); 
                        handleRemoveConnection(conn.source, conn.target, conn.sourcePortIndex, conn.targetPortId);
                    }}
                    className="cursor-pointer" // Add cursor style to the group
                  >
                    {/* Invisible Hitbox (must come first) */}
                    <path
                        d={conn.path}
                        className="connection-hitbox"
                    />
                    {/* Visible Line */}
                    <path
                        d={conn.path}
                        className="connection-line-visible"
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
                  scale={scale} // Passed scale for accurate drag calculation
                />
              ))}
          </div>
          
        </div>
      </div>
    </div>
  );
};

export default App;
