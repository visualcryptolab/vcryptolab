import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { LayoutGrid, Cpu, Key, Zap, Settings, Lock, Unlock, Hash, Clipboard, X, ArrowLeft, ArrowRight } from 'lucide-react'; 

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
};

const HOVER_BORDER_CLASSES = {
  blue: 'hover:border-blue-500', red: 'hover:border-red-500', orange: 'hover:border-orange-500', cyan: 'hover:border-cyan-500', pink: 'hover:border-pink-500', 
  teal: 'hover:border-teal-500', gray: 'hover:border-gray-500', lime: 'hover:border-lime-500', indigo: 'hover:border-indigo-500',
};

const TEXT_ICON_CLASSES = {
  blue: 'text-blue-600', red: 'text-red-600', orange: 'text-orange-600', cyan: 'text-cyan-600', pink: 'text-pink-500', 
  teal: 'text-teal-600', gray: 'text-gray-600', lime: 'text-lime-600', indigo: 'text-indigo-600',
};

const HOVER_BORDER_TOOLBAR_CLASSES = {
  blue: 'hover:border-blue-400', red: 'hover:border-red-400', orange: 'hover:border-orange-400', cyan: 'hover:border-cyan-400', pink: 'hover:border-pink-400', 
  teal: 'hover:border-teal-400', gray: 'hover:border-gray-400', lime: 'hover:border-lime-400', indigo: 'hover:border-indigo-400',
};

// --- Port Configuration ---
const PORT_SIZE = 4; // w-4 h-4
const PORT_VISUAL_OFFSET_PX = 8; // Half port width in pixels
const INPUT_PORT_COLOR = 'bg-stone-500'; // Standard Input (Mandatory)
const OPTIONAL_PORT_COLOR = 'bg-gray-400'; // Optional Input 
const OUTPUT_PORT_COLOR = 'bg-emerald-500'; // Standard Output

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
  OUTPUT_VIEWER: { label: 'Output Viewer', color: 'red', icon: Zap, 
    inputPorts: [{ name: 'Data Input', type: 'data', mandatory: true, id: 'data' }], outputPorts: [] },
  
  // --- Key Generators ---
  KEY_GEN: { label: 'Sym Key Generator', color: 'orange', icon: Key, inputPorts: [], outputPorts: [{ name: 'Key Output (AES)', type: 'key', keyField: 'dataOutput' }] }, 

  RSA_KEY_GEN: { 
    label: 'RSA Key Generator', 
    color: 'cyan', 
    icon: Key, 
    inputPorts: [], 
    outputPorts: [
        { name: 'Public Key', type: 'public', keyField: 'dataOutputPublic' }, // index 0
        { name: 'Private Key', type: 'private', keyField: 'dataOutputPrivate' } // index 1
    ]
  },
  
  // --- Cipher Nodes ---
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

// Initial nodes on the canvas
const INITIAL_NODES = [
  { 
    id: 'input_1', 
    label: 'Data Input', 
    position: { x: 50, y: 150 }, 
    type: 'DATA_INPUT', 
    color: 'blue', 
    content: 'Hello cryptographic world!', 
    format: 'Text (UTF-8)',
    dataOutput: 'Hello cryptographic world!'
  },
];

const INITIAL_CONNECTIONS = []; // No initial connections

const BOX_SIZE = { width: 192, minHeight: 144 }; // w-48 is 192px

// =================================================================
// 2. CRYPTO & UTILITY FUNCTIONS
// =================================================================

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

// --- Data Format Conversion Functions (Still needed by other nodes) ---

/** Converts ArrayBuffer to a hexadecimal string. */
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
    const cleanedHex = hex.replace(/[^0-9a-fA-F]/g, '');
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

/** Converts a data string from a source format to a target format via ArrayBuffer. */
const convertDataFormat = (dataStr, sourceFormat, targetFormat) => {
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
             buffer = hexToArrayBuffer(dataStr);
        } else if (sourceFormat === 'Binary') {
             // Convert binary string (space separated) to ArrayBuffer
             const binaryArray = dataStr.split(/\s+/).map(s => parseInt(s, 2));
             const validBytes = binaryArray.filter(b => !isNaN(b) && b >= 0 && b <= 255);
             buffer = new Uint8Array(validBytes).buffer;
        } else if (sourceFormat === 'Decimal') {
             // Convert decimal string (space separated) to ArrayBuffer
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
        if (targetFormat === 'Text (UTF-8)') {
            return new TextDecoder().decode(buffer);
        } else if (targetFormat === 'Base64') {
            return arrayBufferToBase64(buffer);
        } else if (targetFormat === 'Hexadecimal') {
            return arrayBufferToHex(buffer);
        } else if (targetFormat === 'Binary') {
            return arrayBufferToBinary(buffer);
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
            // Handled by the 'format' property on the node itself
            return 'Text (UTF-8)'; 
        case 'KEY_GEN':
        case 'SYM_ENC':
        case 'XOR_OP':
        case 'SHIFT_OP':
        case 'ASYM_ENC':
            return 'Base64';
        case 'HASH_FN':
            return 'Hexadecimal';
        case 'SYM_DEC':
        case 'ASYM_DEC':
            return 'Text (UTF-8)';
        default:
            return 'Text (UTF-8)';
    }
}

/** Performs XOR operation on two input strings. */
const performBitwiseXor = (strA, strB) => {
    if (!strA || !strB) {
        return "ERROR: Missing one or both inputs.";
    }

    try {
        const encoder = new TextEncoder();
        const bufferA = encoder.encode(strA);
        const bufferB = encoder.encode(strB);

        const len = Math.min(bufferA.length, bufferB.length);
        const result = new Uint8Array(len);

        for (let i = 0; i < len; i++) {
            result[i] = bufferA[i] ^ bufferB[i];
        }

        return arrayBufferToBase64(result.buffer);
    } catch (error) {
        console.error("XOR operation failed:", error);
        return `ERROR: XOR failed. ${error.message}`;
    }
};

/** Performs a byte shift operation on the input string. */
const performByteShiftOperation = (dataStr, shiftType, shiftAmount) => {
    if (!dataStr) return "ERROR: Missing data input.";
    const byteAmount = Math.max(0, parseInt(shiftAmount) || 0);

    try {
        const encoder = new TextEncoder();
        const buffer = encoder.encode(dataStr);
        const numBytes = buffer.length;
        const result = new Uint8Array(numBytes);

        if (byteAmount >= numBytes) {
            return arrayBufferToBase64(result.buffer); 
        }
        
        if (shiftType === 'Left') {
            result.set(buffer.slice(byteAmount), 0);
        } else if (shiftType === 'Right') {
            result.set(buffer.slice(0, numBytes - byteAmount), byteAmount);
        } else {
            return "ERROR: Invalid shift type.";
        }

        return arrayBufferToBase64(result.buffer);
    } catch (error) {
        console.error("Byte Shift operation failed:", error);
        return `ERROR: Byte Shift failed. ${error.message}`;
    }
};

/** Calculates the hash of a given string using the Web Crypto API. */
const calculateHash = async (str, algorithm) => {
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

/** Generates an RSA Key Pair. */
const generateAsymmetricKeyPair = async (algorithm, modulusLength, publicExponentDecimal) => {
    
    let publicExponentArray;
    publicExponentArray = new Uint8Array([0x01, 0x00, 0x01]); 
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
            privateKey: `ERROR: ${error.message}`
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
            { name: algorithm }, privateKey, cipherBuffer
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
const Port = React.memo(({ nodeId, type, isConnecting, onStart, onEnd, title, isMandatory, portId, portIndex, outputType }) => {
    let interactionClasses = "";
    let clickHandler = () => {};
    
    const portColor = type === 'output' ? OUTPUT_PORT_COLOR : (isMandatory ? INPUT_PORT_COLOR : OPTIONAL_PORT_COLOR);

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
        // A port is a target candidate if an output port is active AND port types match
        const isTargetCandidate = isConnecting && isConnecting.sourceId !== nodeId && isConnecting.outputType === portId.split('-')[0]; 
        
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

const DraggableBox = ({ node, setPosition, canvasRef, handleConnectStart, handleConnectEnd, connectingPort, updateNodeContent, connections, handleDeleteNode }) => {
  // Destructure node props and look up definition
  const { id, label, position, type, color, content, format, dataOutput, dataOutputPublic, dataOutputPrivate, viewFormat, isProcessing, hashAlgorithm, keyAlgorithm, symAlgorithm, modulusLength, publicExponent, rsaParameters, asymAlgorithm, convertedData, convertedFormat, isConversionExpanded, sourceFormat, rawInputData } = node; 
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
  const isRSAKeyGen = type === 'RSA_KEY_GEN'; 
  const isSymEnc = type === 'SYM_ENC';
  const isSymDec = type === 'SYM_DEC';
  const isAsymEnc = type === 'ASYM_ENC'; 
  const isAsymDec = type === 'ASYM_DEC'; 
  const isBitShift = type === 'SHIFT_OP'; 
  
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
      const mouseXRelativeToCanvas = clientX - canvasRect.left;
      const mouseYRelativeToCanvas = clientY - canvasRect.top;

      offset.current = {
        x: mouseXRelativeToCanvas - position.x,
        y: mouseYRelativeToCanvas - position.y,
      };
      
      setIsDragging(true);
      e.preventDefault(); 
    }
  }, [canvasRef, position.x, position.y, connectingPort]);

  const handleDragMove = useCallback((e) => {
    if (!isDragging) return;
    const canvas = canvasRef.current;
    if (!canvas) return;

    const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
    const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);

    const canvasRect = canvas.getBoundingClientRect();
    const mouseXRelativeToCanvas = clientX - canvasRect.left;
    const mouseYRelativeToCanvas = clientY - canvasRect.top;
    
    let newX = mouseXRelativeToCanvas - offset.current.x;
    let newY = mouseYRelativeToCanvas - offset.current.y;
    
    // BOUNDS CHECKING
    const maxWidth = canvasRect.width - BOX_SIZE.width;
    const maxHeight = canvasRect.height - BOX_SIZE.minHeight; 

    newX = Math.max(0, Math.min(newX, maxWidth));
    newY = Math.max(0, Math.min(newY, maxHeight));

    setPosition(id, { x: newX, y: newY });
  }, [isDragging, id, setPosition, canvasRef]);

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
        tempTextArea.setSelectionRange(0, 99999); // For mobile devices
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
    }
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
          {isHashFn && <span className={`text-xs text-gray-500 mt-1`}>({hashAlgorithm})</span>}
          {isKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({keyAlgorithm})</span>}
          {isRSAKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({node.keyAlgorithm} {modulusLength} bits, e={publicExponent})</span>}
          {isSymEnc && <span className={`text-xs text-gray-500 mt-1`}>({symAlgorithm})</span>}
          {isSymDec && <span className={`text-xs text-gray-500 mt-1`}>({symAlgorithm})</span>}
          {isAsymEnc && <span className={`text-xs text-gray-500 mt-1`}>({asymAlgorithm})</span>}
          {isAsymDec && <span className={`text-xs text-gray-500 mt-1`}>({asymAlgorithm})</span>}
          
          {/* Show status/algorithm for XOR and Bit Shift */}
          {type === 'XOR_OP' && <span className={`text-xs text-gray-500 mt-1`}>({isProcessing ? 'Processing' : 'Bitwise XOR'})</span>}
          {isBitShift && <span className={`text-xs text-gray-500 mt-1`}>({isProcessing ? 'Processing' : 'Byte Shift'})</span>}

          {!isDataInput && !isOutputViewer && type !== 'HASH_FN' && !isKeyGen && !isSymEnc && !isSymDec && !isRSAKeyGen && !isAsymEnc && !isAsymDec && type !== 'XOR_OP' && !isBitShift && <span className={`text-xs text-gray-500 mt-1`}>({definition.label})</span>}
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
              onChange={(e) => updateNodeContent(id, 'content', e.target.value)}
              onMouseDown={(e) => e.stopPropagation()} 
              onTouchStart={(e) => e.stopPropagation()} 
              onClick={(e) => e.stopPropagation()}
            />
            <select
              className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm 
                         bg-white appearance-none cursor-pointer text-gray-700 
                         focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              value={format || 'Text (UTF-8)'}
              onChange={(e) => updateNodeContent(id, 'format', e.target.value)}
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
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-md 
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
                        <div className="relative w-full break-all text-[10px] leading-tight text-gray-800 bg-white p-1 rounded-md overflow-y-auto border border-gray-200 min-h-[4rem]">
                            <p>{convertedData || 'Select conversion type...'}</p>

                            {/* Copy Button for Converted Output */}
                            <button
                                onClick={(e) => handleCopyToClipboard(e, convertedData)}
                                disabled={!convertedData || convertedData.startsWith('ERROR')}
                                className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-md 
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
        
        {isHashFn && (
             <div className="text-xs w-full text-center">
                {/* Algorithm Selector */}
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

                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-gray-600'}`}>
                    {isProcessing ? 'Calculating...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded">
                        {dataOutput ? `Hash (Hex): ${dataOutput.substring(0, 15)}...` : 'Waiting for input...'}
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
        
        {/* Symmetric Key Generator */}
        {isKeyGen && (
            <div className="text-xs w-full text-center flex flex-col items-center">
                <select
                  className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 
                             bg-white appearance-none cursor-pointer text-gray-700 
                             focus:ring-2 focus:ring-orange-500 focus:border-orange-500 outline-none transition duration-200"
                  value={keyAlgorithm || 'AES-GCM'}
                  onChange={(e) => updateNodeContent(id, 'keyAlgorithm', e.target.value)}
                  onMouseDown={(e) => e.stopPropagation()}
                  onTouchStart={(e) => e.stopPropagation()}
                  onClick={(e) => e.stopPropagation()}
                >
                  {SYM_ALGORITHMS.map(alg => (
                    <option key={alg} value={alg}>{alg}</option>
                  ))}
                </select>
                
                <button
                    onClick={(e) => { e.stopPropagation(); updateNodeContent(id, 'generateKey', true); }}
                    className={`mt-1 w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md bg-orange-500 hover:bg-orange-600`}
                >
                    <Key className="w-4 h-4" />
                    <span>Generate New Key</span>
                </button>

                <span className={`font-semibold mt-2 ${dataOutput ? 'text-orange-600' : 'text-gray-500'}`}>
                    {isProcessing ? 'Generating...' : dataOutput ? 'Key Ready' : 'Click to Generate'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded">
                        {dataOutput ? `Key (Base64): ${dataOutput.substring(0, 15)}...` : 'No key generated.'}
                    </p>
                    {/* Copy Button for Key Output */}
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

        {/* RSA Asymmetric Key Generator */}
        {isRSAKeyGen && (
            <div className="text-xs w-full text-center flex flex-col items-center">
                
                {/* Modulus Length (n size) */}
                <div className="w-full mb-1">
                    <label className="block text-left text-[10px] font-semibold text-gray-600">Modulus Length (bits)</label>
                    <select
                      className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm 
                                 bg-white appearance-none cursor-pointer text-gray-700 
                                 focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 outline-none transition duration-200"
                      value={modulusLength || 2048}
                      onChange={(e) => updateNodeContent(id, 'modulusLength', parseInt(e.target.value))}
                      onMouseDown={(e) => e.stopPropagation()}
                      onTouchStart={(e) => e.stopPropagation()}
                      onClick={(e) => e.stopPropagation()}
                    >
                      {RSA_MODULUS_LENGTHS.map(len => (
                        <option key={len} value={len}>{len} bits</option>
                      ))}
                    </select>
                </div>
                
                {/* Public Exponent (e) - Input */}
                <div className="w-full mb-2">
                    <label className="block text-left text-[10px] font-semibold text-gray-600">Public Exponent (e)</label>
                    <input
                        type="number"
                        className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm 
                                 text-gray-700 focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 outline-none transition duration-200"
                        value={publicExponent || 65537}
                        onChange={(e) => updateNodeContent(id, 'publicExponent', parseInt(e.target.value) || 65537)}
                        onMouseDown={(e) => e.stopPropagation()} 
                        onTouchStart={(e) => e.stopPropagation()} 
                        onClick={(e) => e.stopPropagation()}
                    />
                </div>
                
                <button
                    onClick={(e) => { e.stopPropagation(); updateNodeContent(id, 'generateKey', true); }}
                    className={`mt-1 w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md bg-cyan-500 hover:bg-cyan-600`}
                >
                    <Key className="w-4 h-4" />
                    <span>Generate RSA Key Pair</span>
                </button>
                
                <span className={`font-semibold mt-2 ${dataOutputPublic ? 'text-cyan-600' : 'text-gray-500'}`}>
                    {isProcessing ? 'Generating...' : dataOutputPublic ? 'Keys Ready' : 'Configure and Generate'}
                </span>

                <div className="w-full mt-1 p-1 text-gray-500 break-all text-left border-t border-gray-200 pt-1 space-y-2">
                    <label className="block text-[10px] font-semibold text-gray-600">Extracted Key Parameters (Read Only)</label>
                    
                    {/* READ-ONLY PARAMETERS */}
                    {['n', 'd', 'p', 'q'].map(param => (
                        <div key={param} className="flex flex-col">
                            <label className="text-[10px] font-medium text-gray-500 capitalize">{param} (Base64URL):</label>
                            <input
                                type="text"
                                readOnly
                                className="w-full text-[8px] p-1 border border-gray-100 rounded bg-gray-50 break-all overflow-hidden cursor-default"
                                value={rsaParameters?.[param] ? `${rsaParameters[param].substring(0, 20)}...` : 'N/A'}
                                title={rsaParameters?.[param] || 'Parameter not yet generated'}
                                onMouseDown={(e) => e.stopPropagation()} 
                                onTouchStart={(e) => e.stopPropagation()} 
                                onClick={(e) => e.stopPropagation()}
                            />
                        </div>
                    ))}
                </div>
            </div>
        )}
        
        {/* Sym Encrypt */}
        {isSymEnc && (
            <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-gray-600'}`}>
                    {isProcessing ? 'Encrypting...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded">
                        {dataOutput ? `Ciphertext (Base64): ${dataOutput.substring(0, 15)}...` : 'Waiting for Data and Key...'}
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
            </div>
        )}

        {/* Sym Decrypt */}
        {isSymDec && (
             <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-gray-600'}`}>
                    {isProcessing ? 'Decrypting...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded">
                        {dataOutput ? `Plaintext (UTF-8): ${dataOutput.substring(0, 15)}...` : 'Waiting for Cipher and Key...'}
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
            </div>
        )}

        {/* Asym Encrypt */}
        {isAsymEnc && (
             <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-gray-600'}`}>
                    {isProcessing ? 'Encrypting (RSA-OAEP)...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded">
                        {dataOutput ? `Ciphertext (Base64): ${dataOutput.substring(0, 15)}...` : 'Waiting for Data and Public Key...'}
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
            </div>
        )}

        {/* Asym Decrypt */}
        {isAsymDec && (
             <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-gray-600'}`}>
                    {isProcessing ? 'Decrypting (RSA-OAEP)...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded">
                        {dataOutput ? `Plaintext (UTF-8): ${dataOutput.substring(0, 15)}...` : 'Waiting for Cipher and Private Key...'}
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
            </div>
        )}
        
        {/* XOR Operation */}
        {type === 'XOR_OP' && (
             <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-lime-600'}`}>
                    {isProcessing ? 'Calculating XOR...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded">
                        {dataOutput ? `Result (Base64): ${dataOutput.substring(0, 15)}...` : 'Waiting for two data inputs...'}
                    </p>
                    {/* Copy Button for XOR Output */}
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

        {/* Bit Shift */}
        {isBitShift && (
             <div className="text-xs w-full text-center">
                <span className={`text-[10px] font-semibold text-gray-600 mb-1`}>SHIFT AMOUNT (BYTES)</span>
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
                    {isProcessing ? 'Shifting...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded">
                        {dataOutput ? `Result (Base64): ${dataOutput.substring(0, 15)}...` : 'Waiting for input...'}
                    </p>
                    {/* Copy Button for Bit Shift Output */}
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
        {!isDataInput && !isOutputViewer && type !== 'HASH_FN' && !isKeyGen && !isSymEnc && !isSymDec && !isRSAKeyGen && !isAsymEnc && !isAsymDec && type !== 'XOR_OP' && !isBitShift && (
            <div className="text-xs text-gray-500 mt-2">
                <p>Output: {dataOutput ? dataOutput.substring(0, 10) + '...' : 'Waiting for connection'}</p>
            </div>
        )}
      </div>
    </div>
  );
};


// --- Toolbar Component ---

const Toolbar = ({ addNode }) => {
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

      <div className="flex flex-col space-y-1 p-3 overflow-y-auto pt-4">
        
        {Object.entries(NODE_DEFINITIONS).map(([type, def]) => {
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
    </div>
  );
}


// --- Main Application Component ---

const App = () => {
  const [nodes, setNodes] = useState(INITIAL_NODES);
  const [connections, setConnections] = useState(INITIAL_CONNECTIONS); 
  const [connectingPort, setConnectingPort] = useState(null); 
  const canvasRef = useRef(null);
  
  // --- Core Logic: Graph Recalculation (Data Flow Engine) ---
  
  const recalculateGraph = useCallback((currentNodes, currentConnections, changedNodeId = null) => {
    // FIX: Re-initialize newNodesMap correctly to ensure integrity and reset calculation fields.
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
            } else if (sourceNode.type === 'RSA_KEY_GEN') { 

                 if (sourceNode.keyPairObject || sourceNode.generateKey) {
                    isProcessing = true;
                    
                    if (!sourceNode.keyPairObject || sourceNode.generateKey) {
                         const algorithm = ASYM_ALGORITHMS[0]; 
                         const modulusLength = sourceNode.modulusLength || 2048;
                         const publicExponent = sourceNode.publicExponent || 65537;
                         
                         generateAsymmetricKeyPair(algorithm, modulusLength, publicExponent).then(({ publicKey, privateKey, keyPairObject, rsaParameters }) => {
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
            
            // Step 1: Gather inputs from all upstream nodes
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

                // Store the data using the input port ID ('data', 'key', 'dataA', etc.)
                // FIX: Only accept the FIRST connection for a port ID for single-input ports
                if (!inputs[conn.targetPortId]) { 
                    inputs[conn.targetPortId] = dataToUse;
                }
            });
            
            // Step 2: Execute node logic (using direct inputs lookup)
            switch (sourceNode.type) {
                case 'OUTPUT_VIEWER':
                    const rawInput = inputs['data']; 
                    let convertedDataOutput = sourceNode.convertedData || '';
                    let calculatedSourceFormat = ''; 
                    
                    if (rawInput !== undefined && rawInput !== null && rawInput !== '') {
                        
                        // 1. Store Raw Input Data (as requested)
                        const sourceNodeId = incomingConns.find(c => c.targetPortId === 'data')?.source;
                        const upstreamNode = newNodesMap.get(sourceNodeId);
                        
                        // Determine source format: use format property for DATA_INPUT, else infer from node type
                        calculatedSourceFormat = upstreamNode?.type === 'DATA_INPUT' 
                            ? upstreamNode.format || 'Text (UTF-8)' 
                            : (upstreamNode ? getOutputFormat(upstreamNode.type) : 'Text (UTF-8)');
                        
                        // FIX: Primary output (dataOutput) is the RAW UNCONVERTED input
                        outputData = rawInput; 
                        
                        // 2. Calculate Secondary (Converted) Output if Expanded
                        if (sourceNode.isConversionExpanded) {
                            // Use calculatedSourceFormat for conversion
                            convertedDataOutput = convertDataFormat(rawInput, calculatedSourceFormat, sourceNode.convertedFormat || 'Base64');
                        } else {
                            convertedDataOutput = '';
                        }
                    } else {
                        outputData = 'Not connected or no data.';
                        convertedDataOutput = '';
                        calculatedSourceFormat = 'N/A';
                    }
                    
                    // Update the node's state fields (must happen here as we are inside the graph engine)
                    sourceNode.convertedData = convertedDataOutput;
                    sourceNode.sourceFormat = calculatedSourceFormat; // Set the determined source format
                    sourceNode.rawInputData = outputData; // Store the raw input data separately
                    break;
                    
                case 'HASH_FN':
                    const hashInput = inputs['data'];
                    if (hashInput) { 
                        isProcessing = true; 
                        const algorithm = sourceNode.hashAlgorithm || 'SHA-256';

                        calculateHash(hashInput, algorithm).then(hashResult => {
                            setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId 
                                    ? { ...n, dataOutput: hashResult, isProcessing: false } 
                                    : n
                            ));
                        });
                        outputData = sourceNode.dataOutput || 'Calculating...';
                    } else { 
                        outputData = 'Waiting for data input.'; 
                    }
                    break;
                
                case 'XOR_OP':
                    const dataInputA = inputs['dataA']; 
                    const dataInputB = inputs['dataB']; 

                    if (dataInputA && dataInputB) { 
                        isProcessing = true; 
                        outputData = performBitwiseXor(dataInputA, dataInputB); 
                        isProcessing = false; 
                    } else if (dataInputA && !dataInputB) {
                        outputData = 'Waiting for Input B.';
                    } else if (!dataInputA && dataInputB) {
                        outputData = 'Waiting for Input A.';
                    } else {
                        outputData = 'Waiting for two data inputs.'; 
                    }
                    break;
                
                case 'SHIFT_OP':
                    const shiftDataInput = inputs['data'];
                    const shiftType = sourceNode.shiftType || 'Left';
                    const shiftAmount = sourceNode.shiftAmount || 0;
                    if (shiftDataInput) { 
                        isProcessing = true; 
                        outputData = performByteShiftOperation(shiftDataInput, shiftType, shiftAmount); 
                        isProcessing = false; 
                    } else { 
                        outputData = 'Waiting for data input.'; 
                    }
                    break;

                case 'SYM_ENC':
                    const encDataInput = inputs['data'];
                    const encKeyInput = inputs['key'];

                    if (encDataInput && encKeyInput) {
                        isProcessing = true;
                        const algorithm = sourceNode.symAlgorithm || 'AES-GCM';
                        symmetricEncrypt(encDataInput, encKeyInput, algorithm).then(ciphertext => {
                            setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId ? { ...n, dataOutput: ciphertext, isProcessing: false } : n
                            ));
                        });
                        outputData = sourceNode.dataOutput || 'Encrypting...';
                    } else { outputData = 'Waiting for Data and Key inputs.'; }
                    break;
                
                case 'SYM_DEC': 
                    const decCipherInput = inputs['cipher'];
                    const decKeyInput = inputs['key'];

                    if (decCipherInput && decKeyInput) {
                        isProcessing = true;
                        const algorithm = sourceNode.symAlgorithm || 'AES-GCM'; 
                        symmetricDecrypt(decCipherInput, decKeyInput, algorithm).then(plaintext => {
                            setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId ? { ...n, dataOutput: plaintext, isProcessing: false } : n
                            ));
                        });
                        outputData = sourceNode.dataOutput || 'Decrypting...';
                    } else { outputData = 'Waiting for Cipher and Key inputs.'; }
                    break;

                case 'ASYM_ENC':
                    const asymEncDataInput = inputs['data'];
                    const asymEncPublicKeyInput = inputs['publicKey'];

                    if (asymEncDataInput && asymEncPublicKeyInput) {
                        isProcessing = true;
                        const algorithm = sourceNode.asymAlgorithm || 'RSA-OAEP';
                        asymmetricEncrypt(asymEncDataInput, asymEncPublicKeyInput, algorithm).then(ciphertext => {
                            setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId ? { ...n, dataOutput: ciphertext, isProcessing: false } : n
                            ));
                        });
                        outputData = sourceNode.dataOutput || 'Encrypting...';
                    } else { outputData = 'Waiting for Data and Public Key.'; }
                    break;

                case 'ASYM_DEC':
                    const asymDecCipherInput = inputs['cipher'];
                    const asymDecPrivateKeyInput = inputs['privateKey'];

                    if (asymDecCipherInput && asymDecPrivateKeyInput) {
                        isProcessing = true;
                        const algorithm = sourceNode.asymAlgorithm || 'RSA-OAEP';
                        asymmetricDecrypt(asymDecCipherInput, asymDecPrivateKeyInput, algorithm).then(plaintext => {
                            setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId ? { ...n, dataOutput: plaintext, isProcessing: false } : n
                            ));
                        });
                        outputData = sourceNode.dataOutput || 'Decrypting...';
                    } else { outputData = 'Waiting for Cipher and Private Key.'; }
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
            // NOTE: For OUTPUT_VIEWER, dataOutput now holds the RAW INPUT, set above.
            // We only need to ensure the async update of dataOutput for non-viewer nodes.
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
                    // Conversion Feature State:
                    isConversionExpanded: (field === 'isConversionExpanded' ? value : node.isConversionExpanded),
                    convertedFormat: (field === 'convertedFormat' ? value : node.convertedFormat),
                    viewFormat: (field === 'viewFormat' ? value : node.viewFormat),
                    isProcessing: node.isProcessing,
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
    
    const initialContent = { dataOutput: '', isProcessing: false };

    if (type === 'DATA_INPUT') {
      initialContent.content = '';
      initialContent.format = 'Text (UTF-8)';
    } else if (type === 'OUTPUT_VIEWER') { 
      initialContent.dataOutput = ''; // Will hold RAW input string
      initialContent.rawInputData = ''; // New field
      initialContent.viewFormat = 'Text (UTF-8)'; 
      initialContent.isConversionExpanded = false; // New state
      initialContent.convertedData = ''; // New state
      initialContent.convertedFormat = 'Base64'; // New state
      initialContent.sourceFormat = '';
    } else if (type === 'HASH_FN') { 
      initialContent.hashAlgorithm = 'SHA-256';
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
    } else if (type === 'SYM_ENC' || type === 'SYM_DEC') {
      initialContent.symAlgorithm = 'AES-GCM';
    } else if (type === 'ASYM_ENC' || type === 'ASYM_DEC') {
      initialContent.asymAlgorithm = 'RSA-OAEP';
    } else if (type === 'SHIFT_OP') {
      initialContent.shiftType = 'Left';
      initialContent.shiftAmount = 1;
    }

    setNodes(prevNodes => [
      ...prevNodes,
      { 
        id: newId, 
        label: definition.label, 
        position: { x: 50 + Math.random() * 200, y: 50 + Math.random() * 200 }, 
        type: type, 
        color: color,
        ...initialContent 
      },
    ]);
  }, []);
  
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
    .connection-line:hover {
        stroke: #f87171 !important;
        stroke-width: 6 !important;
        cursor: pointer;
    }
  `;
  
  const handleCanvasClick = useCallback(() => {
    if (connectingPort) {
      handleConnectEnd(null);
    }
  }, [connectingPort, handleConnectEnd]);

  return (
    <div className="h-screen w-screen flex bg-gray-100 font-inter overflow-hidden">
      <style dangerouslySetInnerHTML={{ __html: animatedLineStyle }} />

      <Toolbar addNode={addNode} />

      <div className="flex-grow flex flex-col p-4">
        
        <div 
          ref={canvasRef}
          className="canvas-container relative w-full flex-grow border-4 border-dashed border-gray-300 rounded-2xl bg-white shadow-inner overflow-hidden"
          onClick={handleCanvasClick}
        >
          
          <svg className="absolute top-0 left-0 w-full h-full pointer-events-auto z-0">
            {connectionPaths.map((conn, index) => (
              <path
                key={`${conn.source}-${conn.target}-${conn.sourcePortIndex}-${conn.targetPortId}`}
                d={conn.path}
                stroke="#059669"
                strokeWidth="4"
                fill="none"
                // Removed animate-line class here:
                className="connection-line"
                onClick={(e) => { 
                    e.stopPropagation();
                    handleRemoveConnection(conn.source, conn.target, conn.sourcePortIndex, conn.targetPortId);
                }}
              />
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
            />
          ))}
          
        </div>
      </div>
    </div>
  );
};

export default App;
