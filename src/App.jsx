import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { LayoutGrid, Cpu, Key, Database, Zap, Settings, Lock, Unlock, Hash, ArrowRight, ArrowLeft, Clipboard, Code } from 'lucide-react';

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

const TEXT_LABEL_CLASSES = {
  blue: 'text-blue-500', red: 'text-red-500', orange: 'text-orange-500', cyan: 'text-cyan-500', pink: 'text-pink-500', 
  teal: 'text-teal-500', gray: 'text-gray-500', lime: 'text-lime-500', indigo: 'text-indigo-500',
};

const HOVER_BORDER_TOOLBAR_CLASSES = {
  blue: 'hover:border-blue-400', red: 'hover:border-red-400', orange: 'hover:border-orange-400', cyan: 'hover:border-cyan-400', pink: 'hover:border-pink-400', 
  teal: 'hover:border-teal-400', gray: 'hover:border-gray-400', lime: 'hover:border-lime-400', indigo: 'hover:border-indigo-400',
};

// --- Port Configuration ---
const PORT_SIZE = 4; // w-4 h-4
const INPUT_PORT_COLOR = 'bg-stone-500'; // Standard Input (Mandatory)
const OPTIONAL_PORT_COLOR = 'bg-gray-400'; // Optional Input (for future use)
const OUTPUT_PORT_COLOR = 'bg-emerald-500'; // Standard Output

// Supported Hash Algorithms
const HASH_ALGORITHMS = ['SHA-256', 'SHA-512'];

// Supported Symmetric Algorithms
const SYM_ALGORITHMS = ['AES-GCM']; 

// Supported Asymmetric Algorithms
const ASYM_ALGORITHMS = ['RSA-OAEP']; 
const RSA_MODULUS_LENGTHS = [1024, 2048, 4096];

// --- Node Definitions with detailed Port structure ---
// Note: All nodes now use 'outputPorts' array. keyField specifies which node property holds the output data.

const NODE_DEFINITIONS = {
  // --- Core Nodes ---
  DATA_INPUT: { label: 'Input Data', color: 'blue', icon: LayoutGrid, inputPorts: [], outputPorts: [{ name: 'Data Out', type: 'data', keyField: 'dataOutput' }] },
  OUTPUT_VIEWER: { label: 'Output Viewer', color: 'red', icon: Zap, inputPorts: [{ name: 'Data In', type: 'data', mandatory: true }], outputPorts: [] },
  
  // --- Key Generators ---
  KEY_GEN: { label: 'Sym Key Generator', color: 'orange', icon: Key, inputPorts: [], outputPorts: [{ name: 'Key Out (AES)', type: 'key', keyField: 'dataOutput' }] }, 

  RSA_KEY_GEN: { 
    label: 'RSA Key Generator', 
    color: 'cyan', // Changed color to cyan
    icon: Key, // Changed icon to Key
    inputPorts: [], 
    outputPorts: [
        { name: 'Public Key', type: 'public', keyField: 'dataOutputPublic' },
        { name: 'Private Key', type: 'private', keyField: 'dataOutputPrivate' }
    ]
  },
  
  // --- Cipher Nodes ---
  SYM_ENC: { 
    label: 'Sym Encrypt', 
    color: 'red', 
    icon: Lock, 
    inputPorts: [
        { name: 'Data In', type: 'data', mandatory: true, id: 'data' },
        { name: 'Key In', type: 'key', mandatory: true, id: 'key' }
    ], 
    outputPorts: [{ name: 'Ciphertext', type: 'data', keyField: 'dataOutput' }]
  },
  SYM_DEC: { 
    label: 'Sym Decrypt', 
    color: 'pink', 
    icon: Unlock, 
    inputPorts: [
        { name: 'Cipher In', type: 'data', mandatory: true, id: 'cipher' }, 
        { name: 'Key In', type: 'key', mandatory: true, id: 'key' }
    ], 
    outputPorts: [{ name: 'Plaintext', type: 'data', keyField: 'dataOutput' }] 
  },

  ASYM_ENC: { 
    label: 'Asym Encrypt', 
    color: 'cyan', // Changed color to cyan
    icon: Lock, 
    inputPorts: [
        { name: 'Data In', type: 'data', mandatory: true }, 
        { name: 'Public Key In', type: 'public', mandatory: true }
    ], 
    outputPorts: [{ name: 'Ciphertext', type: 'data', keyField: 'dataOutput' }] 
  },
  ASYM_DEC: { 
    label: 'Asym Decrypt', 
    color: 'teal', 
    icon: Unlock, 
    inputPorts: [
        { name: 'Cipher In', type: 'data', mandatory: true }, 
        { name: 'Private Key In', type: 'private', mandatory: true }
    ], 
    outputPorts: [{ name: 'Plaintext', type: 'data', keyField: 'dataOutput' }]
  },

  // --- Utility Nodes ---
  HASH_FN: { label: 'Hash Function', color: 'gray', icon: Hash, inputPorts: [{ name: 'Data In', type: 'data', mandatory: true }], outputPorts: [{ name: 'Hash Out', type: 'data', keyField: 'dataOutput' }] },

  XOR_OP: { label: 'XOR Operation', color: 'lime', icon: Cpu, inputPorts: [{ name: 'Input A', type: 'data', mandatory: true }, { name: 'Input B', type: 'data', mandatory: true }], outputPorts: [{ name: 'Result', type: 'data', keyField: 'dataOutput' }] },
  SHIFT_OP: { label: 'Bit Shift', color: 'indigo', icon: Settings, inputPorts: [{ name: 'Data In', type: 'data', mandatory: true }], outputPorts: [{ name: 'Result', type: 'data', keyField: 'dataOutput' }] },
};

// Initial nodes on the canvas
const INITIAL_NODES = [
  // Example initial nodes for demonstration
  { 
    id: 'start_key', 
    label: 'Sym Key Generator', 
    position: { x: 50, y: 50 }, 
    type: 'KEY_GEN', 
    color: 'orange', 
    dataOutput: '', 
    keyAlgorithm: 'AES-GCM',
    key: null, // Stores the actual CryptoKey object
  },
  { 
    id: 'start_a', 
    label: 'Input Data', 
    position: { x: 50, y: 250 }, 
    type: 'DATA_INPUT', 
    color: 'blue', 
    content: 'Secret Message', 
    format: 'Text (UTF-8)',
    dataOutput: 'Secret Message'
  },
  { 
    id: 'op_a', 
    label: 'Sym Encrypt', 
    position: { x: 300, y: 150 }, 
    type: 'SYM_ENC', 
    color: 'red', 
    dataOutput: '',
    symAlgorithm: 'AES-GCM', // Sym Encrypt settings
    key: null,
    iv: null,
  },
  { 
    id: 'end_a', 
    label: 'Output Viewer', 
    position: { x: 700, y: 250 }, 
    type: 'OUTPUT_VIEWER', 
    color: 'red', 
    dataOutput: '', 
    viewFormat: 'Text (UTF-8)'
  },
];

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

/**
 * Performs XOR operation on two input strings (converted to Uint8Array).
 * The result is truncated to the length of the shorter input.
 * Returns result as a Base64 string.
 */
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

/**
 * Performs a byte shift operation on the input string (converted to Uint8Array).
 * For simplicity, shiftAmount is treated as number of BYTES to shift.
 * Returns result as a Base64 string.
 */
const performByteShiftOperation = (dataStr, shiftType, shiftAmount) => {
    if (!dataStr) return "ERROR: Missing data input.";
    // Ensure shiftAmount is a safe integer
    const byteAmount = Math.max(0, parseInt(shiftAmount) || 0);

    try {
        const encoder = new TextEncoder();
        const buffer = encoder.encode(dataStr);
        const numBytes = buffer.length;
        const result = new Uint8Array(numBytes);

        if (byteAmount >= numBytes) {
            // If shift amount is >= array length, the result is all zeros
            return arrayBufferToBase64(result.buffer); 
        }
        
        if (shiftType === 'Left') {
            // Shift Left: [A, B, C, D] -> [C, D, 0, 0] (amount 2)
            // Copy remaining bytes to the start, fill end with zeros (default behavior of Uint8Array.set)
            result.set(buffer.slice(byteAmount), 0);
        } else if (shiftType === 'Right') {
            // Shift Right: [A, B, C, D] -> [0, 0, A, B] (amount 2)
            // Copy starting bytes to the shifted position
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
    
    // Convert ArrayBuffer to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return hashHex;
  } catch (error) {
    console.error(`Error calculating hash with ${algorithm}:`, error);
    return `ERROR: Calculation failed with ${algorithm}. Check console for details.`;
  }
};

/** Generates an AES-GCM Key and returns it as a CryptoKey object and Base64 string. */
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
    
    // Standard public exponent 65537 (0x10001) in byte form
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
        
        // Export public key to SPKI format (Base64) - Standard for transport
        const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const base64PublicKey = arrayBufferToBase64(publicKey);
        
        // Export private key to PKCS#8 format (Base64) - Standard for transport
        const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const base64PrivateKey = arrayBufferToBase64(privateKey);
        
        // Export PRIVATE key in JWK format to extract internal parameters (p, q, d, n) for visualization
        const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        
        const rsaParams = {
            n: privateKeyJwk.n, // Modulus (public)
            e: privateKeyJwk.e, // Public Exponent (public)
            d: privateKeyJwk.d, // Private Exponent (private)
            p: privateKeyJwk.p, // First Prime Factor (private)
            q: privateKeyJwk.q, // Second Prime Factor (private)
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
        
        // Import Public Key (SPKI format)
        const publicKey = await crypto.subtle.importKey(
            'spki',
            keyBuffer,
            { name: algorithm, hash: "SHA-256" },
            true, // extractable
            ['encrypt']
        );
        
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(dataStr);

        // Encrypt
        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: algorithm },
            publicKey,
            dataBuffer
        );
        
        // Convert encrypted buffer to Base64 for transport
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
        
        // Import Private Key (PKCS#8 format)
        const privateKey = await crypto.subtle.importKey(
            'pkcs8',
            keyBuffer,
            { name: algorithm, hash: "SHA-256" },
            true, // extractable
            ['decrypt']
        );
        
        // Decode ciphertext
        const cipherBuffer = base64ToArrayBuffer(base64Ciphertext);

        // Decrypt
        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: algorithm },
            privateKey,
            cipherBuffer
        );
        
        // Convert ArrayBuffer back to text
        const decoder = new TextDecoder();
        return decoder.decode(decryptedBuffer);

    } catch (error) {
        console.error("Asymmetric Decryption failed:", error);
        return `ERROR: Asymmetric Decryption failed. ${error.message}`;
    }
};


/** Encrypts data using an AES-GCM key. */
const symmetricEncrypt = async (dataStr, base64Key, algorithm) => {
    if (!dataStr) return 'Missing Data Input.';
    if (!base64Key || typeof base64Key !== 'string' || base64Key.length === 0) {
        return 'Missing or invalid Key Input.'; 
    }
    
    try {
        const keyBuffer = base64ToArrayBuffer(base64Key);
        
        // Import Key
        const key = await crypto.subtle.importKey(
            'raw',
            keyBuffer,
            { name: algorithm, length: 256 },
            true, // extractable
            ['encrypt', 'decrypt']
        );
        
        // Generate a random Initialization Vector (IV)
        const iv = crypto.getRandomValues(new Uint8Array(12)); 
        
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(dataStr);

        // Encrypt
        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: algorithm, iv: iv },
            key,
            dataBuffer
        );
        
        // Concatenate IV and Ciphertext, then convert to Base64 for transport
        const fullCipher = new Uint8Array(iv.byteLength + encryptedBuffer.byteLength);
        fullCipher.set(new Uint8Array(iv), 0);
        fullCipher.set(new Uint8Array(encryptedBuffer), iv.byteLength);

        return arrayBufferToBase64(fullCipher.buffer);

    } catch (error) {
        console.error("Encryption failed:", error);
        return `ERROR: Encryption failed. ${error.message}`;
    }
};

/** Decrypts data using an AES-GCM key. */
const symmetricDecrypt = async (base64Ciphertext, base64Key, algorithm) => {
    if (!base64Ciphertext) return 'Missing Ciphertext Input.';
    if (!base64Key || typeof base64Key !== 'string' || base64Key.length === 0) {
        return 'Missing or invalid Key Input.'; 
    }

    try {
        const keyBuffer = base64ToArrayBuffer(base64Key);
        
        // Import Key
        const key = await crypto.subtle.importKey(
            'raw',
            keyBuffer,
            { name: algorithm, length: 256 },
            true, 
            ['encrypt', 'decrypt']
        );
        
        // Decode the full ciphertext (IV + Encrypted Data)
        const fullCipherBuffer = base64ToArrayBuffer(base64Ciphertext);
        
        // Check if buffer is large enough for IV (12 bytes for AES-GCM)
        if (fullCipherBuffer.byteLength < 12) {
             throw new Error('Ciphertext is too short to contain IV.');
        }

        // Separate IV (first 12 bytes for AES-GCM) and Ciphertext
        const iv = fullCipherBuffer.slice(0, 12);
        const ciphertext = fullCipherBuffer.slice(12);

        // Decrypt
        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: algorithm, iv: new Uint8Array(iv) },
            key,
            ciphertext
        );
        
        // Convert ArrayBuffer back to text
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

// Calculates the path for the line connecting two ports (right of source to left of target)
const getLinePath = (sourceNode, targetNode) => {
  
  // Calculate port positions exactly on the edge
  // We use BOX_SIZE.minHeight / 2 as the vertical offset since Ports are styled with top: 50%
  const p1 = { 
    x: sourceNode.position.x + BOX_SIZE.width, 
    y: sourceNode.position.y + BOX_SIZE.minHeight / 2 
  }; 
  
  const p2 = { 
    x: targetNode.position.x, 
    y: targetNode.position.y + BOX_SIZE.minHeight / 2 
  }; 
  
  // Use a smooth Bezier curve that flows horizontally
  const midX = (p1.x + p2.x) / 2;
  
  // Control points pull horizontally towards the center for a smooth arc
  return `M${p1.x} ${p1.y} C${midX} ${p1.y}, ${midX} ${p2.y}, ${p2.x} ${p2.y}`;
};


// --- Sub-Component for Ports (Visual and Interaction) ---
const Port = React.memo(({ nodeId, type, colorClass, isConnecting, onStart, onEnd, title, portStyle, isMandatory, isInputConnected }) => {
    let interactionClasses = "";
    let clickHandler = () => {};
    
    const portColor = isMandatory ? INPUT_PORT_COLOR : OPTIONAL_PORT_COLOR;

    if (type === 'output') {
        clickHandler = (e) => { e.stopPropagation(); onStart(nodeId); };
        interactionClasses = isConnecting === nodeId 
            ? 'ring-4 ring-emerald-300 animate-pulse' 
            : 'hover:ring-4 hover:ring-emerald-300 transition duration-150';
    } else if (type === 'input') {
        const isTargetCandidate = isConnecting && isConnecting !== nodeId;
        
        if (isTargetCandidate) {
            clickHandler = (e) => { e.stopPropagation(); onEnd(nodeId); };
            interactionClasses = 'ring-4 ring-yellow-300 cursor-pointer animate-pulse-slow';
        } else {
             // FIX: The port is disabled only if it's already connected AND the node only accepts one connection
             // Since we allow multiple connections now (e.g., Sym Encrypt), we only disable the click if 
             // it's NOT a target candidate, otherwise it should be available for connection.
             interactionClasses = 'hover:ring-4 hover:ring-stone-300 transition duration-150';
            clickHandler = (e) => { e.stopPropagation(); }; 
        }
    }
    
    const stopPropagation = (e) => e.stopPropagation();

    return (
        <div 
            className={`w-${PORT_SIZE} h-${PORT_SIZE} rounded-full ${type === 'output' ? OUTPUT_PORT_COLOR : portColor} absolute transform -translate-x-1/2 -translate-y-1/2 
                        shadow-md border-2 border-white cursor-pointer ${interactionClasses}`}
            onClick={clickHandler}
            onMouseDown={stopPropagation}
            onTouchStart={stopPropagation}
            style={portStyle}
            title={title}
        />
    );
});


// --- Component for the Draggable Box ---

const DraggableBox = ({ node, setPosition, canvasRef, handleConnectStart, handleConnectEnd, connectingNodeId, updateNodeContent, connections }) => {
  // Destructure node props and look up definition
  const { id, label, position, type, color, content, format, dataOutput, viewFormat, isProcessing, hashAlgorithm, keyAlgorithm, symAlgorithm, modulusLength, dataOutputPublic, dataOutputPrivate, publicExponent, rsaParameters, asymAlgorithm } = node; 
  const definition = NODE_DEFINITIONS[type];
  const [isDragging, setIsDragging] = useState(false);
  const boxRef = useRef(null);
  const offset = useRef({ x: 0, y: 0 });
  const [copyStatus, setCopyStatus] = useState('Copy'); 

  // Node specific flags
  const isDataInput = type === 'DATA_INPUT';
  const isOutputViewer = type === 'OUTPUT_VIEWER';
  const isHashFn = type === 'HASH_FN';
  const isKeyGen = type === 'KEY_GEN';
  const isRSAKeyGen = type === 'RSA_KEY_GEN'; 
  const isSymEnc = type === 'SYM_ENC';
  const isSymDec = type === 'SYM_DEC';
  const isAsymEnc = type === 'ASYM_ENC'; // NEW FLAG
  const isAsymDec = type === 'ASYM_DEC'; // NEW FLAG
  const isBitShift = type === 'SHIFT_OP'; // NEW FLAG
  
  const FORMATS = ['Text (UTF-8)', 'Binary', 'Decimal', 'Hexadecimal'];
  
  // Get all connections where this node is the target (i.e., this node receives input)
  const incomingConnections = connections.filter(conn => conn.target === id);
  // Check if this node is currently the source of an outgoing connection attempt
  const isPortSource = connectingNodeId === id;
  
  
  // --- Drag Handlers (standard) ---
  const handleDragStart = useCallback((e) => {
    if (connectingNodeId) return; 
    const interactiveTags = ['TEXTAREA', 'SELECT', 'OPTION', 'DIV', 'BUTTON', 'INPUT']; 
    if (e.target.tagName === 'DIV' && e.target.classList.contains('w-4') && e.target.classList.contains('h-4')) {
        return; // Clicked on a port, prevent drag
    }
    if (interactiveTags.includes(e.target.tagName) && e.target.tagName !== 'DIV') {
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
  }, [canvasRef, position.x, position.y, connectingNodeId]);

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
    if (connectingNodeId) {
        handleConnectEnd(null); // Cancel connection if canvas clicked
    }
    e.stopPropagation();
  }, [connectingNodeId, handleConnectEnd, isDragging]);

  // Handle Copy to Clipboard for Output Viewer
  const handleCopyToClipboard = useCallback((e) => {
    e.stopPropagation();
    if (!dataOutput) return;

    try {
        const tempTextArea = document.createElement('textarea');
        tempTextArea.value = dataOutput;
        
        tempTextArea.style.position = 'fixed';
        tempTextArea.style.left = '-9999px';
        tempTextArea.style.top = '0';
        tempTextArea.style.opacity = '0'; 

        document.body.appendChild(tempTextArea);
        
        tempTextArea.select();
        tempTextArea.setSelectionRange(0, 99999); 
        
        document.execCommand('copy');
        
        document.body.removeChild(tempTextArea);
        setCopyStatus('Copied!');
        setTimeout(() => setCopyStatus('Copy'), 1500); 
        
    } catch (err) {
        console.error('Failed to copy text:', err);
        setCopyStatus('Error');
        setTimeout(() => setCopyStatus('Copy'), 2000);
    }
  }, [dataOutput]);


  // Attach global event listeners for dragging
  useEffect(() => {
    if (isDragging) {
      document.addEventListener('mousemove', handleDragMove);
      document.addEventListener('mouseup', handleDragEnd);
      document.addEventListener('touchmove', handleDragMove, { passive: false });
      document.addEventListener('touchend', handleDragEnd);
    } else {
      document.removeEventListener('mousemove', handleDragMove);
      document.removeEventListener('mouseup', handleDragEnd);
      document.removeEventListener('touchmove', handleDragMove);
      document.removeEventListener('touchend', handleDragEnd);
    }
    return () => {
      document.removeEventListener('mousemove', handleDragMove);
      document.removeEventListener('mouseup', handleDragEnd);
      document.removeEventListener('touchmove', handleDragMove);
      document.removeEventListener('touchend', handleDragEnd);
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
        
        return (
            <div 
                key={portDef.name}
                className="absolute -left-2 transform -translate-y-1/2 z-20"
                style={{ top: `${topPosition}%` }}
            >
                <Port 
                    nodeId={id} 
                    type="input"
                    // Use standard input color, but visually differentiate mandatory/optional via title
                    colorClass={portDef.mandatory ? INPUT_PORT_COLOR : OPTIONAL_PORT_COLOR} 
                    isConnecting={connectingNodeId}
                    onStart={handleConnectStart} 
                    // When not a target candidate, click action is still allowed to initiate target process
                    onEnd={handleConnectEnd} 
                    title={`${portDef.name} (${portDef.mandatory ? 'Mandatory' : 'Optional'})`}
                    isMandatory={portDef.mandatory}
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
                    colorClass={OUTPUT_PORT_COLOR} 
                    isConnecting={connectingNodeId}
                    onStart={handleConnectStart}
                    onEnd={handleConnectEnd}
                    title={portDef.name}
                    isMandatory={true} // Output is always considered essential for flow
                />
            </div>
        );
    });
  };
  
  // --- Class Lookups ---
  const iconTextColorClass = TEXT_ICON_CLASSES[color] || 'text-gray-600';

  let specificClasses = `${BORDER_CLASSES[color]} ${HOVER_BORDER_CLASSES[color]} ${isDragging ? 'cursor-grabbing' : 'cursor-grab'}`;

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
      }} 
      onMouseDown={handleDragStart} 
      onTouchStart={handleDragStart} 
      onClick={handleBoxClick} 
    >
      
      {/* -------------------- PORTS -------------------- */}
      {renderInputPorts()}
      {renderOutputPorts()} {/* RENDER PORTS ARRAY */}

      {/* -------------------- CONTENT -------------------- */}
      <div className="flex flex-col h-full w-full justify-start items-center overflow-hidden">
        {/* Top Section: Icon and Main Label */}
        <div className="flex flex-col justify-start items-center w-full flex-shrink-0 mb-2">
          {definition.icon && <definition.icon className={`w-6 h-6 ${iconTextColorClass} mb-1`} />}
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

          {!isDataInput && !isOutputViewer && !isHashFn && !isKeyGen && !isSymEnc && !isSymDec && !isRSAKeyGen && !isAsymEnc && !isAsymDec && type !== 'XOR_OP' && !isBitShift && <span className={`text-xs text-gray-500 mt-1`}>({definition.label})</span>}
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

        {isOutputViewer && (
            /* Output Viewer Display */
            <div className="w-full mt-1 flex flex-col items-center flex-grow text-xs text-gray-700 bg-gray-50 p-2 border border-gray-200 rounded-lg shadow-inner overflow-y-auto">
                <span className="text-center font-bold text-red-600 mb-1 flex-shrink-0">RESULT</span>
                
                <div className="w-full flex-grow break-all text-[10px] leading-tight text-gray-800 bg-white p-1 rounded-md mb-2 overflow-y-auto border border-gray-200 min-h-[4rem]">
                    <p>{dataOutput || 'Not connected or no data.'}</p>
                </div>

                <button
                    onClick={handleCopyToClipboard}
                    disabled={!dataOutput}
                    className={`mt-auto w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md 
                                ${dataOutput 
                                    ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-red-500 hover:bg-red-600'
                                    : 'bg-red-300 cursor-not-allowed'}`}
                >
                    <Clipboard className="w-4 h-4" />
                    <span>{copyStatus}</span>
                </button>

                <span className="text-[10px] text-gray-500 mt-2 flex-shrink-0">
                    Current View: <span className="font-semibold text-gray-700">{viewFormat || 'Text (UTF-8)'}</span>
                </span>
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
                <p className="mt-1 text-gray-500 break-all">
                    {dataOutput ? `Hash: ${dataOutput.substring(0, 15)}...` : 'Waiting for input...'}
                </p>
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
                <p className="mt-1 text-gray-500 break-all">
                    {dataOutput ? `Key (Base64): ${dataOutput.substring(0, 15)}...` : 'No key generated.'}
                </p>
            </div>
        )}

        {/* RSA Asymmetric Key Generator */}
        {isRSAKeyGen && (
            <div className="text-xs w-full text-center flex flex-col items-center">
                
                {/* Modulus Length (n size) */}
                <div className="w-full mb-1">
                    <label className="block text-left text-[10px] font-semibold text-gray-600">Modulus Length (Size of n)</label>
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
                    <label className="block text-[10px] font-semibold text-gray-600">Extracted Key Parameters (Derived Secrets)</label>
                    
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
        
        {isSymEnc && (
            <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-gray-600'}`}>
                    {isProcessing ? 'Encrypting...' : 'Active'}
                </span>
                <p className="mt-1 text-gray-500 break-all">
                    {dataOutput ? `Ciphertext: ${dataOutput.substring(0, 15)}...` : 'Waiting for Data and Key...'}
                </p>
            </div>
        )}

        {isSymDec && (
             <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-gray-600'}`}>
                    {isProcessing ? 'Decrypting...' : 'Active'}
                </span>
                <p className="mt-1 text-gray-500 break-all">
                    {dataOutput ? `Plaintext: ${dataOutput.substring(0, 15)}...` : 'Waiting for Cipher and Key...'}
                </p>
            </div>
        )}

        {isAsymEnc && (
             <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-gray-600'}`}>
                    {isProcessing ? 'Encrypting (RSA-OAEP)...' : 'Active'}
                </span>
                <p className="mt-1 text-gray-500 break-all">
                    {dataOutput ? `Ciphertext: ${dataOutput.substring(0, 15)}...` : 'Waiting for Data and Public Key...'}
                </p>
            </div>
        )}

        {isAsymDec && (
             <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-gray-600'}`}>
                    {isProcessing ? 'Decrypting (RSA-OAEP)...' : 'Active'}
                </span>
                <p className="mt-1 text-gray-500 break-all">
                    {dataOutput ? `Plaintext: ${dataOutput.substring(0, 15)}...` : 'Waiting for Cipher and Private Key...'}
                </p>
            </div>
        )}
        
        {type === 'XOR_OP' && (
             <div className="text-xs w-full text-center">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-lime-600'}`}>
                    {isProcessing ? 'Calculating XOR...' : 'Active'}
                </span>
                <p className="mt-1 text-gray-500 break-all">
                    {dataOutput ? `Result (Base64): ${dataOutput.substring(0, 15)}...` : 'Waiting for two data inputs...'}
                </p>
            </div>
        )}

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
                <p className="mt-1 text-gray-500 break-all">
                    {dataOutput ? `Result (Base64): ${dataOutput.substring(0, 15)}...` : 'Waiting for input...'}
                </p>
            </div>
        )}

        {!isDataInput && !isOutputViewer && !isHashFn && !isKeyGen && !isSymEnc && !isSymDec && !isRSAKeyGen && !isAsymEnc && !isAsymDec && type !== 'XOR_OP' && !isBitShift && (
            <div className="text-xs text-gray-500 mt-2">
                <p>Output: {dataOutput ? dataOutput.substring(0, 10) + '...' : 'Waiting for connection'}</p>
            </div>
        )}
      </div>
    </div>
  );
};


// --- Toolbar Component (Standard) ---

const Toolbar = ({ addNode }) => {
  return (
    <div className="w-64 bg-gray-50 flex-shrink-0 border-r border-gray-200 shadow-lg flex flex-col">
      {/* Logo Container at the top of the left tool bar */}
      <div className="p-4 pt-6 pb-4 border-b border-gray-200 flex justify-center items-center bg-white">
        <img 
          src="VCL - Logo and Name.png"
          alt="VisualCryptoLab Logo and Name" 
          className="w-full h-auto max-w-[180px]"
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
                    {def.icon && <def.icon className={`w-5 h-5 ${iconTextColorClass} flex-shrink-0`} />}
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
  const [connections, setConnections] = useState([]); 
  const [connectingNodeId, setConnectingNodeId] = useState(null); 
  const canvasRef = useRef(null);
  
  // --- Core Logic: Graph Recalculation (Data Flow Engine) ---
  
  const recalculateGraph = useCallback((currentNodes, currentConnections, changedNodeId = null) => {
    const newNodesMap = new Map(currentNodes.map(n => [n.id, { ...n }]));
    
    // FIX: Use NODE_DEFINITIONS to safely check if a node is a source (has no input ports)
    // Initial nodes to process: Data sources (inputs, keygens) and the node that was just changed
    let initialQueue = new Set(currentNodes.filter(n => {
        const def = NODE_DEFINITIONS[n.type];
        // Check if definition exists and if its inputPorts array is empty
        return def && def.inputPorts && def.inputPorts.length === 0;
    }).map(n => n.id));
    
    if (changedNodeId) initialQueue.add(changedNodeId);
    
    const nodesToProcess = Array.from(initialQueue);
    const processed = new Set();
    
    // Helper to traverse the graph: Finds all downstream nodes
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

        let outputData = '';
        let isProcessing = false;

        // --- SOURCE NODES (No input ports) ---
        if (sourceNodeDef.inputPorts.length === 0) {
            
            if (sourceNode.type === 'DATA_INPUT') {
                outputData = sourceNode.content || '';
            } else if (sourceNode.type === 'KEY_GEN') {
                
                if (sourceNode.key || sourceNode.generateKey) {
                    isProcessing = true;
                    // Only generate key if 'generateKey' flag is set (via button click) or if key is null
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
                                    ? { ...n, dataOutput: `ERROR: Key gen failed.`, isProcessing: false, generateKey: false } 
                                    : n
                            ));
                        });
                        outputData = sourceNode.dataOutput || 'Generating Key...';
                    } else {
                        // Key already exists, just pass it through
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
                         const algorithm = ASYM_ALGORITHMS[0]; // RSA-OAEP
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
                        // Keys already exist, just pass it through (Output Public is the main dataOutput)
                        outputData = sourceNode.dataOutputPublic || '';
                        isProcessing = false;
                    }
                } else {
                    outputData = 'Click "Generate RSA Key Pair"';
                }
            }
        
        // --- PROCESSING/SINK NODES (Have input ports) ---
        } else {
            // Collect all incoming connections to this target node
            const incomingConns = currentConnections.filter(c => c.target === sourceId);
            const inputSources = incomingConns.map(conn => newNodesMap.get(conn.source));

            // Map inputs to data types for multi-input nodes
            let dataInput = null; // Data or Ciphertext
            let keyInput = null; // Symmetric Key
            let publicKeyInput = null; // RSA Public Key
            let privateKeyInput = null; // RSA Private Key
            let dataInputA = null; // XOR Input A
            let dataInputB = null; // XOR Input B
            
            inputSources.forEach(input => {
                const outputType = NODE_DEFINITIONS[input.type]?.outputPorts?.[0]?.type; 
                
                if (input.type === 'RSA_KEY_GEN') {
                    const targetInputPorts = sourceNodeDef.inputPorts.map(p => p.type);
                    
                    if (targetInputPorts.includes('public')) {
                        if (!publicKeyInput) publicKeyInput = input.dataOutputPublic;
                    }
                    if (targetInputPorts.includes('private')) {
                        if (!privateKeyInput) privateKeyInput = input.dataOutputPrivate;
                    }
                    
                } else if (outputType === 'data') {
                    // Handle XOR inputs specially since they both are 'data' type
                    if (sourceNode.type === 'XOR_OP') {
                        if (!dataInputA) {
                            dataInputA = input.dataOutput;
                        } else if (!dataInputB) {
                            dataInputB = input.dataOutput;
                        }
                    } else if (!dataInput) {
                        dataInput = input.dataOutput;
                    }
                } else if (outputType === 'key' && !keyInput) {
                    keyInput = input.dataOutput;
                } 
            });


            switch (sourceNode.type) {
                case 'OUTPUT_VIEWER':
                    outputData = dataInput || 'No connected input.';
                    break;
                    
                case 'HASH_FN':
                    const algorithm = sourceNode.hashAlgorithm || 'SHA-256';

                    if (dataInput) {
                        isProcessing = true;
                        calculateHash(dataInput, algorithm).then(hashResult => {
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
                    if (dataInputA && dataInputB) {
                         isProcessing = true;
                         // XOR is sync, so we update the state directly
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
                    const shiftType = sourceNode.shiftType || 'Left';
                    const shiftAmount = sourceNode.shiftAmount || 0;

                    if (dataInput) {
                        isProcessing = true;
                        // Shift is sync, so we update the state directly
                        outputData = performByteShiftOperation(dataInput, shiftType, shiftAmount);
                        isProcessing = false;
                    } else {
                        outputData = 'Waiting for data input.';
                    }
                    break;

                case 'SYM_ENC':
                    if (dataInput && keyInput) {
                        isProcessing = true;
                        const algorithm = sourceNode.symAlgorithm || 'AES-GCM';

                        symmetricEncrypt(dataInput, keyInput, algorithm).then(ciphertext => {
                            setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId 
                                    ? { ...n, dataOutput: ciphertext, isProcessing: false } 
                                    : n
                            ));
                        }).catch(err => {
                             setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId 
                                    ? { ...n, dataOutput: `ERROR: Encrypt failed. ${err.message}`, isProcessing: false } 
                                    : n
                            ));
                        });
                        outputData = sourceNode.dataOutput || 'Encrypting...';
                    } else if (dataInput && !keyInput) {
                        outputData = 'Waiting for Key input.';
                    } else if (!dataInput && keyInput) {
                        outputData = 'Waiting for Data input.';
                    } else {
                        outputData = 'Waiting for Data and Key inputs.';
                    }
                    break;
                
                case 'SYM_DEC': 
                    if (dataInput && keyInput) {
                        isProcessing = true;
                        const algorithm = sourceNode.symAlgorithm || 'AES-GCM'; 

                        symmetricDecrypt(dataInput, keyInput, algorithm).then(plaintext => {
                            setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId 
                                    ? { ...n, dataOutput: plaintext, isProcessing: false } 
                                    : n
                            ));
                        }).catch(err => {
                             setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId 
                                    ? { ...n, dataOutput: `ERROR: Decrypt failed. ${err.message}`, isProcessing: false } 
                                    : n
                            ));
                        });
                        outputData = sourceNode.dataOutput || 'Decrypting...';
                    } else if (dataInput && !keyInput) {
                        outputData = 'Waiting for Key input.';
                    } else if (!dataInput && keyInput) {
                        outputData = 'Waiting for Ciphertext input.';
                    } else {
                        outputData = 'Waiting for Cipher and Key inputs.';
                    }
                    break;

                case 'ASYM_ENC':
                    if (dataInput && publicKeyInput) {
                        isProcessing = true;
                        const algorithm = sourceNode.asymAlgorithm || 'RSA-OAEP';

                        asymmetricEncrypt(dataInput, publicKeyInput, algorithm).then(ciphertext => {
                            setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId 
                                    ? { ...n, dataOutput: ciphertext, isProcessing: false } 
                                    : n
                            ));
                        }).catch(err => {
                             setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId 
                                    ? { ...n, dataOutput: `ERROR: Encrypt failed. ${err.message}`, isProcessing: false } 
                                    : n
                            ));
                        });
                        outputData = sourceNode.dataOutput || 'Encrypting...';
                    } else if (dataInput && !publicKeyInput) {
                        outputData = 'Waiting for Public Key input.';
                    } else if (!dataInput && publicKeyInput) {
                        outputData = 'Waiting for Data input.';
                    } else {
                        outputData = 'Waiting for Data and Public Key inputs.';
                    }
                    break;

                case 'ASYM_DEC':
                    if (dataInput && privateKeyInput) {
                        isProcessing = true;
                        const algorithm = sourceNode.asymAlgorithm || 'RSA-OAEP';

                        asymmetricDecrypt(dataInput, privateKeyInput, algorithm).then(plaintext => {
                            setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId 
                                    ? { ...n, dataOutput: plaintext, isProcessing: false } 
                                    : n
                            ));
                        }).catch(err => {
                             setNodes(prevNodes => prevNodes.map(n => 
                                n.id === sourceId 
                                    ? { ...n, dataOutput: `ERROR: Decrypt failed. ${err.message}`, isProcessing: false } 
                                    : n
                            ));
                        });
                        outputData = sourceNode.dataOutput || 'Decrypting...';
                    } else if (dataInput && !privateKeyInput) {
                        outputData = 'Waiting for Private Key input.';
                    } else if (!dataInput && privateKeyInput) {
                        outputData = 'Waiting for Ciphertext input.';
                    } else {
                        outputData = 'Waiting for Ciphertext and Private Key inputs.';
                    }
                    break;


                // Unimplemented Processing Nodes (They return the placeholder)
                // Removed SHIFT_OP since it is now implemented.
                    
                default:
                    outputData = 'ERROR: Unrecognized Node Type.';
            }

        }
        
        // Update the node's output and processing status
        // For RSA_KEY_GEN, dataOutput is just the public key preview, but we update both in the state
        sourceNode.dataOutput = outputData; 
        sourceNode.isProcessing = isProcessing;
        newNodesMap.set(sourceId, sourceNode);
        processed.add(sourceId);

        // Add targets to the processing queue (only if not already processed)
        const targets = findAllTargets(sourceId);
        nodesToProcess.push(...targets);
    }
    
    // Convert map back to array
    return Array.from(newNodesMap.values());
  }, [setNodes]);
  
  // --- Effects for Recalculation ---
  
  useEffect(() => {
    setNodes(prevNodes => recalculateGraph(prevNodes, connections));
  }, [connections, recalculateGraph]);

  const updateNodeContent = useCallback((id, field, value) => {
    setNodes(prevNodes => {
        const nextNodes = prevNodes.map(node =>
            node.id === id 
                ? { 
                    ...node, 
                    [field]: value, 
                    generateKey: (field === 'generateKey' ? value : node.generateKey), 
                    modulusLength: (field === 'modulusLength' ? value : node.modulusLength), 
                    publicExponent: (field === 'publicExponent' ? value : node.publicExponent),
                    shiftType: (field === 'shiftType' ? value : node.shiftType),
                    shiftAmount: (field === 'shiftAmount' ? value : node.shiftAmount)
                  } 
                : node
        );
        // Pass the changed node ID to ensure recalculation starts from that point.
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
      initialContent.viewFormat = 'Text (UTF-8)';
    } else if (type === 'HASH_FN') { 
      initialContent.hashAlgorithm = 'SHA-256';
    } else if (type === 'KEY_GEN') {
      initialContent.keyAlgorithm = 'AES-GCM';
      initialContent.key = null; // CryptoKey object
    } else if (type === 'RSA_KEY_GEN') { // RSA INITIALIZATION
      initialContent.keyAlgorithm = 'RSA-OAEP';
      initialContent.modulusLength = 2048;
      initialContent.publicExponent = 65537; // Default value for e
      initialContent.dataOutputPublic = '';
      initialContent.dataOutputPrivate = '';
      initialContent.keyPairObject = null;
      // Initialize new parameter object
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

  const handleConnectStart = useCallback((nodeId) => {
    setConnectingNodeId(nodeId);
  }, []);

  const handleConnectEnd = useCallback((targetId) => {
    if (connectingNodeId && targetId && connectingNodeId !== targetId) {
      // 1. Check Constraint: If target has only ONE port, prevent connecting if already connected
      // If the target has multiple ports (like Sym Encrypt), allow multiple connections.
      const targetNodeDef = NODE_DEFINITIONS[nodes.find(n => n.id === targetId)?.type];
      
      if (targetNodeDef.inputPorts.length === 1 && connections.some(c => c.target === targetId)) {
        console.warn(`Cannot connect: Node ${targetId} (Input Port) is already connected.`);
      } else {
        const targetNode = nodes.find(n => n.id === targetId);
        if (!targetNode) {
             console.warn(`Cannot connect: Target node ${targetId} not found.`);
             setConnectingNodeId(null);
             return;
        }

        if (targetNodeDef && targetNodeDef.inputPorts.length > 0) {
             setConnections(prevConnections => [
              ...prevConnections, 
              { source: connectingNodeId, target: targetId }
            ]);
        } else {
             console.warn(`Cannot connect: Node ${targetId} is not configured to receive input.`);
        }
      }
    }
    setConnectingNodeId(null);
  }, [connectingNodeId, connections, nodes]);

  const handleRemoveConnection = useCallback((sourceId, targetId) => {
    setConnections(prevConnections => 
        prevConnections.filter(c => !(c.source === sourceId && c.target === targetId))
    );
  }, []);
  
  const connectionPaths = useMemo(() => {
    return connections.map(conn => {
      const sourceNode = nodes.find(n => n.id === conn.source);
      const targetNode = nodes.find(n => n.id === conn.target);
      
      if (sourceNode && targetNode) {
        return {
            path: getLinePath(sourceNode, targetNode),
            source: conn.source,
            target: conn.target
        };
      }
      return null;
    }).filter(p => p !== null);
  }, [connections, nodes]);


  // Define the CSS for the line animation as a string for injection
  const animatedLineStyle = `
    @keyframes dash {
      to {
        stroke-dashoffset: 0;
      }
    }
    .animate-line {
      stroke-dasharray: 20 10;
      stroke-dashoffset: 1000;
      animation: dash 5s linear infinite;
      transition: stroke-dashoffset 0.5s ease-out;
    }
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
    if (connectingNodeId) {
      handleConnectEnd(null);
    }
  }, [connectingNodeId, handleConnectEnd]);

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
                key={`${conn.source}-${conn.target}`}
                d={conn.path}
                stroke="#059669"
                strokeWidth="4"
                fill="none"
                className="animate-line connection-line"
                onClick={(e) => { 
                    e.stopPropagation();
                    handleRemoveConnection(conn.source, conn.target);
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
              connectingNodeId={connectingNodeId}
              connections={connections}
            />
          ))}
          
        </div>
      </div>
    </div>
  );
};

export default App;
