// src/constants/nodeDefinitions.js
import { LayoutGrid, Cpu, Key, Zap, Settings, Lock, Unlock, Hash, Clipboard, X, ArrowLeft, ArrowRight, Download, Upload, Camera, ChevronDown, ChevronUp, CheckCheck, Fingerprint, Signature, ZoomIn, ZoomOut, Info } from 'lucide-react';
import { XORIcon, BitShiftIcon } from '../components/CustomIcons.jsx'; // Added .jsx extension

// --- Static Tailwind Class Maps ---

export const BORDER_CLASSES = {
  blue: 'border-blue-600', red: 'border-red-600', orange: 'border-orange-600', cyan: 'border-cyan-600', pink: 'border-pink-500', 
  teal: 'border-teal-600', gray: 'border-gray-600', lime: 'border-lime-600', indigo: 'border-indigo-600',
  purple: 'border-purple-600', // Simple RSA PrivKey Gen
  maroon: 'border-red-800', // Simple RSA Encrypt
  rose: 'border-pink-700', // Simple RSA Decrypt
  amber: 'border-amber-500', // Caesar Cipher
  yellow: 'border-yellow-400', // Vigenere Cipher
  fuchsia: 'border-fuchsia-600', // RSA Signature
};

export const HOVER_BORDER_CLASSES = {
  blue: 'hover:border-blue-500', red: 'hover:border-red-500', orange: 'hover:border-orange-500', cyan: 'hover:border-cyan-500', pink: 'hover:border-pink-500', 
  teal: 'hover:border-teal-500', gray: 'hover:border-gray-500', lime: 'hover:border-lime-500', indigo: 'hover:border-indigo-500',
  purple: 'hover:border-purple-500',
  maroon: 'hover:border-red-700',
  rose: 'hover:border-pink-600',
  amber: 'hover:border-amber-400',
  yellow: 'hover:border-yellow-300',
  fuchsia: 'hover:border-fuchsia-500',
};

export const TEXT_ICON_CLASSES = {
  blue: 'text-blue-600', red: 'text-red-600', orange: 'text-orange-600', cyan: 'text-cyan-600', pink: 'text-pink-500', 
  teal: 'text-teal-600', gray: 'text-gray-600', lime: 'text-lime-600', indigo: 'text-indigo-600',
  purple: 'text-purple-600',
  maroon: 'text-red-800',
  rose: 'text-pink-700',
  amber: 'text-amber-500',
  yellow: 'text-yellow-400',
  fuchsia: 'text-fuchsia-600',
};

export const HOVER_BORDER_TOOLBAR_CLASSES = {
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
export const PORT_SIZE = 4; // w-4 h-4
export const PORT_VISUAL_OFFSET_PX = 8; // Half port width in pixels
export const INPUT_PORT_COLOR = 'bg-stone-500'; // Standard Input (Mandatory)
export const OPTIONAL_PORT_COLOR = 'bg-gray-400'; // Optional Input 
export const OUTPUT_PORT_COLOR = 'bg-emerald-500'; // Standard Data Output

// New Specific Key Port Colors
export const PUBLIC_KEY_COLOR = 'bg-lime-500'; // Light Green/Lime for Public Key
export const PRIVATE_KEY_COLOR = 'bg-red-800'; // Dark Red/Maroon for Private Key (Warning)
export const SIGNATURE_COLOR = 'bg-fuchsia-500'; // Fuchsia for Signature Output

// --- Node Dimension Constants (for initial and minimum size) ---
export const NODE_DIMENSIONS = { initialWidth: 256, initialHeight: 256, minWidth: 200, minHeight: 180 };

// --- Node Definitions with detailed Port structure ---

export const NODE_DEFINITIONS = {
  // --- Core Nodes ---
  DATA_INPUT: { label: 'Data Input', color: 'blue', icon: LayoutGrid, inputPorts: [], outputPorts: [{ name: 'Data Output', type: 'data', keyField: 'dataOutput' }] },
  OUTPUT_VIEWER: { 
    label: 'Output Viewer', 
    color: 'red', 
    icon: Zap, 
    inputPorts: [{ name: 'Data Input', type: 'data', mandatory: true, id: 'data' }], 
    outputPorts: [{ name: 'Viewer Data Output', type: 'data', keyField: 'dataOutput' }] 
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
    
  // NEW: Simple RSA Public Key Generator
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
        { name: 'Key Input', type: 'private', mandatory: true, id: 'privateKey' } // Type 'private' for Simple RSA Decrypt
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

  // --- Utility Nodes ---
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
};

// --- Defines the desired rendering order for the toolbar ---
export const ORDERED_NODE_GROUPS = [
    { name: 'CORE TOOLS', types: ['DATA_INPUT', 'OUTPUT_VIEWER', 'HASH_FN', 'XOR_OP', 'SHIFT_OP'] },
    { name: 'CLASSIC CIPHERS', types: ['CAESAR_CIPHER', 'VIGENERE_CIPHER'] }, 
    { name: 'SIMPLE RSA', types: ['SIMPLE_RSA_KEY_GEN', 'SIMPLE_RSA_PUBKEY_GEN', 'SIMPLE_RSA_ENC', 'SIMPLE_RSA_DEC', 'SIMPLE_RSA_SIGN', 'SIMPLE_RSA_VERIFY'] }, 
    { name: 'SYMMETRIC CRYPTO (AES)', types: ['KEY_GEN', 'SYM_ENC', 'SYM_DEC'] }, 
    // { name: 'ADVANCED ASYMMETRIC (WEB CRYPTO)', types: ['RSA_KEY_GEN', 'ASYM_ENC', 'ASYM_DEC'] },
];

// Initial nodes on the canvas
export const INITIAL_NODES = []; 
export const INITIAL_CONNECTIONS = [];