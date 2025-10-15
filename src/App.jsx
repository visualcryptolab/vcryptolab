import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { LayoutGrid, Cpu, Key, Database, Zap, Settings, Lock, Unlock, Hash, ArrowRight, ArrowLeft, Clipboard, Code } from 'lucide-react';

// =================================================================
// 1. HELPER CONSTANTS & STATIC TAILWIND CLASS MAPS
// =================================================================

// --- Static Tailwind Class Maps (Ensures no dynamic class generation) ---

const BORDER_CLASSES = {
  blue: 'border-blue-600', red: 'border-red-600', orange: 'border-orange-600', purple: 'border-purple-600', pink: 'border-pink-600', 
  cyan: 'border-cyan-600', teal: 'border-teal-600', gray: 'border-gray-600', lime: 'border-lime-600', indigo: 'border-indigo-600',
};

const HOVER_BORDER_CLASSES = {
  blue: 'hover:border-blue-500', red: 'hover:border-red-500', orange: 'hover:border-orange-500', purple: 'hover:border-purple-500', pink: 'hover:border-pink-500', 
  cyan: 'hover:border-cyan-500', teal: 'hover:border-teal-500', gray: 'hover:border-gray-500', lime: 'hover:border-lime-500', indigo: 'hover:border-indigo-500',
};

const TEXT_ICON_CLASSES = {
  blue: 'text-blue-600', red: 'text-red-600', orange: 'text-orange-600', purple: 'text-purple-600', pink: 'text-pink-600', 
  cyan: 'text-cyan-600', teal: 'text-teal-600', gray: 'text-gray-600', lime: 'text-lime-600', indigo: 'text-indigo-600',
};

const TEXT_LABEL_CLASSES = {
  blue: 'text-blue-500', red: 'text-red-500', orange: 'text-orange-500', purple: 'text-purple-500', pink: 'text-pink-500', 
  cyan: 'text-cyan-500', teal: 'text-teal-500', gray: 'text-gray-500', lime: 'text-lime-500', indigo: 'text-indigo-500',
};

const HOVER_BORDER_TOOLBAR_CLASSES = {
  blue: 'hover:border-blue-400', red: 'hover:border-red-400', orange: 'hover:border-orange-400', purple: 'hover:border-purple-400', pink: 'hover:border-pink-400', 
  cyan: 'hover:border-cyan-400', teal: 'hover:border-teal-400', gray: 'hover:border-gray-400', lime: 'hover:border-lime-400', indigo: 'hover:border-indigo-400',
};

// --- Port Configuration ---
const PORT_SIZE = 4; // w-4 h-4
const INPUT_PORT_COLOR = 'bg-stone-500'; // Standard Input (Mandatory)
const OPTIONAL_PORT_COLOR = 'bg-gray-400'; // Optional Input (for future use)
const OUTPUT_PORT_COLOR = 'bg-emerald-500'; // Standard Output

// Supported Hash Algorithms
const HASH_ALGORITHMS = ['SHA-256', 'SHA-512'];

// Supported Symmetric Algorithms for KEY_GEN and SYM_ENC
const SYM_ALGORITHMS = ['AES-GCM']; 

// --- Node Definitions with detailed Port structure ---
// inputPorts: [{ name: string, type: 'data'|'key'|'iv'|'public', mandatory: boolean }]
// outputPort: { name: string, type: 'data'|'key'|'public'|'private' }

const NODE_DEFINITIONS = {
  // --- Core Nodes ---
  DATA_INPUT: { label: 'Input Data', color: 'blue', icon: LayoutGrid, inputPorts: [], outputPort: { name: 'Data Out', type: 'data' } },
  OUTPUT_VIEWER: { label: 'Output Viewer', color: 'red', icon: Zap, inputPorts: [{ name: 'Data In', type: 'data', mandatory: true }], outputPort: null },
  
  // --- Key/Cipher Nodes ---
  KEY_GEN: { label: 'Key Generator', color: 'orange', icon: Key, inputPorts: [], outputPort: { name: 'Key Out (AES)', type: 'key' } }, // Outputs an AES Key
  
  SYM_ENC: { 
    label: 'Sym Encrypt', 
    color: 'red', 
    icon: Lock, 
    inputPorts: [
        { name: 'Data In', type: 'data', mandatory: true, id: 'data' },
        { name: 'Key In', type: 'key', mandatory: true, id: 'key' }
    ], 
    outputPort: { name: 'Ciphertext', type: 'data' } 
  },
  SYM_DEC: { label: 'Sym Decrypt', color: 'pink', icon: Unlock, inputPorts: [{ name: 'Cipher In', type: 'data', mandatory: true }, { name: 'Key In', type: 'key', mandatory: true }], outputPort: { name: 'Plaintext', type: 'data' } },

  ASYM_ENC: { label: 'Asym Encrypt', color: 'cyan', icon: Lock, inputPorts: [{ name: 'Data In', type: 'data', mandatory: true }], outputPort: { name: 'Ciphertext', type: 'data' } },
  ASYM_DEC: { label: 'Asym Decrypt', color: 'teal', icon: Unlock, inputPorts: [{ name: 'Cipher In', type: 'data', mandatory: true }], outputPort: { name: 'Plaintext', type: 'data' } },

  // --- Utility Nodes ---
  HASH_FN: { label: 'Hash Function', color: 'gray', icon: Hash, inputPorts: [{ name: 'Data In', type: 'data', mandatory: true }], outputPort: { name: 'Hash Out', type: 'data' } },

  XOR_OP: { label: 'XOR Operation', color: 'lime', icon: Cpu, inputPorts: [{ name: 'Input A', type: 'data', mandatory: true }, { name: 'Input B', type: 'data', mandatory: true }], outputPort: { name: 'Result', type: 'data' } },
  SHIFT_OP: { label: 'Bit Shift', color: 'indigo', icon: Settings, inputPorts: [{ name: 'Data In', type: 'data', mandatory: true }], outputPort: { name: 'Result', type: 'data' } },
};

// Initial nodes on the canvas
const INITIAL_NODES = [
  // Example initial nodes for demonstration
  { 
    id: 'start_key', 
    label: 'Key Generator', 
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

// --- Utility Functions for Web Crypto ---

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

/** Encrypts data using an AES-GCM key. */
const symmetricEncrypt = async (dataStr, base64Key, algorithm) => {
    if (!dataStr) return 'Missing Data Input.';
    if (!base64Key || typeof base64Key !== 'string' || base64Key.length === 0) {
        return 'Missing or invalid Key Input.'; // FIX: Improved key input validation
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


// --- Graph Drawing Utilities ---

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
  const { id, label, position, type, color, content, format, dataOutput, viewFormat, isProcessing, hashAlgorithm, keyAlgorithm, key, symAlgorithm } = node; 
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
  const isSymEnc = type === 'SYM_ENC';
  
  const FORMATS = ['Text (UTF-8)', 'Binary', 'Decimal', 'Hexadecimal'];
  
  // Get all connections where this node is the target (i.e., this node receives input)
  const incomingConnections = connections.filter(conn => conn.target === id);
  // Check if this node is currently the source of an outgoing connection attempt
  const isPortSource = connectingNodeId === id;
  
  
  // --- Drag Handlers (standard) ---
  const handleDragStart = useCallback((e) => {
    if (connectingNodeId) return; 
    const interactiveTags = ['TEXTAREA', 'SELECT', 'OPTION', 'DIV', 'BUTTON']; // Added BUTTON
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
        
        // FIX: Remove 'isPortConnected' logic for visual disabling. 
        // We rely on the App component's connection logic for validation.
        
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

  const renderOutputPort = () => {
    if (!definition.outputPort) return null;
    
    // For simplicity, all single output ports are placed at 50% height
    return (
        <div className="absolute top-1/2 -right-2 transform -translate-y-1/2 z-20">
            <Port 
                nodeId={id} 
                type="output"
                colorClass={OUTPUT_PORT_COLOR} 
                isConnecting={connectingNodeId}
                onStart={handleConnectStart}
                onEnd={handleConnectEnd}
                title={definition.outputPort.name}
                isMandatory={true}
            />
        </div>
    );
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
      {renderOutputPort()}

      {/* -------------------- CONTENT -------------------- */}
      <div className="flex flex-col h-full w-full justify-start items-center overflow-hidden">
        {/* Top Section: Icon and Main Label */}
        <div className="flex flex-col justify-start items-center w-full flex-shrink-0 mb-2">
          {definition.icon && <definition.icon className={`w-6 h-6 ${iconTextColorClass} mb-1`} />}
          <span className={`text-${isDataInput ? 'base' : 'lg'} font-bold text-gray-800 text-center leading-tight`}>{label}</span>
          {/* Show algorithm name for functional nodes */}
          {isHashFn && <span className={`text-xs text-gray-500 mt-1`}>({hashAlgorithm})</span>}
          {isKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({keyAlgorithm})</span>}
          {isSymEnc && <span className={`text-xs text-gray-500 mt-1`}>({symAlgorithm})</span>}
          {!isDataInput && !isOutputViewer && !isHashFn && !isKeyGen && !isSymEnc && <span className={`text-xs text-gray-500 mt-1`}>({definition.label})</span>}
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

        {!isDataInput && !isOutputViewer && !isHashFn && !isKeyGen && !isSymEnc && (
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
      <div className="p-4 pt-6 pb-4 border-b border-gray-200 flex justify-center items-center bg-white">
        <div className="text-xl font-extrabold text-indigo-700">VisualCryptoLab</div>
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
            }
        
        // --- PROCESSING/SINK NODES (Have input ports) ---
        } else {
            // Collect all incoming connections to this target node
            const incomingConns = currentConnections.filter(c => c.target === sourceId);
            const inputSources = incomingConns.map(conn => newNodesMap.get(conn.source));

            // Map inputs to data types for multi-input nodes
            let dataInput = null;
            let keyInput = null; 
            
            inputSources.forEach(input => {
                const outputType = NODE_DEFINITIONS[input.type]?.outputPort?.type;
                if (outputType === 'data' && !dataInput) {
                    dataInput = input.dataOutput;
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

                // Unimplemented Processing Nodes (They return the placeholder)
                case 'SYM_DEC':
                case 'ASYM_ENC':
                case 'ASYM_DEC':
                case 'XOR_OP':
                case 'SHIFT_OP':
                    outputData = `Processed(PENDING) by ${sourceNode.label}`;
                    break;
                    
                default:
                    outputData = 'ERROR: Unrecognized Node Type.';
            }

        }
        
        // Update the node's output and processing status
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
                ? { ...node, [field]: value, generateKey: (field === 'generateKey' ? value : node.generateKey) } // Handle key gen button flag
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
    
    const initialContent = {};

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
    } else if (type === 'SYM_ENC') {
      initialContent.symAlgorithm = 'AES-GCM';
    }

    setNodes(prevNodes => [
      ...prevNodes,
      { 
        id: newId, 
        label: definition.label, 
        position: { x: 50 + Math.random() * 200, y: 50 + Math.random() * 200 }, 
        type: type, 
        color: color,
        dataOutput: '',
        isProcessing: false, 
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
