import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { LayoutGrid, Cpu, Key, Database, Zap, Settings, Lock, Unlock, Hash, ArrowRight, ArrowLeft } from 'lucide-react';

// =================================================================
// 1. HELPER CONSTANTS & STATIC TAILWIND CLASS MAPS
// =================================================================

// --- Static Tailwind Class Maps (Ensures no dynamic class generation) ---

// Map for DraggableBox main border (border-{color}-600)
const BORDER_CLASSES = {
  blue: 'border-blue-600', red: 'border-red-600', orange: 'border-orange-600', purple: 'border-purple-600', pink: 'border-pink-600', 
  cyan: 'border-cyan-600', teal: 'border-teal-600', gray: 'border-gray-600', lime: 'border-lime-600', indigo: 'border-indigo-600',
};

// Map for DraggableBox hover border (hover:border-{color}-500)
const HOVER_BORDER_CLASSES = {
  blue: 'hover:border-blue-500', red: 'hover:border-red-500', orange: 'hover:border-orange-500', purple: 'hover:border-purple-500', pink: 'hover:border-pink-500', 
  cyan: 'hover:border-cyan-500', teal: 'hover:border-teal-500', gray: 'hover:border-gray-500', lime: 'hover:border-lime-500', indigo: 'hover:border-indigo-500',
};

// Map for Icon text color (text-{color}-600)
const TEXT_ICON_CLASSES = {
  blue: 'text-blue-600', red: 'text-red-600', orange: 'text-orange-600', purple: 'text-purple-600', pink: 'text-pink-600', 
  cyan: 'text-cyan-600', teal: 'text-teal-600', gray: 'text-gray-600', lime: 'text-lime-600', indigo: 'text-indigo-600',
};

// Map for Sub-label text color (text-{color}-500)
const TEXT_LABEL_CLASSES = {
  blue: 'text-blue-500', red: 'text-red-500', orange: 'text-orange-500', purple: 'text-purple-500', pink: 'text-pink-500', 
  cyan: 'text-cyan-500', teal: 'text-teal-500', gray: 'text-gray-500', lime: 'text-lime-500', indigo: 'text-indigo-500',
};

// Map for Toolbar hover border (hover:border-{color}-400)
const HOVER_BORDER_TOOLBAR_CLASSES = {
  blue: 'hover:border-blue-400', red: 'hover:border-red-400', orange: 'hover:border-orange-400', purple: 'hover:border-purple-400', pink: 'hover:border-pink-400', 
  cyan: 'hover:border-cyan-400', teal: 'hover:border-teal-400', gray: 'hover:border-gray-400', lime: 'hover:border-lime-400', indigo: 'hover:border-indigo-400',
};

// --- Port Configuration ---
const PORT_SIZE = 4; // w-4 h-4
const INPUT_PORT_COLOR = 'bg-stone-500'; // Rojo/Marrón para Entrada
const OUTPUT_PORT_COLOR = 'bg-emerald-500'; // Verde para Salida

// Node definitions for the simple app
const NODE_DEFINITIONS = {
  // --- Cryptography & Utility Nodes ---
  DATA_INPUT: { label: 'Input Data', color: 'blue', icon: LayoutGrid, hasInput: false, hasOutput: true },
  OUTPUT_VIEWER: { label: 'Output Viewer', color: 'red', icon: Zap, hasInput: true, hasOutput: false },
  
  KEY_GEN: { label: 'Key Generator', color: 'orange', icon: Key, hasInput: false, hasOutput: true }, // Key generator generally acts as a source
  
  SYM_ENC: { label: 'Sym Encrypt', color: 'purple', icon: Lock, hasInput: true, hasOutput: true },
  SYM_DEC: { label: 'Sym Decrypt', color: 'pink', icon: Unlock, hasInput: true, hasOutput: true },

  ASYM_ENC: { label: 'Asym Encrypt', color: 'cyan', icon: Lock, hasInput: true, hasOutput: true },
  ASYM_DEC: { label: 'Asym Decrypt', color: 'teal', icon: Unlock, hasInput: true, hasOutput: true },

  HASH_FN: { label: 'Hash Function', color: 'gray', icon: Hash, hasInput: true, hasOutput: true },

  XOR_OP: { label: 'XOR Operation', color: 'lime', icon: Cpu, hasInput: true, hasOutput: true },
  SHIFT_OP: { label: 'Bit Shift', color: 'indigo', icon: Settings, hasInput: true, hasOutput: true },
};

// Initial nodes on the canvas
const INITIAL_NODES = [
  // Example initial nodes for demonstration
  { 
    id: 'start_a', 
    label: 'Input Data', 
    position: { x: 50, y: 50 }, 
    type: 'DATA_INPUT', 
    color: 'blue', 
    content: 'Hello World! This input box is now taller.', 
    format: 'Text (UTF-8)',
    dataOutput: '' // New field for calculated output
  },
  { id: 'op_a', label: 'Sym Encrypt', position: { x: 250, y: 150 }, type: 'SYM_ENC', color: 'purple', dataOutput: '' },
  { id: 'op_b', label: 'Hash Function', position: { x: 500, y: 50 }, type: 'HASH_FN', color: 'gray', dataOutput: '' },
  { 
    id: 'end_a', 
    label: 'Output Viewer', 
    position: { x: 700, y: 250 }, 
    type: 'OUTPUT_VIEWER', 
    color: 'red', 
    dataOutput: '', 
    viewFormat: 'Text (UTF-8)' // New field for viewing format
  },
];

// CHANGED: Fixed width (w-48) and minimum height for the box. Height is now auto (h-auto).
const BOX_SIZE = { width: 192, minHeight: 144 }; // w-48 is 192px

// Calculates the path for the line connecting two ports (right of source to left of target)
const getLinePath = (sourceNode, targetNode) => {
  
  // FIXED: Calculate port positions exactly on the edge
  // Source Port is on the right edge, at 50% height (based on minHeight which the Port component uses)
  const p1 = { 
    x: sourceNode.position.x + BOX_SIZE.width, 
    y: sourceNode.position.y + BOX_SIZE.minHeight / 2 
  }; 
  
  // Target Port position is on the left edge, at 50% height
  const p2 = { 
    x: targetNode.position.x, 
    y: targetNode.position.y + BOX_SIZE.minHeight / 2 
  }; 
  
  // Use a smooth Bezier curve that flows horizontally
  const midX = (p1.x + p2.x) / 2;
  
  // Draw from p1 (Output Port) to p2 (Input Port)
  // Control points pull horizontally towards the center for a smooth arc
  return `M${p1.x} ${p1.y} C${midX} ${p1.y}, ${midX} ${p2.y}, ${p2.x} ${p2.y}`;
};


// --- Sub-Component for Ports (Visual and Interaction) ---
const Port = React.memo(({ nodeId, type, colorClass, isConnecting, onStart, onEnd }) => {
    // Determine hover/click logic based on port type
    let interactionClasses = "";
    let clickHandler = () => {};
    let isPortActive = false; // Is this port the active connection source?

    if (type === 'output') {
        // Output Ports start connections
        clickHandler = (e) => { e.stopPropagation(); onStart(nodeId); };
        isPortActive = isConnecting === nodeId;
        interactionClasses = isPortActive 
            ? 'ring-4 ring-emerald-300 animate-pulse' 
            : 'hover:ring-4 hover:ring-emerald-300 transition duration-150';
    } else if (type === 'input') {
        // Input Ports end connections (only if another node is currently connecting)
        const isTargetCandidate = isConnecting && isConnecting !== nodeId;
        
        if (isTargetCandidate) {
            // Clicks trigger the onEnd handler (which is handleConnectEnd in DraggableBox)
            clickHandler = (e) => { e.stopPropagation(); onEnd(nodeId); };
            interactionClasses = 'ring-4 ring-yellow-300 cursor-pointer animate-pulse-slow';
        } else {
             // If a connection is already established/no connection attempt is active, block interaction
            interactionClasses = 'cursor-not-allowed opacity-70';
            // Port's click handler stops propagation but does nothing else
            clickHandler = (e) => { e.stopPropagation(); }; 
        }
    }
    
    // Stop propagation on mousedown/touchstart to prevent the parent DraggableBox from starting a drag/connection
    const stopPropagation = (e) => e.stopPropagation();

    return (
        <div 
            className={`w-${PORT_SIZE} h-${PORT_SIZE} rounded-full ${colorClass} absolute transform -translate-x-1/2 -translate-y-1/2 
                        shadow-md border-2 border-white cursor-pointer ${interactionClasses}`}
            onClick={clickHandler}
            onMouseDown={stopPropagation}
            onTouchStart={stopPropagation}
            style={{ top: '50%' }}
            title={`${type === 'input' ? 'Puerto de Entrada' : 'Puerto de Salida'}`}
        />
    );
});


// --- Component for the Draggable Box ---

const DraggableBox = ({ node, setPosition, canvasRef, handleConnectStart, handleConnectEnd, connectingNodeId, updateNodeContent, connections }) => {
  // Destructure node props and look up definition
  const { id, label, position, type, color, content, format, dataOutput, viewFormat } = node; // Added viewFormat
  const definition = NODE_DEFINITIONS[type];
  const [isDragging, setIsDragging] = useState(false);
  const boxRef = useRef(null);
  const offset = useRef({ x: 0, y: 0 });

  // Node specific flags
  const isDataInput = type === 'DATA_INPUT';
  const isOutputViewer = type === 'OUTPUT_VIEWER';
  const FORMATS = ['Text (UTF-8)', 'Binary', 'Decimal', 'Hexadecimal'];
  
  // Constraint check: Check if this node's input port is already connected
  const isInputConnected = connections.some(conn => conn.target === id);

  // Determine connection state for visual feedback
  const isConnectingSource = connectingNodeId === id;
  
  // Pass correct connection status to the Port components
  const canStartConnection = !connectingNodeId;
  const isPortTarget = connectingNodeId && connectingNodeId !== id && !isInputConnected;
  const isPortSource = connectingNodeId === id;
  
  
  // --- Drag Handlers (largely unchanged) ---
  const handleDragStart = useCallback((e) => {
    if (connectingNodeId) return; 

    // Allow drag only if the event didn't originate from an interactive form element (textarea/select/port)
    const interactiveTags = ['TEXTAREA', 'SELECT', 'OPTION', 'DIV'];
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
    const maxHeight = canvasRect.height - BOX_SIZE.minHeight; // Using minHeight for initial boundary check

    newX = Math.max(0, Math.min(newX, maxWidth));
    newY = Math.max(0, Math.min(newY, maxHeight));

    setPosition(id, { x: newX, y: newY });
  }, [isDragging, id, setPosition, canvasRef]);

  const handleDragEnd = useCallback(() => {
    setIsDragging(false);
  }, []);
  
  // Refactored click logic: now primarily handled by Ports for connection
  const handleBoxClick = useCallback((e) => {
    if (isDragging) return; 
    if (connectingNodeId) {
        handleConnectEnd(null); // Cancel connection if canvas clicked
    }
    e.stopPropagation();
  }, [connectingNodeId, handleConnectEnd, isDragging]);


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


  // --- Class Lookups ---
  const iconTextColorClass = TEXT_ICON_CLASSES[color] || 'text-gray-600';
  const labelTextColorClass = TEXT_LABEL_CLASSES[color] || 'text-gray-500';

  let specificClasses = `${BORDER_CLASSES[color]} ${HOVER_BORDER_CLASSES[color]} ${isDragging ? 'cursor-grabbing' : 'cursor-grab'}`;

  // Visual feedback for connection state (now focusing more on drag/grab)
  if (isPortSource) {
    specificClasses = `border-emerald-500 ring-4 ring-emerald-300 cursor-pointer animate-pulse transition duration-200`; 
  } else {
    specificClasses = `${BORDER_CLASSES[color]} ${HOVER_BORDER_CLASSES[color]} ${isDragging ? 'cursor-grabbing' : 'cursor-pointer hover:border-blue-500'}`;
  }


  // UPDATED: Base classes use w-48 and min-h-36, with h-auto and py-3 for padding
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
      {/* Ports are positioned absolutely relative to the container which now has variable height */}

      {/* Input Port (Left Side - Rojo/Marrón) */}
      {definition.hasInput && (
        <div className="absolute top-1/2 -left-2 transform -translate-y-1/2 z-20">
            <Port 
                nodeId={id} 
                type="input"
                colorClass={INPUT_PORT_COLOR} 
                isConnecting={connectingNodeId}
                onStart={handleConnectStart} // Input ports don't start, but pass functions to Port
                // If input is connected, pass a no-op function
                onEnd={isInputConnected ? () => {} : handleConnectEnd} 
            />
        </div>
      )}

      {/* Output Port (Right Side - Verde) */}
      {definition.hasOutput && (
        <div className="absolute top-1/2 -right-2 transform -translate-y-1/2 z-20">
            <Port 
                nodeId={id} 
                type="output"
                colorClass={OUTPUT_PORT_COLOR} 
                isConnecting={connectingNodeId}
                onStart={handleConnectStart} // Output ports start connections
                onEnd={handleConnectEnd}
            />
        </div>
      )}

      {/* -------------------- CONTENT -------------------- */}
      {/* Inner content wrapper, removed p-2 since p-3 is on the parent */}
      <div className="flex flex-col h-full w-full justify-start items-center overflow-hidden">
        {/* Top Section: Icon and Main Label */}
        <div className="flex flex-col justify-start items-center w-full flex-shrink-0 mb-2">
          {definition.icon && <definition.icon className={`w-6 h-6 ${iconTextColorClass} mb-1`} />}
          <span className={`text-${isDataInput ? 'base' : 'lg'} font-bold text-gray-800 text-center leading-tight`}>{label}</span>
          {!isDataInput && !isOutputViewer && <span className={`text-xs ${labelTextColorClass} mt-1`}>({definition.label})</span>}
        </div>
        
        {isDataInput && (
          /* Data Input Specific Controls */
          <div className="w-full flex flex-col items-center flex-grow">
            {/* UPDATED: Textarea rows increased to 4, mb-2 margin added */}
            <textarea
              className="w-full text-xs p-2 border border-gray-200 rounded-lg shadow-md resize-none mb-2 
                         placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 
                         outline-none transition duration-200"
              rows="4" 
              placeholder="Enter data here..."
              value={content || ''}
              onChange={(e) => updateNodeContent(id, 'content', e.target.value)}
              // Stop propagation to allow interaction
              onMouseDown={(e) => e.stopPropagation()} 
              onTouchStart={(e) => e.stopPropagation()} 
              onClick={(e) => e.stopPropagation()}
            />
            {/* UPDATED: Select box with modern styling */}
            <select
              className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm 
                         bg-white appearance-none cursor-pointer text-gray-700 
                         focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              value={format || 'Text (UTF-8)'}
              onChange={(e) => updateNodeContent(id, 'format', e.target.value)}
              // Stop propagation to allow interaction
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
                <span className="text-center font-bold text-red-600 mb-1 flex-shrink-0">RESULTADO</span>
                
                {/* Data Display Area - Increased min-h-16 to give more room */}
                <div className="w-full flex-grow break-all text-[10px] leading-tight text-gray-800 bg-white p-1 rounded-md mb-2 overflow-y-auto border border-gray-200 min-h-[4rem]">
                    <p>{dataOutput || 'No conectado o sin datos.'}</p>
                </div>

                {/* Format Indicator (To be enhanced with a selector later) */}
                <span className="text-[10px] text-gray-500 mt-auto flex-shrink-0">
                    Vista actual: <span className="font-semibold text-gray-700">{viewFormat || 'Text (UTF-8)'}</span>
                </span>
            </div>
        )}

        {!isDataInput && !isOutputViewer && (
            <div className="text-xs text-gray-500 mt-2">
                <p>Output: {dataOutput ? dataOutput.substring(0, 10) + '...' : 'Esperando conexión'}</p>
            </div>
        )}
      </div>
    </div>
  );
};


// --- Toolbar Component (No functional changes) ---

const Toolbar = ({ addNode }) => {
  return (
    <div className="w-64 bg-gray-50 flex-shrink-0 border-r border-gray-200 shadow-lg flex flex-col">
      {/* Logo Container at the top of the left tool bar */}
      <div className="p-4 pt-6 pb-4 border-b border-gray-200 flex justify-center items-center bg-white">
        {/* Placeholder for the logo image */}
        <div className="text-xl font-extrabold text-indigo-700">VisualCryptoLab</div>
      </div>

      {/* Node list container */}
      <div className="flex flex-col space-y-1 p-3 overflow-y-auto pt-4">
        
        {/* Map over all defined node types */}
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

  // Helper to map connections by target (Input Node ID) for easy lookup (Constraint #3)
  const targetMap = useMemo(() => {
    return connections.reduce((acc, conn) => {
      acc[conn.target] = conn.source;
      return acc;
    }, {});
  }, [connections]);
  
  // --- Core Logic: Graph Recalculation (Data Flow Engine Placeholder) ---
  
  const recalculateGraph = useCallback((currentNodes, currentConnections) => {
    const newNodes = new Map(currentNodes.map(n => [n.id, { ...n }]));
    
    // 1. Identify DATA_INPUT nodes as starting points
    const startingNodes = currentNodes.filter(n => n.type === 'DATA_INPUT').map(n => n.id);
    const nodesToProcess = [...startingNodes];
    const processed = new Set();
    
    // Simple Queue for topological sort-like processing
    while (nodesToProcess.length > 0) {
      const sourceId = nodesToProcess.shift();
      // Check if sourceId is a valid node and hasn't been processed
      if (processed.has(sourceId) || !newNodes.has(sourceId)) continue; 
      processed.add(sourceId);

      const sourceNode = newNodes.get(sourceId);
      
      // Determine the data output of the source node
      let outputData = '';
      if (sourceNode.type === 'DATA_INPUT') {
        // DATA_INPUT: output is the content itself
        outputData = sourceNode.content || '';
      } else {
        // Other nodes: output is based on input
        const inputSourceId = currentConnections.find(c => c.target === sourceId)?.source;
        if (inputSourceId) {
          const inputNode = newNodes.get(inputSourceId);
          
          if (inputNode) {
            
            // --- FIX: Logic for OUTPUT_VIEWER ---
            if (sourceNode.type === 'OUTPUT_VIEWER') {
                // OUTPUT_VIEWER (Sink) displays the raw data from its predecessor
                outputData = inputNode.dataOutput || 'No data received from input source.';
            } else {
                // Placeholder for other processing nodes
                outputData = `Processed(${inputNode.dataOutput ? inputNode.dataOutput.substring(0, 10) + '...' : 'Empty'}) by ${sourceNode.label}`;
            }
            // --- END FIX ---

          } else {
            outputData = `Error: Input Source Missing (ID: ${inputSourceId})`;
          }
        } else {
            // No input source, but it's not a DATA_INPUT node.
            outputData = 'Esperando conexión de entrada';
        }
      }
      
      // Update the node's output
      sourceNode.dataOutput = outputData;
      newNodes.set(sourceId, sourceNode);

      // Find all connected target nodes (downstream dependencies)
      const targets = currentConnections
        .filter(c => c.source === sourceId)
        .map(c => c.target)
        .filter(targetId => !processed.has(targetId)); // Avoid immediate cycles

      // Add targets to the processing queue
      nodesToProcess.push(...targets);
    }
    
    // Convert map back to array
    return Array.from(newNodes.values());
  }, []);
  
  // --- Effects for Recalculation ---
  
  // Recalculate graph whenever nodes (content/config) or connections change
  useEffect(() => {
    setNodes(prevNodes => recalculateGraph(prevNodes, connections));
  }, [connections, recalculateGraph]); // Nodes list is not a direct dependency here, as updateNodeContent triggers the next effect

  // Recalculate graph whenever *only* content changes (must run after position/ID changes)
  const updateNodeContent = useCallback((id, field, value) => {
    setNodes(prevNodes => {
        const nextNodes = prevNodes.map(node =>
            node.id === id ? { ...node, [field]: value } : node
        );
        // Recalculate immediately after content change
        return recalculateGraph(nextNodes, connections);
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
        ...initialContent 
      },
    ]);
  }, []);

  // NEW: Start a connection from an Output Port
  const handleConnectStart = useCallback((nodeId) => {
    setConnectingNodeId(nodeId);
  }, []);

  // NEW: End a connection at an Input Port
  const handleConnectEnd = useCallback((targetId) => {
    // Check if connection attempt is valid
    if (connectingNodeId && targetId && connectingNodeId !== targetId) {
      // 1. Check Constraint: Only one connection per Input Port (target node)
      const isTargetAlreadyConnected = connections.some(c => c.target === targetId);
      
      if (isTargetAlreadyConnected) {
        console.warn(`Cannot connect: Node ${targetId} (Input Port) is already connected.`);
        // Note: No alert() used, just a console log
      } else {
        // 2. Check Constraint: Must connect output (source) to input (target)
        const targetNode = nodes.find(n => n.id === targetId);
        // Safety check if target node exists
        if (!targetNode) {
             console.warn(`Cannot connect: Target node ${targetId} not found.`);
             setConnectingNodeId(null);
             return;
        }

        const targetDef = NODE_DEFINITIONS[targetNode.type];
        if (targetDef && targetDef.hasInput) {
             setConnections(prevConnections => [
              ...prevConnections, 
              { source: connectingNodeId, target: targetId }
            ]);
        } else {
             console.warn(`Cannot connect: Node ${targetId} is not configured to receive input.`);
        }
      }
    }
    // Always reset the connecting state
    setConnectingNodeId(null);
  }, [connectingNodeId, connections, nodes]);

  // NEW: Function to remove a connection by its source and target IDs
  const handleRemoveConnection = useCallback((sourceId, targetId) => {
    setConnections(prevConnections => 
        prevConnections.filter(c => !(c.source === sourceId && c.target === targetId))
    );
  }, []);
  
  // Prepare connections data for SVG
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
      transition: stroke-dashoffset 0.5s ease-out; /* Smooth transition */
    }
    /* Slow blink for target port candidate */
    @keyframes animate-pulse-slow {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    .animate-pulse-slow {
      animation: animate-pulse-slow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    }
    .connection-line:hover {
        stroke: #f87171 !important; /* Tailwind red-400 */
        stroke-width: 6 !important; /* Make line thicker on hover */
        cursor: pointer;
    }
  `;
  
  // Handle click on canvas background to cancel connection
  const handleCanvasClick = useCallback(() => {
    if (connectingNodeId) {
      handleConnectEnd(null); // Cancel connection
    }
  }, [connectingNodeId, handleConnectEnd]);

  return (
    // Outer container: Flex row layout, h-screen w-screen for full viewport
    <div className="h-screen w-screen flex bg-gray-100 font-inter overflow-hidden">
      {/* Inject custom CSS for animation */}
      <style dangerouslySetInnerHTML={{ __html: animatedLineStyle }} />

      {/* 1. Toolbar (Left Panel) */}
      <Toolbar addNode={addNode} />

      {/* 2. Main Content Area (Flex Column to hold header and canvas) */}
      <div className="flex-grow flex flex-col p-4">
        
        {/* Main Canvas Container - uses flex-grow to fill remaining vertical space. */}
        <div 
          ref={canvasRef}
          className="canvas-container relative w-full flex-grow border-4 border-dashed border-gray-300 rounded-2xl bg-white shadow-inner overflow-hidden"
          onClick={handleCanvasClick}
        >
          
          {/* SVG layer for the connection lines */}
          <svg className="absolute top-0 left-0 w-full h-full pointer-events-auto z-0">
            {connectionPaths.map((conn, index) => (
              <path
                key={`${conn.source}-${conn.target}`}
                d={conn.path}
                stroke="#059669" // Emerald 600
                strokeWidth="4"
                fill="none"
                className="animate-line connection-line" // Added connection-line class
                // Enable click interaction on the line itself
                onClick={(e) => { 
                    e.stopPropagation(); // Prevent canvas click from cancelling connection mode
                    handleRemoveConnection(conn.source, conn.target);
                }}
              />
            ))}
          </svg>

          {/* Render all Draggable Boxes (z-10 ensures they are above the SVG) */}
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
              connections={connections} // Pass connections to enforce the one-input constraint visually
            />
          ))}
          
        </div>
      </div>
    </div>
  );
};

export default App;
