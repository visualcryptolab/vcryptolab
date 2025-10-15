import React, { useState, useCallback, useRef, useEffect } from 'react';
import { LayoutGrid, Cpu, Key, Database, Zap, Settings, Lock, Unlock, Hash } from 'lucide-react';

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


// Node definitions for the simple app
const NODE_DEFINITIONS = {
  // --- Cryptography & Utility Nodes ---
  DATA_INPUT: { label: 'Input Data', color: 'blue', icon: LayoutGrid },
  OUTPUT_VIEWER: { label: 'Output Viewer', color: 'red', icon: Zap },
  
  KEY_GEN: { label: 'Key Generator', color: 'orange', icon: Key },
  
  SYM_ENC: { label: 'Sym Encrypt', color: 'purple', icon: Lock },
  SYM_DEC: { label: 'Sym Decrypt', color: 'pink', icon: Unlock },

  ASYM_ENC: { label: 'Asym Encrypt', color: 'cyan', icon: Lock },
  ASYM_DEC: { label: 'Asym Decrypt', color: 'teal', icon: Unlock },

  HASH_FN: { label: 'Hash Function', color: 'gray', icon: Hash },

  XOR_OP: { label: 'XOR Operation', color: 'lime', icon: Cpu },
  SHIFT_OP: { label: 'Bit Shift', color: 'indigo', icon: Settings },
};

// Initial nodes on the canvas
const INITIAL_NODES = [
  // Example initial nodes for demonstration
  { id: 'start_a', label: 'Input Data', position: { x: 50, y: 50 }, type: 'DATA_INPUT', color: 'blue' },
  { id: 'op_a', label: 'Sym Encrypt', position: { x: 250, y: 150 }, type: 'SYM_ENC', color: 'purple' },
  { id: 'op_b', label: 'Hash Function', position: { x: 500, y: 50 }, type: 'HASH_FN', color: 'gray' },
  { id: 'end_a', label: 'Output Viewer', position: { x: 700, y: 250 }, type: 'OUTPUT_VIEWER', color: 'red' },
];

const BOX_SIZE = { width: 144, height: 144 }; // w-36 h-36 is 144px

// Calculates the center coordinates of a box
const getBoxCenter = (position) => {
  return {
    x: position.x + BOX_SIZE.width / 2,
    y: position.y + BOX_SIZE.height / 2,
  };
};

// Calculates the path for the line connecting two centers
const getLinePath = (pos1, pos2) => {
  const c1 = getBoxCenter(pos1);
  const c2 = getBoxCenter(pos2);
  
  // Use a smooth, S-shaped Bezier curve for better visual flow (midpoint control)
  const midX = (c1.x + c2.x) / 2;
  const midY = (c1.y + c2.y) / 2;
  
  // Adjust control points based on flow direction (C1 is slightly closer to C1, C2 slightly closer to C2)
  return `M${c1.x} ${c1.y} C${c1.x + 50} ${c1.y}, ${c2.x - 50} ${c2.y}, ${c2.x} ${c2.y}`;
};


// --- Component for the Draggable Box ---

const DraggableBox = ({ node, setPosition, canvasRef, handleConnectStart, handleConnectEnd, connectingNodeId }) => {
  const { id, label, position, type, color } = node;
  const definition = NODE_DEFINITIONS[type];
  const [isDragging, setIsDragging] = useState(false);
  const boxRef = useRef(null);
  const offset = useRef({ x: 0, y: 0 });

  // NEW: Determine connection state for visual feedback
  const isConnectingSource = connectingNodeId === id;
  const isTargetCandidate = connectingNodeId && connectingNodeId !== id;
  
  // Handle drag start
  const handleDragStart = useCallback((e) => {
    // Only allow drag if not currently in a connection attempt mode
    if (connectingNodeId) return; 

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

  // Handle drag movement
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
    const maxHeight = canvasRect.height - BOX_SIZE.height;

    newX = Math.max(0, Math.min(newX, maxWidth));
    newY = Math.max(0, Math.min(newY, maxHeight));

    setPosition(id, { x: newX, y: newY });
  }, [isDragging, id, setPosition, canvasRef]);

  // Handle drag end
  const handleDragEnd = useCallback(() => {
    setIsDragging(false);
  }, []);
  
  // NEW: Handle click for connection logic
  const handleBoxClick = useCallback((e) => {
    if (isDragging) return; // Ignore click if it was part of a drag movement

    if (isConnectingSource) {
        // If it's the source, clicking again cancels the connection
        handleConnectEnd(null); 
    } else if (connectingNodeId) {
        // If another node is the source, this click attempts to be the target
        handleConnectEnd(id);
    } else {
        // No connection active, start a new one
        handleConnectStart(id);
    }
    e.stopPropagation(); // Prevent canvas container click if implemented
  }, [id, isConnectingSource, connectingNodeId, handleConnectStart, handleConnectEnd, isDragging]);


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


  // --- REFACTOR: Use static class lookups instead of interpolation ---
  const iconTextColorClass = TEXT_ICON_CLASSES[color] || 'text-gray-600';
  const labelTextColorClass = TEXT_LABEL_CLASSES[color] || 'text-gray-500';

  let specificClasses = `${BORDER_CLASSES[color]} ${HOVER_BORDER_CLASSES[color]} ${isDragging ? 'cursor-grabbing' : 'cursor-grab'}`;

  if (isConnectingSource) {
    // Green highlight for the source node
    specificClasses = `border-green-500 ring-4 ring-green-300 cursor-pointer animate-pulse transition duration-200`; 
  } else if (isTargetCandidate) {
    // Yellow highlight for potential targets
    specificClasses = `border-yellow-400 hover:border-yellow-500 cursor-pointer transition duration-200`;
  } else {
    // Normal state
    specificClasses = `${BORDER_CLASSES[color]} ${HOVER_BORDER_CLASSES[color]} ${isDragging ? 'cursor-grabbing' : 'cursor-pointer hover:border-blue-500'}`;
  }


  const baseClasses = 
    `w-[${BOX_SIZE.width}px] h-[${BOX_SIZE.height}px] flex flex-col justify-center items-center 
    bg-white shadow-xl rounded-xl border-4 transition duration-150 ease-in-out 
    hover:shadow-2xl absolute select-none z-10`;

  return (
    <div
      ref={boxRef}
      id={id}
      className={`${baseClasses} ${specificClasses}`}
      style={{ 
        left: `${position.x}px`, 
        top: `${position.y}px`,
        width: `${BOX_SIZE.width}px`,
        height: `${BOX_SIZE.height}px`,
      }} 
      onMouseDown={handleDragStart}
      onTouchStart={handleDragStart}
      onClick={handleBoxClick} // NEW: Handle click for connection logic
    >
      {/* Refactored icon class usage */}
      {definition.icon && <definition.icon className={`w-8 h-8 ${iconTextColorClass} mb-2`} />}
      <span className="text-lg font-bold text-gray-800 text-center px-2">{label}</span>
      {/* Refactored label class usage */}
      <span className={`text-xs ${labelTextColorClass} mt-1`}>({definition.label})</span>
    </div>
  );
};


// --- Toolbar Component ---

const Toolbar = ({ addNode }) => {
  return (
    <div className="w-64 bg-gray-50 flex-shrink-0 border-r border-gray-200 shadow-lg flex flex-col">
      {/* Logo Container at the top of the left tool bar */}
      <div className="p-4 pt-6 pb-4 border-b border-gray-200 flex justify-center items-center bg-white">
        <img 
          src="/VCL - Logo and Name.png" 
          alt="VisualCryptoLab Logo and Name" 
          className="w-full h-auto max-w-[180px]"
        />
      </div>

      {/* Node list container - REMOVED 'Add Nodes' H3. Added pt-4 for separation. */}
      <div className="flex flex-col space-y-1 p-3 overflow-y-auto pt-4">
        
        {/* Map over all defined node types */}
        {Object.entries(NODE_DEFINITIONS).map(([type, def]) => {
            // --- REFACTOR: Use static class lookups instead of interpolation ---
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
                    {/* Refactored icon class usage */}
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
  const [connections, setConnections] = useState([]); // NEW: State to store {source: id, target: id}
  const [connectingNodeId, setConnectingNodeId] = useState(null); // NEW: State for connection source
  const canvasRef = useRef(null);

  // Function to update the position of a specific box
  const setPosition = useCallback((id, newPos) => {
    setNodes(prevNodes => prevNodes.map(node =>
      node.id === id ? { ...node, position: newPos } : node
    ));
  }, []);

  // Function to add a new node
  const addNode = useCallback((type, label, color) => {
    const newId = `${type}_${Date.now()}`;
    const definition = NODE_DEFINITIONS[type];
    
    setNodes(prevNodes => [
      ...prevNodes,
      { 
        id: newId, 
        label: definition.label, 
        position: { x: 50 + Math.random() * 200, y: 50 + Math.random() * 200 }, // Random spawn near top-left
        type: type, 
        color: color 
      },
    ]);
  }, []);

  // NEW: Start a new connection
  const handleConnectStart = useCallback((nodeId) => {
    setConnectingNodeId(nodeId);
  }, []);

  // NEW: End a connection or cancel if target is null
  const handleConnectEnd = useCallback((targetId) => {
    if (connectingNodeId && targetId && connectingNodeId !== targetId) {
      // Check if connection already exists (source -> target or target -> source)
      const isDuplicate = connections.some(
        c => (c.source === connectingNodeId && c.target === targetId) || 
             (c.source === targetId && c.target === connectingNodeId)
      );

      if (!isDuplicate) {
        setConnections(prevConnections => [
          ...prevConnections, 
          { source: connectingNodeId, target: targetId }
        ]);
      }
    }
    // Always reset the connecting state
    setConnectingNodeId(null);
  }, [connectingNodeId, connections]);
  
  // NEW: Prepare connections data for SVG
  const connectionPaths = connections.map(conn => {
    const sourceNode = nodes.find(n => n.id === conn.source);
    const targetNode = nodes.find(n => n.id === conn.target);
    
    if (sourceNode && targetNode) {
      return getLinePath(sourceNode.position, targetNode.position);
    }
    return null;
  }).filter(path => path !== null);


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
        
        {/* Header Container - REMOVED entirely, leaving only the canvas */}
        
        {/* Main Canvas Container - uses flex-grow to fill remaining vertical space. Removed mt-4 for better fit. */}
        <div 
          ref={canvasRef}
          className="canvas-container relative w-full flex-grow border-4 border-dashed border-gray-300 rounded-2xl bg-white shadow-inner overflow-hidden"
          onClick={handleCanvasClick}
        >
          
          {/* SVG layer for the connection lines */}
          <svg className="absolute top-0 left-0 w-full h-full pointer-events-none z-0">
            {connectionPaths.map((path, index) => (
              <path
                key={index}
                d={path}
                stroke="#059669" // Emerald 600
                strokeWidth="4"
                fill="none"
                className="animate-line"
              />
            ))}
          </svg>

          {/* Render all Draggable Boxes (z-10 ensures they are above the SVG) */}
          {nodes.map(node => (
            <DraggableBox
              key={node.id}
              node={node}
              setPosition={setPosition}
              canvasRef={canvasRef}
              handleConnectStart={handleConnectStart} // NEW
              handleConnectEnd={handleConnectEnd}     // NEW
              connectingNodeId={connectingNodeId}     // NEW
            />
          ))}
          
        </div>
      </div>
    </div>
  );
};

export default App;
