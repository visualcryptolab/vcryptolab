import React, { useState, useCallback, useRef, useEffect } from 'react';
// Import icons for the new toolbar buttons (Added Lock, Unlock, Hash)
import { Play, LayoutGrid, Cpu, Key, Database, Zap, Settings, Lock, Unlock, Hash } from 'lucide-react';

// =================================================================
// 1. HELPER CONSTANTS & FUNCTIONS
// =================================================================

// Node definitions for the simple app (used for toolbar and box styling)
const NODE_DEFINITIONS = {
  // --- Requested Cryptography & Utility Nodes ---
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

// Initial nodes on the canvas (now empty as requested)
const INITIAL_NODES = [];

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
  
  // SVG Path: M (Move to) x1, y1 L (Line to) x2, y2 (A straight line)
  return `M${c1.x} ${c1.y} L${c2.x} ${c2.y}`;
};


// --- Component for the Draggable Box ---

const DraggableBox = ({ node, setPosition, canvasRef }) => {
  const { id, label, position, type, color } = node;
  const definition = NODE_DEFINITIONS[type];
  const [isDragging, setIsDragging] = useState(false);
  const boxRef = useRef(null);
  const offset = useRef({ x: 0, y: 0 });

  // Handle drag start
  const handleDragStart = useCallback((e) => {
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
  }, [canvasRef, position.x, position.y]);

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

  // Attach global event listeners
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

  // Tailwind classes for the box style (using dynamic coloring)
  const borderColorClass = `border-${color}-600`;
  const hoverBorderColorClass = `hover:border-${color}-500`;

  // Note: Using pixel values directly for width/height in style to prevent sizing issues if Tailwind is slow to load.
  const baseClasses = 
    `w-[${BOX_SIZE.width}px] h-[${BOX_SIZE.height}px] flex flex-col justify-center items-center 
    bg-white shadow-xl rounded-xl border-4 ${borderColorClass} transition duration-150 ease-in-out 
    hover:shadow-2xl ${hoverBorderColorClass} absolute select-none z-10`;

  return (
    <div
      ref={boxRef}
      id={id}
      className={`${baseClasses} ${isDragging ? 'cursor-grabbing' : 'cursor-grab'}`}
      style={{ 
        left: `${position.x}px`, 
        top: `${position.y}px`,
        width: `${BOX_SIZE.width}px`,
        height: `${BOX_SIZE.height}px`,
      }} 
      onMouseDown={handleDragStart}
      onTouchStart={handleDragStart}
    >
      {definition.icon && <definition.icon className={`w-8 h-8 text-${color}-600 mb-2`} />}
      <span className="text-lg font-bold text-gray-800 text-center px-2">{label}</span>
      <span className={`text-xs text-${color}-500 mt-1`}>({definition.label})</span>
    </div>
  );
};


// --- Toolbar Component ---

const Toolbar = ({ addNode }) => {
  return (
    <div className="w-64 bg-gray-50 flex-shrink-0 border-r border-gray-200 shadow-lg flex flex-col">
      <h3 className="p-4 text-xl font-extrabold text-gray-800 border-b border-gray-200">
        Add Nodes
      </h3>
      <div className="flex flex-col space-y-1 p-3 overflow-y-auto">
        
        {/* Map over all defined node types */}
        {Object.entries(NODE_DEFINITIONS).map(([type, def]) => (
            <button 
                key={type}
                onClick={() => addNode(type, def.label, def.color)}
                className={`w-full py-3 px-4 flex items-center justify-start space-x-3 
                            bg-white hover:bg-gray-100 border-2 border-transparent hover:border-${def.color}-400 
                            transition duration-150 text-gray-700 rounded-lg shadow-sm`}
            >
                {def.icon && <def.icon className={`w-5 h-5 text-${def.color}-600 flex-shrink-0`} />}
                <span className="font-medium text-left">{def.label}</span>
            </button>
        ))}

      </div>
    </div>
  );
}


// --- Main Application Component ---

const App = () => {
  const [nodes, setNodes] = useState(INITIAL_NODES);
  const canvasRef = useRef(null);

  // Function to update the position of a specific box
  const setPosition = useCallback((id, newPos) => {
    setNodes(prevNodes => prevNodes.map(node =>
      node.id === id ? { ...node, position: newPos } : node
    ));
  }, []);

  // Function to add a new node
  const addNode = useCallback((type, label, color) => {
    const newId = `node${Date.now()}`;
    const definition = NODE_DEFINITIONS[type];
    
    setNodes(prevNodes => [
      ...prevNodes,
      { 
        id: newId, 
        label: definition.label, 
        position: { x: 50 + Math.random() * 100, y: 50 + Math.random() * 100 }, // Random spawn near top-left
        type: type, 
        color: color 
      },
    ]);
  }, []);

  // Since INITIAL_NODES is now empty, these lookups will return undefined.
  // This is correct as it prevents the line from drawing initially.
  const node1Pos = nodes.find(n => n.id === 'node1')?.position;
  const node2Pos = nodes.find(n => n.id === 'node2')?.position;

  // Calculate the SVG path only if both connected nodes exist
  const linePath = (node1Pos && node2Pos) ? getLinePath(node1Pos, node2Pos) : '';

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

  return (
    // Outer container: Flex row layout, h-screen w-screen for full viewport
    <div className="h-screen w-screen flex bg-gray-100 font-inter overflow-hidden">
      {/* Inject custom CSS for animation */}
      <style dangerouslySetInnerHTML={{ __html: animatedLineStyle }} />

      {/* 1. Toolbar (Left Panel) */}
      <Toolbar addNode={addNode} />

      {/* 2. Main Content Area (Flex Column to hold header and canvas) */}
      <div className="flex-grow flex flex-col p-4">
        
        {/* Header Container */}
        <div className="py-2 px-4 w-full flex flex-col items-center flex-shrink-0">
          <h1 className="text-3xl font-extrabold text-gray-800 mb-2">
            VisualCryptoLab
          </h1>
          <p className="text-gray-600">
            Click the buttons on the left to add nodes. Drag them to see the green line update.
          </p>
        </div>
        
        {/* Main Canvas Container - uses flex-grow to fill remaining vertical space */}
        <div 
          ref={canvasRef}
          className="canvas-container relative w-full flex-grow mt-4 border-4 border-dashed border-gray-300 rounded-2xl bg-white shadow-inner overflow-hidden"
        >
          
          {/* SVG layer for the connection line */}
          <svg className="absolute top-0 left-0 w-full h-full pointer-events-none">
            {node1Pos && node2Pos && ( // Only render line if both connected nodes exist
              <path
                d={linePath}
                stroke="#059669" // Emerald 600
                strokeWidth="4"
                fill="none"
                className="animate-line"
              />
            )}
          </svg>

          {/* Render all Draggable Boxes */}
          {nodes.map(node => (
            <DraggableBox
              key={node.id}
              node={node}
              setPosition={setPosition}
              canvasRef={canvasRef}
            />
          ))}
          
        </div>
      </div>
    </div>
  );
};

export default App;
