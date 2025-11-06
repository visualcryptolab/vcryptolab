// src/components/Port.jsx
import React from 'react';
import { 
    INPUT_PORT_COLOR, OPTIONAL_PORT_COLOR, OUTPUT_PORT_COLOR, 
    PUBLIC_KEY_COLOR, PRIVATE_KEY_COLOR, TEXT_ICON_CLASSES, SIGNATURE_COLOR 
} from '../constants/nodeDefinitions.js';

/**
 * Renders an interactive connection port for a node.
 */
export const Port = React.memo(({ nodeId, type, isConnecting, onStart, onEnd, title, isMandatory, portId, portIndex, outputType, nodes }) => {
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
        // --- Input validation logic (simplified check based on isConnecting) ---
        
        // We assume type matching is done in App.jsx's handleConnectEnd.
        const isConnectionActive = isConnecting && isConnecting.sourceId !== nodeId;
        
        if (isConnectionActive) {
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

    return (
        <div 
            className={`w-4 h-4 rounded-full ${portColor} absolute transform -translate-x-1/2 -translate-y-1/2 
                         shadow-md border-2 border-white cursor-pointer ${interactionClasses}`}
            onClick={clickHandler}
            onMouseDown={stopPropagation}
            onTouchStart={stopPropagation}
            title={title}
        />
    );
});