import React from 'react';
import {
    NODE_DEFINITIONS,
    PORT_SIZE,
    INPUT_PORT_COLOR,
    OPTIONAL_PORT_COLOR,
    OUTPUT_PORT_COLOR,
    PUBLIC_KEY_COLOR,
    PRIVATE_KEY_COLOR,
    SIGNATURE_COLOR,
    TEXT_ICON_CLASSES
} from '../constants/appConstants';

const Port = React.memo(({ nodeId, type, isConnecting, onStart, onEnd, title, isMandatory, portId, portIndex, outputType, nodes }) => {
    let interactionClasses = "";
    let clickHandler = () => { };
    let portColor = OUTPUT_PORT_COLOR;
    if (outputType === 'public' || outputType === 'private') {
        portColor = outputType === 'public' ? PUBLIC_KEY_COLOR : PRIVATE_KEY_COLOR;
    } else if (type === 'input') {
        portColor = isMandatory ? INPUT_PORT_COLOR : OPTIONAL_PORT_COLOR;
    }
    if (type === 'output' && outputType === 'key') portColor = TEXT_ICON_CLASSES['orange'].replace('text', 'bg');
    if (type === 'output' && outputType === 'signature') portColor = SIGNATURE_COLOR.replace('border', 'bg');

    if (type === 'output') {
        clickHandler = (e) => { e.stopPropagation(); onStart(nodeId, portIndex, outputType); };
        interactionClasses = isConnecting?.sourceId === nodeId ? 'ring-4 ring-emerald-300 animate-pulse' : 'hover:ring-4 hover:ring-emerald-300 transition duration-150';
    } else if (type === 'input') {
        const targetNode = nodes.find(n => n.id === nodeId);
        const targetNodeDef = NODE_DEFINITIONS[targetNode?.type];
        const inputPortDef = targetNodeDef.inputPorts.find(p => p.id === portId);
        const inputPortType = inputPortDef?.type;
        const isTargetCandidate = isConnecting && isConnecting.sourceId !== nodeId && isConnecting.outputType === inputPortType;
        if (isTargetCandidate) {
            clickHandler = (e) => { e.stopPropagation(); onEnd(nodeId, portId); };
            interactionClasses = 'ring-4 ring-yellow-300 cursor-pointer animate-pulse-slow';
        } else {
            interactionClasses = 'hover:ring-4 hover:ring-stone-300 transition duration-150';
            clickHandler = (e) => { e.stopPropagation(); };
        }
    }
    const stopPropagation = (e) => e.stopPropagation();
    return (
        <div
            className={`w-${PORT_SIZE} h-${PORT_SIZE} rounded-full ${portColor} absolute transform -translate-x-1/2 -translate-y-1/2 shadow-md border-2 border-white cursor-pointer ${interactionClasses}`}
            onClick={clickHandler} onMouseDown={stopPropagation} onTouchStart={stopPropagation} title={title}
        />
    );
});

export default Port;
