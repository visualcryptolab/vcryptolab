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
    let rejectionReason = null;
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
        let isTargetCandidate = isConnecting && isConnecting.sourceId !== nodeId && isConnecting.outputType === inputPortType;

        // Smart Check: PRNG Requirements
        if (isTargetCandidate && inputPortDef?.requiresPrime) {
            const sourceNode = nodes.find(n => n.id === isConnecting.sourceId);
            if (sourceNode?.type === 'PRNG_GEN') {
                const isPrimeSet = sourceNode.isPrime === true;
                const isInteger = sourceNode.prngType === 'Integer'; // Floats are never primes regardless of checkbox
                if (!isPrimeSet || !isInteger) {
                    isTargetCandidate = false;
                }
            } else {
                // If it's not a PRNG node, we can't verify 'primality' easily, so we might block or allow depending on strictness.
                // Assuming "smart connection" means specifically for PRNG -> Input Text scenario.
                // If the user connects a manual Data Input or another tool, we might let it through because we don't know the content yet.
                // But generally, requiresPrime implies integer requirement.
            }
        }

        if (isTargetCandidate) {
            clickHandler = (e) => { e.stopPropagation(); onEnd(nodeId, portId); };
            interactionClasses = 'ring-4 ring-yellow-300 cursor-pointer animate-pulse-slow';
        } else {
            // If we are connecting, but this port is not a candidate, check if it was rejected by Smart Check
            if (isConnecting && isConnecting.sourceId !== nodeId && isConnecting.outputType === inputPortType) {
                // It matched types, so it must have failed the smart check (or some other logic if added later)
                if (inputPortDef?.requiresPrime) {
                    const sourceNode = nodes.find(n => n.id === isConnecting.sourceId);
                    if (sourceNode?.type === 'PRNG_GEN') {
                        const isInteger = sourceNode.prngType === 'Integer';
                        const isPrimeSet = sourceNode.isPrime === true;
                        if (!isInteger) rejectionReason = "Requires 'Integer' type";
                        else if (!isPrimeSet) rejectionReason = "Requires 'Prime' checkbox set";
                    }
                }
            }

            if (rejectionReason) {
                interactionClasses = 'ring-2 ring-red-400 cursor-not-allowed opacity-50'; // Visual cue for invalid
                clickHandler = (e) => { e.stopPropagation(); }; // Prevent click
            } else {
                interactionClasses = 'hover:ring-4 hover:ring-stone-300 transition duration-150';
                clickHandler = (e) => { e.stopPropagation(); };
            }
        }
    }
    const stopPropagation = (e) => e.stopPropagation();

    // Append rejection reason to title if present
    const finalTitle = rejectionReason ? `${title || ''} (Invalid: ${rejectionReason})` : title;

    return (
        <div
            className={`w-${PORT_SIZE} h-${PORT_SIZE} rounded-full ${portColor} absolute transform -translate-x-1/2 -translate-y-1/2 shadow-md border-2 border-white cursor-pointer ${interactionClasses}`}
            onClick={clickHandler} onMouseDown={stopPropagation} onTouchStart={stopPropagation} title={finalTitle}
        />
    );
});

export default Port;
