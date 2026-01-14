import { NODE_DEFINITIONS } from '../constants/appConstants';

export const getLinePath = (sourceNode, targetNode, connection) => {
    const sourceDef = NODE_DEFINITIONS[sourceNode.type];
    const targetDef = NODE_DEFINITIONS[targetNode.type];
    const getVerticalPosition = (nodeDef, index, isInput, nodeHeight) => {
        const numPorts = isInput ? nodeDef.inputPorts.length : nodeDef.outputPorts.length;
        const step = nodeHeight / (numPorts + 1);
        return (index + 1) * step;
    };
    const sourceVerticalPos = getVerticalPosition(sourceDef, connection.sourcePortIndex, false, sourceNode.height);
    const targetPortIndex = targetDef.inputPorts.findIndex(p => p.id === connection.targetPortId);
    const targetVerticalPos = getVerticalPosition(targetDef, targetPortIndex, true, targetNode.height);
    const p1 = { x: sourceNode.position.x + sourceNode.width, y: sourceNode.position.y + sourceVerticalPos };
    const p2 = { x: targetNode.position.x, y: targetNode.position.y + targetVerticalPos };
    const midX = (p1.x + p2.x) / 2;
    return `M${p1.x} ${p1.y} C${midX} ${p1.y}, ${midX} ${p2.y}, ${p2.x} ${p2.y}`;
};
