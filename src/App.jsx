import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import {
    NODE_DEFINITIONS,
    PROJECT_SCHEMA_VERSION,
    INITIAL_NODES,
    INITIAL_CONNECTIONS,
    NODE_DIMENSIONS
} from './constants/appConstants';
import { globalStyles } from './styles/globalStyles';
import { migrateProjectData, downloadFile } from './utils/projectUtils';
import { getLinePath } from './utils/canvasUtils';
import { recalculateGraph } from './utils/graphUtils';
import { getOutputFormat } from './utils/cryptoUtils';
import Toolbar from './components/Toolbar';
import DraggableBox from './components/DraggableBox';
import StatusNotification from './components/ui/StatusNotification';
import ReactGA from 'react-ga4';
import CookieConsent from 'react-cookie-consent';

const App = () => {
    const [nodes, setNodes] = useState(INITIAL_NODES);
    const [connections, setConnections] = useState(INITIAL_CONNECTIONS);
    const [connectingPort, setConnectingPort] = useState(null);
    const [statusMessage, setStatusMessage] = useState(null);
    const [scale, setScale] = useState(1);
    const canvasRef = useRef(null);

    const clearStatusMessage = useCallback(() => setStatusMessage(null), []);

    useEffect(() => { setNodes(prevNodes => recalculateGraph(prevNodes, connections, null, setNodes)); }, [connections]);

    const updateNodeContent = useCallback((id, field, value) => {
        setNodes(prevNodes => {
            const nextNodes = prevNodes.map(node => node.id === id ? { ...node, [field]: value } : node);
            return recalculateGraph(nextNodes, connections, id, setNodes);
        });
    }, [connections]);

    const setPosition = useCallback((id, newPos) => setNodes(prev => prev.map(n => n.id === id ? { ...n, position: newPos } : n)), []);
    const handleNodeResize = useCallback((id, w, h) => setNodes(prev => prev.map(n => n.id === id ? { ...n, width: Math.max(NODE_DIMENSIONS.minWidth, w), height: Math.max(NODE_DIMENSIONS.minHeight, h) } : n)), []);

    const addNode = useCallback((type, label, color) => {
        const newId = `${type}_${Date.now()}`;
        const def = NODE_DEFINITIONS[type];
        const initialContent = { dataOutput: '', isProcessing: false, outputFormat: getOutputFormat(type), width: (['SHIFT_OP', 'XOR_OP', 'DATA_SPLIT', 'DATA_CONCAT'].includes(type) ? 300 : NODE_DIMENSIONS.initialWidth), height: (['SHIFT_OP', 'XOR_OP', 'DATA_SPLIT', 'DATA_CONCAT'].includes(type) ? 300 : NODE_DIMENSIONS.initialHeight) };
        const cv = canvasRef.current;
        let x = ((cv?.clientWidth || 800) / 2) - 150 + (Math.random() * 200 - 100);
        let y = ((cv?.clientHeight || 600) / 2) - 140 + (Math.random() * 200 - 100);
        // Explicitly handle initial values for specific node types
        if (type === 'DATA_INPUT') { initialContent.content = ''; initialContent.format = 'Binary'; }
        else if (type === 'OUTPUT_VIEWER') { initialContent.isConversionExpanded = false; initialContent.convertedFormat = 'Base64'; }
        else if (type === 'CAESAR_CIPHER') initialContent.shiftKey = 3;
        else if (type === 'VIGENERE_CIPHER') { initialContent.keyword = 'HELLO'; initialContent.vigenereMode = 'ENCRYPT'; }
        else if (type === 'SIMPLE_RSA_KEY_GEN') { initialContent.generateKey = true; initialContent.modulusLength = 0; }
        else if (type === 'SHIFT_OP') { initialContent.shiftType = 'Left'; initialContent.shiftAmount = 1; }

        // Track event in GA
        ReactGA.event({
            category: "Tools",
            action: "Add Node",
            label: label
        });

        setNodes(prev => [...prev, { id: newId, label: def.label, position: { x: Math.max(20, x), y: Math.max(20, y) }, type, color, ...initialContent }]);
    }, []);

    const handleDeleteNode = useCallback((id) => {
        setNodes(prev => prev.filter(n => n.id !== id));
        setConnections(prev => prev.filter(c => c.source !== id && c.target !== id));
    }, []);

    const handleConnectStart = useCallback((nodeId, portIndex, outputType) => setConnectingPort({ sourceId: nodeId, sourcePortIndex: portIndex, outputType }), []);
    const handleConnectEnd = useCallback((targetId, targetPortId) => {
        if (connectingPort && targetId && connectingPort.sourceId !== targetId) {
            const { sourceId, sourcePortIndex } = connectingPort;
            const targetNode = nodes.find(n => n.id === targetId);
            const targetNodeDef = NODE_DEFINITIONS[targetNode?.type];
            if (targetNodeDef && targetNodeDef.inputPorts.some(p => p.id === targetPortId)) {
                setConnections(prev => [...prev, { source: sourceId, sourcePortIndex, target: targetId, targetPortId }]);
            }
        }
        setConnectingPort(null);
    }, [connectingPort, nodes]);

    const handleRemoveConnection = useCallback((s, t, sIdx, tId) => setConnections(prev => prev.filter(c => !(c.source === s && c.target === t && c.sourcePortIndex === sIdx && c.targetPortId === tId))), []);

    const handleZoomIn = useCallback(() => setScale(prev => Math.min(prev + 0.1, 2)), []);
    const handleZoomOut = useCallback(() => setScale(prev => Math.max(prev - 0.1, 0.5)), []);

    const handleDownloadProject = useCallback(() => {
        const projectData = { schemaVersion: PROJECT_SCHEMA_VERSION, nodes: nodes, connections: connections };
        downloadFile(JSON.stringify(projectData, null, 2), `visual_crypto_project_v${PROJECT_SCHEMA_VERSION}.json`, 'application/json');
        setStatusMessage({ type: 'success', message: 'Project exported successfully!' });
        setTimeout(clearStatusMessage, 3000);
    }, [nodes, connections, clearStatusMessage]);

    const handleUploadProject = useCallback((fileInput) => {
        clearStatusMessage();
        const file = fileInput.files?.[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const projectData = JSON.parse(e.target.result);
                if (!projectData || !Array.isArray(projectData.nodes)) throw new Error("Invalid JSON");
                const { migratedData, wasMigrated } = migrateProjectData(projectData);
                setNodes(migratedData.nodes);
                setConnections(migratedData.connections);
                setStatusMessage({ type: 'success', message: wasMigrated ? 'Project migrated & loaded!' : 'Project loaded successfully!' });
            } catch (error) { setStatusMessage({ type: 'error', message: 'Import failed: Invalid file.' }); }
            setTimeout(clearStatusMessage, 3000);
        };
        reader.readAsText(file);
        fileInput.value = '';
    }, [clearStatusMessage]);

    const connectionPaths = useMemo(() => {
        let maxX = 0; let maxY = 0; const padding = 50;
        nodes.forEach(node => { maxX = Math.max(maxX, node.position.x + node.width); maxY = Math.max(maxY, node.position.y + node.height); });
        const svgWidth = Math.max(maxX + padding, (canvasRef.current?.clientWidth || 0) / scale);
        const svgHeight = Math.max(maxY + padding, (canvasRef.current?.clientHeight || 0) / scale);
        return {
            size: { width: svgWidth, height: svgHeight },
            paths: connections.map(conn => {
                const sN = nodes.find(n => n.id === conn.source);
                const tN = nodes.find(n => n.id === conn.target);
                return (sN && tN) ? { path: getLinePath(sN, tN, conn), source: conn.source, target: conn.target, sourcePortIndex: conn.sourcePortIndex, targetPortId: conn.targetPortId } : null;
            }).filter(Boolean)
        };
    }, [connections, nodes, scale]);

    const handleCanvasClick = useCallback(() => { if (connectingPort) handleConnectEnd(null); }, [connectingPort, handleConnectEnd]);

    const handleAcceptCookie = () => {
        ReactGA.initialize(import.meta.env.VITE_GA_ID);
    };

    return (
        <div className="h-screen w-screen flex bg-gray-100 font-inter overflow-hidden">
            <style dangerouslySetInnerHTML={{ __html: globalStyles }} />
            <Toolbar addNode={addNode} onDownloadProject={handleDownloadProject} onUploadProject={handleUploadProject} onZoomIn={handleZoomIn} onZoomOut={handleZoomOut} />
            <div className="flex-grow flex flex-col p-4">
                <div ref={canvasRef} className="canvas-container relative w-full flex-grow border-4 border-dashed border-gray-300 rounded-2xl bg-white shadow-inner overflow-auto" onClick={handleCanvasClick}>
                    <div style={{ transform: `scale(${scale})`, transformOrigin: 'top left', width: `${connectionPaths.size.width}px`, height: `${connectionPaths.size.height}px`, minWidth: `100%`, minHeight: `100%` }} className="absolute top-0 left-0">
                        <svg className="absolute top-0 left-0 pointer-events-auto z-0" style={{ width: `${connectionPaths.size.width}px`, height: `${connectionPaths.size.height}px` }}>
                            {connectionPaths.paths.map((conn) => (
                                <g key={`${conn.source}-${conn.target}-${conn.sourcePortIndex}-${conn.targetPortId}`} onClick={(e) => { e.stopPropagation(); handleRemoveConnection(conn.source, conn.target, conn.sourcePortIndex, conn.targetPortId); }} className="cursor-pointer">
                                    <path d={conn.path} className="connection-hitbox" style={{ strokeWidth: `${15 / scale}px` }} />
                                    <path d={conn.path} className="connection-line-visible" style={{ strokeWidth: `${4 / scale}px` }} />
                                </g>
                            ))}
                        </svg>
                        {nodes.map(node => (
                            <DraggableBox key={node.id} node={node} setPosition={setPosition} updateNodeContent={updateNodeContent} canvasRef={canvasRef} handleConnectStart={handleConnectStart} handleConnectEnd={handleConnectEnd} connectingPort={connectingPort} connections={connections} handleDeleteNode={handleDeleteNode} nodes={nodes} scale={scale} handleResize={handleNodeResize} />
                        ))}
                    </div>
                </div>
                {statusMessage && <StatusNotification status={statusMessage.type} message={statusMessage.message} onClose={clearStatusMessage} />}
            </div>
            <CookieConsent
                location="bottom"
                buttonText="I Accept"
                cookieName="VCL_GA_CONSENT"
                style={{ background: "#2B373B" }}
                buttonStyle={{ color: "#4e503b", fontSize: "13px" }}
                expires={150}
                onAccept={handleAcceptCookie}
            >
                This website uses cookies to enhance the user experience. By clicking "I Accept", you consent to the use of cookies for analytics purposes.
            </CookieConsent>
        </div>
    );
};

export default App;