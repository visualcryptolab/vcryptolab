import React, { useState, useCallback, useRef, useEffect } from 'react';
import { Clipboard, X, Key } from 'lucide-react';
import {
    NODE_DEFINITIONS,
    TEXT_ICON_CLASSES,
    BORDER_CLASSES,
    HOVER_BORDER_CLASSES,
    NODE_DIMENSIONS,
    HASH_ALGORITHMS,
    ALL_FORMATS
} from '../constants/appConstants';
import { isContentCompatible } from '../utils/cryptoUtils';
import Port from './Port';

const DraggableBox = ({ node, setPosition, canvasRef, handleConnectStart, handleConnectEnd, connectingPort, updateNodeContent, connections, handleDeleteNode, nodes, scale, handleResize }) => {
    const { id, label, position, type, color, content, format, dataOutput, dataOutputPublic, dataOutputPrivate, isProcessing, hashAlgorithm, keyAlgorithm, symAlgorithm, modulusLength, publicExponent, sourceFormat, rawInputData, p, q, e, d, n, phiN, shiftKey, keyword, vigenereMode, dStatus, n_pub, e_pub, isReadOnly, width, height, keyBase64, shiftDescription, chunk1, chunk2, convertedData, convertedFormat, isConversionExpanded, interpretAsText } = node;
    const definition = NODE_DEFINITIONS[type];
    const [isDragging, setIsDragging] = useState(false);
    const [isResizing, setIsResizing] = useState(false);
    const boxRef = useRef(null);
    const offset = useRef({ x: 0, y: 0 });
    const resizeOffset = useRef({ x: 0, y: 0 });
    const [copyStatus, setCopyStatus] = useState('Copy');

    const isDataInput = type === 'DATA_INPUT';
    const isOutputViewer = type === 'OUTPUT_VIEWER';
    const isHashFn = type === 'HASH_FN';
    const isKeyGen = type === 'KEY_GEN';
    const isSimpleRSAKeyGen = type === 'SIMPLE_RSA_KEY_GEN';
    const isSimpleRSAPubKeyGen = type === 'SIMPLE_RSA_PUBKEY_GEN';
    const isRSAKeyGen = type === 'RSA_KEY_GEN';
    const isSimpleRSAEnc = type === 'SIMPLE_RSA_ENC';
    const isSimpleRSADec = type === 'SIMPLE_RSA_DEC';
    const isSimpleRSASign = type === 'SIMPLE_RSA_SIGN';
    const isSimpleRSAVerify = type === 'SIMPLE_RSA_VERIFY';
    const isSymEnc = type === 'SYM_ENC';
    const isSymDec = type === 'SYM_DEC';
    const isAsymEnc = type === 'ASYM_ENC';
    const isAsymDec = type === 'ASYM_DEC';
    const isBitShift = type === 'SHIFT_OP';
    const isCaesarCipher = type === 'CAESAR_CIPHER';
    const isVigenereCipher = type === 'VIGENERE_CIPHER';
    const isDataSplit = type === 'DATA_SPLIT';
    const isDataConcat = type === 'DATA_CONCAT';

    const FORMATS = ALL_FORMATS;
    const isPortSource = connectingPort?.sourceId === id;
    const iconTextColorClass = TEXT_ICON_CLASSES[color] || 'text-gray-600';
    let specificClasses = '';
    if (isPortSource) specificClasses = `border-emerald-500 ring-4 ring-emerald-300 cursor-pointer animate-pulse transition duration-200`;
    else specificClasses = `${BORDER_CLASSES[color]} ${HOVER_BORDER_CLASSES[color]} ${isDragging ? 'cursor-grabbing' : 'cursor-pointer hover:border-blue-500'}`;
    if (isProcessing) specificClasses = `border-yellow-500 ring-4 ring-yellow-300 animate-pulse transition duration-200`;

    let requiredMinHeight = NODE_DIMENSIONS.minHeight;
    if (isOutputViewer) requiredMinHeight = isConversionExpanded ? 280 : 250;
    if (isBitShift || type === 'XOR_OP' || isDataSplit || isDataConcat) requiredMinHeight = 300;
    const effectiveMinHeight = requiredMinHeight;
    const baseClasses = `h-auto flex flex-col justify-start items-center p-3 bg-white shadow-xl rounded-xl border-4 transition duration-150 ease-in-out hover:shadow-2xl absolute select-none z-10`;
    const boxStyle = { left: `${position.x}px`, top: `${position.y}px`, width: `${width}px`, minHeight: `${effectiveMinHeight}px`, height: `${height}px` };
    const contentHeightExcludingHeader = height - 50;

    const handleDragStart = useCallback((e) => {
        if (connectingPort || isResizing) return;
        const interactiveTags = ['TEXTAREA', 'SELECT', 'OPTION', 'BUTTON', 'INPUT'];
        if (e.target.tagName === 'DIV' && e.target.classList.contains('w-4') && e.target.classList.contains('h-4')) return;
        if (interactiveTags.includes(e.target.tagName)) return;
        const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
        const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);
        const canvas = canvasRef.current;
        if (boxRef.current && canvas) {
            const canvasRect = canvas.getBoundingClientRect();
            const unscaledMouseX = (clientX - canvasRect.left) / scale;
            const unscaledMouseY = (clientY - canvasRect.y) / scale;
            offset.current = { x: unscaledMouseX - position.x, y: unscaledMouseY - position.y };
            setIsDragging(true);
            e.preventDefault();
        }
    }, [canvasRef, position.x, position.y, connectingPort, isResizing, scale]);

    const handleDragMove = useCallback((e) => {
        if (!isDragging) return;
        const canvas = canvasRef.current;
        if (!canvas) return;
        const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
        const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);
        const canvasRect = canvas.getBoundingClientRect();
        const unscaledMouseX = (clientX - canvasRect.left) / scale;
        const unscaledMouseY = (clientY - canvasRect.y) / scale;
        let newX = unscaledMouseX - offset.current.x;
        let newY = unscaledMouseY - offset.current.y;
        newX = Math.max(0, newX);
        newY = Math.max(0, newY);
        setPosition(id, { x: newX, y: newY });
    }, [isDragging, id, setPosition, canvasRef, scale]);

    const handleDragEnd = useCallback(() => setIsDragging(false), []);

    const handleResizeStart = useCallback((e) => {
        e.stopPropagation(); setIsResizing(true);
        const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
        const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);
        const canvas = canvasRef.current.getBoundingClientRect();
        const unscaledMouseX = (clientX - canvas.left) / scale;
        const unscaledMouseY = (clientY - canvas.y) / scale;
        resizeOffset.current = { x: unscaledMouseX - (node.position.x + node.width), y: unscaledMouseY - (node.position.y + node.height) };
    }, [node.position.x, node.position.y, node.width, node.height, scale, canvasRef]);

    const handleResizeMove = useCallback((e) => {
        if (!isResizing) return;
        const canvas = canvasRef.current;
        if (!canvas) return;
        const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
        const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);
        const canvasRect = canvas.getBoundingClientRect();
        const unscaledMouseX = (clientX - canvasRect.left) / scale;
        const unscaledMouseY = (clientY - canvasRect.y) / scale;
        let newWidth = unscaledMouseX - node.position.x - resizeOffset.current.x;
        let newHeight = unscaledMouseY - node.position.y - resizeOffset.current.y;
        handleResize(id, newWidth, newHeight);
        e.preventDefault();
    }, [isResizing, id, handleResize, node.position.x, node.position.y, scale]);

    const handleResizeEnd = useCallback(() => setIsResizing(false), []);

    useEffect(() => {
        const globalHandleMove = (e) => { if (isDragging) handleDragMove(e); else if (isResizing) handleResizeMove(e); };
        const globalHandleUp = (e) => { if (isDragging) handleDragEnd(e); else if (isResizing) handleResizeEnd(e); };
        if (isDragging || isResizing) {
            document.addEventListener('mousemove', globalHandleMove);
            document.addEventListener('mouseup', globalHandleUp);
            document.addEventListener('touchmove', globalHandleMove, { passive: false });
            document.addEventListener('touchend', globalHandleUp);
        }
        return () => {
            document.removeEventListener('mousemove', globalHandleMove);
            document.removeEventListener('mouseup', globalHandleUp);
            document.removeEventListener('touchmove', globalHandleMove);
            document.removeEventListener('touchend', globalHandleUp);
        };
    }, [isDragging, isResizing, handleDragMove, handleDragEnd, handleResizeMove, handleResizeEnd]);

    const handleBoxClick = useCallback((e) => {
        if (isDragging || isResizing) return;
        if (connectingPort) handleConnectEnd(null);
        e.stopPropagation();
    }, [connectingPort, handleConnectEnd, isDragging, isResizing]);

    const handleCopyToClipboard = useCallback((e, textToCopy) => {
        e.stopPropagation();
        if (!textToCopy || textToCopy.startsWith('ERROR')) return;
        try {
            const tempTextArea = document.createElement('textarea');
            tempTextArea.value = textToCopy;
            tempTextArea.style.position = 'fixed';
            tempTextArea.style.left = '-9999px';
            document.body.appendChild(tempTextArea);
            tempTextArea.select();
            document.execCommand('copy');
            document.body.removeChild(tempTextArea);
            setCopyStatus('Copied!');
            setTimeout(() => setCopyStatus('Copy'), 1500);
        } catch (err) { console.error('Failed to copy text:', err); setCopyStatus('Error'); setTimeout(() => setCopyStatus('Copy'), 2000); }
    }, [setCopyStatus]);

    const renderInputPorts = () => {
        if (!definition.inputPorts || definition.inputPorts.length === 0) return null;
        const step = height / (definition.inputPorts.length + 1);
        return definition.inputPorts.map((portDef, index) => {
            const topPosition = (index + 1) * step;
            const isInputConnected = connections.some(c => c.target === id && c.targetPortId === portDef.id);
            return (
                <div key={portDef.id} className="absolute -left-2 transform -translate-y-1/2 z-20" style={{ top: `${topPosition}px` }}>
                    <Port nodeId={id} type="input" portId={portDef.id} isConnecting={connectingPort} onStart={handleConnectStart} onEnd={handleConnectEnd} title={`${portDef.name} (${portDef.mandatory ? 'Mandatory' : 'Optional'}) - Type: ${portDef.type}`} isMandatory={portDef.mandatory} isInputConnected={isInputConnected} nodes={nodes} />
                </div>
            );
        });
    };

    const renderOutputPorts = () => {
        if (!definition.outputPorts || definition.outputPorts.length === 0) return null;
        const step = height / (definition.outputPorts.length + 1);
        return definition.outputPorts.map((portDef, index) => {
            const topPosition = (index + 1) * step;
            return (
                <div key={portDef.name} className="absolute -right-2 transform -translate-y-1/2 z-20" style={{ top: `${topPosition}px` }}>
                    <Port nodeId={id} type="output" portId={`${portDef.type}-${index}`} portIndex={index} outputType={portDef.type} isConnecting={connectingPort} onStart={handleConnectStart} onEnd={handleConnectEnd} title={`${portDef.name} - Type: ${portDef.type}`} isMandatory={true} nodes={nodes} />
                </div>
            );
        });
    };

    return (
        <div ref={boxRef} id={id} className={`${baseClasses} ${specificClasses}`} style={boxStyle} onMouseDown={handleDragStart} onTouchStart={handleDragStart} onClick={handleBoxClick}>
            <div className="absolute bottom-0 right-0 w-4 h-4 rounded-tl-lg bg-gray-200 opacity-60 hover:opacity-100 transition duration-150 cursor-nwse-resize z-30" onMouseDown={handleResizeStart} onTouchStart={handleResizeStart} onClick={(e) => e.stopPropagation()} title="Resize">
                <div className="w-1 h-1 bg-gray-600 absolute bottom-1 right-1"></div>
            </div>
            <button className="absolute top-1 right-1 p-1 rounded-full bg-gray-100 hover:bg-gray-200 text-gray-400 hover:text-gray-600 z-30 transition duration-150" onClick={(e) => { e.stopPropagation(); handleDeleteNode(id); }} title="Delete Node"><X className="w-3 h-3" /></button>
            {renderInputPorts()} {renderOutputPorts()}
            <div className="flex flex-col w-full justify-start items-center overflow-hidden" style={{ height: `${contentHeightExcludingHeader}px` }}>
                <div className="flex flex-col justify-start items-center w-full flex-shrink-0 mb-2">
                    {definition.icon && (<definition.icon className={`w-6 h-6 ${iconTextColorClass} mb-1`} />)}
                    <span className={`text-${isDataInput ? 'base' : 'lg'} font-bold text-gray-800 text-center leading-tight`}>{label}</span>
                    {isCaesarCipher && <span className={`text-xs text-gray-500 mt-1`}>k = {node.shiftKey || 0}</span>}
                    {isVigenereCipher && <span className={`text-xs text-gray-500 mt-1`}>Keyword: {node.keyword || 'None'}</span>}
                    {isSimpleRSASign && <span className={`text-xs text-gray-500 mt-1`}>Signing (m^d mod n)</span>}
                    {isSimpleRSAVerify && <span className={`text-xs text-gray-500 mt-1`}>Verifying (s^e mod n)</span>}
                    {isSimpleRSAEnc && <span className={`text-xs text-gray-500 mt-1`}>Encryption: (c = m^e mod n)</span>}
                    {isSimpleRSADec && <span className={`text-xs text-gray-500 mt-1`}>Decryption: (m = c^d mod n)</span>}
                    {isHashFn && (
                        <div className="text-xs w-full text-center flex flex-col items-center">
                            <span className={`text-[10px] font-semibold text-gray-600 mb-1`}>ALGORITHM</span>
                            <select className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 bg-white appearance-none cursor-pointer text-gray-700 focus:ring-2 focus:ring-gray-500 focus:border-gray-500 outline-none transition duration-200" value={hashAlgorithm || 'SHA-256'} onChange={(e) => updateNodeContent(id, 'hashAlgorithm', e.target.value)} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()}>
                                {HASH_ALGORITHMS.map(alg => (<option key={alg} value={alg}>{alg}</option>))}
                            </select>
                        </div>
                    )}
                    {isKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({keyAlgorithm})</span>}
                    {isSimpleRSAKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({modulusLength} bits)</span>}
                    {type === 'XOR_OP' && <span className={`text-xs text-gray-500 mt-1`}>({isProcessing ? 'Processing' : 'Bitwise XOR'})</span>}
                    {isBitShift && <span className={`text-xs text-gray-500 mt-1`}>({isProcessing ? 'Processing' : (shiftDescription || 'Bit Shift')})</span>}
                    {isSimpleRSAPubKeyGen && <span className={`text-xs text-gray-500 mt-1`}>Public Key Output</span>}
                    {isDataSplit && <span className={`text-xs text-gray-500 mt-1`}>Split by: Character/Hex/Bit</span>}
                    {isDataConcat && <span className={`text-xs text-gray-500 mt-1`}>Concatenation: Data A + Data B</span>}
                </div>

                {isDataInput && (
                    <div className="w-full flex flex-col items-center flex-grow">
                        <textarea className="w-full text-xs p-2 border border-gray-200 rounded-lg shadow-md resize-y flex-grow mb-2 placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200" placeholder="Enter data here..." value={content || ''} onChange={(e) => {
                            const newContent = e.target.value;
                            const currentFormat = node.format;
                            let newFormat = currentFormat;
                            const formatsByRestrictiveness = ['Binary', 'Decimal', 'Hexadecimal', 'Base64', 'Text (UTF-8)'];
                            if (!isContentCompatible(newContent, currentFormat)) {
                                for (const formatCheck of formatsByRestrictiveness) {
                                    if (isContentCompatible(newContent, formatCheck)) { newFormat = formatCheck; break; }
                                }
                            }
                            if (newFormat !== currentFormat) updateNodeContent(id, 'format', newFormat);
                            updateNodeContent(id, 'content', newContent);
                        }} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} />
                        <select className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm flex-shrink-0 bg-white appearance-none cursor-pointer text-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200" value={format || 'Text (UTF-8)'} onChange={(e) => {
                            e.stopPropagation();
                            const selectedFormat = e.target.value;
                            const currentContent = content || '';
                            let finalFormat = selectedFormat;
                            if (!isContentCompatible(currentContent, selectedFormat)) {
                                const formatsByRestrictiveness = ['Binary', 'Decimal', 'Hexadecimal', 'Base64', 'Text (UTF-8)'];
                                for (const formatCheck of formatsByRestrictiveness) {
                                    if (isContentCompatible(currentContent, formatCheck)) { finalFormat = formatCheck; break; }
                                }
                            }
                            updateNodeContent(id, 'format', finalFormat);
                        }} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()}>
                            {FORMATS.map(f => (<option key={f} value={f}>{f}</option>))}
                        </select>
                    </div>
                )}

                {isOutputViewer && (
                    <div className="w-full mt-1 flex flex-col items-center flex-grow text-xs text-gray-700 bg-gray-50 p-2 border border-gray-200 rounded-lg shadow-inner overflow-y-auto">
                        <span className="text-center font-bold text-red-600 mb-1 flex-shrink-0">RAW INPUT DATA</span>
                        <div className="w-full mb-1 flex-shrink-0">
                            <label className="block text-left text-[10px] font-semibold text-gray-600 mb-0.5">Source Data Type</label>
                            <div className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm bg-gray-100 text-gray-700 truncate">{sourceFormat || 'N/A'}</div>
                        </div>
                        <div className={`relative w-full break-all text-[10px] leading-tight text-gray-800 bg-white p-1 rounded-md mb-2 overflow-y-auto border border-gray-200`} style={{ flexGrow: isConversionExpanded ? 0.5 : 1.2, minHeight: '40px' }}>
                            <p>{rawInputData || 'Not connected or no data.'}</p>
                            <button onClick={(e) => handleCopyToClipboard(e, rawInputData)} disabled={!rawInputData || rawInputData.startsWith('ERROR')} className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm ${rawInputData && !rawInputData.startsWith('ERROR') ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500' : 'bg-gray-300 cursor-not-allowed'}`} title="Copy to Clipboard"><Clipboard className="w-3 h-3" /></button>
                        </div>
                        <button onClick={(e) => { e.stopPropagation(); updateNodeContent(id, 'isConversionExpanded', !isConversionExpanded); }} className={`mt-1 w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md bg-red-500 hover:bg-red-600 flex-shrink-0`}><span>{isConversionExpanded ? 'Hide Conversion' : 'Convert Type'}</span></button>
                        {isConversionExpanded && (
                            <div className="w-full mt-2 pt-2 border-t border-gray-200 flex flex-col space-y-2 flex-grow">
                                <span className="text-center font-bold text-red-600 text-[10px] flex-shrink-0">CONVERTED VIEW</span>
                                <div className="relative w-full break-all text-[10px] leading-tight text-gray-800 bg-white p-1 rounded-md mb-2 overflow-y-auto border border-gray-200" style={{ flexGrow: 1, minHeight: '40px' }}>
                                    <p>{convertedData || 'Select conversion type...'}</p>
                                    <button onClick={(e) => handleCopyToClipboard(e, convertedData)} disabled={!convertedData || convertedData.startsWith('ERROR')} className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm ${convertedData && !convertedData.startsWith('ERROR') ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500' : 'bg-gray-300 cursor-not-allowed'}`} title="Copy to Clipboard"><Clipboard className="w-3 h-3" /></button>
                                </div>
                                <select className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm flex-shrink-0 bg-white appearance-none cursor-pointer text-gray-700 focus:ring-2 focus:ring-red-500 focus:border-red-500 outline-none transition duration-200" value={convertedFormat || 'Base64'} onChange={(e) => updateNodeContent(id, 'convertedFormat', e.target.value)} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()}>
                                    {FORMATS.map(f => (<option key={f} value={f}>{f}</option>))}
                                </select>
                            </div>
                        )}
                    </div>
                )}

                {isCaesarCipher && (
                    <div className="text-xs w-full text-center flex flex-col items-center flex-grow">
                        <span className={`text-[10px] font-semibold text-gray-600 mb-1 flex-shrink-0`}>SHIFT KEY (k)</span>
                        <input type="number" min="0" max="25" step="1" className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 flex-shrink-0 text-gray-700 focus:ring-2 focus:ring-amber-500 focus:border-amber-500 outline-none transition duration-200" value={node.shiftKey || 0} onChange={(e) => updateNodeContent(id, 'shiftKey', parseInt(e.target.value) || 0)} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} />
                        <span className={`font-semibold mt-2 ${isProcessing ? 'text-yellow-600' : 'text-amber-600'} flex-shrink-0`}>{isProcessing ? 'Encrypting...' : 'Active'}</span>
                        <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                            <p className={`text-left text-[10px] break-all p-2 bg-gray-100 rounded overflow-auto h-full ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>{dataOutput ? `Result (${node.outputFormat}): ${dataOutput}` : 'Waiting for Plaintext...'}</p>
                            <button onClick={(e) => handleCopyToClipboard(e, dataOutput)} disabled={!dataOutput || dataOutput.startsWith('ERROR')} className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm ${dataOutput && !dataOutput.startsWith('ERROR') ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500' : 'bg-gray-300 cursor-not-allowed'}`} title="Copy to Clipboard"><Clipboard className="w-3 h-3" /></button>
                        </div>
                    </div>
                )}

                {isSimpleRSAKeyGen && (
                    <div className="text-xs w-full flex flex-col items-center flex-grow space-y-2">
                        <div className="w-full grid grid-cols-2 gap-2 flex-shrink-0">
                            <label className="block"><span className="block text-[10px] font-semibold text-gray-600 mb-0.5">P (Prime 1)</span><input type="text" placeholder="Auto" className="w-full text-[10px] p-1 border border-gray-200 rounded-lg shadow-sm text-gray-700 focus:ring-2 focus:ring-purple-500 outline-none transition" value={p || ''} onChange={(e) => updateNodeContent(id, 'p', e.target.value.replace(/[^0-9]/g, ''))} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} /></label>
                            <label className="block"><span className="block text-[10px] font-semibold text-gray-600 mb-0.5">Q (Prime 2)</span><input type="text" placeholder="Auto" className="w-full text-[10px] p-1 border border-gray-200 rounded-lg shadow-sm text-gray-700 focus:ring-2 focus:ring-purple-500 outline-none transition" value={q || ''} onChange={(e) => updateNodeContent(id, 'q', e.target.value.replace(/[^0-9]/g, ''))} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} /></label>
                        </div>
                        <div className="w-full grid grid-cols-2 gap-2 flex-shrink-0">
                            <label className="block"><span className="block text-[10px] font-semibold text-gray-600 mb-0.5">N (Modulus)</span><div className="text-[10px] p-1.5 border border-gray-200 rounded-lg bg-gray-100 overflow-hidden break-all h-6">{n || 'N/A'}</div></label>
                            <label className="block"><span className="block text-[10px] font-semibold text-gray-600 mb-0.5">Phi(N)</span><div className="text-[10px] p-1.5 border border-gray-200 rounded-lg bg-gray-100 overflow-hidden break-all h-6">{phiN || 'N/A'}</div></label>
                        </div>
                        <div className="w-full grid grid-cols-2 gap-2 flex-shrink-0">
                            <label className="block"><span className="block text-[10px] font-semibold text-gray-600 mb-0.5">E (Public Exp)</span><input type="text" placeholder="Auto" className="w-full text-[10px] p-1 border border-gray-200 rounded-lg shadow-sm text-gray-700 focus:ring-2 focus:ring-purple-500 outline-none transition" value={e || ''} onChange={(e) => updateNodeContent(id, 'e', e.target.value.replace(/[^0-9]/g, ''))} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} /></label>
                            <label className="block"><span className="block text-[10px] font-semibold text-red-800 mb-0.5">D (Private Key)</span><input type="text" placeholder="Calculated D" className="w-full text-[10px] p-1 border border-gray-200 rounded-lg shadow-sm text-gray-700 focus:ring-2 focus:ring-red-800 outline-none transition" value={d || ''} onChange={(e) => updateNodeContent(id, 'd', e.target.value.replace(/[^0-9]/g, ''))} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} /></label>
                        </div>
                        <button onClick={(e) => { e.stopPropagation(); updateNodeContent(id, 'generateKey', true); }} className={`w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md ${isProcessing ? 'bg-yellow-500 animate-pulse' : 'bg-purple-600 hover:bg-purple-700'} flex-shrink-0`} disabled={isProcessing}><Key className="w-4 h-4" /><span>{isProcessing ? 'Generating...' : 'Generate Keys'}</span></button>
                        <div className="relative w-full text-left flex-grow">
                            <span className={`block text-[10px] font-semibold text-red-800 mb-0.5`}>PRIVATE KEY D OUTPUT (d)</span>
                            <div className={`text-[10px] p-1 bg-gray-100 rounded border h-full overflow-y-auto break-all ${dStatus?.startsWith('INCORRECT') || dStatus?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                                <p>D: {dataOutputPrivate || 'N/A'}</p>
                                <p className="mt-1 font-bold italic text-gray-700">Status: {dStatus || 'Idle'}</p>
                            </div>
                        </div>
                    </div>
                )}

                {/* Simplified renders for other nodes to save space in the component - core logic is identical to original app */}
                {!isDataInput && !isOutputViewer && !isCaesarCipher && !isSimpleRSAKeyGen && (
                    <div className="text-xs w-full text-center flex flex-col items-center flex-grow">
                        {/* Specific Controls per node type */}
                        {isVigenereCipher && (
                            <>
                                <input type="text" placeholder="Keyword" className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-1 flex-shrink-0 text-gray-700 focus:ring-2 focus:ring-yellow-500 outline-none transition" value={keyword || ''} onChange={(e) => updateNodeContent(id, 'keyword', e.target.value.toUpperCase().replace(/[^A-Z]/g, ''))} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} />
                                <select className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm bg-white cursor-pointer text-gray-700 focus:ring-2 focus:ring-yellow-500 outline-none transition" value={vigenereMode || 'ENCRYPT'} onChange={(e) => updateNodeContent(id, 'vigenereMode', e.target.value)} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()}>
                                    <option value="ENCRYPT">Encrypt (C = P + K)</option>
                                    <option value="DECRYPT">Decrypt (P = C - K)</option>
                                </select>
                            </>
                        )}
                        {isBitShift && (
                            <>
                                <input type="number" min="0" className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 flex-shrink-0 text-gray-700 focus:ring-2 focus:ring-indigo-500 outline-none transition" value={node.shiftAmount || 0} onChange={(e) => updateNodeContent(id, 'shiftAmount', parseInt(e.target.value) || 0)} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} />
                                <select className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 bg-white cursor-pointer text-gray-700 focus:ring-2 focus:ring-indigo-500 outline-none transition" value={node.shiftType || 'Left'} onChange={(e) => updateNodeContent(id, 'shiftType', e.target.value)} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()}>
                                    <option value="Left">Left Shift (ROL)</option>
                                    <option value="Right">Right Shift (ROR)</option>
                                </select>
                            </>
                        )}
                        {isKeyGen && (
                            <button onClick={(e) => { e.stopPropagation(); updateNodeContent(id, 'generateKey', true); }} className={`w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md ${isProcessing ? 'bg-yellow-500 animate-pulse' : 'bg-orange-500 hover:bg-orange-600'} flex-shrink-0`} disabled={isProcessing}><Key className="w-4 h-4" /><span>{isProcessing ? 'Generating...' : 'Generate Key'}</span></button>
                        )}
                        {isSimpleRSAPubKeyGen && (
                            <div className="w-full space-y-2">
                                <label className="block w-full flex-shrink-0">
                                    <span className="block text-[10px] font-semibold text-gray-600 mb-0.5">N (Modulus)</span>
                                    <input type="text" className={`w-full text-[10px] p-1 border rounded ${isReadOnly ? 'bg-gray-100' : 'bg-white'}`} value={n_pub || ''} onChange={(e) => updateNodeContent(id, 'n_pub', e.target.value.replace(/[^0-9]/g, ''))} readOnly={isReadOnly} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} />
                                </label>
                                <label className="block w-full flex-shrink-0">
                                    <span className="block text-[10px] font-semibold text-gray-600 mb-0.5">E (Public Exponent)</span>
                                    <input type="text" className={`w-full text-[10px] p-1 border rounded ${isReadOnly ? 'bg-gray-100' : 'bg-white'}`} value={e_pub || ''} onChange={(e) => updateNodeContent(id, 'e_pub', e.target.value.replace(/[^0-9]/g, ''))} readOnly={isReadOnly} onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} />
                                </label>
                                <div className="relative w-full text-left flex-grow">
                                    <span className={`block text-[10px] font-semibold text-lime-600 mb-0.5`}>PUBLIC KEY (N, E) OUTPUT</span>
                                    <div className={`text-[10px] p-1 bg-gray-100 rounded border h-full overflow-y-auto break-all text-gray-800`}>
                                        <p>{dataOutputPublic || 'N/A'}</p>
                                    </div>
                                </div>
                            </div>
                        )}
                        {isDataConcat && (
                            <div className="w-full flex flex-col items-center">
                                <label className="flex items-center space-x-2 cursor-pointer mb-2">
                                    <input
                                        type="checkbox"
                                        className="form-checkbox h-3 w-3 text-teal-600 transition duration-150 ease-in-out"
                                        checked={interpretAsText || false}
                                        onChange={(e) => updateNodeContent(id, 'interpretAsText', e.target.checked)}
                                    />
                                    <span className="text-[10px] text-gray-600">Interpret inputs as Text</span>
                                </label>
                            </div>
                        )}

                        {/* Generic Output Area - for nodes NOT using custom output display logic above */}
                        {!isSimpleRSAPubKeyGen && (
                            <>
                                <span className={`font-semibold mt-2 ${isProcessing ? 'text-yellow-600' : 'text-gray-600'} flex-shrink-0`}>{isProcessing ? 'Processing...' : 'Active'}</span>
                                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                                    <p className={`text-left text-[10px] break-all p-1 bg-gray-100 rounded overflow-auto h-full ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                                        {dataOutput ? (dataOutput.length > 200 ? dataOutput.substring(0, 200) + '...' : dataOutput) : (chunk1 ? `Chunk 1: ${chunk1}\nChunk 2: ${chunk2}` : 'Waiting for input...')}
                                    </p>
                                    <button onClick={(e) => handleCopyToClipboard(e, dataOutput || chunk1)} disabled={!dataOutput && !chunk1} className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm bg-gray-400 hover:bg-gray-500`} title="Copy"><Clipboard className="w-3 h-3" /></button>
                                </div>
                            </>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};

export default DraggableBox;
