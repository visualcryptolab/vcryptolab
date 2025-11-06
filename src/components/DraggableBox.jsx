// src/components/DraggableBox.jsx
import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { X, Clipboard, Info, Key, CheckCheck, Signature } from 'lucide-react';
import { Port } from './Port';
import { 
    NODE_DEFINITIONS, NODE_DIMENSIONS, BORDER_CLASSES, HOVER_BORDER_CLASSES, 
    TEXT_ICON_CLASSES, HOVER_BORDER_TOOLBAR_CLASSES, PORT_VISUAL_OFFSET_PX, 
    PUBLIC_KEY_COLOR, PRIVATE_KEY_COLOR, INPUT_PORT_COLOR, OPTIONAL_PORT_COLOR, 
    OUTPUT_PORT_COLOR, SIGNATURE_COLOR 
} from '../constants/nodeDefinitions.js'; // Added .js extension
import { ALL_FORMATS, isContentCompatible } from '../crypto/utils.js'; // Added .js extension

/**
 * Renders a draggable, resizable node box with port interfaces and specific controls.
 */
export const DraggableBox = ({ 
    node, setPosition, canvasRef, handleConnectStart, handleConnectEnd, 
    connectingPort, updateNodeContent, connections, handleDeleteNode, 
    nodes, scale, handleResize, handleCopyToClipboard, copyStatus, setCopyStatus 
}) => {
  // Destructure node props and look up definition
  const { 
    id, label, position, type, color, content, format, dataOutput, dataOutputPublic, 
    dataOutputPrivate, viewFormat, isProcessing, hashAlgorithm, keyAlgorithm, 
    symAlgorithm, modulusLength, publicExponent, rsaParameters, asymAlgorithm, 
    convertedData, convertedFormat, isConversionExpanded, sourceFormat, rawInputData, 
    p, q, e, d, n, phiN, shiftKey, keyword, vigenereMode, dStatus, n_pub, e_pub, 
    isReadOnly, width, height, keyBase64, generateKey, shiftType, shiftAmount 
  } = node; 
  
  const definition = NODE_DEFINITIONS[type];
  
  const [isDragging, setIsDragging] = useState(false);
  const [isResizing, setIsResizing] = useState(false); 
  const boxRef = useRef(null);
  const offset = useRef({ x: 0, y: 0 });
  const resizeOffset = useRef({ x: 0, y: 0 }); 

  // Node specific flags
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
  
  const FORMATS = ALL_FORMATS;
  
  const isPortSource = connectingPort?.sourceId === id;
  
  // --- Drag/Resize Handlers (Copied/Refactored from App.jsx) ---
  
  const handleDragStart = useCallback((e) => {
    if (connectingPort || isResizing) return; 
    const interactiveTags = ['TEXTAREA', 'SELECT', 'OPTION', 'BUTTON', 'INPUT']; 
    if (e.target.tagName === 'DIV' && e.target.classList.contains('w-4') && e.target.classList.contains('h-4')) {
        return; 
    }
    if (interactiveTags.includes(e.target.tagName)) {
        return; 
    }

    const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
    const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);
    const canvas = canvasRef.current;
    
    if (boxRef.current && canvas) {
      const canvasRect = canvas.getBoundingClientRect();

      const unscaledMouseX = (clientX - canvasRect.left) / scale;
      const unscaledMouseY = (clientY - canvasRect.y) / scale;

      offset.current = {
        x: unscaledMouseX - position.x,
        y: unscaledMouseY - position.y,
      };
      
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

  const handleDragEnd = useCallback(() => {
    setIsDragging(false);
  }, []);
  
  const handleResizeStart = useCallback((e) => {
    e.stopPropagation(); 
    setIsResizing(true);
    
    const clientX = e.clientX || (e.touches?.[0]?.clientX ?? 0);
    const clientY = e.clientY || (e.touches?.[0]?.clientY ?? 0);
    
    const canvas = canvasRef.current.getBoundingClientRect();
    const unscaledMouseX = (clientX - canvas.left) / scale;
    const unscaledMouseY = (clientY - canvas.y) / scale;

    resizeOffset.current = {
        x: unscaledMouseX - (node.position.x + node.width),
        y: unscaledMouseY - (node.position.y + node.height),
    };
    
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

  const handleResizeEnd = useCallback(() => {
    setIsResizing(false);
  }, []);
  
  
  // --- Combined Global Event Listeners ---
  useEffect(() => {
    const globalHandleMove = (e) => {
        if (isDragging) {
            handleDragMove(e);
        } else if (isResizing) {
            handleResizeMove(e);
        }
    };
    
    const globalHandleUp = (e) => {
        if (isDragging) {
            handleDragEnd(e);
        } else if (isResizing) {
            handleResizeEnd(e);
        }
    };

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
    if (connectingPort) {
      handleConnectEnd(null); 
    }
    e.stopPropagation();
  }, [connectingPort, handleConnectEnd, isDragging, isResizing]);


  // --- Port Rendering Logic ---
  
  const renderInputPorts = () => {
    if (!definition.inputPorts || definition.inputPorts.length === 0) return null;
    
    const numPorts = definition.inputPorts.length;
    const nodeHeight = height; 
    const step = nodeHeight / (numPorts + 1); 

    return definition.inputPorts.map((portDef, index) => {
        const topPosition = (index + 1) * step;
        const portId = portDef.id;
        
        return (
            <div 
                key={portId}
                className="absolute -left-2 transform -translate-y-1/2 z-20"
                style={{ top: `${topPosition}px` }} 
            >
                <Port 
                    nodeId={id} 
                    type="input"
                    portId={portId} 
                    outputType={portDef.type} 
                    isConnecting={connectingPort}
                    onStart={handleConnectStart} 
                    onEnd={handleConnectEnd} 
                    title={`${portDef.name} (${portDef.mandatory ? 'Mandatory' : 'Optional'}) - Type: ${portDef.type}`}
                    isMandatory={portDef.mandatory}
                    nodes={nodes} 
                />
            </div>
        );
    });
  };

  const renderOutputPorts = () => {
    if (!definition.outputPorts || definition.outputPorts.length === 0) return null;
    
    const numPorts = definition.outputPorts.length;
    const nodeHeight = height; 
    const step = nodeHeight / (numPorts + 1); 

    return definition.outputPorts.map((portDef, index) => {
        const topPosition = (index + 1) * step;
        
        return (
            <div 
                key={portDef.name}
                className="absolute -right-2 transform -translate-y-1/2 z-20"
                style={{ top: `${topPosition}px` }} 
            >
                <Port 
                    nodeId={id} 
                    type="output"
                    portId={`${portDef.type}-${index}`} 
                    portIndex={index} 
                    outputType={portDef.type} 
                    isConnecting={connectingPort}
                    onStart={handleConnectStart}
                    onEnd={handleConnectEnd}
                    title={`${portDef.name} - Type: ${portDef.type}`}
                    isMandatory={true} 
                    nodes={nodes} 
                />
            </div>
        );
    });
  };
  
  // --- Class Lookups ---
  const iconTextColorClass = TEXT_ICON_CLASSES[color] || 'text-gray-600';

  let specificClasses = '';

  if (isPortSource) {
    specificClasses = `border-emerald-500 ring-4 ring-emerald-300 cursor-pointer animate-pulse transition duration-200`; 
  } else {
    specificClasses = `${BORDER_CLASSES[color]} ${HOVER_BORDER_CLASSES[color]} ${isDragging ? 'cursor-grabbing' : 'cursor-pointer hover:border-blue-500'}`;
  }
  
  if (isProcessing) {
     specificClasses = `border-yellow-500 ring-4 ring-yellow-300 animate-pulse transition duration-200`; 
  }
  
  const effectiveMinHeight = isOutputViewer && isConversionExpanded ? 280 : NODE_DIMENSIONS.minHeight;

  const baseClasses = 
    `h-auto flex flex-col justify-start items-center p-3 
    bg-white shadow-xl rounded-xl border-4 transition duration-150 ease-in-out 
    hover:shadow-2xl absolute select-none z-10`;
    
  // --- Dynamic Style Object ---
  const boxStyle = {
      left: `${position.x}px`,
      top: `${position.y}px`,
      width: `${width}px`,
      minHeight: `${effectiveMinHeight}px`,
      height: `${height}px`,
  };
  
  const contentHeightExcludingHeader = height - 50; 

  // --- Render ---
  return (
    <div
      ref={boxRef}
      id={id}
      className={`${baseClasses} ${specificClasses}`}
      style={boxStyle} 
      onMouseDown={handleDragStart} 
      onTouchStart={handleDragStart} 
      onClick={handleBoxClick} 
    >
      
      {/* Resizing Handle (Bottom Right Corner) */}
      <div 
          className="absolute bottom-0 right-0 w-4 h-4 rounded-tl-lg bg-gray-200 opacity-60 hover:opacity-100 transition duration-150 cursor-nwse-resize z-30"
          onMouseDown={handleResizeStart}
          onTouchStart={handleResizeStart}
          onClick={(e) => e.stopPropagation()}
          title="Resize"
      >
        <div className="w-1 h-1 bg-gray-600 absolute bottom-1 right-1"></div>
        <div className="w-1 h-1 bg-gray-600 absolute bottom-2 right-2"></div>
        <div className="w-1 h-1 bg-gray-600 absolute bottom-2 right-1"></div>
        <div className="w-1 h-1 bg-gray-600 absolute bottom-1 right-2"></div>
      </div>

      {/* Delete Button */}
      <button
        className="absolute top-1 right-1 p-1 rounded-full bg-gray-100 hover:bg-gray-200 text-gray-400 hover:text-gray-600 z-30 transition duration-150"
        onClick={(e) => {
            e.stopPropagation();
            handleDeleteNode(id);
        }}
        title="Delete Node"
      >
        <X className="w-3 h-3" />
      </button>

      {/* -------------------- PORTS -------------------- */}
      {renderInputPorts()}
      {renderOutputPorts()} 

      {/* -------------------- CONTENT -------------------- */}
      <div 
          className="flex flex-col w-full justify-start items-center overflow-hidden" 
          style={{ height: `${contentHeightExcludingHeader}px` }}
      >
        {/* Top Section: Icon and Main Label */}
        <div className="flex flex-col justify-start items-center w-full flex-shrink-0 mb-2">
          {definition.icon && typeof definition.icon === 'function' ? (
              <definition.icon className={`w-6 h-6 ${iconTextColorClass} mb-1`} />
          ) : (
              definition.icon && <definition.icon className={`w-6 h-6 ${iconTextColorClass} mb-1`} />
          )}
          <span className={`text-${isDataInput ? 'base' : 'lg'} font-bold text-gray-800 text-center leading-tight`}>{label}</span>
          
          {isCaesarCipher && <span className={`text-xs text-gray-500 mt-1`}>k = {shiftKey || 0}</span>}
          {isVigenereCipher && <span className={`text-xs text-gray-500 mt-1`}>Keyword: {keyword || 'None'}</span>}
          {isSimpleRSASign && <span className={`text-xs text-gray-500 mt-1`}>Signing (m^d mod n)</span>}
          {isSimpleRSAVerify && <span className={`text-xs text-gray-500 mt-1`}>Verifying (s^e mod n)</span>}
          {isSimpleRSAEnc && <span className={`text-xs text-gray-500 mt-1`}>Encryption: (c = m^e mod n)</span>}
          {isSimpleRSADec && <span className={`text-xs text-gray-500 mt-1`}>Decryption: (m = c^d mod n)</span>}

          {isHashFn && (
              <div className="text-xs w-full text-center flex flex-col items-center">
                  <span className={`text-[10px] font-semibold text-gray-600 mb-1`}>ALGORITHM</span>
                  <select
                      className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 bg-white appearance-none cursor-pointer text-gray-700 focus:ring-2 focus:ring-gray-500 focus:border-gray-500 outline-none transition duration-200"
                      value={hashAlgorithm || 'SHA-256'}
                      onChange={(e) => updateNodeContent(id, 'hashAlgorithm', e.target.value)}
                      onMouseDown={(e) => e.stopPropagation()}
                      onTouchStart={(e) => e.stopPropagation()}
                      onClick={(e) => e.stopPropagation()}
                  >
                      {['SHA-256', 'SHA-512'].map(alg => (
                          <option key={alg} value={alg}>{alg}</option>
                      ))}
                  </select>
              </div>
          )}
          {isKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({keyAlgorithm})</span>}
          {isSimpleRSAKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({modulusLength} bits)</span>}
          {isRSAKeyGen && <span className={`text-xs text-gray-500 mt-1`}>({node.keyAlgorithm} {modulusLength} bits, e={publicExponent})</span>}
          {isBitShift && <span className={`text-xs text-gray-500 mt-1`}>({isProcessing ? 'Processing' : 'Bit Shift'})</span>}
          {isSimpleRSAPubKeyGen && <span className={`text-xs text-gray-500 mt-1`}>Public Key Output</span>} 
        </div>
        
        {isDataInput && (
          <div className="w-full flex flex-col items-center flex-grow">
            <textarea
              className="w-full text-xs p-2 border border-gray-200 rounded-lg shadow-md resize-y flex-grow mb-2 placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Enter data here..."
              value={content || ''}
              onChange={(e) => {
                  const newContent = e.target.value;
                  const currentFormat = node.format;
                  let newFormat = currentFormat;
                  
                  const formatsByRestrictiveness = ['Binary', 'Decimal', 'Hexadecimal', 'Base64', 'Text (UTF-8)'];
                  
                  if (!isContentCompatible(newContent, currentFormat)) {
                       let detectedFormat = 'Text (UTF-8)'; 
                       for (const formatCheck of formatsByRestrictiveness) {
                            if (isContentCompatible(newContent, formatCheck)) {
                                detectedFormat = formatCheck;
                                break; 
                            }
                       }
                       newFormat = detectedFormat;
                  }
                  
                  if (newFormat !== currentFormat) {
                      updateNodeContent(id, 'format', newFormat);
                  }
                  
                  updateNodeContent(id, 'content', newContent);
              }}
              onMouseDown={(e) => e.stopPropagation()} 
              onTouchStart={(e) => e.stopPropagation()} 
              onClick={(e) => e.stopPropagation()}
            />
            <select
              className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm flex-shrink-0 bg-white appearance-none cursor-pointer text-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              value={format || 'Text (UTF-8)'}
              onChange={(e) => {
                e.stopPropagation();
                const selectedFormat = e.target.value;
                const currentContent = content || '';
                let finalFormat = selectedFormat;

                if (!isContentCompatible(currentContent, selectedFormat)) {
                    const formatsByRestrictiveness = ['Binary', 'Decimal', 'Hexadecimal', 'Base64', 'Text (UTF-8)'];
                    for (const formatCheck of formatsByRestrictiveness) {
                        if (isContentCompatible(currentContent, formatCheck)) {
                            finalFormat = formatCheck;
                            break;
                        }
                    }
                    if (finalFormat !== selectedFormat) {
                        console.warn(`Content incompatible with ${selectedFormat}. Reverted to compatible format: ${finalFormat}`);
                    }
                }

                updateNodeContent(id, 'format', finalFormat);
              }}
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
            <div className="w-full mt-1 flex flex-col items-center flex-grow text-xs text-gray-700 bg-gray-50 p-2 border border-gray-200 rounded-lg shadow-inner overflow-y-auto">
                <span className="text-center font-bold text-red-600 mb-1 flex-shrink-0">RAW INPUT DATA</span>
                
                <div className="w-full mb-1 flex-shrink-0">
                    <label className="block text-left text-[10px] font-semibold text-gray-600 mb-0.5">Source Data Type</label>
                    <select
                        className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm bg-gray-100 cursor-default text-gray-700 appearance-none pointer-events-none"
                        value={sourceFormat || 'N/A'}
                        onChange={() => {}}
                        onMouseDown={(e) => e.stopPropagation()}
                        onClick={(e) => e.stopPropagation()}
                        disabled
                    >
                        <option>{sourceFormat || 'N/A'}</option>
                    </select>
                </div>

                <div 
                    className={`relative w-full break-all text-[10px] leading-tight text-gray-800 bg-white p-1 rounded-md mb-2 overflow-y-auto border border-gray-200`}
                    style={{ flexGrow: isConversionExpanded ? 0.5 : 1 }}
                >
                    <p>{rawInputData || 'Not connected or no data.'}</p>
                    
                    <button
                        onClick={(e) => handleCopyToClipboard(e, rawInputData, setCopyStatus)}
                        disabled={!rawInputData || rawInputData.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm 
                                    ${rawInputData && !rawInputData.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>

                <button
                    onClick={(e) => { 
                        e.stopPropagation();
                        updateNodeContent(id, 'isConversionExpanded', !isConversionExpanded);
                    }}
                    className={`mt-1 w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md bg-red-500 hover:bg-red-600 flex-shrink-0`}
                >
                    <span>{isConversionExpanded ? 'Hide Conversion' : 'Convert Type'}</span>
                </button>


                {isConversionExpanded && (
                    <div className="w-full mt-2 pt-2 border-t border-gray-200 flex flex-col space-y-2 flex-grow">
                        <span className="text-center font-bold text-red-600 text-[10px] flex-shrink-0">CONVERTED VIEW</span>

                        <div 
                            className="relative w-full break-all text-[10px] leading-tight text-gray-800 bg-white p-1 rounded-md mb-2 overflow-y-auto border border-gray-200"
                            style={{ flexGrow: 1 }}
                        >
                            <p>{convertedData || 'Select conversion type...'}</p>

                            <button
                                onClick={(e) => handleCopyToClipboard(e, convertedData, setCopyStatus)}
                                disabled={!convertedData || convertedData.startsWith('ERROR')}
                                className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                             ${convertedData && !convertedData.startsWith('ERROR')
                                                 ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                                 : 'bg-gray-300 cursor-not-allowed'}`}
                                title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                            >
                                <Clipboard className="w-3 h-3" />
                            </button>
                        </div>

                        <select
                            className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm flex-shrink-0 bg-white appearance-none cursor-pointer text-gray-700 focus:ring-2 focus:ring-red-500 focus:border-red-500 outline-none transition duration-200"
                            value={convertedFormat || 'Base64'}
                            onChange={(e) => updateNodeContent(id, 'convertedFormat', e.target.value)}
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
            </div>
        )}

        {isCaesarCipher && (
            <div className="text-xs w-full text-center flex flex-col items-center flex-grow">
                <span className={`text-[10px] font-semibold text-gray-600 mb-1 flex-shrink-0`}>SHIFT KEY (k)</span>
                <input
                    type="number"
                    min="0"
                    max="25"
                    step="1"
                    className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 flex-shrink-0 text-gray-700 focus:ring-2 focus:ring-amber-500 focus:border-amber-500 outline-none transition duration-200"
                    value={shiftKey || 0}
                    onChange={(e) => updateNodeContent(id, 'shiftKey', parseInt(e.target.value) || 0)}
                    onMouseDown={(e) => e.stopPropagation()} 
                    onTouchStart={(e) => e.stopPropagation()} 
                    onClick={(e) => e.stopPropagation()}
                />
                
                <span className={`font-semibold mt-2 ${isProcessing ? 'text-yellow-600' : 'text-amber-600'} flex-shrink-0`}>
                    {isProcessing ? 'Encrypting...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                    <p className={`text-left text-[10px] break-all p-2 bg-gray-100 rounded overflow-auto h-full ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                        {dataOutput ? `Result (${node.outputFormat}): ${dataOutput}` : 'Waiting for Plaintext...'}
                    </p>
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput, setCopyStatus)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR') && node.outputFormat === 'Text (UTF-8)' 
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
            </div>
        )}

        {isVigenereCipher && (
             <div className="text-xs w-full text-center flex flex-col items-center flex-grow">
                <span className={`text-[10px] font-semibold text-gray-600 mb-1 flex-shrink-0`}>KEYWORD (A-Z only)</span>
                <input
                    type="text"
                    placeholder="Keyword"
                    className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-1 flex-shrink-0 text-gray-700 focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 outline-none transition duration-200"
                    value={keyword || ''}
                    onChange={(e) => updateNodeContent(id, 'keyword', e.target.value.toUpperCase().replace(/[^A-Z]/g, ''))} 
                    onMouseDown={(e) => e.stopPropagation()} 
                    onTouchStart={(e) => e.stopPropagation()} 
                    onClick={(e) => e.stopPropagation()}
                />

                <div className="w-full mb-2 flex-shrink-0">
                    <label className="block text-left text-[10px] font-semibold text-gray-600 mb-0.5">OPERATION MODE</label>
                    <select
                        className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm bg-white appearance-none cursor-pointer text-gray-700 focus:ring-2 focus:ring-yellow-500 outline-none transition duration-200"
                        value={vigenereMode || 'ENCRYPT'}
                        onChange={(e) => updateNodeContent(id, 'vigenereMode', e.target.value)}
                        onMouseDown={(e) => e.stopPropagation()} 
                        onClick={(e) => e.stopPropagation()}
                    >
                        <option value="ENCRYPT">Encrypt (C = P + K)</option>
                        <option value="DECRYPT">Decrypt (P = C - K)</option>
                    </select>
                </div>
                
                <span className={`font-semibold mt-2 ${isProcessing ? 'text-yellow-600' : 'text-yellow-600'} flex-shrink-0`}>
                    {isProcessing ? 'Processing...' : `Active (${vigenereMode})`}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                    <p className={`text-left text-[10px] break-all p-2 bg-gray-100 rounded overflow-auto h-full ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                        {dataOutput ? `Result (${node.outputFormat}): ${dataOutput}` : 'Waiting for Data and Keyword...'}
                    </p>
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput, setCopyStatus)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR') && node.outputFormat === 'Text (UTF-8)' 
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
            </div>
        )}

        {isHashFn && (
            <div className="text-xs w-full text-center flex flex-col items-center flex-grow">
                <span className={`font-semibold mt-2 ${isProcessing ? 'text-yellow-600' : 'text-gray-600'} flex-shrink-0`}>
                    {isProcessing ? 'Calculating Hash...' : 'Active'}
                </span>
                
                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                    <p className={`text-left text-[10px] break-all p-1 bg-gray-100 rounded overflow-y-auto h-full ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                        {dataOutput ? `Hash (${node.outputFormat}): ${dataOutput}` : 'Waiting for Data Input...'}
                    </p>
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput, setCopyStatus)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
            </div>
        )}

        {isKeyGen && (
            <div className="text-xs w-full text-center flex flex-col items-center flex-grow">
                <span className={`text-[10px] font-semibold text-gray-600 mb-2 flex-shrink-0`}>ALGORITHM ({keyAlgorithm} 256-bit)</span>
                
                <button
                    onClick={(e) => { e.stopPropagation(); updateNodeContent(id, 'generateKey', true); }}
                    className={`w-full flex items-center justify-center space-x-2 py-1.5 px-3 rounded-lg text-white font-semibold transition duration-150 text-xs shadow-md 
                                ${isProcessing ? 'bg-yellow-500 animate-pulse' : 'bg-orange-500 hover:bg-orange-600'} flex-shrink-0`}
                    disabled={isProcessing}
                >
                    <Key className="w-4 h-4" />
                    <span>{isProcessing ? 'Generating Key...' : 'Generate New Key'}</span>
                </button>
                
                <span className={`font-semibold mt-4 ${dataOutput && !dataOutput.startsWith('ERROR') ? 'text-orange-600' : 'text-gray-500'} flex-shrink-0`}>
                    {dataOutput && !dataOutput.startsWith('ERROR') ? 'Key Ready' : 'Key Not Generated'}
                </span>

                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                    <p className={`text-left text-[10px] break-all p-1 bg-gray-100 rounded overflow-y-auto h-full ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                        {keyBase64 ? `Key (Base64): ${keyBase64}` : 'Waiting for generation...'}
                    </p>
                    <button
                        onClick={(e) => handleCopyToClipboard(e, keyBase64, setCopyStatus)}
                        disabled={!keyBase64 || keyBase64.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${keyBase64 && !keyBase64.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
            </div>
        )}
        
        {isSymEnc && (
             <div className="text-xs w-full text-center flex flex-col flex-grow">
                <span className={`text-[10px] font-semibold text-gray-600 mb-1 flex-shrink-0`}>ALGORITHM</span>
                <select
                    className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 flex-shrink-0 bg-white appearance-none cursor-pointer text-gray-700 focus:ring-2 focus:ring-red-500 focus:border-red-500 outline-none transition duration-200"
                    value={symAlgorithm || 'AES-GCM'}
                    onChange={(e) => updateNodeContent(id, 'symAlgorithm', e.target.value)}
                    onMouseDown={(e) => e.stopPropagation()}
                    onTouchStart={(e) => e.stopPropagation()}
                    onClick={(e) => e.stopPropagation()}
                >
                    {['AES-GCM'].map(alg => (
                        <option key={alg} value={alg}>{alg} (256-bit)</option>
                    ))}
                </select>
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-red-600'} flex-shrink-0`}>
                    {isProcessing ? 'Encrypting...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                    <p className={`text-left text-[10px] break-all p-1 bg-gray-100 rounded overflow-y-auto h-full ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                        {dataOutput ? `Ciphertext (Base64): ${dataOutput}` : 'Waiting for Data and Key...'}
                    </p>
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput, setCopyStatus)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
            </div>
        )}

        {isSymDec && (
             <div className="text-xs w-full text-center flex flex-col flex-grow">
                <span className={`text-[10px] font-semibold text-gray-600 mb-1 flex-shrink-0`}>ALGORITHM</span>
                <select
                    className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 flex-shrink-0 bg-white appearance-none cursor-pointer text-gray-700 focus:ring-2 focus:ring-pink-500 focus:border-pink-500 outline-none transition duration-200"
                    value={symAlgorithm || 'AES-GCM'}
                    onChange={(e) => updateNodeContent(id, 'symAlgorithm', e.target.value)}
                    onMouseDown={(e) => e.stopPropagation()}
                    onTouchStart={(e) => e.stopPropagation()}
                    onClick={(e) => e.stopPropagation()}
                >
                    {['AES-GCM'].map(alg => (
                        <option key={alg} value={alg}>{alg} (256-bit)</option>
                    ))}
                </select>
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-pink-600'} flex-shrink-0`}>
                    {isProcessing ? 'Decrypting...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                    <p className={`text-left text-[10px] break-all p-1 bg-gray-100 rounded overflow-y-auto h-full ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'}`}>
                        {dataOutput ? `Plaintext (UTF-8): ${dataOutput}` : 'Waiting for Cipher and Key...'}
                    </p>
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput, setCopyStatus)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
            </div>
        )}

        {isSimpleRSAEnc && (
             <div className="text-xs w-full text-center flex flex-col flex-grow">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-gray-600'} flex-shrink-0`}>
                    {isProcessing ? 'Encrypting (m^e mod n)...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded overflow-y-auto h-full">
                        {dataOutput ? `Ciphertext (c): ${dataOutput}` : 'Waiting for m and Public Key...'}
                    </p>
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput, setCopyStatus)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
                <span className="text-[10px] text-gray-500 mt-2 flex-shrink-0">Input/Output are Decimal Numbers.</span>
            </div>
        )}

        {isSimpleRSADec && (
             <div className="text-xs w-full text-center flex flex-col flex-grow">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-gray-600'} flex-shrink-0`}>
                    {isProcessing ? 'Decrypting (c^d mod n)...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded overflow-y-auto h-full">
                        {dataOutput ? `Plaintext (m): ${dataOutput}` : 'Waiting for c and Private Key...'}
                    </p>
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput, setCopyStatus)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
                <span className="text-[10px] text-gray-500 mt-2 flex-shrink-0">Input/Output are Decimal Numbers.</span>
            </div>
        )}

        {isSimpleRSASign && (
             <div className="text-xs w-full text-center flex flex-col flex-grow">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-fuchsia-600'} flex-shrink-0`}>
                    {isProcessing ? 'Signing...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded overflow-y-auto h-full">
                        {dataOutput ? `Signature (s): ${dataOutput}` : 'Waiting for m and Private Key...'}
                    </p>
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput, setCopyStatus)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
                <span className="text-[10px] text-gray-500 mt-2 flex-shrink-0">Input/Output are Decimal Numbers.</span>
            </div>
        )}

        {isSimpleRSAVerify && (
             <div className="text-xs w-full text-center flex flex-col flex-grow">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-fuchsia-600'} flex-shrink-0`}>
                    {isProcessing ? 'Verifying...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                    <p className={`text-left text-[10px] break-all p-1 rounded overflow-auto h-full 
                                     ${dataOutput?.includes('SUCCESS') ? 'bg-green-100 text-green-700 font-bold' : dataOutput?.includes('FAILURE') || dataOutput?.startsWith('ERROR') ? 'bg-red-100 text-red-700 font-bold' : 'bg-gray-100 text-gray-800'}`}>
                        {dataOutput || 'Waiting for m, s, and Public Key...'}
                    </p>
                </div>
            </div>
        )}
        
        {type === 'XOR_OP' && (
             <div className="text-xs w-full text-center flex flex-col flex-grow">
                <span className={`font-semibold ${isProcessing ? 'text-yellow-600' : 'text-lime-600'} flex-shrink-0`}>
                    {isProcessing ? 'Calculating XOR...' : 'Active'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                    <p className="text-left text-[10px] break-all p-1 bg-gray-100 rounded overflow-y-auto h-full">
                        {dataOutput ? `Result (${node.outputFormat || 'Base64'}): ${dataOutput?.substring(0, 10) + '...'}` : 'Waiting for two data inputs...'}
                    </p>
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput, setCopyStatus)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
            </div>
        )}

        {isBitShift && (
             <div className="text-xs w-full text-center flex flex-col flex-grow">
                <span className={`text-[10px] font-semibold text-gray-600 mb-1 flex-shrink-0`}>SHIFT AMOUNT (BITS)</span>
                <input
                    type="number"
                    min="0"
                    className="w-full text-xs p-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 flex-shrink-0 text-gray-700 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition duration-200"
                    value={shiftAmount || 0}
                    onChange={(e) => updateNodeContent(id, 'shiftAmount', parseInt(e.target.value) || 0)}
                    onMouseDown={(e) => e.stopPropagation()} 
                    onTouchStart={(e) => e.stopPropagation()} 
                    onClick={(e) => e.stopPropagation()}
                />
                
                <span className={`text-[10px] font-semibold text-gray-600 mb-1 flex-shrink-0`}>SHIFT DIRECTION</span>
                <select
                    className="w-full text-xs px-2 py-1.5 border border-gray-200 rounded-lg shadow-sm mb-2 flex-shrink-0 bg-white appearance-none cursor-pointer text-gray-700 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition duration-200"
                    value={shiftType || 'Left'}
                    onChange={(e) => updateNodeContent(id, 'shiftType', e.target.value)}
                    onMouseDown={(e) => e.stopPropagation()}
                    onTouchStart={(e) => e.stopPropagation()}
                    onClick={(e) => e.stopPropagation()}
                >
                    <option value="Left">Left (&lt;&lt;)</option>
                    <option value="Right">Right (&gt;&gt;)</option>
                </select>

                <span className={`font-semibold mt-2 ${isProcessing ? 'text-yellow-600' : 'text-indigo-600'} flex-shrink-0`}>
                    {isProcessing ? 'Shifting...' : 'Active (Single Number Mode)'}
                </span>
                <div className="relative mt-1 text-gray-500 break-all w-full flex-grow">
                    <p className={`text-left text-[10px] break-all p-1 bg-gray-100 rounded ${dataOutput?.startsWith('ERROR') ? 'text-red-600 font-bold' : 'text-gray-800'} overflow-y-auto h-full`}>
                        {dataOutput ? `Result (${node.outputFormat || 'N/A'}): ${dataOutput?.substring(0, 10) + '...'}` : 'Waiting for single numeric input...'}
                    </p>
                    <button
                        onClick={(e) => handleCopyToClipboard(e, dataOutput, setCopyStatus)}
                        disabled={!dataOutput || dataOutput.startsWith('ERROR')}
                        className={`absolute top-1 right-1 p-1 rounded-full text-white font-semibold transition duration-150 text-xs shadow-sm
                                    ${dataOutput && !dataOutput.startsWith('ERROR')
                                        ? copyStatus === 'Copied!' ? 'bg-green-500 hover:bg-green-600' : 'bg-gray-400 hover:bg-gray-500'
                                        : 'bg-gray-300 cursor-not-allowed'}`}
                        title={copyStatus === 'Copied!' ? 'Copied!' : 'Copy to Clipboard'}
                    >
                        <Clipboard className="w-3 h-3" />
                    </button>
                </div>
            </div>
        )}

        {!isDataInput && !isOutputViewer && !isHashFn && !isKeyGen && !isSymEnc && !isSymDec && !isRSAKeyGen && !isAsymEnc && !isAsymDec && type !== 'XOR_OP' && !isBitShift && !isSimpleRSAKeyGen && !isSimpleRSAPubKeyGen && !isSimpleRSAEnc && !isSimpleRSADec && !isCaesarCipher && !isVigenereCipher && !isSimpleRSASign && !isSimpleRSAVerify && (
            <div className="text-xs text-gray-500 mt-2">
                <p>Output: {dataOutput ? dataOutput.substring(0, 10) + '...' : 'Waiting for connection'}</p>
            </div>
        )}
      </div>
    </div>
  );
};