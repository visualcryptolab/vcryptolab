// src/App.jsx
import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { X, Clipboard } from 'lucide-react'; 

// --- Imports from modular files ---
import { Toolbar } from './components/Toolbar';
import { DraggableBox } from './components/DraggableBox';
import { 
    NODE_DEFINITIONS, INITIAL_NODES, INITIAL_CONNECTIONS, NODE_DIMENSIONS, 
    PORT_VISUAL_OFFSET_PX
} from './constants/nodeDefinitions.js'; // Added .js extension
import { 
    modPow, generateSmallPrimes, generateSmallE, modInverse, 
    caesarEncrypt, vigenereEncryptDecrypt, calculateHash, 
    generateSymmetricKey, symmetricEncrypt, symmetricDecrypt, 
    generateAsymmetricKeyPair, asymmetricEncrypt, asymmetricDecrypt,
    convertToUint8Array, convertDataFormat, getOutputFormat, 
    performBitwiseXor, stringToBigInt, performBitShiftOperation, 
    HASH_ALGORITHMS, SYM_ALGORITHMS, ASYM_ALGORITHMS, isContentCompatible
} from './crypto/utils.js'; // Added .js extension

// --- CSS Styles (Consolidated from src/App.css, src/main.css, and src/styles.css) ---
const globalStyles = `
/* Styles from src/main.css and src/styles.css (Tailwind directives) */
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Styles from src/App.css */
html, body, #root { 
  height: 100%;
  margin: 0;
  padding: 0;
}

@keyframes animate-pulse-slow {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}
.animate-pulse-slow {
    animation: animate-pulse-slow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}
.connection-line-visible {
    stroke: #059669; /* Emerald 600 */
    stroke-width: 4;
    fill: none;
    pointer-events: none; /* Invisible to mouse, only the hitbox is active */
}
.connection-hitbox {
    stroke: transparent;
    stroke-width: 15; /* Large clickable area */
    fill: none;
    cursor: pointer;
    pointer-events: stroke; /* Only sensitive to stroke clicks */
}
.connection-hitbox:hover {
    stroke: rgba(248, 113, 129, 0.5); /* Semi-transparent red on hover */
}
`;

// =================================================================
// 1. CORE GRAPH LOGIC (Recalculation, Connections, Drag/Resize)
// =================================================================

/**
 * Calculates the SVG path for the line connecting two specific ports.
 */
const getLinePath = (sourceNode, targetNode, connection) => {
    const sourceDef = NODE_DEFINITIONS[sourceNode.type];
    const targetDef = NODE_DEFINITIONS[targetNode.type];
    
    // 1. Calculate vertical position based on port index and node height
    const getVerticalPosition = (nodeDef, index, isInput, nodeHeight) => {
        const numPorts = isInput ? nodeDef.inputPorts.length : nodeDef.outputPorts.length;
        const step = nodeHeight / (numPorts + 1); 
        return (index + 1) * step;
    };

    // Calculate vertical position for Source Output Port
    const sourceVerticalPos = getVerticalPosition(sourceDef, connection.sourcePortIndex, false, sourceNode.height);
    
    // Find the index of the targetPortId in the target node's inputPorts array
    const targetPortIndex = targetDef.inputPorts.findIndex(p => p.id === connection.targetPortId);
    // Calculate vertical position for Target Input Port
    const targetVerticalPos = getVerticalPosition(targetDef, targetPortIndex, true, targetNode.height);

    // P1: Source connection point 
    const p1 = { 
      x: sourceNode.position.x + sourceNode.width + PORT_VISUAL_OFFSET_PX, 
      y: sourceNode.position.y + sourceVerticalPos 
    }; 
    
    // P2: Target connection point
    const p2 = { 
      x: targetNode.position.x - PORT_VISUAL_OFFSET_PX, 
      y: targetNode.position.y + targetVerticalPos
    }; 
    
    // Use a smooth Bezier curve
    const midX = (p1.x + p2.x) / 2;
    
    return `M${p1.x} ${p1.y} C${midX} ${p1.y}, ${midX} ${p2.y}, ${p2.x} ${p2.y}`;
};


// --- Core Data Flow Engine ---

const recalculateGraph = (currentNodes, currentConnections, changedNodeId = null, setNodes) => {
    // Re-initialize newNodesMap correctly to ensure integrity and reset calculation fields.
    const newNodesMap = new Map(currentNodes.map(n => {
        const newNode = { ...n };
        newNode.isProcessing = false;
        if (newNode.type === 'OUTPUT_VIEWER') {
             newNode.convertedData = newNode.convertedData || ''; 
             newNode.convertedFormat = newNode.convertedFormat || 'Base64';
             newNode.isConversionExpanded = newNode.isConversionExpanded || false;
             newNode.sourceFormat = newNode.sourceFormat || ''; 
             newNode.rawInputData = newNode.rawInputData || ''; 
        }
        return [n.id, newNode];
    })); 
    
    // --- Step 0: Identify nodes to process based on inputs/triggers ---
    
    let initialQueue = new Set(currentNodes.filter(n => {
        const def = NODE_DEFINITIONS[n.type];
        return def && def.inputPorts && def.inputPorts.length === 0;
    }).map(n => n.id));
    
    if (changedNodeId) {
        initialQueue.add(changedNodeId);
    }
    
    let nodesToProcess = Array.from(initialQueue);
    const processed = new Set();
    
    const findAllTargets = (sourceId) => {
        return currentConnections
            .filter(c => c.source === sourceId)
            .map(c => c.target)
            .filter(targetId => !processed.has(targetId));
    };

    // --- Step 1: Process nodes synchronously (Key generation, Data input, Crypto operations) ---
    while (nodesToProcess.length > 0) {
        const sourceId = nodesToProcess.shift();
        if (processed.has(sourceId) || !newNodesMap.has(sourceId)) continue; 

        const sourceNode = newNodesMap.get(sourceId);
        const sourceNodeDef = NODE_DEFINITIONS[sourceNode.type];

        let outputData = sourceNode.dataOutput || '';
        let isProcessing = false;
        
        // --- 1.1 Source Nodes (No input ports) ---
        if (sourceNodeDef.inputPorts.length === 0) {
            
            if (sourceNode.type === 'DATA_INPUT') {
                outputData = sourceNode.content || ''; 
            } else if (sourceNode.type === 'KEY_GEN') {
                const algorithm = sourceNode.keyAlgorithm || SYM_ALGORITHMS[0];

                if (sourceNode.generateKey || !sourceNode.keyBase64) {
                    isProcessing = true;
                    generateSymmetricKey(algorithm).then(({ keyBase64 }) => {
                        setNodes(prevNodes => prevNodes.map(n => 
                            n.id === sourceId 
                                ? { 
                                    ...n, 
                                    dataOutput: keyBase64,
                                    keyBase64: keyBase64,
                                    isProcessing: false, 
                                    generateKey: false 
                                  } 
                                : n
                        ));
                    }).catch(err => {
                         setNodes(prevNodes => prevNodes.map(n => 
                             n.id === sourceId 
                                 ? { ...n, dataOutput: `ERROR: Key generation failed. ${err.message}`, keyBase64: `ERROR: Key generation failed. ${err.message}`, isProcessing: false, generateKey: false } 
                                 : n
                         ));
                    });
                    
                    outputData = sourceNode.dataOutput || 'Generating Key...';
                    sourceNode.isProcessing = isProcessing;
                    sourceNode.generateKey = false;
                    newNodesMap.set(sourceId, sourceNode);
                    
                    processed.add(sourceId);
                    nodesToProcess.push(...findAllTargets(sourceId));
                    continue; 

                } else if (sourceNode.keyBase64) {
                    outputData = sourceNode.keyBase64; 
                    isProcessing = false;
                }
                
            } else if (sourceNode.type === 'RSA_KEY_GEN' || sourceNode.type === 'SIMPLE_RSA_KEY_GEN') { 
                
                 // Logic for Simple RSA Key Gen (Synchronous) is complex and kept here.
                 if (sourceNode.type === 'SIMPLE_RSA_KEY_GEN' && sourceNode.generateKey) {
                     isProcessing = true;
                     
                     const rawP = sourceNode.p;
                     const rawQ = sourceNode.q;
                     const rawE = sourceNode.e;
                     const userD = sourceNode.d && !isNaN(Number(sourceNode.d)) ? BigInt(sourceNode.d) : null; 

                     let p_val, q_val, e_val, d_val;
                     let n_val, phiN_val;
                     let error = null;
                     let d_status = ''; 

                     
                     try {
                        const userP = rawP && !isNaN(Number(rawP)) ? BigInt(rawP) : null;
                        const userQ = rawQ && !isNaN(Number(rawQ)) ? BigInt(rawQ) : null;
                        
                        if (userP && userQ && userP > BigInt(0) && userQ > BigInt(0)) {
                            p_val = userP;
                            q_val = userQ;
                        } else {
                            ({ p: p_val, q: q_val } = generateSmallPrimes());
                        }

                        n_val = p_val * q_val;
                        phiN_val = (p_val - BigInt(1)) * (q_val - BigInt(1)); 

                        const userE = rawE && !isNaN(Number(rawE)) ? BigInt(rawE) : null;
                        
                        if (userE && userE > BigInt(1) && userE < phiN_val && gcd(userE, phiN_val) === BigInt(1)) {
                            e_val = userE;
                        } else if (!userE || userE <= BigInt(0)) {
                            e_val = generateSmallE(phiN_val);
                        } else {
                            error = `ERROR: Invalid E (${userE.toString()}). Must be 1 < E < phi(n) and gcd(E, phi(n)) = 1.`;
                            throw new Error(error);
                        }
                         
                        const calculatedD = modInverse(e_val, phiN_val);
                        d_val = calculatedD; 
                         
                        if (userD && userD > BigInt(0)) {
                           if ((userD * e_val) % phiN_val === BigInt(1) && userD < phiN_val) {
                               d_status = `CORRECT (User input D: ${userD.toString()}). Using calculated value for consistency.`;
                           } else {
                               d_status = `INCORRECT (User input D: ${userD.toString()}). The correct value is: ${calculatedD.toString()}.`;
                           }
                        } else {
                            d_status = 'CORRECT (Calculated).';
                        }
                         
                     } catch (err) {
                         error = err.message.startsWith("ERROR") ? err.message : `ERROR: Calculation failed. ${err.message}`;
                     }
                     
                     if (!error) {
                         sourceNode.dataOutputPublic = `${n_val.toString()},${e_val.toString()}`; 
                         sourceNode.dataOutputPrivate = d_val.toString();
                         sourceNode.n = n_val.toString();
                         sourceNode.phiN = phiN_val.toString();
                         sourceNode.d = d_val.toString(); 
                         sourceNode.p = p_val.toString();
                         sourceNode.q = q_val.toString();
                         sourceNode.e = e_val.toString();
                         sourceNode.dStatus = d_status; 
                         
                         outputData = sourceNode.dataOutputPrivate; 
                         isProcessing = false;
                     } else {
                         outputData = error;
                         sourceNode.dataOutputPublic = outputData;
                         sourceNode.dataOutputPrivate = outputData;
                         sourceNode.n = ''; sourceNode.phiN = ''; 
                         sourceNode.p = rawP; 
                         sourceNode.q = rawQ;
                         sourceNode.e = rawE;
                         sourceNode.d = '';
                         sourceNode.dStatus = error;
                     }

                     sourceNode.isProcessing = isProcessing;
                     sourceNode.generateKey = false; 
                     newNodesMap.set(sourceId, sourceNode);
                     
                     processed.add(sourceId);
                     nodesToProcess.push(...findAllTargets(sourceId));
                     continue;

                 } else if (sourceNode.type === 'RSA_KEY_GEN' && (sourceNode.keyPairObject || sourceNode.generateKey)) {
                     // Advanced RSA Key Gen Logic (ASYNC)
                     isProcessing = true;
                     
                     if (!sourceNode.keyPairObject || sourceNode.generateKey) {
                          const algorithm = ASYM_ALGORITHMS[0]; 
                          const modulusLength = sourceNode.modulusLength || 2048;
                          const publicExponentToUse = sourceNode.publicExponent || 65537;
                          
                          generateAsymmetricKeyPair(algorithm, modulusLength, publicExponentToUse).then(({ publicKey, privateKey, keyPairObject, rsaParameters }) => {
                              setNodes(prevNodes => prevNodes.map(n => 
                                  n.id === sourceId 
                                      ? { 
                                          ...n, 
                                          dataOutputPublic: publicKey, 
                                          dataOutputPrivate: privateKey, 
                                          keyPairObject: keyPairObject, 
                                          rsaParameters: rsaParameters, 
                                          isProcessing: false, 
                                          generateKey: false 
                                        } 
                                      : n
                              ));
                          });
                          outputData = sourceNode.dataOutputPublic || 'Generating Keys...';
                     } else {
                         outputData = sourceNode.dataOutputPublic || '';
                         isProcessing = false;
                     }
                 } else if (sourceNode.type === 'RSA_KEY_GEN') {
                     outputData = 'Click "Generate RSA Key Pair"';
                 }
            }
        
        // --- 1.2 Processing/Sink Nodes (Have input ports) ---
        } else {
            const incomingConns = currentConnections.filter(c => c.target === sourceId);
            let inputs = {};
            
            // Step 1: Gather inputs and their formats from all upstream nodes
            incomingConns.forEach(conn => {
                const inputSourceNode = newNodesMap.get(conn.source);
                if (!inputSourceNode) return;

                let dataToUse;
                const sourceDef = NODE_DEFINITIONS[inputSourceNode.type];
                
                if (sourceDef && sourceDef.outputPorts.length > conn.sourcePortIndex) {
                    const keyField = sourceDef.outputPorts[conn.sourcePortIndex].keyField;
                    dataToUse = inputSourceNode[keyField];
                } else {
                    dataToUse = inputSourceNode.dataOutput; 
                }

                const sourceFormat = inputSourceNode.type === 'DATA_INPUT' 
                    ? inputSourceNode.format 
                    : (inputSourceNode.outputFormat || getOutputFormat(inputSourceNode.type)); 

                if (!inputs[conn.targetPortId]) { 
                    inputs[conn.targetPortId] = { 
                        data: dataToUse, 
                        format: sourceFormat,
                        nodeId: inputSourceNode.id
                    };
                }
            });
            
            // Step 2: Execute node logic 
            switch (sourceNode.type) {
                case 'OUTPUT_VIEWER':
                    const inputObj = inputs['data'];
                    const rawInput = inputObj?.data; 
                    let convertedDataOutput = sourceNode.convertedData || '';
                    let calculatedSourceFormat = inputObj?.format || 'N/A';
                    
                    if (rawInput !== undefined && rawInput !== null && rawInput !== '' && !rawInput?.startsWith('ERROR')) {
                        const isSourceBinary = ['Hexadecimal', 'Binary', 'Decimal', 'Base64'].includes(calculatedSourceFormat);
                        const isSLNTarget = ['Decimal', 'Hexadecimal', 'Binary'].includes(sourceNode.convertedFormat);
                        const shouldBeSingleNumber = isSLNTarget && isSourceBinary;

                        if (sourceNode.isConversionExpanded) {
                            convertedDataOutput = convertDataFormat(rawInput, calculatedSourceFormat, sourceNode.convertedFormat || 'Base64', shouldBeSingleNumber);
                        } else {
                            convertedDataOutput = '';
                        }
                        
                        if (sourceNode.isConversionExpanded && convertedDataOutput && !convertedDataOutput.startsWith('ERROR')) {
                            outputData = convertedDataOutput;
                            sourceNode.outputFormat = sourceNode.convertedFormat; 
                        } else {
                            outputData = rawInput;
                            sourceNode.outputFormat = calculatedSourceFormat === 'N/A' ? 'Text (UTF-8)' : calculatedSourceFormat; 
                        }

                    } else {
                        outputData = 'Not connected or no data.';
                        convertedDataOutput = '';
                        calculatedSourceFormat = 'N/A';
                        sourceNode.outputFormat = 'Text (UTF-8)'; 
                    }
                    
                    sourceNode.convertedData = convertedDataOutput;
                    sourceNode.sourceFormat = calculatedSourceFormat; 
                    sourceNode.rawInputData = rawInput || outputData; 
                    break;
                
                case 'CAESAR_CIPHER':
                    const plaintextInput = inputs['plaintext']?.data;
                    const plainFormat = inputs['plaintext']?.format;
                    const shiftKey = sourceNode.shiftKey; 
                    
                    if (plaintextInput !== undefined && plaintextInput !== null) {
                        isProcessing = true;
                        
                        const k = parseInt(shiftKey) || 0;
                        const { output, format } = caesarEncrypt(plaintextInput, plainFormat, k);
                        outputData = output;
                        sourceNode.outputFormat = format;
                        isProcessing = false;
                        
                    } else {
                        outputData = 'Waiting for plaintext input.';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    }
                    break;
                
                case 'VIGENERE_CIPHER':
                    const vigenereInput = inputs['data']?.data;
                    const vigenereFormat = inputs['data']?.format;
                    const keyword = sourceNode.keyword;
                    const mode = sourceNode.vigenereMode || 'ENCRYPT';

                    if (vigenereInput !== undefined && vigenereInput !== null) {
                        isProcessing = true;
                        
                        if (vigenereFormat !== 'Text (UTF-8)') {
                            outputData = `ERROR: Vigenère Cipher requires Text (UTF-8) input. Received: ${vigenereFormat}`;
                            sourceNode.outputFormat = vigenereFormat;
                            isProcessing = false;
                            break;
                        }

                        const { output, format } = vigenereEncryptDecrypt(vigenereInput, keyword, mode);
                        outputData = output;
                        sourceNode.outputFormat = format;
                        isProcessing = false;
                    } else {
                        outputData = 'Waiting for input data and keyword.';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    }
                    break;
                    
                case 'SIMPLE_RSA_PUBKEY_GEN':
                    const keySourceConn = incomingConns.find(c => c.targetPortId === 'keySource');
                    const sourceKeyGenNode = keySourceConn ? newNodesMap.get(keySourceConn.source) : null;
                    
                    let n_pub = sourceNode.n_pub;
                    let e_pub = sourceNode.e_pub;
                    let isReadOnly = false;

                    if (sourceKeyGenNode && sourceKeyGenNode.n && sourceKeyGenNode.e) {
                        n_pub = sourceKeyGenNode.n;
                        e_pub = sourceKeyGenNode.e;
                        isReadOnly = true;
                    } 
                    
                    sourceNode.isReadOnly = isReadOnly;
                    sourceNode.n_pub = n_pub;
                    sourceNode.e_pub = e_pub;

                    if (n_pub && e_pub) {
                        try {
                            BigInt(n_pub);
                            BigInt(e_pub);
                            sourceNode.dataOutputPublic = `${n_pub},${e_pub}`;
                        } catch (err) {
                            sourceNode.dataOutputPublic = `ERROR: Invalid N or E format. Must be numeric.`;
                        }
                    } else {
                        sourceNode.dataOutputPublic = 'N/A (Missing N or E input)';
                    }

                    outputData = sourceNode.dataOutputPublic;
                    break;
                    
                case 'SIMPLE_RSA_ENC':
                    try {
                        const mStr = inputs['message']?.data; 
                        const pkInputObj = inputs['publicKey'];
                        const pkSourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'publicKey');
                        const sourceNodeKeyGen = newNodesMap.get(pkSourceConn?.source);

                        let n, e;

                        if (sourceNodeKeyGen?.type === 'SIMPLE_RSA_PUBKEY_GEN' && sourceNodeKeyGen.n_pub && sourceNodeKeyGen.e_pub) {
                            n = BigInt(sourceNodeKeyGen.n_pub);
                            e = BigInt(sourceNodeKeyGen.e_pub);
                        } else if (pkInputObj?.data) {
                            const [nStr, eStr] = pkInputObj.data.split(',');
                            if (nStr && eStr) {
                                n = BigInt(nStr);
                                e = BigInt(eStr);
                            }
                        }

                        if (!mStr || !n || !e) {
                            outputData = 'Waiting for message (m) and Public Key (n, e).';
                            break;
                        }
                        
                        let mValue = mStr.replace(/\s+/g, '');
                        if (isNaN(Number(mValue))) {
                            outputData = `ERROR: Message must be a valid DECIMAL number. Received: ${mStr}`;
                            break;
                        }
                        
                        const m = BigInt(mValue);

                        if (m >= n) {
                            outputData = `ERROR: Message (m=${mStr}) must be less than Modulus (n=${n.toString()}).`;
                        } else {
                            isProcessing = true;
                            const c = modPow(m, e, n);
                            outputData = c.toString();
                            isProcessing = false;
                        }
                    } catch (err) {
                        outputData = `ERROR: Encryption failed. Check inputs are valid numbers. ${err.message}`;
                    }
                    break;
                
                case 'SIMPLE_RSA_DEC':
                    try {
                        const cStr = inputs['cipher']?.data;
                        const dStr = inputs['privateKey']?.data;
                        
                        if (isNaN(Number(cStr))) {
                            outputData = `ERROR: Ciphertext must be a valid number. Received: ${cStr}`;
                            break;
                        }
                        
                        const sourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'privateKey');
                        const sourceNodeKeyGen = newNodesMap.get(sourceConn?.source);
                        
                        if (!cStr || !dStr || !sourceNodeKeyGen || !sourceNodeKeyGen.n) {
                            outputData = 'Waiting for ciphertext (c) and Private Key (d, n).';
                            break;
                        }
                        
                        const c = BigInt(cStr);
                        const d = BigInt(dStr);
                        const n = BigInt(sourceNodeKeyGen.n);

                        isProcessing = true;
                        const m = modPow(c, d, n);
                        outputData = m.toString();
                        isProcessing = false;
                        
                    } catch (err) {
                         outputData = `ERROR: Decryption failed. Check if Private Key was generated correctly. ${err.message}`;
                    }
                    break;

                case 'SIMPLE_RSA_SIGN':
                    try {
                        const mStr = inputs['message']?.data;
                        const dStr = inputs['privateKey']?.data;

                        if (!mStr || !dStr) {
                             outputData = 'Waiting for message (m) and Private Key (d, n).';
                             break;
                        }
                        
                        let mValue = mStr.replace(/\s+/g, '');
                        if (isNaN(Number(mValue))) {
                            outputData = `ERROR: Message must be a valid DECIMAL number. Received: ${mStr}`;
                            break;
                        }
                        
                        const sourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'privateKey');
                        const sourceNodeKeyGen = newNodesMap.get(sourceConn?.source);

                        if (!sourceNodeKeyGen || !sourceNodeKeyGen.n) {
                            outputData = 'ERROR: Cannot find modulus (n). Ensure Private Key is connected from Simple RSA PrivKey Gen.';
                            break;
                        }

                        const m = BigInt(mValue);
                        const d = BigInt(dStr);
                        const n = BigInt(sourceNodeKeyGen.n);

                        isProcessing = true;
                        const s = modPow(m, d, n);
                        outputData = s.toString();
                        isProcessing = false;

                    } catch (err) {
                        outputData = `ERROR: Signature failed. Check inputs. ${err.message}`;
                    }
                    break;
                
                case 'SIMPLE_RSA_VERIFY':
                    try {
                        const mStr = inputs['message']?.data;
                        const sStr = inputs['signature']?.data;
                        const pkInputObj = inputs['publicKey'];
                        const pkSourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'publicKey');
                        const sourceNodeKeyGen = newNodesMap.get(pkSourceConn?.source);

                        let n, e;

                        if (sourceNodeKeyGen?.type === 'SIMPLE_RSA_PUBKEY_GEN' && sourceNodeKeyGen.n_pub && sourceNodeKeyGen.e_pub) {
                            n = BigInt(sourceNodeKeyGen.n_pub);
                            e = BigInt(sourceNodeKeyGen.e_pub);
                        } else if (pkInputObj?.data) {
                            const [nStr, eStr] = pkInputObj.data.split(',');
                            if (nStr && eStr) {
                                n = BigInt(nStr);
                                e = BigInt(eStr);
                            }
                        }

                        if (!mStr || !sStr || !n || !e) {
                            outputData = 'Waiting for message (m), signature (s), and Public Key (n, e).';
                            break;
                        }
                        
                        let mValue = mStr.replace(/\s+/g, '');
                        let sValue = sStr.replace(/\s+/g, '');
                        
                        if (isNaN(Number(mValue)) || isNaN(Number(sValue))) {
                            outputData = 'ERROR: Message and Signature must be valid DECIMAL numbers.';
                            break;
                        }

                        const m = BigInt(mValue);
                        const s = BigInt(sValue);
                        
                        isProcessing = true;
                        const decryptedM = modPow(s, e, n);
                        isProcessing = false;

                        if (decryptedM === m) {
                            outputData = `SUCCESS: Signature verified. Decrypted message m'=${decryptedM.toString()} equals original message m=${m.toString()}.`;
                        } else {
                            outputData = `FAILURE: Signature verification failed. Calculated m'=${decryptedM.toString()} does not equal original m=${m.toString()}.`;
                        }

                    } catch (err) {
                        outputData = `ERROR: Verification failed. Check inputs. ${err.message}`;
                    }
                    break;
                    
                case 'HASH_FN':
                    const hashInput = inputs['data']?.data;
                    if (hashInput && !hashInput.startsWith('ERROR')) { 
                        isProcessing = true; 
                        const algorithm = sourceNode.hashAlgorithm || HASH_ALGORITHMS[0];

                        calculateHash(hashInput, algorithm).then(hashResult => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: hashResult, isProcessing: false } : n));
                        });
                        outputData = sourceNode.dataOutput || 'Calculating...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                        
                        sourceNode.isProcessing = isProcessing;
                        newNodesMap.set(sourceId, sourceNode);
                        processed.add(sourceId);
                        nodesToProcess.push(...findAllTargets(sourceId));
                        continue; 

                    } else if (hashInput && hashInput.startsWith('ERROR')) {
                        outputData = hashInput;
                    } else {
                        outputData = 'Waiting for data input.'; 
                    }
                    break;
                
                case 'XOR_OP':
                    const dataInputA = inputs['dataA']?.data; 
                    const dataInputB = inputs['dataB']?.data; 
                    const formatA = inputs['dataA']?.format; 
                    const formatB = inputs['dataB']?.format;

                    if (dataInputA && dataInputB && !dataInputA.startsWith('ERROR') && !dataInputB.startsWith('ERROR')) { 
                        const bytesA = convertToUint8Array(dataInputA, formatA);
                        const bytesB = convertToUint8Array(dataInputB, formatB);

                        isProcessing = true; 
                        const base64Result = performBitwiseXor(bytesA, bytesB); 
                        let outputFormat = formatA; 
                        if (outputFormat === 'N/A' || outputFormat === 'Decimal') outputFormat = 'Base64'; 
                        
                        outputData = convertDataFormat(base64Result, 'Base64', outputFormat);
                        sourceNode.outputFormat = outputFormat; 
                        isProcessing = false; 
                    } else if (dataInputA?.startsWith('ERROR')) {
                        outputData = dataInputA;
                    } else if (dataInputB?.startsWith('ERROR')) {
                        outputData = dataInputB;
                    } else if (dataInputA && !dataInputB) {
                        outputData = 'Waiting for Input B.';
                        sourceNode.outputFormat = formatA || ''; 
                    } else if (!dataInputA && dataInputB) {
                        outputData = 'Waiting for Input A.';
                        sourceNode.outputFormat = formatB || ''; 
                    } else {
                        outputData = 'Waiting for two data inputs.'; 
                        sourceNode.outputFormat = '';
                    }
                    break;
                
                case 'SHIFT_OP':
                    const shiftDataInput = inputs['data']?.data;
                    const shiftFormat = inputs['data']?.format; 
                    const shiftType = sourceNode.shiftType || 'Left';
                    const shiftAmount = sourceNode.shiftAmount || 0;
                    
                    if (shiftDataInput && !shiftDataInput.startsWith('ERROR')) {
                        isProcessing = true;
                        
                        if (shiftFormat === 'Decimal' || shiftFormat === 'Hexadecimal' || shiftFormat === 'Binary') {
                            
                            outputData = performBitShiftOperation(shiftDataInput, shiftType, shiftAmount, shiftFormat);
                            sourceNode.outputFormat = shiftFormat;
                            
                        } else {
                            outputData = `ERROR: Bit Shift requires input data to be a single number (Decimal, Hexadecimal, or Binary). Received: ${shiftFormat}.`;
                            sourceNode.outputFormat = shiftFormat;
                        }

                        isProcessing = false; 
                    } else if (shiftDataInput?.startsWith('ERROR')) {
                         outputData = shiftDataInput;
                    } else { 
                        outputData = 'Waiting for data input.'; 
                        sourceNode.outputFormat = '';
                    }
                    break;

                case 'SYM_ENC':
                    if (inputs['data']?.data && inputs['key']?.data && !inputs['data'].data.startsWith('ERROR') && !inputs['key'].data.startsWith('ERROR')) {
                        isProcessing = true;
                        const algorithm = sourceNode.symAlgorithm || SYM_ALGORITHMS[0];
                        
                        symmetricEncrypt(inputs['data'].data, inputs['key'].data, algorithm).then(ciphertext => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: ciphertext, isProcessing: false } : n));
                        });
                        outputData = sourceNode.dataOutput || 'Encrypting...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                        
                        sourceNode.isProcessing = isProcessing;
                        newNodesMap.set(sourceId, sourceNode);
                        processed.add(sourceId);
                        nodesToProcess.push(...findAllTargets(sourceId));
                        continue; 

                    } else if (inputs['data']?.data?.startsWith('ERROR')) {
                        outputData = inputs['data'].data;
                    } else if (inputs['key']?.data?.startsWith('ERROR')) {
                        outputData = inputs['key'].data;
                    } else {
                        outputData = 'Waiting for Data and Key inputs.';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    }
                    break;
                
                case 'SYM_DEC':
                    if (inputs['cipher']?.data && inputs['key']?.data && !inputs['cipher'].data.startsWith('ERROR') && !inputs['key'].data.startsWith('ERROR')) {
                        isProcessing = true;
                        const algorithm = sourceNode.symAlgorithm || SYM_ALGORITHMS[0]; 
                        
                        symmetricDecrypt(inputs['cipher'].data, inputs['key'].data, algorithm).then(plaintext => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: plaintext, isProcessing: false } : n));
                        });
                        outputData = sourceNode.dataOutput || 'Decrypting...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                        
                        sourceNode.isProcessing = isProcessing;
                        newNodesMap.set(sourceId, sourceNode);
                        processed.add(sourceId);
                        nodesToProcess.push(...findAllTargets(sourceId));
                        continue; 
                        
                    } else if (inputs['cipher']?.data?.startsWith('ERROR')) {
                        outputData = inputs['cipher'].data;
                    } else if (inputs['key']?.data?.startsWith('ERROR')) {
                        outputData = inputs['key'].data;
                    } else {
                        outputData = 'Waiting for Cipher and Key inputs.';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    }
                    break;

                case 'ASYM_ENC':
                    if (inputs['data']?.data && inputs['publicKey']?.data) {
                        isProcessing = true;
                        const algorithm = sourceNode.asymAlgorithm || ASYM_ALGORITHMS[0];
                        asymmetricEncrypt(inputs['data'].data, inputs['publicKey'].data, algorithm).then(ciphertext => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: ciphertext, isProcessing: false } : n));
                        });
                        outputData = sourceNode.dataOutput || 'Encrypting...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    } else {
                        outputData = 'Waiting for Data and Public Key inputs.';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    }
                    break;
                
                case 'ASYM_DEC':
                    if (inputs['cipher']?.data && inputs['privateKey']?.data) {
                        isProcessing = true;
                        const algorithm = sourceNode.asymAlgorithm || ASYM_ALGORITHMS[0];
                        asymmetricDecrypt(inputs['cipher'].data, inputs['privateKey'].data, algorithm).then(plaintext => {
                            setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: plaintext, isProcessing: false } : n));
                        });
                        outputData = sourceNode.dataOutput || 'Decrypting...';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    } else {
                        outputData = 'Waiting for Cipher and Private Key inputs.';
                        sourceNode.outputFormat = getOutputFormat(sourceNode.type);
                    }
                    break;
                    
                default:
                    outputData = 'ERROR: Unrecognized Node Type.';
            }

        }
        
        const primaryOutputPort = sourceNodeDef.outputPorts?.[0];
        if (primaryOutputPort && primaryOutputPort.keyField === 'dataOutput') {
            sourceNode.dataOutput = outputData; 
        } else if (!primaryOutputPort) {
            if (sourceNode.type !== 'OUTPUT_VIEWER') {
                sourceNode.dataOutput = outputData;
            }
        }

        sourceNode.isProcessing = isProcessing;
        newNodesMap.set(sourceId, sourceNode);
        processed.add(sourceId);

        const targets = findAllTargets(sourceId);
        nodesToProcess.push(...targets);
    }
    
    return Array.from(newNodesMap.values());
};

// =================================================================
// 2. MAIN APP COMPONENT
// =================================================================

const App = () => {
  const [nodes, setNodes] = useState(INITIAL_NODES);
  const [connections, setConnections] = useState(INITIAL_CONNECTIONS); 
  const [connectingPort, setConnectingPort] = useState(null); 
  const [scale, setScale] = useState(1.0); 
  const [uploadError, setUploadError] = useState(null);
  const [copyStatus, setCopyStatus] = useState('Copy'); 

  const MAX_SCALE = 2.0;
  const MIN_SCALE = 0.5;
  const ZOOM_STEP = 0.2;

  const canvasRef = useRef(null);
  
  // --- Memoized recalculation function with setNodes dependency ---
  const recalculate = useCallback((currentNodes, currentConnections, changedNodeId = null) => {
      // Pass setNodes to handle asynchronous updates from crypto functions
      return recalculateGraph(currentNodes, currentConnections, changedNodeId, setNodes);
  }, [setNodes]); 

  // --- Effects for Recalculation ---
  useEffect(() => {
    // Initial calculation or on connection change
    // Trigger recalculation on component mount and whenever connections change.
    setNodes(prevNodes => recalculate(prevNodes, connections));
  }, [connections, recalculate]); 

  // --- Handlers (passed down to children) ---

  const handleCopyToClipboard = useCallback((e, textToCopy, localSetCopyStatus) => {
    e.stopPropagation();
    
    if (!textToCopy || textToCopy.startsWith('ERROR')) return;

    try {
        const tempTextArea = document.createElement('textarea');
        tempTextArea.value = textToCopy;
        
        tempTextArea.style.position = 'fixed';
        tempTextArea.style.left = '-9999px';
        tempTextArea.style.top = '0';
        tempTextArea.style.opacity = '0'; 

        document.body.appendChild(tempTextArea);
        
        document.execCommand('copy');
        
        document.body.removeChild(tempTextArea);
        localSetCopyStatus('Copied!'); 
        setTimeout(() => localSetCopyStatus('Copy'), 1500); 
        
    } catch (err) {
        console.error('Failed to copy text:', err);
        localSetCopyStatus('Error');
        setTimeout(() => localSetCopyStatus('Copy'), 2000);
    }
  }, []);

  const handleZoomIn = useCallback(() => {
      setScale(prevScale => Math.min(MAX_SCALE, prevScale + ZOOM_STEP));
  }, []);

  const handleZoomOut = useCallback(() => {
      setScale(prevScale => Math.max(MIN_SCALE, prevScale - ZOOM_STEP));
  }, []);

  const clearUploadError = useCallback(() => setUploadError(null), []);
    
  const downloadFile = (data, filename, type) => {
    const blob = new Blob([data], { type: type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadProject = useCallback(() => {
    const projectData = {
        nodes: nodes,
        connections: connections
    };
    const data = JSON.stringify(projectData, null, 2);
    downloadFile(data, 'visual_crypto_project.json', 'application/json');
  }, [nodes, connections]);

  const handleUploadProject = useCallback((fileInput) => {
      clearUploadError();
      
      const file = fileInput.files?.[0]; 
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (e) => {
          let projectData = null;
          
          try {
              projectData = JSON.parse(e.target.result);
          } catch (error) {
              console.error("Error parsing project file:", error);
              setUploadError("The file could not be read as valid JSON. This may indicate the file is corrupted or belongs to an older application version.");
              return;
          }

          if (projectData && Array.isArray(projectData.nodes) && Array.isArray(projectData.connections)) {
              // Ensure all nodes have necessary fields (like width/height) for new components
              const sanitizedNodes = projectData.nodes.map(n => ({
                  ...n,
                  width: n.width || NODE_DIMENSIONS.initialWidth,
                  height: n.height || NODE_DIMENSIONS.initialHeight,
              }));
              
              setNodes(sanitizedNodes);
              setConnections(projectData.connections);
          } else {
              console.error("Invalid project file structure:", projectData);
              setUploadError("The JSON file is missing the required 'nodes' or 'connections' data structure. This suggests the file might be from an incompatible or older version of the application.");
          }
      };
      
      reader.onerror = (e) => {
           console.error("Error reading file:", e);
           setUploadError("An error occurred while reading the file from disk.");
      };
      
      reader.readAsText(file);
      fileInput.value = ''; 
  }, [clearUploadError]);

  const setPosition = useCallback((id, newPos) => {
    setNodes(prevNodes => prevNodes.map(node =>
      node.id === id ? { ...node, position: newPos } : node
    ));
  }, []);
  
  const handleNodeResize = useCallback((id, newWidth, newHeight) => {
      setNodes(prevNodes => prevNodes.map(node => {
          if (node.id === id) {
              const finalWidth = Math.max(NODE_DIMENSIONS.minWidth, newWidth);
              const finalHeight = Math.max(NODE_DIMENSIONS.minHeight, newHeight);
              
              if (finalWidth !== node.width || finalHeight !== node.height) {
                  return { ...node, width: finalWidth, height: finalHeight };
              }
          }
          return node;
      }));
  }, []);

  const updateNodeContent = useCallback((id, field, value) => {
    setNodes(prevNodes => {
        const nextNodes = prevNodes.map(node => {
            if (node.id === id) {
                // Simplified content update logic, keeping other fields consistent
                const updatedNode = { 
                    ...node, 
                    [field]: value, 
                    // Explicitly reset triggers/statuses that should cause re-calc
                    generateKey: (field === 'generateKey' ? value : node.generateKey), 
                    dStatus: (field === 'd' ? '' : node.dStatus), // Clear status if D is edited
                };
                return updatedNode;
            }
            return node;
        });
        // Recalculate immediately after content update
        return recalculate(nextNodes, connections, id);
    });
  }, [connections, recalculate]);
  
  const addNode = useCallback((type, label, color) => {
    const newId = `${type}_${Date.now()}`;
    const definition = NODE_DEFINITIONS[type];
    
    const initialContent = { 
        dataOutput: '', 
        isProcessing: false, 
        outputFormat: getOutputFormat(type),
        width: NODE_DIMENSIONS.initialWidth, 
        height: NODE_DIMENSIONS.initialHeight, 
    };
    
    const canvas = canvasRef.current;
    const canvasWidth = canvas?.clientWidth > 100 ? canvas.clientWidth : 800;
    const canvasHeight = canvas?.clientHeight > 100 ? canvas.clientHeight : 600;
    
    let x = (canvasWidth / 2) - (NODE_DIMENSIONS.initialWidth / 2);
    let y = (canvasHeight / 2) - (NODE_DIMENSIONS.initialHeight / 2);
    
    const randomOffset = () => Math.floor(Math.random() * 200) - 100;
    x += randomOffset();
    y += randomOffset();

    x = Math.max(20, Math.min(x, canvasWidth - NODE_DIMENSIONS.initialWidth - 20));
    y = Math.max(20, Math.min(y, canvasHeight - NODE_DIMENSIONS.initialHeight - 20));
    
    const position = { x, y };

    if (type === 'DATA_INPUT') {
      initialContent.content = '';
      initialContent.format = 'Binary';
    } else if (type === 'OUTPUT_VIEWER') { 
      initialContent.convertedFormat = 'Base64';
    } else if (type === 'CAESAR_CIPHER') {
      initialContent.shiftKey = 3;
    } else if (type === 'VIGENERE_CIPHER') {
      initialContent.keyword = 'HELLO';
      initialContent.vigenereMode = 'ENCRYPT';
    } else if (type === 'HASH_FN') { 
      initialContent.hashAlgorithm = 'SHA-256';
    } else if (type === 'KEY_GEN') {
      initialContent.keyAlgorithm = 'AES-GCM';
      initialContent.keyBase64 = ''; 
      initialContent.generateKey = false; 
    } else if (type === 'RSA_KEY_GEN') { 
      initialContent.keyAlgorithm = 'RSA-OAEP';
      initialContent.modulusLength = 2048;
      initialContent.publicExponent = 65537; 
    } else if (type === 'SIMPLE_RSA_KEY_GEN') {
      initialContent.p = '';
      initialContent.q = '';
      initialContent.e = '';
      initialContent.d = ''; 
    } else if (type === 'SIMPLE_RSA_PUBKEY_GEN') {
      initialContent.outputFormat = 'Decimal';
      initialContent.isReadOnly = false;
    } else if (type === 'SIMPLE_RSA_ENC' || type === 'SIMPLE_RSA_DEC') {
      initialContent.outputFormat = 'Decimal';
    } else if (type === 'SIMPLE_RSA_SIGN') {
      initialContent.outputFormat = 'Decimal';
    } else if (type === 'SIMPLE_RSA_VERIFY') {
      initialContent.outputFormat = 'Text (UTF-8)';
    } else if (type === 'SYM_ENC' || type === 'SYM_DEC') {
      initialContent.symAlgorithm = 'AES-GCM'; 
    } else if (type === 'ASYM_ENC' || type === 'ASYM_DEC') {
      initialContent.asymAlgorithm = 'RSA-OAEP';
    } else if (type === 'SHIFT_OP') {
      initialContent.shiftType = 'Left';
      initialContent.shiftAmount = 1;
    }

    setNodes(prevNodes => [
      ...prevNodes,
      { 
        id: newId, 
        label: definition.label, 
        position: position, 
        type: type, 
        color: color,
        ...initialContent 
      },
    ]);
  }, [canvasRef]); 

  
  const handleDeleteNode = useCallback((nodeIdToDelete) => {
      setNodes(prevNodes => prevNodes.filter(n => n.id !== nodeIdToDelete));
      setConnections(prevConnections => 
          prevConnections.filter(c => c.source !== nodeIdToDelete && c.target !== nodeIdToDelete)
      );
  }, []);

  const handleConnectStart = useCallback((nodeId, portIndex, outputType) => {
    setConnectingPort({ sourceId: nodeId, sourcePortIndex: portIndex, outputType: outputType });
  }, []);

  const handleConnectEnd = useCallback((targetId, targetPortId) => {
    if (connectingPort && targetId && connectingPort.sourceId !== targetId) {
      
      const { sourceId, sourcePortIndex, outputType } = connectingPort;
      
      // 1. Get Target Input Port Type
      const targetNode = nodes.find(n => n.id === targetId);
      const targetNodeDef = NODE_DEFINITIONS[targetNode?.type];
      const targetPortDef = targetNodeDef.inputPorts.find(p => p.id === targetPortId);
      const targetPortType = targetPortDef?.type;

      // 2. Perform Type Check
      if (outputType !== targetPortType) {
           console.error(`Connection failed: Output type '${outputType}' does not match target port type '${targetPortType}'.`);
           setConnectingPort(null);
           return;
      }
      
      // 3. Perform Uniqueness/Duplicate Checks
      const isDuplicate = connections.some(c => 
          c.source === sourceId && 
          c.sourcePortIndex === sourcePortIndex && 
          c.target === targetId && 
          c.targetPortId === targetPortId
      );

      const isInputPortAlreadyConnected = connections.some(c => 
          c.target === targetId && 
          c.targetPortId === targetPortId
      );
      
      if (isDuplicate) {
          console.warn('Duplicate connection detected and prevented.');
      } else if (isInputPortAlreadyConnected) {
          console.warn(`Input port (${targetPortId}) on node ${targetId} is already connected. Only one connection per input port is allowed.`);
      } else if (targetPortDef) {
        setConnections(prevConnections => [
         ...prevConnections, 
         { 
             source: sourceId, 
             sourcePortIndex: sourcePortIndex, 
             target: targetId,
             targetPortId: targetPortId 
         }
       ]);
      } else {
           console.warn(`Cannot connect: Node ${targetId} is not configured to receive input at port ${targetPortId}.`);
      }
    }
    setConnectingPort(null); 
  }, [connectingPort, connections, nodes]);

  const handleRemoveConnection = useCallback((sourceId, targetId, sourcePortIndex, targetPortId) => {
    setConnections(prevConnections => 
        prevConnections.filter(c => !(
            c.source === sourceId && 
            c.target === targetId &&
            c.sourcePortIndex === sourcePortIndex &&
            c.targetPortId === targetPortId
        ))
    );
  }, []);
  
  const connectionPaths = useMemo(() => {
    return connections.map(conn => {
      const sourceNode = nodes.find(n => n.id === conn.source);
      const targetNode = nodes.find(n => n.id === conn.target);
      
      if (sourceNode && targetNode) {
        return {
            path: getLinePath(sourceNode, targetNode, conn), 
            source: conn.source,
            target: conn.target,
            sourcePortIndex: conn.sourcePortIndex,
            targetPortId: conn.targetPortId,
        };
      }
      return null;
    }).filter(p => p !== null);
  }, [connections, nodes]);

  
  const handleCanvasClick = useCallback(() => {
    if (connectingPort) {
      handleConnectEnd(null);
    }
  }, [connectingPort, handleConnectEnd]);
  
  const handleCopy = useCallback((e, textToCopy) => {
    e.stopPropagation();
    
    if (!textToCopy || textToCopy.startsWith('ERROR')) return;

    try {
        const tempTextArea = document.createElement('textarea');
        tempTextArea.value = textToCopy;
        
        tempTextArea.style.position = 'fixed';
        tempTextArea.style.left = '-9999px';
        tempTextArea.style.top = '0';
        tempTextArea.style.opacity = '0'; 

        document.body.appendChild(tempTextArea);
        
        document.execCommand('copy');
        
        document.body.removeChild(tempTextArea);
        setCopyStatus('Copied!'); 
        setTimeout(() => setCopyStatus('Copy'), 1500); 
        
    } catch (err) {
        console.error('Failed to copy text:', err);
        setCopyStatus('Error');
        setTimeout(() => setCopyStatus('Copy'), 2000);
    }
  }, []);

  return (
    <div className="h-screen w-screen flex bg-gray-100 font-inter overflow-hidden">
        
      <style dangerouslySetInnerHTML={{ __html: globalStyles }} />

      <Toolbar 
        addNode={addNode} 
        onDownloadProject={handleDownloadProject}
        onUploadProject={handleUploadProject}
        onZoomIn={handleZoomIn} 
        onZoomOut={handleZoomOut} 
      />

      <div className="flex-grow flex flex-col p-4">
        
        <div 
          ref={canvasRef}
          className="canvas-container relative w-full flex-grow border-4 border-dashed border-gray-300 rounded-2xl bg-white shadow-inner overflow-auto" 
          onClick={handleCanvasClick}
        >
          
          <div 
              style={{ 
                  transform: `scale(${scale})`, 
                  transformOrigin: 'top left',
                  minWidth: `calc(100% / ${scale})`,
                  minHeight: `calc(100% / ${scale})`,
                  width: `calc(100% / ${scale})`, 
                  height: `calc(100% / ${scale})`,
              }} 
              className="absolute top-0 left-0"
          >
              <svg 
                  className="absolute top-0 left-0 w-full h-full pointer-events-auto z-0" 
                  style={{ width: `calc(100% * ${scale})`, height: `calc(100% * ${scale})` }} 
              >
                {connectionPaths.map((conn, index) => (
                  <g 
                    key={`${conn.source}-${conn.target}-${conn.sourcePortIndex}-${conn.targetPortId}`}
                    onClick={(e) => { 
                        e.stopPropagation(); 
                        handleRemoveConnection(conn.source, conn.target, conn.sourcePortIndex, conn.targetPortId);
                    }}
                    className="cursor-pointer" 
                  >
                    <path d={conn.path} className="connection-hitbox"/>
                    <path d={conn.path} className="connection-line-visible"/>
                  </g>
                ))}
              </svg>

              {nodes.map(node => (
                <DraggableBox
                  key={node.id}
                  node={node}
                  setPosition={setPosition}
                  updateNodeContent={updateNodeContent}
                  canvasRef={canvasRef}
                  handleConnectStart={handleConnectStart}
                  handleConnectEnd={handleConnectEnd}
                  connectingPort={connectingPort}
                  connections={connections}
                  handleDeleteNode={handleDeleteNode}
                  nodes={nodes} 
                  scale={scale} 
                  handleResize={handleNodeResize} 
                  handleCopyToClipboard={handleCopy} 
                  copyStatus={copyStatus} 
                  setCopyStatus={setCopyStatus} 
                />
              ))}
          </div>
          
        </div>
        
        {/* --- ERROR Notification Overlay --- */}
        {uploadError && (
            <div className="fixed top-0 left-0 w-full h-full flex items-center justify-center bg-black bg-opacity-50 z-50 p-4">
                <div className="bg-white p-6 rounded-xl shadow-2xl max-w-sm w-full text-center border-4 border-red-500 animate-pulse-slow">
                    <X className="w-6 h-6 text-red-500 mx-auto mb-3" />
                    <h3 className="text-lg font-bold text-red-700 mb-2">Project Load Error</h3>
                    <p className="text-sm text-gray-700 mb-4">{uploadError}</p>
                    <button
                        onClick={clearUploadError}
                        className="w-full py-2 px-4 bg-red-500 text-white font-semibold rounded-lg hover:bg-red-600 transition"
                    >
                        Dismiss
                    </button>
                </div>
            </div>
        )}
      </div>
    </div>
  );
};

export default App;