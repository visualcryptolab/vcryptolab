import { NODE_DEFINITIONS } from '../constants/appConstants';
import {
    getOutputFormat,
    caesarEncrypt,
    vigenereEncryptDecrypt,
    calculateHash,
    performBitwiseXor,
    modPow,
    generateSmallPrimes,
    gcd,
    generateSmallE,
    modInverse,
    performBitShiftOperation,
    splitDataIntoChunks,
    concatenateData,
    generateSymmetricKey,
    symmetricEncrypt,
    symmetricDecrypt,
    generatePRNG,
    isPrime
} from './cryptoUtils';
import { convertDataFormat } from './formatUtils';

export const recalculateGraph = (currentNodes, currentConnections, changedNodeId = null, setNodes) => {
    const newNodesMap = new Map(currentNodes.map(n => {
        const newNode = { ...n, isProcessing: false };
        if (newNode.type === 'OUTPUT_VIEWER') {
            newNode.convertedData = newNode.convertedData || '';
            newNode.convertedFormat = newNode.convertedFormat || 'Base64';
            newNode.isConversionExpanded = newNode.isConversionExpanded || false;
            newNode.sourceFormat = newNode.sourceFormat || '';
            newNode.rawInputData = newNode.rawInputData || '';
        }
        return [n.id, newNode];
    }));

    const inDegree = new Map();
    const adjList = new Map();
    currentNodes.forEach(n => {
        inDegree.set(n.id, 0);
        adjList.set(n.id, []);
    });

    currentConnections.forEach(c => {
        if (inDegree.has(c.target) && adjList.has(c.source)) {
            inDegree.set(c.target, inDegree.get(c.target) + 1);
            adjList.get(c.source).push(c.target);
        }
    });

    const queue = [];
    currentNodes.forEach(n => {
        if (inDegree.get(n.id) === 0) queue.push(n.id);
    });

    const sortedNodes = [];
    while (queue.length > 0) {
        const sourceId = queue.shift();
        sortedNodes.push(sourceId);
        adjList.get(sourceId).forEach(targetId => {
            const currentInDegree = inDegree.get(targetId) - 1;
            inDegree.set(targetId, currentInDegree);
            if (currentInDegree === 0) queue.push(targetId);
        });
    }

    currentNodes.forEach(n => {
        if (!sortedNodes.includes(n.id)) sortedNodes.push(n.id);
    });

    for (const sourceId of sortedNodes) {
        const sourceNode = newNodesMap.get(sourceId);
        if (!sourceNode) continue;
        const sourceNodeDef = NODE_DEFINITIONS[sourceNode.type];
        let outputData = sourceNode.dataOutput || '';
        let isProcessing = false;

        if (sourceNodeDef.inputPorts.length === 0) {
            if (sourceNode.type === 'DATA_INPUT') outputData = sourceNode.content || '';
            else if (sourceNode.type === 'KEY_GEN') {
                if (sourceNode.generateKey || !sourceNode.keyBase64) {
                    isProcessing = true;
                    generateSymmetricKey(sourceNode.keyAlgorithm || 'AES-GCM').then(({ keyBase64 }) => {
                        setNodes(prevNodes => {
                            const nextNodes = prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: keyBase64, keyBase64: keyBase64, isProcessing: false, generateKey: false } : n);
                            return recalculateGraph(nextNodes, currentConnections, sourceId, setNodes);
                        });
                    });
                    continue;
                } else outputData = sourceNode.keyBase64;
            } else if (sourceNode.type === 'PRNG_GEN') {
                const res = generatePRNG(sourceNode.seed, sourceNode.prngType, sourceNode.min, sourceNode.max, sourceNode.precision, sourceNode.isPrime);
                outputData = res;
            }
        } else {
            const incomingConns = currentConnections.filter(c => c.target === sourceId);
            let inputs = {};
            incomingConns.forEach(conn => {
                const srcNode = newNodesMap.get(conn.source);
                if (!srcNode) return;
                let dataToUse;
                const srcDef = NODE_DEFINITIONS[srcNode.type];
                if (srcDef && srcDef.outputPorts.length > conn.sourcePortIndex) {
                    const keyField = srcDef.outputPorts[conn.sourcePortIndex].keyField;
                    dataToUse = srcNode.type === 'DATA_SPLIT' && (keyField === 'chunk1' || keyField === 'chunk2') ? srcNode[keyField] : srcNode[keyField];
                } else dataToUse = srcNode.dataOutput;
                inputs[conn.targetPortId] = { data: dataToUse, format: srcNode.type === 'DATA_INPUT' ? srcNode.format : (srcNode.outputFormat || getOutputFormat(srcNode.type)) };
            });

            switch (sourceNode.type) {
                case 'OUTPUT_VIEWER':
                    const rawInput = inputs['data']?.data;
                    let converted = '';
                    let srcFormat = inputs['data']?.format || 'N/A';
                    if (rawInput && !rawInput.startsWith('ERROR')) {
                        const isBinary = ['Hexadecimal', 'Binary', 'Decimal', 'Base64'].includes(srcFormat);
                        const isSLNTarget = ['Decimal', 'Hexadecimal', 'Binary'].includes(sourceNode.convertedFormat);
                        if (sourceNode.isConversionExpanded) converted = convertDataFormat(rawInput, srcFormat, sourceNode.convertedFormat || 'Base64', isSLNTarget && isBinary);
                        outputData = (sourceNode.isConversionExpanded && converted && !converted.startsWith('ERROR')) ? converted : rawInput;
                        sourceNode.outputFormat = sourceNode.isConversionExpanded ? sourceNode.convertedFormat : (srcFormat === 'N/A' ? 'Text (UTF-8)' : srcFormat);
                    } else outputData = 'Not connected or no data.';
                    sourceNode.convertedData = converted; sourceNode.sourceFormat = srcFormat; sourceNode.rawInputData = rawInput || outputData;
                    break;
                case 'CAESAR_CIPHER':
                    const plain = inputs['plaintext']?.data;
                    if (plain) {
                        const { output, format } = caesarEncrypt(plain, inputs['plaintext']?.format, parseInt(sourceNode.shiftKey) || 0);
                        outputData = output; sourceNode.outputFormat = format;
                    } else outputData = 'Waiting for inputs:\n• Plaintext';
                    break;
                case 'VIGENERE_CIPHER':
                    const vInput = inputs['data']?.data;
                    if (vInput) {
                        if (inputs['data']?.format !== 'Text (UTF-8)') outputData = "ERROR: Needs Text (UTF-8)";
                        else { const { output, format } = vigenereEncryptDecrypt(vInput, sourceNode.keyword, sourceNode.vigenereMode); outputData = output; sourceNode.outputFormat = format; }
                    } else outputData = 'Waiting for inputs:\n• Plaintext / Ciphertext';
                    break;
                case 'HASH_FN':
                    const hashData = inputs['data']?.data;
                    const hashAlgo = sourceNode.hashAlgorithm || 'SHA-256';
                    if (hashData && !hashData.startsWith('ERROR')) {
                        const inputsKey = `${hashData}|${hashAlgo}`;
                        if (sourceNode.lastProcessedInputs === inputsKey && sourceNode.dataOutput && !sourceNode.isProcessing) {
                            outputData = sourceNode.dataOutput;
                            break;
                        }
                        isProcessing = true;
                        calculateHash(hashData, inputs['data'].format, hashAlgo).then(res => {
                            setNodes(prev => {
                                const nextNodes = prev.map(n => n.id === sourceId ? { ...n, dataOutput: res, isProcessing: false, lastProcessedInputs: inputsKey } : n);
                                return recalculateGraph(nextNodes, currentConnections, sourceId, setNodes);
                            });
                        });
                        continue;
                    } else outputData = 'Waiting for inputs:\n• Data to hash';
                    break;
                case 'XOR_OP':
                    const xA = inputs['dataA']?.data; const xB = inputs['dataB']?.data;
                    const missingXOR = [];
                    if (!xA || xA.startsWith('ERROR') || xA.startsWith('Waiting')) missingXOR.push('Input A');
                    if (!xB || xB.startsWith('ERROR') || xB.startsWith('Waiting')) missingXOR.push('Input B');
                    if (missingXOR.length === 0) {
                        const res = performBitwiseXor(xA, inputs['dataA'].format, xB, inputs['dataB'].format);
                        outputData = res.output; sourceNode.outputFormat = res.format;
                    } else {
                        outputData = 'Waiting for inputs:\n' + missingXOR.map(m => `• ${m}`).join('\n');
                    }
                    break;
                case 'SIMPLE_RSA_ENC':
                    try {
                        const mStr = inputs['message']?.data; const pkStr = inputs['publicKey']?.data;
                        let n, e;
                        const pkSourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'publicKey');
                        const sourceNodeKeyGen = newNodesMap.get(pkSourceConn?.source);
                        if (sourceNodeKeyGen?.n_pub) { n = BigInt(sourceNodeKeyGen.n_pub); e = BigInt(sourceNodeKeyGen.e_pub); }
                        else if (sourceNodeKeyGen?.n) { n = BigInt(sourceNodeKeyGen.n); e = BigInt(sourceNodeKeyGen.e); }
                        else if (pkStr && pkStr !== 'N/A' && !pkStr.startsWith('Waiting')) { 
                            const parts = pkStr.split(',');
                            if (parts.length >= 2) { n = BigInt(parts[0]); e = BigInt(parts[1]); }
                        }
                        const missing = [];
                        if (!mStr || mStr.startsWith('Waiting') || mStr.startsWith('ERROR')) missing.push('Plaintext Message');
                        if (!n) missing.push('Public Key');
                        if (missing.length === 0) {
                            const m = BigInt(mStr.replace(/\s+/g, ''));
                            outputData = (m >= n) ? "ERROR: m >= n" : modPow(m, e, n).toString();
                        } else {
                            outputData = 'Waiting for inputs:\n' + missing.map(m => `• ${m}`).join('\n');
                        }
                    } catch (err) { outputData = "ERROR: Invalid Input"; }
                    break;
                case 'SIMPLE_RSA_DEC':
                    try {
                        const cStr = inputs['cipher']?.data; const dStr = inputs['privateKey']?.data;
                        const privConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'privateKey');
                        const privSource = newNodesMap.get(privConn?.source);
                        let n, d;
                        if (privSource?.n) { n = BigInt(privSource.n); d = BigInt(privSource.d || dStr); }
                        else if (dStr && dStr !== 'N/A' && !dStr.startsWith('Waiting')) { 
                            d = BigInt(dStr); 
                            if (privSource?.n_pub) n = BigInt(privSource.n_pub);
                        }
                        const missing = [];
                        if (!cStr || cStr.startsWith('Waiting') || cStr.startsWith('ERROR')) missing.push('Ciphertext');
                        if (!d || !n) missing.push('Private Key (needs N and D)');
                        if (missing.length === 0) {
                            outputData = modPow(BigInt(cStr), d, n).toString();
                        } else {
                            outputData = 'Waiting for inputs:\n' + missing.map(m => `• ${m}`).join('\n');
                        }
                    } catch (err) { outputData = "ERROR: Invalid Input"; }
                    break;
                case 'SHIFT_OP':
                    if (inputs['data']?.data && !inputs['data'].data.startsWith('ERROR')) {
                        const res = performBitShiftOperation(inputs['data'].data, sourceNode.shiftType, sourceNode.shiftAmount, inputs['data'].format);
                        outputData = res.output; sourceNode.shiftDescription = res.description; sourceNode.outputFormat = inputs['data'].format;
                    } else outputData = 'Waiting for inputs:\n• Data to shift';
                    break;
                case 'DATA_SPLIT':
                    if (inputs['data']?.data && !inputs['data'].data.startsWith('ERROR')) {
                        const splitRes = splitDataIntoChunks(inputs['data'].data, inputs['data'].format);
                        sourceNode.chunk1 = splitRes.chunk1; sourceNode.chunk2 = splitRes.chunk2; sourceNode.outputFormat = splitRes.outputFormat;
                    } else { sourceNode.chunk1 = 'Waiting for inputs:\n• Data'; sourceNode.chunk2 = 'Waiting for inputs:\n• Data'; }
                    outputData = '';
                    break;
                case 'DATA_CONCAT':
                    const inputsA = inputs['dataA'];
                    const inputsB = inputs['dataB'];
                    const missingConcat = [];
                    if (!inputsA || inputsA.data?.startsWith('Waiting') || inputsA.data?.startsWith('ERROR')) missingConcat.push('Data A');
                    if (!inputsB || inputsB.data?.startsWith('Waiting') || inputsB.data?.startsWith('ERROR')) missingConcat.push('Data B');
                    if (missingConcat.length === 0) {
                        const concatRes = concatenateData(inputsA.data, inputsA.format, inputsB.data, inputsB.format, sourceNode.interpretAsText);
                        outputData = concatRes.output;
                        sourceNode.outputFormat = concatRes.format;
                    } else {
                        outputData = 'Waiting for inputs:\n' + missingConcat.map(m => `• ${m}`).join('\n');
                    }
                    break;
                case 'SIMPLE_RSA_PUBKEY_GEN':
                    const kSourceConn = incomingConns.find(c => c.targetPortId === 'keySource');
                    const kSource = newNodesMap.get(kSourceConn?.source);
                    if (kSource?.n) { sourceNode.n_pub = kSource.n; sourceNode.e_pub = kSource.e; sourceNode.isReadOnly = true; }
                    sourceNode.dataOutputPublic = (sourceNode.n_pub && sourceNode.e_pub) ? `${sourceNode.n_pub},${sourceNode.e_pub}` : 'N/A';
                    outputData = sourceNode.dataOutputPublic;
                    break;
                case 'SIMPLE_RSA_SIGN':
                    try {
                        const mS = inputs['message']?.data; const dS = inputs['privateKey']?.data;
                        const pC = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'privateKey');
                        const pS = newNodesMap.get(pC?.source);
                        let n, d;
                        if (pS?.n) { n = BigInt(pS.n); d = BigInt(pS.d || dS); }
                        const missing = [];
                        if (!mS || mS.startsWith('Waiting') || mS.startsWith('ERROR')) missing.push('Message');
                        if (!n || !d) missing.push('Private Key');
                        if (missing.length === 0) {
                            outputData = modPow(BigInt(mS.replace(/\s+/g, '')), d, n).toString();
                        } else {
                            outputData = 'Waiting for inputs:\n' + missing.map(m => `• ${m}`).join('\n');
                        }
                    } catch (err) { outputData = "ERROR: Invalid Input"; }
                    break;
                case 'SIMPLE_RSA_VERIFY':
                    try {
                        const mV = inputs['message']?.data; const sV = inputs['signature']?.data;
                        const pkC = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'publicKey');
                        const pkS = newNodesMap.get(pkC?.source);
                        let nV, eV;
                        if (pkS?.n_pub) { nV = BigInt(pkS.n_pub); eV = BigInt(pkS.e_pub); }
                        else if (pkS?.n) { nV = BigInt(pkS.n); eV = BigInt(pkS.e); }
                        else if (inputs['publicKey']?.data && inputs['publicKey'].data !== 'N/A' && !inputs['publicKey'].data.startsWith('Waiting')) {
                            const parts = inputs['publicKey'].data.split(',');
                            if (parts.length >= 2) { nV = BigInt(parts[0]); eV = BigInt(parts[1]); }
                        }
                        const missing = [];
                        if (!mV || mV.startsWith('Waiting') || mV.startsWith('ERROR')) missing.push('Message');
                        if (!sV || sV.startsWith('Waiting') || sV.startsWith('ERROR')) missing.push('Signature');
                        if (!nV || !eV) missing.push('Public Key');
                        if (missing.length === 0) {
                            const dec = modPow(BigInt(sV.replace(/\s+/g, '')), eV, nV);
                            outputData = (dec === BigInt(mV.replace(/\s+/g, ''))) ? "SUCCESS: Signature Valid" : "FAILURE: Signature Invalid";
                        } else {
                            outputData = 'Waiting for inputs:\n' + missing.map(m => `• ${m}`).join('\n');
                        }
                    } catch (err) { outputData = "ERROR: Invalid Input"; }
                    break;
                case 'SYM_ENC':
                    const encData = inputs['data']?.data;
                    const encKey = inputs['key']?.data;
                    const encAlgo = sourceNode.symAlgorithm || 'AES-GCM';
                    const missingSymEnc = [];
                    if (!encData || encData.startsWith('ERROR') || encData.startsWith('Waiting')) missingSymEnc.push('Plaintext Data');
                    if (!encKey || encKey.startsWith('Waiting')) missingSymEnc.push('Symmetric Key');
                    if (missingSymEnc.length === 0) {
                        const inputsKey = `${encData}|${encKey}|${encAlgo}`;
                        if (sourceNode.lastProcessedInputs === inputsKey && sourceNode.dataOutput && !sourceNode.isProcessing) {
                            outputData = sourceNode.dataOutput;
                            break;
                        }
                        isProcessing = true;
                        symmetricEncrypt(encData, encKey, encAlgo).then(res => {
                            setNodes(prev => {
                                const nextNodes = prev.map(n => n.id === sourceId ? { ...n, dataOutput: res, isProcessing: false, lastProcessedInputs: inputsKey } : n);
                                return recalculateGraph(nextNodes, currentConnections, sourceId, setNodes);
                            });
                        });
                        continue;
                    } else {
                        outputData = 'Waiting for inputs:\n' + missingSymEnc.map(m => `• ${m}`).join('\n');
                    }
                    break;
                case 'SYM_DEC':
                    const decCipher = inputs['cipher']?.data;
                    const decKey = inputs['key']?.data;
                    const decAlgo = sourceNode.symAlgorithm || 'AES-GCM';
                    const missingSymDec = [];
                    if (!decCipher || decCipher.startsWith('ERROR') || decCipher.startsWith('Waiting')) missingSymDec.push('Ciphertext Data');
                    if (!decKey || decKey.startsWith('Waiting')) missingSymDec.push('Symmetric Key');
                    if (missingSymDec.length === 0) {
                        const inputsKey = `${decCipher}|${decKey}|${decAlgo}`;
                        if (sourceNode.lastProcessedInputs === inputsKey && sourceNode.dataOutput && !sourceNode.isProcessing) {
                            outputData = sourceNode.dataOutput;
                            break;
                        }
                        isProcessing = true;
                        symmetricDecrypt(decCipher, decKey, decAlgo).then(res => {
                            setNodes(prev => {
                                const nextNodes = prev.map(n => n.id === sourceId ? { ...n, dataOutput: res, isProcessing: false, lastProcessedInputs: inputsKey } : n);
                                return recalculateGraph(nextNodes, currentConnections, sourceId, setNodes);
                            });
                        });
                        continue;
                    } else {
                        outputData = 'Waiting for inputs:\n' + missingSymDec.map(m => `• ${m}`).join('\n');
                    }
                    break;
                case 'SIMPLE_RSA_KEY_GEN':
                    if (sourceNode.generateKey) {
                        isProcessing = true;
                        const incomingP = inputs['p']?.data;
                        const incomingQ = inputs['q']?.data;
                        const rawP = incomingP || sourceNode.p;
                        const rawQ = incomingQ || sourceNode.q;
                        const rawE = sourceNode.e;
                        let p_val, q_val, e_val, d_val, n_val, phiN_val;
                        let error = null;
                        try {
                            const userP = rawP && !isNaN(Number(rawP)) ? BigInt(rawP) : null;
                            const userQ = rawQ && !isNaN(Number(rawQ)) ? BigInt(rawQ) : null;

                            if (incomingP && !userP) throw new Error("ERROR: Input P is not a valid number");
                            if (incomingQ && !userQ) throw new Error("ERROR: Input Q is not a valid number");

                            if (userP && userQ) {
                                if (!isPrime(Number(userP))) throw new Error(`ERROR: P (${userP}) is not prime`);
                                if (!isPrime(Number(userQ))) throw new Error(`ERROR: Q (${userQ}) is not prime`);
                                p_val = userP; q_val = userQ;
                            } else { ({ p: p_val, q: q_val } = generateSmallPrimes()); }

                            n_val = p_val * q_val;
                            phiN_val = (p_val - BigInt(1)) * (q_val - BigInt(1));
                            const userE = rawE && !isNaN(Number(rawE)) ? BigInt(rawE) : null;
                            if (userE && userE > BigInt(1) && userE < phiN_val && gcd(userE, phiN_val) === BigInt(1)) e_val = userE;
                            else e_val = generateSmallE(phiN_val);
                            d_val = modInverse(e_val, phiN_val);
                        } catch (err) { error = err.message.startsWith('ERROR') ? err.message : `ERROR: Calculation failed. ${err.message}`; }
                        if (!error) {
                            sourceNode.dataOutputPublic = `${n_val},${e_val}`; sourceNode.dataOutputPrivate = d_val.toString();
                            sourceNode.n = n_val.toString(); sourceNode.phiN = phiN_val.toString(); sourceNode.d = d_val.toString();
                            sourceNode.p = p_val.toString(); sourceNode.q = q_val.toString(); sourceNode.e = e_val.toString();
                            outputData = sourceNode.dataOutputPrivate;
                            sourceNode.dStatus = d_val.toString(); // Success message or key
                        } else { outputData = error; sourceNode.dStatus = error; }
                        sourceNode.isProcessing = false; sourceNode.generateKey = false;
                        newNodesMap.set(sourceId, sourceNode); continue;
                    } else {
                        outputData = sourceNode.dataOutputPrivate || '';
                    }
                    break;
            }
        }
        if (sourceNode.type === 'DATA_SPLIT') { }
        else {
            const primOut = sourceNodeDef.outputPorts?.[0];
            if (primOut && primOut.keyField === 'dataOutput') sourceNode.dataOutput = outputData;
            else if (!primOut && sourceNode.type !== 'OUTPUT_VIEWER') sourceNode.dataOutput = outputData;
        }
        sourceNode.isProcessing = isProcessing;
        newNodesMap.set(sourceId, sourceNode);
    }
    return Array.from(newNodesMap.values());
};
