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
    symmetricDecrypt
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

    let initialQueue = new Set(currentNodes.filter(n => NODE_DEFINITIONS[n.type]?.inputPorts.length === 0).map(n => n.id));
    if (changedNodeId) initialQueue.add(changedNodeId);
    let nodesToProcess = Array.from(initialQueue);
    const processed = new Set();
    const findAllTargets = (sourceId) => currentConnections.filter(c => c.source === sourceId).map(c => c.target).filter(targetId => !processed.has(targetId));

    while (nodesToProcess.length > 0) {
        const sourceId = nodesToProcess.shift();
        if (processed.has(sourceId) || !newNodesMap.has(sourceId)) continue;
        const sourceNode = newNodesMap.get(sourceId);
        const sourceNodeDef = NODE_DEFINITIONS[sourceNode.type];
        let outputData = sourceNode.dataOutput || '';
        let isProcessing = false;

        if (sourceNodeDef.inputPorts.length === 0) {
            if (sourceNode.type === 'DATA_INPUT') outputData = sourceNode.content || '';
            else if (sourceNode.type === 'KEY_GEN') {
                if (sourceNode.generateKey || !sourceNode.keyBase64) {
                    isProcessing = true;
                    generateSymmetricKey(sourceNode.keyAlgorithm || 'AES-GCM').then(({ keyBase64 }) => {
                        setNodes(prevNodes => prevNodes.map(n => n.id === sourceId ? { ...n, dataOutput: keyBase64, keyBase64: keyBase64, isProcessing: false, generateKey: false } : n));
                    });
                    processed.add(sourceId); nodesToProcess.push(...findAllTargets(sourceId)); continue;
                } else outputData = sourceNode.keyBase64;
            } else if (sourceNode.type === 'SIMPLE_RSA_KEY_GEN' && sourceNode.generateKey) {
                isProcessing = true;
                const rawP = sourceNode.p; const rawQ = sourceNode.q; const rawE = sourceNode.e;
                let p_val, q_val, e_val, d_val, n_val, phiN_val;
                let error = null;
                try {
                    const userP = rawP && !isNaN(Number(rawP)) ? BigInt(rawP) : null;
                    const userQ = rawQ && !isNaN(Number(rawQ)) ? BigInt(rawQ) : null;
                    if (userP && userQ) { p_val = userP; q_val = userQ; } else { ({ p: p_val, q: q_val } = generateSmallPrimes()); }
                    n_val = p_val * q_val;
                    phiN_val = (p_val - BigInt(1)) * (q_val - BigInt(1));
                    const userE = rawE && !isNaN(Number(rawE)) ? BigInt(rawE) : null;
                    if (userE && userE > BigInt(1) && userE < phiN_val && gcd(userE, phiN_val) === BigInt(1)) e_val = userE;
                    else e_val = generateSmallE(phiN_val);
                    d_val = modInverse(e_val, phiN_val);
                } catch (err) { error = `ERROR: Calculation failed.`; }
                if (!error) {
                    sourceNode.dataOutputPublic = `${n_val},${e_val}`; sourceNode.dataOutputPrivate = d_val.toString();
                    sourceNode.n = n_val.toString(); sourceNode.phiN = phiN_val.toString(); sourceNode.d = d_val.toString();
                    sourceNode.p = p_val.toString(); sourceNode.q = q_val.toString(); sourceNode.e = e_val.toString();
                    outputData = sourceNode.dataOutputPrivate;
                } else { outputData = error; sourceNode.dStatus = error; }
                sourceNode.isProcessing = false; sourceNode.generateKey = false;
                newNodesMap.set(sourceId, sourceNode); processed.add(sourceId); nodesToProcess.push(...findAllTargets(sourceId)); continue;
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
                    } else outputData = 'Waiting for plaintext input.';
                    break;
                case 'VIGENERE_CIPHER':
                    const vInput = inputs['data']?.data;
                    if (vInput) {
                        if (inputs['data']?.format !== 'Text (UTF-8)') outputData = "ERROR: Needs Text (UTF-8)";
                        else { const { output, format } = vigenereEncryptDecrypt(vInput, sourceNode.keyword, sourceNode.vigenereMode); outputData = output; sourceNode.outputFormat = format; }
                    } else outputData = 'Waiting for data.';
                    break;
                case 'HASH_FN':
                    if (inputs['data']?.data && !inputs['data'].data.startsWith('ERROR')) {
                        isProcessing = true;
                        calculateHash(inputs['data'].data, inputs['data'].format, sourceNode.hashAlgorithm || 'SHA-256').then(res => setNodes(prev => prev.map(n => n.id === sourceId ? { ...n, dataOutput: res, isProcessing: false } : n)));
                        processed.add(sourceId); nodesToProcess.push(...findAllTargets(sourceId)); continue;
                    } else outputData = 'Waiting for data.';
                    break;
                case 'XOR_OP':
                    const xA = inputs['dataA']?.data; const xB = inputs['dataB']?.data;
                    if (xA && xB && !xA.startsWith('ERROR') && !xB.startsWith('ERROR')) {
                        const res = performBitwiseXor(xA, inputs['dataA'].format, xB, inputs['dataB'].format);
                        outputData = res.output; sourceNode.outputFormat = res.format;
                    } else outputData = 'Waiting for inputs.';
                    break;
                case 'SIMPLE_RSA_ENC':
                    try {
                        const mStr = inputs['message']?.data; const pkStr = inputs['publicKey']?.data;
                        let n, e;
                        const pkSourceConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'publicKey');
                        const sourceNodeKeyGen = newNodesMap.get(pkSourceConn?.source);
                        if (sourceNodeKeyGen?.n_pub) { n = BigInt(sourceNodeKeyGen.n_pub); e = BigInt(sourceNodeKeyGen.e_pub); }
                        else if (pkStr) { const [nStr, eStr] = pkStr.split(','); n = BigInt(nStr); e = BigInt(eStr); }
                        if (mStr && n) {
                            const m = BigInt(mStr.replace(/\s+/g, ''));
                            outputData = (m >= n) ? "ERROR: m >= n" : modPow(m, e, n).toString();
                        } else outputData = 'Waiting for input.';
                    } catch (err) { outputData = "ERROR"; }
                    break;
                case 'SIMPLE_RSA_DEC':
                    try {
                        const cStr = inputs['cipher']?.data; const dStr = inputs['privateKey']?.data;
                        const privConn = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'privateKey');
                        const privSource = newNodesMap.get(privConn?.source);
                        if (cStr && dStr && privSource?.n) {
                            outputData = modPow(BigInt(cStr), BigInt(dStr), BigInt(privSource.n)).toString();
                        } else outputData = 'Waiting for input.';
                    } catch (err) { outputData = "ERROR"; }
                    break;
                case 'SHIFT_OP':
                    if (inputs['data']?.data && !inputs['data'].data.startsWith('ERROR')) {
                        const res = performBitShiftOperation(inputs['data'].data, sourceNode.shiftType, sourceNode.shiftAmount, inputs['data'].format);
                        outputData = res.output; sourceNode.shiftDescription = res.description; sourceNode.outputFormat = inputs['data'].format;
                    } else outputData = 'Waiting for input.';
                    break;
                case 'DATA_SPLIT':
                    if (inputs['data']?.data && !inputs['data'].data.startsWith('ERROR')) {
                        const splitRes = splitDataIntoChunks(inputs['data'].data, inputs['data'].format);
                        sourceNode.chunk1 = splitRes.chunk1; sourceNode.chunk2 = splitRes.chunk2; sourceNode.outputFormat = splitRes.outputFormat;
                    } else { sourceNode.chunk1 = 'Waiting...'; sourceNode.chunk2 = 'Waiting...'; }
                    outputData = '';
                    break;
                case 'DATA_CONCAT':
                    const inputsA = inputs['dataA'];
                    const inputsB = inputs['dataB'];
                    if (inputsA && inputsB) {
                        const concatRes = concatenateData(inputsA.data, inputsA.format, inputsB.data, inputsB.format, sourceNode.interpretAsText);
                        outputData = concatRes.output;
                        sourceNode.outputFormat = concatRes.format;
                    } else {
                        outputData = 'Waiting for inputs.';
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
                        if (mS && dS && pS?.n) outputData = modPow(BigInt(mS.replace(/\s+/g, '')), BigInt(dS), BigInt(pS.n)).toString();
                        else outputData = 'Waiting...';
                    } catch (err) { outputData = "ERROR"; }
                    break;
                case 'SIMPLE_RSA_VERIFY':
                    try {
                        const mV = inputs['message']?.data; const sV = inputs['signature']?.data;
                        const pkC = currentConnections.find(c => c.target === sourceId && c.targetPortId === 'publicKey');
                        const pkS = newNodesMap.get(pkC?.source);
                        let nV, eV;
                        if (pkS?.n_pub) { nV = BigInt(pkS.n_pub); eV = BigInt(pkS.e_pub); }
                        if (mV && sV && nV) {
                            const dec = modPow(BigInt(sV.replace(/\s+/g, '')), eV, nV);
                            outputData = (dec === BigInt(mV.replace(/\s+/g, ''))) ? "SUCCESS: Signature Valid" : "FAILURE: Signature Invalid";
                        } else outputData = 'Waiting...';
                    } catch (err) { outputData = "ERROR"; }
                    break;
                case 'SYM_ENC':
                    if (inputs['data']?.data && inputs['key']?.data && !inputs['data'].data.startsWith('ERROR')) {
                        isProcessing = true;
                        symmetricEncrypt(inputs['data'].data, inputs['key'].data, sourceNode.symAlgorithm || 'AES-GCM').then(res => setNodes(prev => prev.map(n => n.id === sourceId ? { ...n, dataOutput: res, isProcessing: false } : n)));
                        processed.add(sourceId); nodesToProcess.push(...findAllTargets(sourceId)); continue;
                    } else outputData = 'Waiting...';
                    break;
                case 'SYM_DEC':
                    if (inputs['cipher']?.data && inputs['key']?.data && !inputs['cipher'].data.startsWith('ERROR')) {
                        isProcessing = true;
                        symmetricDecrypt(inputs['cipher'].data, inputs['key'].data, sourceNode.symAlgorithm || 'AES-GCM').then(res => setNodes(prev => prev.map(n => n.id === sourceId ? { ...n, dataOutput: res, isProcessing: false } : n)));
                        processed.add(sourceId); nodesToProcess.push(...findAllTargets(sourceId)); continue;
                    } else outputData = 'Waiting...';
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
        processed.add(sourceId);
        nodesToProcess.push(...findAllTargets(sourceId));
    }
    return Array.from(newNodesMap.values());
};
