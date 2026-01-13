export const arrayBufferToBase64 = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
};

export const base64ToArrayBuffer = (base64) => {
    const binary_string = atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
};

export const arrayBufferToHex = (buffer) => {
    const byteArray = new Uint8Array(buffer);
    return Array.from(byteArray).map(byte => byte.toString(16).padStart(2, '0')).join('');
};

export const hexToArrayBuffer = (hex) => {
    const cleanedHex = hex.replace(/\s/g, '');
    if (cleanedHex.length === 0) return new ArrayBuffer(0);
    const paddedHex = cleanedHex.length % 2 !== 0 ? '0' + cleanedHex : cleanedHex;
    const len = paddedHex.length / 2;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = parseInt(paddedHex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes.buffer;
};

export const arrayBufferToBigIntString = (buffer) => {
    const hex = arrayBufferToHex(buffer);
    if (hex.length === 0) return '0';
    try {
        return BigInt(`0x${hex}`).toString(10);
    } catch (e) {
        return `ERROR: Data too large for BigInt conversion (${buffer.byteLength} bytes).`;
    }
};

export const arrayBufferToHexBig = (buffer) => {
    return arrayBufferToHex(buffer).toUpperCase();
};

export const arrayBufferToBinaryBig = (buffer) => {
    const byteArray = new Uint8Array(buffer);
    let binary = '';
    for (const byte of byteArray) {
        binary += byte.toString(2).padStart(8, '0');
    }
    return binary;
};

export const arrayBufferToBinary = (buffer) => {
    const byteArray = new Uint8Array(buffer);
    return Array.from(byteArray).map(byte => byte.toString(2).padStart(8, '0')).join(' ');
};

export const bigIntToString = (bigIntValue, format, originalLength = 0, isHexLength = false) => {
    if (bigIntValue === null) return 'N/A';
    switch (format) {
        case 'Decimal': return bigIntValue.toString(10);
        case 'Hexadecimal':
            let hexString = bigIntValue.toString(16).toUpperCase();
            if (originalLength > 0) {
                const hexLength = isHexLength ? originalLength : Math.ceil(originalLength / 4);
                hexString = hexString.padStart(hexLength, '0');
                if (hexString.length > hexLength) hexString = hexString.substring(hexString.length - hexLength);
            }
            return hexString;
        case 'Binary':
            let binaryString = bigIntValue.toString(2);
            if (originalLength > 0) {
                binaryString = binaryString.padStart(originalLength, '0');
                if (binaryString.length > originalLength) binaryString = binaryString.substring(binaryString.length - originalLength);
            }
            return binaryString;
        default: return bigIntValue.toString(10);
    }
};

export const convertToUint8Array = (dataStr, sourceFormat) => {
    if (!dataStr) return new Uint8Array(0);
    try {
        if (sourceFormat === 'Text (UTF-8)') return new TextEncoder().encode(dataStr);
        if (sourceFormat === 'Base64') return new Uint8Array(base64ToArrayBuffer(dataStr));
        if (sourceFormat === 'Hexadecimal') {
            const cleanedHex = dataStr.replace(/\s/g, '');
            return new Uint8Array(hexToArrayBuffer(cleanedHex));
        }
        if (sourceFormat === 'Binary') {
            const binaryArray = dataStr.replace(/\s+/g, '').match(/.{1,8}/g) || [];
            const validBytes = binaryArray.map(s => parseInt(s, 2)).filter(b => !isNaN(b));
            return new Uint8Array(validBytes);
        }
        if (sourceFormat === 'Decimal') {
            const decimalArray = dataStr.split(/\s+/).map(s => parseInt(s, 10));
            const validBytes = decimalArray.filter(b => !isNaN(b) && b >= 0 && b >= 255);
            return new Uint8Array(validBytes);
        }
        return new TextEncoder().encode(dataStr);
    } catch (e) {
        console.error(`Conversion to Uint8Array failed for format ${sourceFormat}:`, e);
        return new Uint8Array(0);
    }
};

export const convertDataFormat = (dataStr, sourceFormat, targetFormat, toSingleNumber = false) => {
    if (!dataStr) return '';
    if (sourceFormat === targetFormat || dataStr.startsWith('ERROR')) return dataStr;
    let buffer;
    try {
        if (sourceFormat === 'Text (UTF-8)') buffer = new TextEncoder().encode(dataStr).buffer;
        else if (sourceFormat === 'Base64') buffer = base64ToArrayBuffer(dataStr);
        else if (sourceFormat === 'Hexadecimal') buffer = hexToArrayBuffer(dataStr.replace(/\s/g, ''));
        else if (sourceFormat === 'Binary') {
            const binaryArray = dataStr.replace(/\s+/g, '').match(/.{1,8}/g) || [];
            const validBytes = binaryArray.map(s => parseInt(s, 2)).filter(b => !isNaN(b) && b >= 0 && b <= 255);
            buffer = new Uint8Array(validBytes).buffer;
        } else if (sourceFormat === 'Decimal') {
            const decimalArray = dataStr.split(/\s+/).map(s => parseInt(s, 10));
            const validBytes = decimalArray.filter(b => !isNaN(b) && b >= 0 && b <= 255);
            buffer = new Uint8Array(validBytes).buffer;
        } else buffer = new TextEncoder().encode(dataStr).buffer;
    } catch (e) { return `DECODING ERROR: Failed source format (${sourceFormat}).`; }

    try {
        if (toSingleNumber) {
            if (targetFormat === 'Decimal') return arrayBufferToBigIntString(buffer);
            if (targetFormat === 'Hexadecimal') return arrayBufferToHexBig(buffer);
            if (targetFormat === 'Binary') return arrayBufferToBinaryBig(buffer);
        }
        if (targetFormat === 'Text (UTF-8)') return new TextDecoder().decode(buffer);
        if (targetFormat === 'Base64') return arrayBufferToBase64(buffer);
        if (targetFormat === 'Hexadecimal') return arrayBufferToHex(buffer).toUpperCase().match(/.{1,2}/g)?.join(' ') || '';
        if (targetFormat === 'Binary') return arrayBufferToBinary(buffer);
        if (targetFormat === 'Decimal') return Array.from(new Uint8Array(buffer)).join(' ');
        return `ERROR: Unsupported target format (${targetFormat})`;
    } catch (e) { return `ENCODING ERROR: Failed conversion to ${targetFormat}.`; }
};

export const stringToBigInt = (dataStr, format) => {
    if (!dataStr) return null;
    if (dataStr.includes(' ') && format !== 'Text (UTF-8)' && format !== 'Base64') return null;
    const cleanedStr = dataStr.replace(/\s/g, '');
    try {
        if (format === 'Decimal') { if (!/^\d+$/.test(cleanedStr)) return null; return BigInt(cleanedStr); }
        if (format === 'Hexadecimal') { if (!/^[0-9a-fA-F]+$/.test(cleanedStr)) return null; return BigInt(`0x${cleanedStr}`); }
        if (format === 'Binary') {
            if (!/^[01]+$/.test(cleanedStr)) return null;
            const paddedBinary = cleanedStr.padStart(Math.ceil(cleanedStr.length / 4) * 4, '0');
            return BigInt(`0b${paddedBinary}`);
        }
    } catch (e) { return null; }
    return null;
};
