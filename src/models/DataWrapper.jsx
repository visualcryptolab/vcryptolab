// Define a constant object with the possible input types
export const FORMAT_TYPES = {
  BINARY: "Binary",
  DECIMAL: "Decimal",
  HEXADECIMAL: "Hexadecimal",
  TEXT: "Text (UTF-8)",
};

// Class definition using the INPUT_TYPES constant
class DataWrapper {
  constructor(value = '', format = FORMAT_TYPES.DECIMAL) {
    this.value = value;
    this.format = format;
  }

  get value() {
    return this._value;
  }

  set value(newValue) {
    this._value = newValue;
  }

  get format() {
    return this._format;
  }

  set format(newFormat) {
    if (Object.values(FORMAT_TYPES).includes(newFormat)) {
      this._format = newFormat;
    } else {
      this._format = FORMAT_TYPES.TEXT;
    }
  }

  /**
   * Checks if the given input matches the expected format type.
   * @param {string} value - The input string to validate.
   * @param {string} format - The expected format type (Binary, Decimal, Hexadecimal, Text).
   * @returns {boolean} - Returns true if the value is valid for the given format, otherwise false.
   */
  static isCompatibleType(value, format) {
    switch (format) {
      case FORMAT_TYPES.BINARY:
        return /^[01]+$/.test(value);
      case FORMAT_TYPES.DECIMAL:
        return /^(0|[1-9][0-9]*)$/.test(value);
      case FORMAT_TYPES.HEXADECIMAL:
        return /^[0-9a-fA-F]+$/.test(value);
      case FORMAT_TYPES.TEXT:
        return value !== undefined && value !== null;
      default:
        return false;
    }
  }

  static determineType(str) {
    if (/^[0-9]+$/.test(str)) return FORMAT_TYPES.DECIMAL;
    else if (/^[01]+$/.test(str)) return FORMAT_TYPES.BINARY;
    else if (/^[0-9a-fA-F]+$/.test(str)) return FORMAT_TYPES.HEXADECIMAL;
    else if (str !== undefined && str !== null) return FORMAT_TYPES.TEXT;
    return FORMAT_TYPES.TEXT; // Default to Text if not recognized
  }

  static convertToType(inputString, originalType, resultType) {
    let binaryString = '';
  
    // Step 1: Interpret the inputString according to originalType and convert to binary
    switch (originalType) {
      case FORMAT_TYPES.TEXT:
        binaryString = inputString.split('')
          .map(char => char.charCodeAt(0).toString(2).padStart(8, '0'))
          .join(' ');
        break;
      case FORMAT_TYPES.BINARY:
        binaryString = inputString;  // Already in binary, no need to convert
        break;
      case FORMAT_TYPES.HEXADECIMAL:
        binaryString = inputString.split(' ')
          .map(hex => parseInt(hex, 16).toString(2).padStart(8, '0'))
          .join(' ');
        break;
      case FORMAT_TYPES.DECIMAL:
        binaryString = inputString.split(' ')
          .map(num => parseInt(num, 10).toString(2).padStart(8, '0'))
          .join(' ');
        break;
      default:
        binaryString = '';
        break;
    }
    console.log("bin: " + binaryString);

    // Step 2: Convert binaryString to the desired resultType
    switch (resultType) {
      case FORMAT_TYPES.TEXT:
        return binaryString.split(' ')
          .map(bin => String.fromCharCode(parseInt(bin, 2)))
          .join('');
  
      case FORMAT_TYPES.BINARY:
        return binaryString;
  
      case FORMAT_TYPES.HEXADECIMAL:
        return binaryString.split(' ')
          .map(bin => parseInt(bin, 2).toString(16).padStart(2, '0'))
          .join(' ');
  
      case FORMAT_TYPES.DECIMAL:
        return binaryString.split(' ')
          .map(bin => parseInt(bin, 2).toString(10))
          .join(' ');
  
      default:
        return "Invalid result type";
    }
  }
}

export default DataWrapper;
