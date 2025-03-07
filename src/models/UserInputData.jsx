// Define a constant object with the possible input types
export const INPUT_TYPES = {
  BINARY: "Binary",
  DECIMAL: "Decimal",
  HEXADECIMAL: "Hexadecimal",
  TEXT: "Text (UTF-8)",
};

// Class definition using the INPUT_TYPES constant
class UserInputData {
  constructor(inputValue = '', inputFormat = INPUT_TYPES.DECIMAL) {
    this.inputValue = inputValue;
    this.inputFormat = inputFormat;
  }

  /**
   * Checks if the given input matches the expected format type.
   * @param {string} value - The input string to validate.
   * @param {string} format - The expected format type (Binary, Decimal, Hexadecimal, Text).
   * @returns {boolean} - Returns true if the value is valid for the given format, otherwise false.
   */
  static isCompatibleType(value, format) {
    switch (format) {
      case INPUT_TYPES.BINARY:
        return /^[01]+$/.test(value);
      case INPUT_TYPES.DECIMAL:
        return /^(0|[1-9][0-9]*)$/.test(value);
      case INPUT_TYPES.HEXADECIMAL:
        return /^[0-9a-fA-F]+$/.test(value);
      case INPUT_TYPES.TEXT:
        return value !== undefined && value !== null;
      default:
        return false;
    }
  }

  static determineType(str) {
    if (/^[0-9]+$/.test(str)) return INPUT_TYPES.DECIMAL;
    else if (/^[01]+$/.test(str)) return INPUT_TYPES.BINARY;
    else if (/^[0-9a-fA-F]+$/.test(str)) return INPUT_TYPES.HEXADECIMAL;
    else if (str !== undefined && str !== null) return INPUT_TYPES.TEXT;
    return INPUT_TYPES.TEXT; // Default to Text if not recognized
  }
  
  static convertToType(inputString, originalType, resultType) {
    let interpretedString = '';
  
    // Step 1: Interpret the inputString according to originalType
    switch (originalType) {
      case INPUT_TYPES.TEXT:
        interpretedString = inputString;
        break;
      case INPUT_TYPES.BINARY:
        interpretedString = inputString.split(' ').map(bin => String.fromCharCode(parseInt(bin, 2))).join('');
        break;
      case INPUT_TYPES.HEXADECIMAL:
        interpretedString = inputString.split(' ').map(hex => String.fromCharCode(parseInt(hex, 16))).join('');
        break;
      case INPUT_TYPES.DECIMAL:
        interpretedString = inputString.split(' ').map(num => String.fromCharCode(parseInt(num, 10))).join('');
        break;
      default:
        interpretedString = '';
        break;
    }
  
    // Step 2: Convert interpretedString to the desired resultType
    switch (resultType) {
      case INPUT_TYPES.TEXT:
        return interpretedString;
  
      case INPUT_TYPES.BINARY:
        return interpretedString.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');
  
      case INPUT_TYPES.HEXADECIMAL:
        return interpretedString.split('').map(char => char.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
  
      case INPUT_TYPES.DECIMAL:
        return interpretedString.split('').map(char => char.charCodeAt(0).toString(10)).join(' ');
  
      default:
        return "Invalid result type";
    }
  }

  /**
 * Casts the input value to a string and converts it to the specified type.
 * 
 * @param {any} value - The value to be casted and converted.
 * @param {string} targetType - The target type to convert the string value to. 
 *  Supported types: "Decimal", "Binary", "Hexadecimal", "Text".
 * @returns {string} - The converted value in the specified type.
 */
  static castAndConvert = (value, targetType) => {
    // Cast the value to a string
    let stringValue = String(value);
  
    // Convert the string value to the desired type
    switch (targetType) {
      case INPUT_TYPES.BINARY:
        return stringValue.split(' ').map(bin => parseInt(bin, 2)); // Convert binary to number
      case INPUT_TYPES.DECIMAL:
        return parseInt(stringValue, 10); // Convert decimal string to number
      case INPUT_TYPES.HEXADECIMAL:
        return parseInt(stringValue, 16); // Convert hexadecimal string to number
      case INPUT_TYPES.TEXT:
        return stringValue; // Return as string
      default:
        return stringValue; // Default to original string value if unknown type
    }
  };
}

export default UserInputData;
