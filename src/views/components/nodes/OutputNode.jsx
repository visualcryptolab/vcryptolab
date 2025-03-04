/* global BigInt */
import { memo, useEffect, useState, useMemo } from "react";
import { Handle, Position } from "@xyflow/react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCopy } from "@fortawesome/free-solid-svg-icons";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import styled from "styled-components";

const NodeContainer = styled.div`
  padding: 20px;
  border: 1px solid #ccc;
  border-radius: 8px;
  background-color: #f9f9f9;
  text-align: center;
  box-sizing: border-box;
  position: relative;
  min-width: 220px;
  box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1);
`;

const OutputText = styled.p`
  font-size: 1rem;
  color: #333;
  margin: 12px 0;
  padding: 8px;
  background-color: #f1f1f1;
  border-radius: 4px;
  font-family: 'Courier New', Courier, monospace;
  width: 100%; /* To expand the output to the full width */
`;

const Icon = styled(FontAwesomeIcon)`
  cursor: pointer;
  color: #ff6600;
  transition: transform 0.2s ease-in-out;

  &:hover {
    transform: scale(1.1);
  }
`;

const Button = styled.button`
  background-color: #007bff;
  color: #fff;
  border: none;
  padding: 8px 16px;
  border-radius: 4px;
  margin-top: 10px;
  cursor: pointer;
  font-size: 14px;

  &:hover {
    background-color: #0056b3;
  }

  &:focus {
    outline: none;
  }
`;

const SelectWrapper = styled.div`
  margin: 10px 0;
`;

const Label = styled.label`
  font-weight: bold;
  margin-bottom: 5px;
  display: block;
  text-align: left;
  font-size: 14px;
  color: #444;
`;

const Row = styled.div`
  display: flex;
  justify-content: space-between;
  gap: 15px;
  margin-bottom: 15px;
`;

const RowWithButton = styled.div`
  display: flex;
  justify-content: space-between;
  gap: 10px;
  align-items: center;
`;

const determineType = (str) => {
  if (/^[0-9]+$/.test(str)) return "Decimal";
  if (/^[01]+$/.test(str)) return "Binary";
  if (/^[0-9a-fA-F]+$/.test(str)) return "Hexadecimal";
  if (/^[a-zA-Z\s]+$/.test(str)) return "Text (UTF-16)";
  return "Text (UTF-16)"; // Default to Text if not recognized
};

const isCompatibleType = (str, type) => {
  switch (type) {
    case "Binary": return /^[01]+$/.test(str);
    case "Decimal": return /^(0|[1-9][0-9]*)$/.test(str);
    case "Hexadecimal": return /^[0-9a-fA-F]+$/.test(str);
    case "Text (UTF-16)": return /^[a-zA-Z\s]+$/.test(str);
    default: return false;
  }
};

const convertToType = (inputString, originalType, resultType) => {
  let interpretedString = '';

  // Step 1: Interpret the inputString according to originalType
  if (originalType === "Text (UTF-16)") {
    interpretedString = inputString;
  } else if (originalType === "Binary") {
    interpretedString = inputString.split(' ').map(bin => String.fromCharCode(parseInt(bin, 2))).join('');
  } else if (originalType === "Hexadecimal") {
    interpretedString = inputString.split(' ').map(hex => String.fromCharCode(parseInt(hex, 16))).join('');
  } else if (originalType === "Decimal") {
    interpretedString = inputString.split(' ').map(num => String.fromCharCode(parseInt(num, 10))).join('');
  }

  // Step 2: Convert interpretedString to the desired resultType
  switch (resultType) {
    case "Text (UTF-16)":
      return interpretedString;

    case "Binary":
      return interpretedString.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');

    case "Hexadecimal":
      return interpretedString.split('').map(char => char.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');

    case "Decimal":
      return interpretedString.split('').map(char => char.charCodeAt(0).toString(10)).join(' ');

    default:
      return "Invalid result type";
  }
};

const OutputNode = ({ data, nodeKey }) => {
  const [selectedType, setSelectedType] = useState("Decimal");
  const [typeToConvert, setTypeToConvert] = useState("Decimal");
  const [output, setOutput] = useState("");
  const [outputConverted, setOutputConverted] = useState("");
  const [showConversion, setShowConversion] = useState(false);  // State for toggle visibility

  const types = useMemo(() => ({
    "Decimal": "Decimal",
    "Binary": "Binary",
    "Hexadecimal": "Hexadecimal",
    "Text (UTF-16)": "Text (UTF-16)",
  }), []);

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    toast.success("Text copied to clipboard", { position: "top-right", autoClose: 2000 });
  };

  useEffect(() => {
    if (data.input !== undefined && data.input !== null) {
      setOutput(data.input);

      // Check if the selected type is compatible with the input value
      const compatible = isCompatibleType(data.input, selectedType);
      if (!compatible) {
        const compatibleType = determineType(data.input);
        setSelectedType(compatibleType);
        toast.error(`Input type is incompatible. Switching to "${compatibleType}"`, { position: "top-right", autoClose: 5000 });
      }
      setTypeToConvert(typeToConvert);
    } else {
      setOutput("");
      setSelectedType("");
    }
  }, [data.input, selectedType, typeToConvert]);

  useEffect(() => {
    if (showConversion) {
      // Automatically convert to Decimal when toggle button is clicked
      setOutputConverted(convertToType(data.input, selectedType, "Decimal"));
    }
  }, [showConversion, data.input, selectedType]);

  return (
    <NodeContainer>
      <Handle type="target" position={Position.Top} id="input-in-top" />
      <Handle type="target" position={Position.Left} id="input-in-left" />
      <Handle type="target" position={Position.Right} id="input-in-right" />
      <Handle type="target" position={Position.Bottom} id="input-in-bottom" />

      {/* Input Type Selector */}
      <Row>
        <div>
          <Label>Input Type</Label>
          <select value={selectedType} onChange={(e) => {
            setSelectedType(e.target.value);
          }}>
            {Object.keys(types).map((name) => (
              <option key={name} value={name}>{name}</option>
            ))}
          </select>
        </div>

        {/* Convert Button */}
        <Button onClick={() => setShowConversion(!showConversion)}>
          {showConversion ? "Don't Convert" : "Convert Type"}
        </Button>
      </Row>

      {/* Output Section */}
      <RowWithButton>
        <OutputText>{output}</OutputText>
        <Icon icon={faCopy} onClick={() => handleCopy(output)} />
      </RowWithButton>

      {/* Conversion Section */}
      {showConversion && (
        <>
          <Row>
            <div>
              <Label>Convert to</Label>
              <select value={typeToConvert} onChange={(e) => {
                setTypeToConvert(e.target.value);
                setOutputConverted(convertToType(data.input, selectedType, e.target.value));
              }}>
                {Object.keys(types).map((name) => (
                  <option key={name} value={name}>{name}</option>
                ))}
              </select>
            </div>
          </Row>

          <RowWithButton>
            <OutputText>{outputConverted}</OutputText>
            <Icon icon={faCopy} onClick={() => handleCopy(outputConverted)} />
          </RowWithButton>
        </>
      )}

      <Handle type="source" position={Position.Top} id="output-out-top" />
      <Handle type="source" position={Position.Left} id="output-out-left" />
      <Handle type="source" position={Position.Right} id="output-out-right" />
      <Handle type="source" position={Position.Bottom} id="output-out-bottom" />
    </NodeContainer>
  );
};

export default memo(OutputNode);
