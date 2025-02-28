/* global BigInt */
import { memo, useEffect, useState, useMemo } from "react";
import { Handle, Position } from "@xyflow/react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCopy} from "@fortawesome/free-solid-svg-icons";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import styled from "styled-components";

const NodeContainer = styled.div`
  padding: 10px;
  border: 1px solid #ccc;
  border-radius: 4px;
  background-color: #fff;
  text-align: center;
  box-sizing: border-box;
  position: relative;
  min-width: 120px;
`;

const OutputText = styled.p`
  font-size: 1rem;
  color: #333;
  margin: 8px 0;
`;

const Icon = styled(FontAwesomeIcon)`
  cursor: pointer;
  color: #ff6600;
  position: absolute;
  bottom: 5px;
  right: 5px;
`;

const determineType = (str) => {
  // If it's binary
  if (/^[01]+$/.test(str)) {
    return "Binary"; // Return the type as "Binary"
  }
  // If it's hexadecimal
  else if (/^[0-9a-fA-F]+$/.test(str)) {
    return "Hexadecimal"; // Return the type as "Hexadecimal"
  }
  // If it's text (only letters and spaces)
  else if (/^[a-zA-Z\s]+$/.test(str)) {
    return "Text"; // Return the type as "Text"
  }
  // If it's not recognized, return "Unknown"
  else {
    return "Unknown"; // Return the type as "Unknown"
  }
};

const convertToType = (inputString, type) => {
  // Step 1: Convert the input string into an array of numbers
  const asciiCodes = inputString.split(' ')
    .map(num => parseInt(num, 10));  // Convert each string number to a base-10 integer (ASCII code)

  switch(type) {
    case "Text":
      // Convert ASCII codes back to characters (text)
      return asciiCodes.map(code => String.fromCharCode(code)).join(''); // Convert each ASCII code to the corresponding character

    case "Binary":
      // Convert ASCII codes to binary
      return asciiCodes.map(code => code.toString(2).padStart(8, '0')).join(' '); // Convert each to 8-bit binary

    case "Hexadecimal":
      // Convert ASCII codes to hexadecimal
      return asciiCodes.map(code => code.toString(16).padStart(2, '0')).join(' '); // Convert each to hex

    case "Decimal":
      // Return the ASCII codes as decimal values
      return asciiCodes.join(' '); // Return ASCII codes as space-separated decimals

    default:
      return "Invalid type"; // Return an error if the type is not recognized
  }
};





const OutputNode = ({ data, nodeKey }) => {
  const [selectedType, setSelectedType] = useState("Decimal");
  const [output, setOutput] = useState("");

  const types = useMemo(
      () => ({
        "Decimal": "Decimal",
        "Binary": "Binary",
        "Hexadecimal": "Hexadecimal",
        "Text": "Text",
      }),
      []
    );

  const handleCopy = () => {
    navigator.clipboard.writeText(output.toString());
    toast.success("Text copied to clipboard", {
      position: "top-right",
      autoClose: 2000,
    });
  };
 
  useEffect(() => {
    if (data.input !== undefined && data.input !== null) {
        toast.error(data.input + " ||| " + selectedType, {
          position: "top-right",
        });
        setOutput(convertToType(data.input, selectedType));
    } else {
      setOutput("");
      setSelectedType("Decimal");
    }
  }, [data.input, selectedType]);

  return (
    <NodeContainer>
      <Handle type="target" position={Position.Top} id="input-in-top" />
      <Handle type="target" position={Position.Left} id="input-in-left" />
      <Handle type="target" position={Position.Right} id="input-in-right" />
      <Handle type="target" position={Position.Bottom} id="input-in-bottom" />
      
      <div>
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
          >
            {Object.keys(types).map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>

      <OutputText>{output}</OutputText>
      <Icon icon={faCopy} style={{color:"ff0072"}} onClick={handleCopy} />
      <Handle type="source" position={Position.Top} id="output-out-top" />
      <Handle type="source" position={Position.Left} id="output-out-left" />
      <Handle type="source" position={Position.Right} id="output-out-right" />
      <Handle type="source" position={Position.Bottom} id="output-out-bottom" />
    </NodeContainer>
  );
};

export default memo(OutputNode);