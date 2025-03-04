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
  // If it's decimal
  if (/^[0-9]+$/.test(str)) {
    return "Decimal"; // Return the type as "Decimal"
  }
  // If it's binary. Now this is never going to be selected, since it will fall into the Decimal category. 
  // Possible improvement, take as binary inputs that start with 0. 
  else if (/^[01]+$/.test(str)) {
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
    return "Text"; 
  }
};

const isCompatibleType = (str, type) => {
  switch (type) {
    case "Binary":
      return /^[01]+$/.test(str); // Acepta solo caracteres 0 y 1

    case "Decimal":
      return /^(0|[1-9][0-9]*)$/.test(str); // Asegura que es un número decimal válido

    case "Hexadecimal":
      return /^[0-9a-fA-F]+$/.test(str); // Acepta solo caracteres hexadecimales

    case "Text":
      return /^[a-zA-Z\s]+$/.test(str); // Solo letras y espacios

    default:
      return false; // Tipo desconocido o no válido
  }
};



const convertToType = (inputString, originalType, resultType) => {
  // Step 1: Interpret inputString according to originalType
  let interpretedString = '';

  if (originalType === "Text") {
    // If the original type is text, keep the string as is
    interpretedString = inputString;
  } else if (originalType === "Binary") {
    // If the original type is binary, convert it to text (ASCII)
    interpretedString = inputString.split(' ').map(bin => String.fromCharCode(parseInt(bin, 2))).join('');
  } else if (originalType === "Hexadecimal") {
    // If the original type is hexadecimal, convert it to text (ASCII)
    interpretedString = inputString.split(' ').map(hex => String.fromCharCode(parseInt(hex, 16))).join('');
  } else if (originalType === "Decimal") {
    // If the original type is decimal, convert it to text (ASCII)
    interpretedString = inputString.split(' ').map(num => String.fromCharCode(parseInt(num, 10))).join('');
  } else {
    return "Invalid original type"; // Return an error if the original type is not recognized
  }

  // Step 2: Convert interpretedString to the desired type (resultType)
  switch (resultType) {
    case "Text":
      // Convert to text (already interpreted as text)
      return interpretedString;

    case "Binary":
      // Convert to binary
      return interpretedString.split('').map(char => char.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');

    case "Hexadecimal":
      // Convert to hexadecimal
      return interpretedString.split('').map(char => char.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');

    case "Decimal":
      // Convert to decimal
      return interpretedString.split('').map(char => char.charCodeAt(0).toString(10)).join(' ');

    default:
      return "Invalid result type"; // Return an error if the result type is not recognized
  }
};





const OutputNode = ({ data, nodeKey }) => {
  const [selectedType, setSelectedType] = useState("Decimal");
  const [typeToConvert, setTypeToConvert] = useState("Decimal");
  const [output, setOutput] = useState("");
  const [outputConverted, setOutputConverted] = useState("");
  const [typeSelectorHasChanged, setTypeSelectorHasChanged] = useState(false);

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
        toast.error(data.input + " ||| " + selectedType + " ||| " + typeSelectorHasChanged, {
          position: "top-right",
        });
        //setOutput(convertToType(data.input, selectedType));
        setOutput(data.input);
        if (typeSelectorHasChanged && isCompatibleType(data.input, selectedType)) {
          setSelectedType(selectedType);
        } else {
          setSelectedType(determineType(data.input));
        }
        setTypeToConvert(typeToConvert);
    } else {
      setOutput("");
      setSelectedType("");
    }
  }, [data.input]);

  return (
    <NodeContainer>
      <Handle type="target" position={Position.Top} id="input-in-top" />
      <Handle type="target" position={Position.Left} id="input-in-left" />
      <Handle type="target" position={Position.Right} id="input-in-right" />
      <Handle type="target" position={Position.Bottom} id="input-in-bottom" />
      
      <div>
          <select
            value={selectedType}
            onChange={(e) => {
              setSelectedType(e.target.value);
              setTypeSelectorHasChanged(true);  
            }}
          >
            {Object.keys(types).map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>

      <OutputText>{output}</OutputText>

      <div>
          <select
            value={typeToConvert}
            onChange={(e) => {
              setTypeToConvert(e.target.value);
              setOutputConverted(convertToType(data.input, selectedType, typeToConvert));
            }}
          >
            {Object.keys(types).map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>

      <OutputText>{outputConverted}</OutputText>
      <Icon icon={faCopy} style={{color:"ff0072"}} onClick={handleCopy} />
      <Handle type="source" position={Position.Top} id="output-out-top" />
      <Handle type="source" position={Position.Left} id="output-out-left" />
      <Handle type="source" position={Position.Right} id="output-out-right" />
      <Handle type="source" position={Position.Bottom} id="output-out-bottom" />
    </NodeContainer>
  );
};

export default memo(OutputNode);