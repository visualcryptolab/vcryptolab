import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCopy } from "@fortawesome/free-solid-svg-icons";
import { Handle, Position } from "@xyflow/react";
import { memo, useState, useEffect, useMemo } from "react";
import "react-toastify/dist/ReactToastify.css";
import NodeWrapper from "./NodeWrapper";
import styled from "styled-components";
import { toast } from "react-toastify";

const NodeContainer = styled.div`
  padding: 15px;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  background-color: #ffffff;
  text-align: center;
  width: 100%;
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
  transition: transform 0.2s, box-shadow 0.2s;
  box-sizing: border-box;
  &:hover {
    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
  }
`;

const StyledInput = styled.textarea`
  width: 100%;
  height: auto;
  background-color: transparent;
  border: none;
  resize: none;
  overflow: hidden;
  outline: none;
  font-size: 14px;
  color: #333;
  padding: 5px;
  box-sizing: border-box;
  &::placeholder {
    color: #aaa;
  }
`;

const IconContainer = styled.div`
  position: absolute;
  bottom: 3px;
  right: 3px;
  cursor: pointer;
  color: #ff0071;
`;

const InputNode = ({ data }) => {
  const [selectedType, setSelectedType] = useState("Decimal");
  const [text, setText] = useState("0");
  const [forceAscii, setForceAscii] = useState(false);
  const [showInfo, setShowInfo] = useState(false);

  const types = useMemo(
        () => ({
          "Decimal": "Decimal",
          "Binary": "Binary",
          "Hexadecimal": "Hexadecimal",
          "Text": "Text",
        }),
        []
      );

  const convertTextOld = (input, forceAscii) => {
    if (input === "") return "";
    if (forceAscii) {
      return Array.from(input)
        .map((char) => char.charCodeAt(0))
        .join("");
    } else if (/^[01]+$/.test(input)) {
      return input[0] === "0" ? parseInt(input, 2).toString() : input;
    } else if (/^\d+$/.test(input)) {
      return input;
    } else if (/[a-zA-Z]/.test(input)) {
      return Array.from(input)
        .map((char) => char.charCodeAt(0))
        .join("");
    }
    return input;
  };

  const convertToType = (inputString, type) => {
    switch (type) {
      case "Text":
        //No conversion. The input is directly a string.
        return inputString;
        /*// Convierte una secuencia de códigos ASCII en texto
        return inputString
          .split(" ")
          .map(code => String.fromCharCode(parseInt(code, 10)))
          .join("");*/
  
      case "Binary":
        // Convierte un texto a su representación binaria ASCII
        return Array.from(inputString)
          .map(char => char.charCodeAt(0).toString(2).padStart(8, "0"))
          .join(" ");
  
      case "Hexadecimal":
        // Convierte un texto a su representación hexadecimal ASCII
        return Array.from(inputString)
          .map(char => char.charCodeAt(0).toString(16).padStart(2, "0"))
          .join(" ");
  
      case "Decimal":
        return inputString;
        /*
        // Convierte un texto en códigos ASCII decimales
        return Array.from(inputString)
          .map(char => char.charCodeAt(0).toString(10))
          .join(" ");*/
  
      default:
        // By default we transfer a 0
        //input[0] === "0" ? parseInt(input, 2).toString() : input;
        return "0";
    }
  };
  

  const convertToTypeOld = (inputString, type) => {
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

  const handleChange = (event) => {
    const input = event.target.value;
    setText(input);
    //const output = convertText(input, forceAscii);
    const output = convertToType(input, selectedType);
    data.output = output;
    data.rawOutput = input;
    event.target.style.height = "auto";
    event.target.style.height = `${event.target.scrollHeight}px`;
  };

  useEffect(() => {
    //const output = convertText(text, forceAscii);    
    const output = convertToType(text, selectedType);
    data.output = output;
    toast.success(text + " **** " + selectedType + " **** " + output, {
      position: "top-right",
      autoClose: 2000,
    });

  }, [forceAscii, selectedType]);

  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    toast.success("Text copied to clipboard", {
      position: "top-right",
      autoClose: 2000,
      hideProgressBar: false,
      closeOnClick: true,
      pauseOnHover: true,
      draggable: true,
      progress: undefined,
    });
  };

  return (
    <>
      {showInfo && (
        <div
          style={{
            position: "absolute",
            bottom: "calc(100% + 5px)",
            left: "5px",
            padding: "10px",
            backgroundColor: "#fff",
            border: "1px solid #ccc",
            borderRadius: "4px",
            boxShadow: "0 2px 6px rgba(0, 0, 0, 0.1)",
            zIndex: 100,
            fontSize: "12px",
            width: "250px",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "5px",
            }}
          >
            <strong>Input Node Info</strong>
            <span
              style={{ cursor: "pointer", fontWeight: "bold" }}
              onClick={() => setShowInfo(false)}
            >
              ✖
            </span>
          </div>
          <p style={{ margin: "0 0 5px", color: "#555" }}>
            This node converts text based on its content:
          </p>
          <ul style={{ paddingLeft: "15px", margin: "0" }}>
            <li>Binary (starting with 0): converted to a number</li>
            <li>Numeric: remains unchanged</li>
            <li>Alphabetic: converted to ASCII codes</li>
            <li>Toggle: force ASCII conversion</li>

          </ul>
        </div>
      )}
      <NodeContainer style={{ position: "relative", zIndex: 3 }}>
        <Handle type="target" position={Position.Top} id="input-top" />
        <Handle type="target" position={Position.Left} id="input-left" />
        <Handle type="target" position={Position.Right} id="input-right" />
        <Handle type="target" position={Position.Bottom} id="input-bottom" />
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
  
        <div
          style={{
            position: "absolute",
            top: "0px",
            left: "5px",
            cursor: "pointer",
            borderRadius: "100%",
          }}
          onClick={() => setShowInfo(true)}
        >
          <span style={{ fontSize: "18px", color: "#007bff" }}>ℹ️</span>
        </div>
  
        <div style={{ position: "absolute", top: "5px", right: "5px" }}>
          <label
            title="Toggle Force ASCII"
            style={{
              position: "relative",
              display: "inline-block",
              width: "50px",
              height: "24px",
              margin: 0,
              cursor: "pointer",
            }}
          >
            <input
              type="checkbox"
              checked={forceAscii}
              onChange={() => setForceAscii(!forceAscii)}
              style={{
                opacity: 0,
                width: 0,
                height: 0,
              }}
            />
            <span
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                backgroundColor: forceAscii ? "#ff0071" : "#ccc",
                transition: "0.4s",
                borderRadius: "24px",
              }}
            ></span>
            <span
              style={{
                position: "absolute",
                height: "18px",
                width: "18px",
                left: forceAscii ? "26px" : "4px",
                bottom: "3px",
                backgroundColor: "white",
                transition: "0.4s",
                borderRadius: "50%",
              }}
            ></span>
          </label>
        </div>
  
        <StyledInput
          value={text}
          onChange={handleChange}
          placeholder="Enter text here"
          rows={1}
          style={{ marginTop: "10px" }}  // added margin to separate from icons
        />
        <IconContainer onClick={handleCopy}>
          <FontAwesomeIcon icon={faCopy} />
        </IconContainer>
        <Handle type="source" position={Position.Top} id="output-top" />
        <Handle type="source" position={Position.Left} id="output-left" />
        <Handle type="source" position={Position.Right} id="output-right" />
        <Handle type="source" position={Position.Bottom} id="output-bottom" />
      </NodeContainer>
    </>
  );
};

export default memo(InputNode);
