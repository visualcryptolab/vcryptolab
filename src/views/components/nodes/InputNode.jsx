import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCopy } from "@fortawesome/free-solid-svg-icons";
import { Handle, Position } from "@xyflow/react";
import { memo, useState, useEffect, useMemo } from "react";
import "react-toastify/dist/ReactToastify.css";
import styled from "styled-components";
import { toast } from "react-toastify";
import data from "../../../models/UserInputData";
import UserInputData from "../../../models/UserInputData";

// Styled components for input node
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
  width: 80%; /* Adjusted width to match the output node input size */
  height: 40px;  // Adjusted height to match output node input size
  background-color: transparent;
  border: none;
  resize: none;
  overflow: hidden;
  outline: none;
  font-size: 14px;
  color: #333;
  padding: 5px;
  box-sizing: border-box;
  text-align: center; /* Ensures text inside is centered */
  &::placeholder {
    color: #aaa;
  }
`;

const IconContainer = styled.div`
  position: absolute;
  bottom: 3px;
  right: 3px;
  cursor: pointer;
  color: #ff6f00;  /* Orange color for the copy icon */
`;

const SelectorContainer = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
`;

const Label = styled.label`
  font-size: 14px;
  color: #333;
  font-weight: bold;
  margin-right: 10px;
`;

const ButtonContainer = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
  margin-top: 10px;
`;

const InputNode = ({ data }) => {
  const [selectedType, setSelectedType] = useState("Decimal");
  const [text, setText] = useState("0");

  // Types that are available in the selector
  const types = useMemo(
    () => ({
      "Decimal": "Decimal",
      "Binary": "Binary",
      "Hexadecimal": "Hexadecimal",
      "Text (UTF-16)": "Text (UTF-16)",
    }),
    []
  );

  const convertToType = (inputString, type) => {
    switch (type) {
      case "Text (UTF-16)":
        return inputString;
      case "Binary":
        return Array.from(inputString)
          .map(char => char.charCodeAt(0).toString(2).padStart(8, "0"))
          .join(" ");
      case "Hexadecimal":
        return Array.from(inputString)
          .map(char => char.charCodeAt(0).toString(16).padStart(2, "0"))
          .join(" ");
      case "Decimal":
        return inputString;
      default:
        return "0";
    }
  };

  const handleChange = (event) => {
    const input = event.target.value;
    setText(input);
    const userInputData = new UserInputData(input, selectedType);
    data.output = userInputData;
    event.target.style.height = "auto";
    event.target.style.height = `${event.target.scrollHeight}px`;
  };

  useEffect(() => {
    //const output = convertToType(text, selectedType);
    const userInputData = new UserInputData(text, selectedType);
    data.output = userInputData;
  }, [selectedType]);

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
    <NodeContainer>
      <Handle type="target" position={Position.Top} id="input-top" />
      <Handle type="target" position={Position.Left} id="input-left" />
      <Handle type="target" position={Position.Right} id="input-right" />
      <Handle type="target" position={Position.Bottom} id="input-bottom" />

      <SelectorContainer>
        <Label htmlFor="inputType">Input Type</Label>
        <select
          id="inputType"
          value={selectedType}
          onChange={(e) => setSelectedType(e.target.value)}
        >
          {Object.keys(types).map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
      </SelectorContainer>

      <StyledInput
        value={text}
        onChange={handleChange}
        placeholder="Enter text here"
        rows={1}
      />

      <ButtonContainer>
        <IconContainer onClick={handleCopy}>
          <FontAwesomeIcon icon={faCopy} />
        </IconContainer>
      </ButtonContainer>

      <Handle type="source" position={Position.Top} id="output-top" />
      <Handle type="source" position={Position.Left} id="output-left" />
      <Handle type="source" position={Position.Right} id="output-right" />
      <Handle type="source" position={Position.Bottom} id="output-bottom" />
    </NodeContainer>
  );
};

export default memo(InputNode);
