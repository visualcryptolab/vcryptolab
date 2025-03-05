/* global BigInt */
import { memo, useEffect, useState, useMemo } from "react";
import { Handle, Position } from "@xyflow/react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCopy } from "@fortawesome/free-solid-svg-icons";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import styled from "styled-components";
import UserInputData, { INPUT_TYPES } from "../../../models/UserInputData";

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

const OutputNode = ({ data, nodeKey }) => {
  const [selectedType, setSelectedType] = useState(INPUT_TYPES.DECIMAL);
  const [typeToConvert, setTypeToConvert] = useState(INPUT_TYPES.DECIMAL);
  const [output, setOutput] = useState("");
  const [outputConverted, setOutputConverted] = useState("");
  const [showConversion, setShowConversion] = useState(false);

  const types = useMemo(() => ({
    [INPUT_TYPES.DECIMAL]: INPUT_TYPES.DECIMAL,
    [INPUT_TYPES.BINARY]: INPUT_TYPES.BINARY,
    [INPUT_TYPES.HEXADECIMAL]: INPUT_TYPES.HEXADECIMAL,
    [INPUT_TYPES.TEXT]: INPUT_TYPES.TEXT,
  }), []);

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    toast.success("Text copied to clipboard", { position: "top-right", autoClose: 2000 });
  };

  useEffect(() => {
    if (data.input !== undefined && data.input !== null) {
      const userInput = data.input;
      setOutput(userInput.inputValue);
      setSelectedType(userInput.inputFormat);
      toast.success("Output:" + userInput.inputValue, { position: "top-right", autoClose: 2000 });
      // Validate if the selected type is compatible with the input value
      if (!UserInputData.isCompatibleType(output, selectedType)) {
        const compatibleType = UserInputData.determineType(output);
        setSelectedType(compatibleType);
        toast.error(`Input type is incompatible. Switching to "${compatibleType}"`, { position: "top-right", autoClose: 5000 });
      }
    } else {
      setOutput("");
      setSelectedType("");
    }
  }, [data.input, selectedType]);

  useEffect(() => {
    if (showConversion) {
      // Automatically convert to Decimal when toggle button is clicked
      setOutputConverted(UserInputData.convertToType(output, selectedType, INPUT_TYPES.DECIMAL));
    }
  }, [showConversion, output, selectedType]);

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
                setOutputConverted(UserInputData.convertToType(data.input.inputValue, selectedType, e.target.value));
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
