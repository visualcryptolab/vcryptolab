/* global BigInt */
import { memo, useEffect, useState, useMemo } from "react";
import { Handle, Position } from "@xyflow/react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCopy, faInfoCircle } from "@fortawesome/free-solid-svg-icons"; 
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import styled from "styled-components";
import DataWrapper, { FORMAT_TYPES } from "../../../models/DataWrapper";

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

const InfoIcon = styled(FontAwesomeIcon)`
  cursor: pointer;
  color: #ff6600;
  margin-left: 5px;
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
  const [selectedType, setSelectedType] = useState("");
  const [typeToConvert, setTypeToConvert] = useState("");
  const [output, setOutput] = useState("");
  const [outputConverted, setOutputConverted] = useState("");
  const [showConversion, setShowConversion] = useState(false);

  const types = useMemo(() => ({
    [FORMAT_TYPES.DECIMAL]: FORMAT_TYPES.DECIMAL,
    [FORMAT_TYPES.BINARY]: FORMAT_TYPES.BINARY,
    [FORMAT_TYPES.HEXADECIMAL]: FORMAT_TYPES.HEXADECIMAL,
    [FORMAT_TYPES.TEXT]: FORMAT_TYPES.TEXT,
  }), []);

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    toast.success("Text copied to clipboard", { position: "top-right", autoClose: 2000 });
  };

  useEffect(() => {
    //console.log("data.input: " + JSON.stringify(data.input, null, 2));

    console.log("data.model: " + JSON.stringify(data.model, null, 2));
    //console.log("inputs: " + JSON.stringify(data.model.inputs, null, 2));
    if (data?.model?.inputs.length >0) {
      const sourceInput = data.model.inputs[0]; //If there is more than 1 input, we just use the first one.
      console.log("1st input: " + JSON.stringify(sourceInput, null, 2));
      setOutput(sourceInput.data.value);
      setSelectedType(sourceInput.data.format);
      
      // Validate if the selected type is compatible with the input value
      if (!DataWrapper.isCompatibleType(sourceInput.data.value, selectedType)) {
        const compatibleType = DataWrapper.determineType(sourceInput.data.value);
        setSelectedType(compatibleType);
        toast.error(`Input type is incompatible. Switching to "${compatibleType}"`, { position: "top-right", autoClose: 5000 });
      }
      let newTypeToConvert = typeToConvert;
      if(typeToConvert == "") {
        newTypeToConvert = sourceInput.data.format; 
        setTypeToConvert(newTypeToConvert);
      }

      let newOutputConverted = "";
      if (sourceInput.data.value !== undefined && sourceInput.data.value !== null && sourceInput.data.value !== ""){
        newOutputConverted = DataWrapper.convertToType(sourceInput.data.value, sourceInput.data.format, newTypeToConvert);
        setOutputConverted(newOutputConverted);
        const newOutput = new DataWrapper(outputConverted, newTypeToConvert);
        //data.output = newOutput;
        data.model.data.value = newOutput.value;
        data.model.data.format = newOutput.format;
      } else {
        setOutput("");
        setOutputConverted("");
        data.model.data.value = sourceInput.data.value;
        data.model.data.format = sourceInput.data.format;
      }
    } else {
      setOutput("");
      setSelectedType("");
      setTypeToConvert("");
      setOutputConverted("");
    }
  }, [data]);

  useEffect(() => {
    // Validate if the selected type is compatible with the input value
    if (!DataWrapper.isCompatibleType(output, selectedType)) {
      const compatibleType = DataWrapper.determineType(output);
      setSelectedType(compatibleType);
      toast.error(`Input type is incompatible. Switching to "${compatibleType}"`, { position: "top-right", autoClose: 5000 });
    } 
    const newOutputConverted = DataWrapper.convertToType(output, selectedType, typeToConvert);
    setOutputConverted(newOutputConverted);
    const newOutput = new DataWrapper(newOutputConverted, typeToConvert);
    //data.output = newOutput;

    data.model.data.value = newOutput.value;
    data.model.data.format = newOutput.format;
    if (showConversion) {
      // Automatically convert when toggle button is clicked
      //const outputConverted = DataWrapper.convertToType(output, selectedType, typeToConvert);
      //setOutputConverted(outputConverted);
    }
}, [selectedType]);


  useEffect(() => {
    const newOutputConverted = DataWrapper.convertToType(output, selectedType, typeToConvert);
    setOutputConverted(newOutputConverted);
    const newOutput = new DataWrapper(newOutputConverted, typeToConvert);
    data.output = newOutput;
}, [typeToConvert]);

  useEffect(() => {
    if (showConversion) {
      // Automatically convert when toggle button is clicked
      /*const outputConverted = DataWrapper.convertToType(output, selectedType, typeToConvert);
      setOutputConverted(outputConverted);
      setOutput(outputConverted);*/
      const newOutputConverted = DataWrapper.convertToType(outputConverted, selectedType, typeToConvert);
      const newOutput = new DataWrapper(newOutputConverted, typeToConvert);
      data.output = newOutput;
    } else {
      data.output = data.input;
    }
  }, [showConversion]);

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
          <select disabled value={selectedType} onChange={(e) => {
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
              <div style={{ display: "flex", alignItems: "center" }}>
                <select value={typeToConvert} onChange={(e) => {
                  setTypeToConvert(e.target.value);
                  //setOutputConverted(DataWrapper.convertToType(output, selectedType, e.target.value));
                }}>
                  {Object.keys(types).map((name) => (
                    <option key={name} value={name}>{name}</option>
                  ))}
                </select>
                {/* Information Icon with Tooltip */}
                <InfoIcon 
                  icon={faInfoCircle} 
                  title="The conversion process first involves converting the input to binary and then converting from binary to the desired output type." 
                />
              </div>
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
