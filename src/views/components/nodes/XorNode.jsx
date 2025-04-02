import { memo, useState, useEffect, useMemo } from "react";
import { Handle, Position } from "@xyflow/react";
import NodeWrapper from "./NodeWrapper";
import DataWrapper, { FORMAT_TYPES } from "../../../models/DataWrapper";
import styled from "styled-components";
import { toast } from "react-toastify";

// Styled component for missing parameters notification
const ParameterBox = styled.div`
  border: 1px dashed #999;
  padding: 8px;
  margin-bottom: 10px;
  font-size: 0.9rem;
  color: #666;
  background-color: #f9f9f9;
  border-radius: 4px;
`;

const nodeStyle = {
  padding: "15px",
  border: "1px solid #e0e0e0",
  borderRadius: "8px",
  backgroundColor: "#fff",
  textAlign: "center",
  width: "18vw",
  boxShadow: "0 4px 8px rgba(0, 0, 0, 0.1)",
};

const XorNode = ({ data }) => {
  const [output, setOutput] = useState("");
  const [missingParams, setMissingParams] = useState([]);

  useEffect(() => {
    //console.log("Data: " + data); 
    console.log("Data: " + JSON.stringify(data, null, 2)); 

    //console.log("Sources:", JSON.stringify(data.sources, null, 2));
  //onsole.log("Output:", JSON.stringify(data.output, null, 2));

    let updatedMissingParams = [];
    let firstInput;
    let secondInput;
    let inputValue;

    if(data?.sources!=null && data?.sources!=undefined){
      //console.log(data.sources);
      for (const key in data.sources) {
        //console.log("Key: " + key);
        if (data.sources.hasOwnProperty(key)) {
          if(data.sources[key]?.input?.inputValue!==null && data.sources[key]?.input?.inputValue!==undefined){
            inputValue = data.sources[key].input.inputValue;
            if(!firstInput) {
              firstInput = inputValue;
              //console.log("Input 1: " + inputValue); 
            } else {
              secondInput = inputValue;
              //console.log("Input 2: " + inputValue); 
              break;  
            }            
          } 
        }
      }
    }


    if (!firstInput) updatedMissingParams.push("First input");
    if (!secondInput) updatedMissingParams.push("Second input");

    if (firstInput && secondInput) {
      // Ensure both inputs are binary strings
      const binary1 = firstInput.padStart(Math.max(firstInput.length, secondInput.length), "0");
      const binary2 = secondInput.padStart(Math.max(firstInput.length, secondInput.length), "0");
      
      // Perform bitwise XOR
      const xorResult = binary1
        .split("")
        .map((bit, index) => (bit === binary2[index] ? "0" : "1"))
        .join("");
      
      //console.log("xor: " + firstInput + " + " + secondInput + " = " + xorResult); 
      // Store result in DataWrapper format
      const outputData = new DataWrapper(xorResult, FORMAT_TYPES.BINARY);
      data.output = outputData;
      setOutput(xorResult);
    }

    setMissingParams(updatedMissingParams);
  }, [data.input]);//data]);[JSON.stringify(data)]);//data]);

  return (
    <NodeWrapper nodeType="XOR">
      <div style={nodeStyle}>
        <Handle type="target" position={Position.Top} id="xor-in-t" />
        <Handle type="target" position={Position.Left} id="xor-in-l" />
        <Handle type="target" position={Position.Right} id="xor-in-r" />
        <Handle type="target" position={Position.Bottom} id="xor-in-b" />

        {/* Show missing parameters notification if needed */}
        {missingParams.length > 0 && (
          <ParameterBox>
            <strong>Missing parameters:</strong>
            <ul>
              {missingParams.map((param, index) => (
                <li key={index}>{param}</li>
              ))}
            </ul>
          </ParameterBox>
        )}

        <div>
          <label>Output:</label>
          <input type="text" value={output} readOnly />
        </div>

        <Handle type="source" position={Position.Top} id="xor-out-t" />
        <Handle type="source" position={Position.Left} id="xor-out-l" />
        <Handle type="source" position={Position.Right} id="xor-out-r" />
        <Handle type="source" position={Position.Bottom} id="xor-out-b" />
      </div>
    </NodeWrapper>
  );
};

export default memo(XorNode);