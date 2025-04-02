import { memo, useState, useEffect, useMemo } from "react";
import { Handle, Position } from "@xyflow/react";
import NodeWrapper from "./NodeWrapper";
import CryptoJS from "crypto-js";
import styled from "styled-components";
import DataWrapper, { FORMAT_TYPES } from "../../../models/DataWrapper";
import { toast } from "react-toastify";

const NodeContainer = styled.div`
  padding: 15px;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  background-color: #fff;
  text-align: center;
  width: 18vw;
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
`;

const ParameterBox = styled.div`
  border: 1px dashed #999;
  padding: 8px;
  margin-bottom: 10px;
  font-size: 0.9rem;
  color: #666;
  background-color: #f9f9f9;
  border-radius: 4px;
`;

const OutputBox = styled.div`
  font-size: 1rem;
  color: #333;
  padding: 10px;
  background-color: #f1f1f1;
  border-radius: 4px;
  font-family: 'Courier New', Courier, monospace;
  word-break: break-all;
  margin-top: 10px;
`;

const HashNode = ({ data }) => {
  const [algorithm, setAlgorithm] = useState("MD5");
  const [output, setOutput] = useState("");
  const [inputProvided, setInputProvided] = useState(false);

  const algorithms = useMemo(
    () => ({
      MD5: CryptoJS.MD5,
      "SHA-1": CryptoJS.SHA1,
      "SHA-256": CryptoJS.SHA256,
      "SHA-512": CryptoJS.SHA512,
    }),
    []
  );

 
  useEffect(() => {
    //if (data.input !== undefined && data.input !== null) {
    if (data?.model?.inputs.length >0) {
      //console.log("data.model: " + JSON.stringify(data.model, null, 2));
      const sourceInput = data.model.inputs[0]; //If there is more than 1 input, we just use the first one.

      const value = sourceInput.data.value;
      const format = sourceInput.data.format;
      
      if (value) {
        setInputProvided(true);
        const valueWithFormat = DataWrapper.convertToType(value, format, FORMAT_TYPES.TEXT);
        const hash = algorithms[algorithm](valueWithFormat).toString();
        setOutput(hash);
        //data.output = new DataWrapper(hash, FORMAT_TYPES.HEXADECIMAL);
        
        data.model.data.value = hash;
        data.model.data.format = FORMAT_TYPES.HEXADECIMAL;
      } else {
        setInputProvided(false);
      }
    }
  }, [data, algorithm]);

  return (
    <NodeWrapper nodeType="Hash">
      <NodeContainer>
        <Handle type="target" position={Position.Top} id="hash-in-t" />
        <Handle type="target" position={Position.Left} id="hash-in-l" />
        <Handle type="target" position={Position.Right} id="hash-in-r" />
        <Handle type="target" position={Position.Bottom} id="hash-in-b" />
        
        {!inputProvided && (
          <ParameterBox>
            Input required: Please provide a message to hash.
          </ParameterBox>
        )}

        <div>
          <label>Select Hash Algorithm:</label>
          <select
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value)}
          >
            {Object.keys(algorithms).map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>
        
        {inputProvided && <OutputBox>{output}</OutputBox>}

        <Handle type="source" position={Position.Top} id="hash-out-t" />
        <Handle type="source" position={Position.Left} id="hash-out-l" />
        <Handle type="source" position={Position.Right} id="hash-out-r" />
        <Handle type="source" position={Position.Bottom} id="hash-out-b" />
      </NodeContainer>
    </NodeWrapper>
  );
};

export default memo(HashNode);
