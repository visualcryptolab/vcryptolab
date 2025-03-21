import { memo, useState, useEffect, useMemo, useRef } from "react";
import { Handle, Position } from "@xyflow/react";
import * as Algorithms from "../algorithms";
import NodeWrapper from "./NodeWrapper";
import { toast } from "react-toastify";
import UserInputData, { INPUT_TYPES } from "../../../models/UserInputData";
import styled from "styled-components";

const controlStyle = {
  padding: "15px",
  border: "1px solid #e0e0e0",
  borderRadius: "8px",
  backgroundColor: "#ffffff",
  textAlign: "center",
  width: "18vw",
  boxShadow: "0 4px 8px rgba(0, 0, 0, 0.1)",
  transition: "transform 0.2s, box-shadow 0.2s",
};

const ParameterBox = styled.div`
  border: 1px dashed #999;
  padding: 8px;
  margin-bottom: 10px;
  font-size: 0.9rem;
  color: #666;
  background-color: #f9f9f9;
  border-radius: 4px;
`;

const DecryptNode = ({ data }) => {
  const [algorithm, setAlgorithm] = useState("RSA");
  const [missingParams, setMissingParams] = useState([]);

  const algorithms = useMemo(() => {
    const algos = {};
    Object.keys(Algorithms).forEach((key) => {
      algos[key] = new Algorithms[key]();
    });
    return algos;
  }, []);

  const algorithmsNames = Object.keys(algorithms).map((name) =>
    name.replace("Algorithm", "")
  );

  useEffect(() => {
    let updatedMissingParams = [];

    if (data?.sources !== undefined && data?.sources !== null) {
      const firstSourceWithInput = Object.values(data?.sources).find(source => source.input);
      const firstInput = firstSourceWithInput?.input;
      
      const firstSourceWithKey = Object.values(data?.sources).find(source => source.privKey);
      const firstKey = firstSourceWithKey?.privKey;
      
      if (!firstInput) updatedMissingParams.push("Ciphertext to decrypt");
      if (!firstKey) updatedMissingParams.push("Private key");
      
      if (firstInput && firstKey && algorithms[algorithm + "Algorithm"]) {
        const value = firstInput.inputValue;
        const format = firstInput.inputFormat;
        
        const valueWithFormat = UserInputData.convertToType(value, format, INPUT_TYPES.DECIMAL).toString();
        
        const result = algorithms[algorithm + "Algorithm"].decrypt(valueWithFormat, firstKey);
        const outputData = new UserInputData(result, INPUT_TYPES.DECIMAL);
        data.output = outputData;
        //toast.error("output: " + result , { position: "top-right", autoClose: 5000 });
      }
    } else {
      updatedMissingParams.push("Ciphertext to decrypt");
      updatedMissingParams.push("Private key");
    }

    setMissingParams(updatedMissingParams);
  }, [algorithm, algorithms, data]);

  const handleAlgorithmChange = (event) => {
    setAlgorithm(event.target.value);
  };

  return (
    <NodeWrapper nodeType={"Decrypt"}>
      <div style={controlStyle}>
        <Handle type="target" position={Position.Top} id="decrypt-top" />
        <Handle type="target" position={Position.Left} id="decrypt-left" />
        <Handle type="target" position={Position.Right} id="decrypt-right" />
        <Handle type="target" position={Position.Bottom} id="decrypt-bottom" />

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
          <label>
            <select value={algorithm} onChange={handleAlgorithmChange}>
              {algorithmsNames.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </label>
        </div>

        <Handle type="source" position={Position.Top} id="decrypt-output-top" />
        <Handle type="source" position={Position.Left} id="decrypt-output-left" />
        <Handle type="source" position={Position.Right} id="decrypt-output-right" />
        <Handle type="source" position={Position.Bottom} id="decrypt-output-bottom" />
      </div>
    </NodeWrapper>
  );
};

export default memo(DecryptNode);
