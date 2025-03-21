import { memo, useState, useEffect, useMemo, useRef } from "react";
import { Handle, Position } from "@xyflow/react";
import * as Algorithms from "../algorithms";
import RSAPublicKey from "../algorithms/RSAPublicKey";
import NodeWrapper from "./NodeWrapper";
import { toast } from "react-toastify";
import UserInputData, { INPUT_TYPES } from "../../../models/UserInputData";
import styled from "styled-components";

// Styles for the control container
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

// Styles for missing parameters notification
const missingParamsStyle = {
  padding: "10px",
  border: "2px dashed red",
  borderRadius: "5px",
  backgroundColor: "#fff5f5",
  color: "#d9534f",
  marginBottom: "10px",
};

// Styled component for parameter box
const ParameterBox = styled.div`
  border: 1px dashed #999;
  padding: 8px;
  margin-bottom: 10px;
  font-size: 0.9rem;
  color: #666;
  background-color: #f9f9f9;
  border-radius: 4px;
`;

const EncryptNode = ({ data }) => {
  // State for algorithm selection
  const [algorithm, setAlgorithm] = useState("RSA");
  // State for output text
  const [outputText, setOutputText] = useState("");
  // State for storing parameters
  const [params, setParams] = useState({});
  // References to previous state values for comparison
  const prevParamsRef = useRef(params);
  const prevDataRef = useRef(data);
  // Local state for handling data updates
  //const [localData, setLocalData] = useState(data);

  // State to track missing parameters
  const [missingParams, setMissingParams] = useState([]);

  // Create algorithms dynamically from the imported module
  const algorithms = useMemo(() => {
    const algos = {};
    Object.keys(Algorithms).forEach((key) => {
      algos[key] = new Algorithms[key](setParams);
    });
    return algos;
  }, []);

  // List of algorithm names
  const algorithmsNames = Object.keys(algorithms).map((name) =>
    name.replace("Algorithm", "")
  );

  // Effect to update missing parameters when the data changes
  useEffect(() => {
    // Display data in the toast for debugging purposes
    //toast.error("Data: " + JSON.stringify(data, null, 2), { position: "top-right", autoClose: 5000 });

    // Initialize missingParams array
    let updatedMissingParams = [];
    
    // Check if the data has sources
    if (data?.sources !== undefined && data?.sources !== null) {
      // Find the first source with input
      const firstSourceWithInput = Object.values(data?.sources).find(source => source.input);
      const firstInput = firstSourceWithInput?.input;
      
      // Find the first source with a public key
      const firstSourceWithKey = Object.values(data?.sources).find(source => source.pubKey);
      const firstKey = firstSourceWithKey?.pubKey;

      // If the input or public key is missing, add them to the list
      if (!firstInput) updatedMissingParams.push("Message to encrypt");
      if (!firstKey) updatedMissingParams.push("Public key");

           
      
      // If the selected algorithm is available, run the encryption
      if (firstInput && firstKey && algorithms[algorithm + "Algorithm"]) {
        const value = firstInput.inputValue;
        const format = firstInput.inputFormat;

        // Convert the input value to the required type
        const valueWithFormat = UserInputData.convertToType(value, format, INPUT_TYPES.DECIMAL).toString();


        //toast.error("Message: " + valueWithFormat, { position: "top-right", autoClose: 50000 });
        //toast.error("Key: " + JSON.stringify(firstKey, null, 2), { position: "top-right", autoClose: 50000 });

        const result = algorithms[algorithm + "Algorithm"].encrypt(valueWithFormat, firstKey);
        const outputData = new UserInputData(result, INPUT_TYPES.DECIMAL);
        data.output = outputData;
      }
    } else {
      // If no sources exist, add both missing parameters
      updatedMissingParams.push("Message to encrypt");
      updatedMissingParams.push("Public key");
    }

    // Update the missingParams state with the new values
    setMissingParams(updatedMissingParams);
  }, [algorithm, algorithms, data]); // Depend on data so the effect runs when it changes

  // Handle change in algorithm selection
  const handleAlgorithmChange = (event) => {
    setAlgorithm(event.target.value);
  };

  return (
    <NodeWrapper nodeType={"Encrypt"}>
      <div style={controlStyle}>
        {/* Handle connections for inputs and outputs */}
        <Handle type="target" position={Position.Top} id="encrypt-top" />
        <Handle type="target" position={Position.Left} id="encrypt-left" />
        <Handle type="target" position={Position.Right} id="encrypt-right" />
        <Handle type="target" position={Position.Bottom} id="encrypt-bottom" />

        {/* Display missing parameters if any */}
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

        {/* Dropdown for selecting algorithm */}
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

        {/* Handle connections for output */}
        <Handle type="source" position={Position.Top} id="encrypt-output-top" />
        <Handle type="source" position={Position.Left} id="encrypt-output-left" />
        <Handle type="source" position={Position.Right} id="encrypt-output-right" />
        <Handle type="source" position={Position.Bottom} id="encrypt-output-bottom" />
      </div>
    </NodeWrapper>
  );
};

export default memo(EncryptNode);
