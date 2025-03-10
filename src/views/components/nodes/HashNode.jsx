import { memo, useState, useEffect, useMemo } from "react";
import { Handle, Position } from "@xyflow/react";
import NodeWrapper from "./NodeWrapper";
import CryptoJS from "crypto-js";
import { toast } from "react-toastify";
import UserInputData, { INPUT_TYPES } from "../../../models/UserInputData";

const nodeStyle = {
  padding: "15px",
  border: "1px solid #e0e0e0",
  borderRadius: "8px",
  backgroundColor: "#fff",
  textAlign: "center",
  width: "18vw",
  boxShadow: "0 4px 8px rgba(0, 0, 0, 0.1)",
};

const HashNode = ({ data }) => {
  const [algorithm, setAlgorithm] = useState("MD5");
  const [output, setOutput] = useState("");

  // Memoized object for supported hash algorithms
  const algorithms = useMemo(
    () => ({
      MD5: CryptoJS.MD5,
      "SHA-1": CryptoJS.SHA1,
      "SHA-2": CryptoJS.SHA256,
      "SHA-3": CryptoJS.SHA3,
      "SHA-256": CryptoJS.SHA256,
      "SHA-512": CryptoJS.SHA512,
    }),
    []
  );


  useEffect(() => {
    if (data.input !== undefined && data.input !== null) {
      const userInput = data.input;
      
      const value = userInput.inputValue;
      const format = userInput.inputFormat;

      const valueWithFormat = UserInputData.convertToType(value, format, INPUT_TYPES.TEXT);
      
      const hash = algorithms[algorithm](valueWithFormat).toString();
      setOutput(hash);

      // Create a new instance of UserInputData for the hash output
      const outputData = new UserInputData(hash, INPUT_TYPES.HEXADECIMAL);  // Using INPUT_TYPES.Text as hash is a string
      data.output = outputData;  // Assigning the output to data.output
    }
  }, [data.input, algorithm]);

  return (
    <NodeWrapper nodeType="Hash">
      <div style={nodeStyle}>
        <Handle type="target" position={Position.Top} id="hash-in-t" />
        <Handle type="target" position={Position.Left} id="hash-in-l" />
        <Handle type="target" position={Position.Right} id="hash-in-r" />
        <Handle type="target" position={Position.Bottom} id="hash-in-b" />

        <div>
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

        <Handle type="source" position={Position.Top} id="hash-out-t" />
        <Handle type="source" position={Position.Left} id="hash-out-l" />
        <Handle type="source" position={Position.Right} id="hash-out-r" />
        <Handle type="source" position={Position.Bottom} id="hash-out-b" />
      </div>
    </NodeWrapper>
  );
};

export default memo(HashNode);
