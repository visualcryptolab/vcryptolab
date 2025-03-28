import { memo, useState, useEffect } from "react";
import { Handle, Position } from "@xyflow/react";
import NodeWrapper from "./NodeWrapper";

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
  const [input1, setInput1] = useState("");  // Store input1 from InputNode
  const [input2, setInput2] = useState("");  // Store input2 from InputNode
  const [output, setOutput] = useState("");  // Store XOR output

  useEffect(() => {
    // Check if input1 and input2 are available and perform XOR
    if (data.input1 && data.input2) {
      const xorResult = data.input1
        .split("")
        .map((char, index) => {
          const xorValue =
            char.charCodeAt(0) ^ data.input2.charCodeAt(index % data.input2.length);
          // Convert the XOR result to a hexadecimal string
          const hexString = xorValue.toString(16).padStart(2, "0");
          return hexString;
        })
        .join("");
      setOutput(xorResult);  // Update output after XOR operation
      data.output = xorResult;  // Update the output in parent data
    }
  }, [data]);

  return (
    <NodeWrapper nodeType="XOR">
      <div style={nodeStyle}>
        <Handle type="target" position={Position.Top} id="xor-in-t" />
        <Handle type="target" position={Position.Left} id="xor-in-l" />
        <Handle type="target" position={Position.Right} id="xor-in-r" />
        <Handle type="target" position={Position.Bottom} id="xor-in-b" />

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
