import { memo, useState, useEffect, useMemo } from "react";
import { Handle, Position } from "@xyflow/react";
import NodeWrapper from "./NodeWrapper";
import cryptojs from "crypto-js";
import { toast } from "react-toastify";

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

  const algorithms = useMemo(
    () => ({
      MD5: cryptojs.MD5,
      "SHA-1": cryptojs.SHA1,
      "SHA-2": cryptojs.SHA256,
      "SHA-3": cryptojs.SHA3,
      "SHA-256": cryptojs.SHA256,
      "SHA-512": cryptojs.SHA512,
    }),
    []
  );

  useEffect(() => {
    if (data.input && algorithms[algorithm]) {
      toast.success("To hash: " + typeof data.input, {
            position: "top-right",
            autoClose: 2000,
          });
      const hash = algorithms[algorithm](data.input).toString();
      setOutput(hash);
      data.output = hash;
    }
  }, [data.input, algorithm, algorithms]);

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
