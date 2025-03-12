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

const PublicKeyNode = ({ data }) => {
  const [e, setE] = useState("");
  const [n, setN] = useState("");

  useEffect(() => {
    if (e && n) {
      const keyPair = [parseInt(e), parseInt(n)];
      data.pubKey = keyPair;
    }
  }, [e, n]);

  return (
    <NodeWrapper nodeType="Public Key">
    <div style={nodeStyle}>
      <Handle type="target" position={Position.Top} id="publicKey-in-t" />
      <Handle type="target" position={Position.Left} id="publicKey-in-l" /> 
      <Handle type="target" position={Position.Right} id="publicKey-in-r" />
      <Handle type="target" position={Position.Bottom} id="publicKey-in-b" />

      <div>
        <div>
          <label>e: </label>
          <input 
            type="number" 
            value={e}
            onChange={(evt) => setE(evt.target.value)}
          />
        </div>
        <div>
          <label>n: </label>
          <input 
            type="number" 
            value={n}
            onChange={(evt) => setN(evt.target.value)}
          />
        </div>
      </div>

      <Handle type="source" position={Position.Top} id="publicKey-out-t" />
      <Handle type="source" position={Position.Left} id="publicKey-out-l" />
      <Handle type="source" position={Position.Right} id="publicKey-out-r" />
      <Handle type="source" position={Position.Bottom} id="publicKey-out-b" />
    </div>
    </NodeWrapper>
  );
};

export default memo(PublicKeyNode);