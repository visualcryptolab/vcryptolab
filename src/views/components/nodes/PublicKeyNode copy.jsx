import { memo, useEffect, useState } from "react";
import { Handle, Position } from "@xyflow/react";
import NodeWrapper from "./NodeWrapper";
import RSAPublicKey from "../algorithms/RSAPublicKey";

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
    if (data?.pubKey) {
      setE(data.pubKey.e);
      setN(data.pubKey.n);
    } else {
      data.pubKey = new RSAPublicKey(e, n);
    }
  }, [data, e, n]);

  return (
    <NodeWrapper nodeType="Public Key">
      <div style={nodeStyle}>
        <Handle type="target" position={Position.Top} id="publicKey-in" />

        <div>
          <label>
            Exponent (e):
            <input type="text" value={e} onChange={(e) => setE(e.target.value)} />
          </label>
          <br />
          <label>
            Modulus (n):
            <input type="text" value={n} onChange={(e) => setN(e.target.value)} />
          </label>
        </div>

        <Handle type="source" position={Position.Bottom} id="publicKey-out" />
      </div>
    </NodeWrapper>
  );
};

export default memo(PublicKeyNode);
