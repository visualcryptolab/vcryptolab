/* global BigInt */

import { memo, useEffect, useState } from "react";
import { Handle, Position } from "@xyflow/react";
import NodeWrapper from "./NodeWrapper";
//import RSAPrivateKey from "../algorithms/RSAPrivateKey";
import RSAPrivateKey from "../../../models/RSAPrivateKey";

const nodeStyle = {
  padding: "15px",
  border: "1px solid #e0e0e0",
  borderRadius: "8px",
  backgroundColor: "#fff",
  textAlign: "center",
  width: "18vw",
  boxShadow: "0 4px 8px rgba(0, 0, 0, 0.1)",
};

const PrivateKeyNode = ({ data }) => {
  const [d, setD] = useState("");
  const [n, setN] = useState("");

  useEffect(() => {
    if (data?.model?.inputs?.length > 0) {    
      //console.log("public key generada: " + JSON.stringify(data.model, null, 2));  
      const sourcePrivKey = data.model.inputs[0]; //If there is more than 1 input, we just use the first one.
      setD(sourcePrivKey.privateKey.d);
      setN(sourcePrivKey.privateKey.n);
      data.model.privateKey.d = sourcePrivKey.privateKey.d;
      data.model.privateKey.n = sourcePrivKey.privateKey.n;
    } else {    
      //console.log("public key: " + JSON.stringify(data.model, null, 2));
      
      if (/^-?\d+$/.test(n)) {      
        data.model.privateKey.n = n;        
      } else {
        data.model.privateKey.n = null;
      }

      if (/^-?\d+$/.test(d)) {
        data.model.privateKey.d = d;        
      } else {
        data.model.privateKey.d = null;
      }
    }
    data.model.generateHash();
  }, [data.model.inputs[0]?.hash, d, n]);

  return (
    <NodeWrapper nodeType="Private Key">
      <div style={nodeStyle}>
        <Handle type="target" position={Position.Top} id="privateKey-in-t" />
        <Handle type="target" position={Position.Left} id="privateKey-in-l" />
        <Handle type="target" position={Position.Right} id="privateKey-in-r" />
        <Handle type="target" position={Position.Bottom} id="privateKey-in-b" />

        <div>
          <label>
            Private Exponent (d):
            <input type="text" value={d} onChange={(e) => setD(e.target.value)} />
          </label>
          <br />
          <label>
            Modulus (n):
            <input type="text" value={n} onChange={(e) => setN(e.target.value)} />
          </label>
        </div>

        <Handle type="source" position={Position.Top} id="privateKey-out-t" />
        <Handle type="source" position={Position.Left} id="privateKey-out-l" />
        <Handle type="source" position={Position.Right} id="privateKey-out-r" />
        <Handle type="source" position={Position.Bottom} id="privateKey-out-b" />
      </div>
    </NodeWrapper>
  );
};

export default memo(PrivateKeyNode);
