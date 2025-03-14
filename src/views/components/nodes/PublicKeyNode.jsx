import { memo, useState, useEffect, useMemo } from "react";
import { Handle, Position } from "@xyflow/react";
import NodeWrapper from "./NodeWrapper";
import * as Algorithms from "../algorithms";
import RSAPublicKey from "../algorithms/RSAPublicKey";
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

const PublicKeyNode = ({ data }) => {
  const [algorithm, setAlgorithm] = useState("RSA");
  const [params, setParams] = useState({p:"281", q:"167", e:"39423", n:"46927", d:"26767"});
  //const [e, setE] = useState("");
  //const [n, setN] = useState("");
  //const keyPair2 = [parseInt(-2), parseInt(-2)];
  //data.pubKey = keyPair2;

  const algorithms = useMemo(() => {
      const algos = {};
      Object.keys(Algorithms).forEach((key) => {
        algos[key] = new Algorithms[key](setParams);
      });
      return algos;
    }, []);
  
    const algorithmsNames = Object.keys(algorithms).map((name) =>
      name.replace("Algorithm", "")
    );

    const handleAlgorithmChange = (event) => {
      setAlgorithm(event.target.value);
    };

  useEffect(() => {
    
      if (params.e && params.n) {
        const keyPair = new RSAPublicKey(params.e, params.n);
        data.pubKey = keyPair;
      } else {
        const keyPair = new RSAPublicKey(-1, -1);
        data.pubKey = keyPair;
      }
  }, [params.e, params.n]);

  return (
    <NodeWrapper nodeType="Public Key">
    <div style={nodeStyle}>
      <Handle type="target" position={Position.Top} id="publicKey-in-t" />
      <Handle type="target" position={Position.Left} id="publicKey-in-l" /> 
      <Handle type="target" position={Position.Right} id="publicKey-in-r" />
      <Handle type="target" position={Position.Bottom} id="publicKey-in-b" />
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
        {algorithms[algorithm + "Algorithm"] ? (
          algorithms[algorithm + "Algorithm"].getInputs(params)
        ) : (
          <div>Error: Algorithm not found</div>
        )}
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