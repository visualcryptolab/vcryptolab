import { memo, useState, useMemo, useEffect } from "react";
import { Handle, Position } from "@xyflow/react";
import NodeWrapper from "./NodeWrapper";
import * as Algorithms from "../algorithms";
import RSAPublicKey from "../algorithms/RSAPublicKey";
import RSAPrivateKey from "../algorithms/RSAPrivateKey";

const nodeStyle = {
  padding: "15px",
  border: "1px solid #e0e0e0",
  borderRadius: "8px",
  backgroundColor: "#fff",
  textAlign: "center",
  width: "18vw",
  boxShadow: "0 4px 8px rgba(0, 0, 0, 0.1)",
};

const KeyGeneratorNode = ({ data }) => {
  const [algorithm, setAlgorithm] = useState("RSA");
  const [params, setParams] = useState({ p: "", q: "", e: "39423", n: "46927", d: "26767" });

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

  useEffect(() => {
    if (params.e && params.n && params.d) {
      data.pubKey = new RSAPublicKey(params.e, params.n);
      data.privKey = new RSAPrivateKey(params.d, params.n);
    }
  }, [params]);

  const handleAlgorithmChange = (event) => {
    setAlgorithm(event.target.value);
  };

  return (
    <NodeWrapper nodeType="Key Generator">
      <div style={nodeStyle}>
        <Handle type="target" position={Position.Top} id="keygen-in-t" />
        <Handle type="target" position={Position.Left} id="keygen-in-l" />
        <Handle type="target" position={Position.Right} id="keygen-in-r" />
        <Handle type="target" position={Position.Bottom} id="keygen-in-b" />

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

        <Handle type="source" position={Position.Top} id="keygen-out-t" />
        <Handle type="source" position={Position.Left} id="keygen-out-l" />
        <Handle type="source" position={Position.Right} id="keygen-out-r" />
        <Handle type="source" position={Position.Bottom} id="keygen-out-b" />
      </div>
    </NodeWrapper>
  );
};

export default memo(KeyGeneratorNode);
