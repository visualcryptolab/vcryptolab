import { memo, useState, useEffect, useMemo, useRef } from "react";
import { Handle, Position } from "@xyflow/react";
import * as Algorithms from "../algorithms";
import NodeWrapper from "./NodeWrapper";
import { toast } from "react-toastify";
import UserInputData, { INPUT_TYPES } from "../../../models/UserInputData";

const controlStyle = {
  padding: "15px",
  border: "1px,solid #e0e0e0",
  borderRadius: "8px",
  backgroundColor: "#ffffff",
  textAlign: "center",
  width: "18vw",
  boxShadow: "0 4px 8px rgba(0, 0, 0, 0.1)",
  transition: "transform,0.2s, box-shadow 0.2s",
};

const EncryptNode = ({ data }) => {
  const [algorithm, setAlgorithm] = useState("RSA");
  const [outputText, setOutputText] = useState("");
  const [inputText, setInputText] = useState("");
  const [params, setParams] = useState({p:"281", q:"167", e:"39423", n:"46927", d:"26767"});
  const prevParamsRef = useRef(params);
  const prevDataRef = useRef(data);

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
    params.input = "";//data.input;

    if (data.input !== undefined && data.input !== null) {
      const userInput = data.input;
      const value = userInput.inputValue;
      const format = userInput.inputFormat;
      const valueWithFormat = UserInputData.convertToType(value, format, INPUT_TYPES.DECIMAL).toString();
      //toast.error("To encrypt "  + valueWithFormat, { position: "top-right", autoClose: 5000 });
      //params.input = "10";//valueWithFormat
      params.input = valueWithFormat
      /*
      if (algorithms[algorithm + "Algorithm"]) {

        //toast.error("To encrypt "  + params, { position: "top-right", autoClose: 5000 });
        const result = algorithms[algorithm + "Algorithm"].encrypt(params);
        //setOutputText(result);
        //data.output = result;

        //toast.error("Encrypted "  + result, { position: "top-right", autoClose: 5000 });

        const outputData = new UserInputData(result, INPUT_TYPES.DECIMAL);  
        
        data.output = outputData;
      }*/
    }
    params.pubKey = data.pubKey;
    params.privKey = data.privKey;
  }, [data.input, data.pubKey, data.privKey]);

  useEffect(() => {
    const prevParams = prevParamsRef.current;
    if (JSON.stringify(prevParams) !== JSON.stringify(params)) {
      if (algorithms[algorithm + "Algorithm"]) {
        const result = algorithms[algorithm + "Algorithm"].encrypt(params);
        //setOutputText(result);
        //data.output = result;

        //toast.error("Encrypted "  + result, { position: "top-right", autoClose: 5000 });

        const outputData = new UserInputData(result, INPUT_TYPES.DECIMAL);  
        
        data.output = outputData;
      }
      prevParamsRef.current = params;
    }
  }, [algorithm, params, algorithms, data.input, data.pubKey, data.privKey]);

  const handleAlgorithmChange = (event) => {
    setAlgorithm(event.target.value);
  };

  useEffect(() => {
    if (JSON.stringify(prevDataRef.current) !== JSON.stringify(data)) {
      prevDataRef.current = data;
      if (data.input) {
        setInputText(data.input);
      }
    }
  }, [data]);

  return (
    <NodeWrapper nodeType={"Encrypt"}>
    <div style={controlStyle}>
      <Handle type="target" position={Position.Top} id="encrypt-top" />
      <Handle type="target" position={Position.Left} id="encrypt-left" />
      <Handle type="target" position={Position.Right} id="encrypt-right" />
      <Handle type="target" position={Position.Bottom} id="encrypt-bottom" />
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
      <Handle type="source" position={Position.Top} id="encrypt-output-top" />
      <Handle type="source" position={Position.Left} id="encrypt-output-left" />
      <Handle
        type="source"
        position={Position.Right}
        id="encrypt-output-right"
      />
      <Handle
        type="source"
        position={Position.Bottom}
        id="encrypt-output-bottom"
      />
    </div>
    </NodeWrapper>
  );
};

export default memo(EncryptNode);
