/* global BigInt */
import { memo, useEffect, useState } from "react";
import { Handle, Position } from "@xyflow/react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCopy, faArrowRight, faArrowLeft } from "@fortawesome/free-solid-svg-icons";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import styled from "styled-components";

const NodeContainer = styled.div`
  padding: 10px;
  border: 1px solid #ccc;
  border-radius: 4px;
  background-color: #fff;
  text-align: center;
  box-sizing: border-box;
  position: relative;
  min-width: 120px;
`;

const ButtonContainer = styled.div`
  display: flex;
  justify-content: space-around;
  margin-bottom: 8px;
`;

const ShiftButton = styled.button`
  max-width: 40px; // Reduced width for a smaller button
  border: none;
  border-radius: 4px;
  padding: 4px 6px; // Reduced horizontal padding for a smaller button width
  cursor: pointer;
  color: #fff;
  font-size: 0.9rem;
  transition: transform 0.2s ease;
  
  &:hover {
    transform: scale(1.05);
  }
  
  &:active {
    transform: scale(0.95);
  }
`;

const OutputText = styled.p`
  font-size: 1rem;
  color: #333;
  margin: 8px 0;
`;

const Counter = styled.div`
  font-size: 0.8rem;
  color: #555;
  margin-top: 8px;
`;

const Icon = styled(FontAwesomeIcon)`
  cursor: pointer;
  color: #ff6600;
  position: absolute;
  bottom: 5px;
  right: 5px;
`;


const OutputNode = ({ data, nodeKey }) => {
  const [output, setOutput] = useState("");
  const [shiftCount, setShiftCount] = useState(0);

  const handleCopy = () => {
    navigator.clipboard.writeText(output.toString());
    toast.success("Text copied to clipboard", {
      position: "top-right",
      autoClose: 2000,
    });
  };

  const handleShiftLeft = (shiftAmount = 1) => {
    const num = Number(output) || 0;
    if (isNaN(num)) {
      toast.error("Invalid number for shifting.", {
        position: "top-right",
      });
      return;
    }

    let binary = num.toString(2);
    if (binary.length === 0) binary = "0";

    const paddedBinary = binary.padStart(binary.length, '0');
    const effectiveShift = shiftAmount % paddedBinary.length || 1;

    const shiftedBinary = (BigInt(`0b${paddedBinary}`) << BigInt(effectiveShift)).toString(2);
    const newBinary = shiftedBinary.padStart(paddedBinary.length, '0');
    const newNumber = parseInt(newBinary, 2);

    setOutput(newNumber);
    setShiftCount(prev => prev - effectiveShift);
    data.output = newNumber;
  };

  const handleShiftRight = (shiftAmount = 1) => {
    const num = Number(output) || 0;
    if (isNaN(num)) {
      toast.error("Invalid number for shifting.", {
        position: "top-right",
      });
      return;
    }

    let binary = num.toString(2);
    if (binary.length === 0) binary = "0";

    const paddedBinary = binary.padStart(binary.length, '0');
    const effectiveShift = shiftAmount % paddedBinary.length || 1;

    const shiftedBinary = (BigInt(`0b${paddedBinary}`) >> BigInt(effectiveShift)).toString(2);
    const newBinary = shiftedBinary.padStart(paddedBinary.length, '0');
    const newNumber = parseInt(newBinary, 2);

    setOutput(newNumber);
    setShiftCount(prev => prev + effectiveShift);
    data.output = newNumber;
  };

  useEffect(() => {
    if (data.input !== undefined && data.input !== null) {
      /*
      const numInput = Number(data.input);
      if (isNaN(numInput)) {
        toast.error("Input must be a number.", {
          position: "top-right",
        });
        setOutput("");
        data.output = "";
      } else {
        data.output = numInput;
        setOutput(numInput);
        setShiftCount(0);
      }
        */

      
      if (isNaN(data.input)) {
        data.output = data.input;
        setOutput(data.input);
      } else {
        const numInput = Number(data.input);
        data.output = numInput;
        setOutput(numInput);
        setShiftCount(0);
      }
    } else {
      data.output = "";
      setOutput("");
      setShiftCount(0);
    }
  }, [data.input]);

  return (
    <NodeContainer>
      <Handle type="target" position={Position.Top} id="input-in-top" />
      <Handle type="target" position={Position.Left} id="input-in-left" />
      <Handle type="target" position={Position.Right} id="input-in-right" />
      <Handle type="target" position={Position.Bottom} id="input-in-bottom" />

      <ButtonContainer>
        <ShiftButton onClick={() => handleShiftLeft(1)}>
          <FontAwesomeIcon icon={faArrowLeft} />
        </ShiftButton>
        <ShiftButton onClick={() => handleShiftRight(1)}>
          <FontAwesomeIcon icon={faArrowRight} />
        </ShiftButton>
      </ButtonContainer>
      <OutputText>{output}</OutputText>
      <Icon icon={faCopy} style={{color:"ff0072"}} onClick={handleCopy} />
      <Counter>Shift Count: {shiftCount}</Counter>
      <Handle type="source" position={Position.Top} id="output-out-top" />
      <Handle type="source" position={Position.Left} id="output-out-left" />
      <Handle type="source" position={Position.Right} id="output-out-right" />
      <Handle type="source" position={Position.Bottom} id="output-out-bottom" />
    </NodeContainer>
  );
};

export default memo(OutputNode);