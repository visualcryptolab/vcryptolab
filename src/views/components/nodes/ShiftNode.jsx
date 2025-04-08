/* global BigInt */
import { memo, useEffect, useState } from "react";
import { Handle, Position } from "@xyflow/react";
import styled from "styled-components";
import DataWrapper, { FORMAT_TYPES } from "../../../models/DataWrapper";

const NodeContainer = styled.div`
  padding: 20px;
  border: 1px solid #ccc;
  border-radius: 8px;
  background-color: #f9f9f9;
  text-align: center;
  box-sizing: border-box;
  position: relative;
  min-width: 100px; /* Ancho reducido */
  box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1);
`;

const Label = styled.label`
  font-weight: bold;
  margin-bottom: 5px;
  display: block;
  text-align: left;
  font-size: 14px;
  color: #444;
`;

const Row = styled.div`
  display: flex;
  justify-content: flex-start;
  gap: 10px;
  align-items: center;
  margin-bottom: 15px;
`;

const TextBox = styled.input`
  padding: 8px;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 1rem;
  font-family: 'Courier New', Courier, monospace;
  background-color: #f1f1f1;
  color: #333;
  text-align: right;
`;

const AmountBox = styled(TextBox)`
  width: 40px; /* Reducido para que sea más estrecho */
`;

const Button = styled.button`
  background-color: #007bff;
  color: #fff;
  border: none;
  padding: 6px 12px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;

  &:hover {
    background-color: #0056b3;
  }
`;

const Select = styled.select`
  padding: 6px;
  border-radius: 4px;
  border: 1px solid #ccc;
  font-size: 14px;
`;

const ShiftNode = ({ data }) => {
  const [shiftAmount, setShiftAmount] = useState(0);
  const [direction, setDirection] = useState("left");
  const [inputValue, setInputValue] = useState(0);
  const [shiftedValue, setShiftedValue] = useState(0);
  const [resultType, setResultType] = useState("decimal");

  useEffect(() => {
    if (data?.model?.inputs?.length > 0) {
      const rawInput = data.model.inputs[0].data.value;
      console.log("in: " + rawInput);
      let numericInput = 0;

      if (data.model.inputs[0]?.data.format !== FORMAT_TYPES.DECIMAL) {
        numericInput = DataWrapper.convertToType(rawInput.toString(), data.model.inputs[0]?.data.format, FORMAT_TYPES.DECIMAL);
      } else {
        numericInput = parseInt(rawInput)
      }

      console.log("in: " + rawInput + " - Numeric: " + numericInput);
      setInputValue(numericInput);
    }
  }, [data.model.inputs[0]?.hash]);

  useEffect(() => {
    let resultInt;
    if (direction === "left") {
      // Realizamos el desplazamiento de bits a la izquierda
      resultInt = inputValue << shiftAmount;
      //console.log("in: " + inputValue + " - amount: " + shiftAmount + " - Result: " + resultInt);
    } else {
      // Realizamos el desplazamiento de bits a la derecha
      resultInt = inputValue >>> shiftAmount;
    }
    setShiftedValue(resultInt);
    let result = resultInt;
    if (data.model.inputs[0]?.data.format !== FORMAT_TYPES.DECIMAL) {
      result = DataWrapper.convertToType(resultInt.toString(), FORMAT_TYPES.DECIMAL, data.model.inputs[0]?.data.format);
    }
    data.model.data.value = result;
    data.model.data.format = data.model.inputs[0]?.data.format;
    data.model.generateHash();
  }, [inputValue, shiftAmount, direction]);

  const incrementShift = () => setShiftAmount((prev) => prev + 1);
  const decrementShift = () => setShiftAmount((prev) => Math.max(0, prev - 1));

  const formatDecimal = (value) => value.toString(10); // Convertir a decimal
  const formatBinary = (value) => value.toString(2); // Convertir a binario

  return (
    <NodeContainer>
      <Handle type="target" position={Position.Top} id="input-in-top" />
      <Handle type="target" position={Position.Left} id="input-in-left" />
      <Handle type="target" position={Position.Right} id="input-in-right" />
      <Handle type="target" position={Position.Bottom} id="input-in-bottom" />

      <Row>
        <Label>Direction</Label>
        <Select value={direction} onChange={(e) => setDirection(e.target.value)}>
          <option value="left">Left</option>
          <option value="right">Right</option>
        </Select>

        <Label>Shift Amount</Label>
        <Button onClick={decrementShift}>-</Button>
        <AmountBox type="text" value={shiftAmount} readOnly />
        <Button onClick={incrementShift}>+</Button>
      </Row>

      <Label>Bit Shift Result</Label>
      <Row>
        <div>
          <Label>Decimal</Label>
          <TextBox type="text" value={formatDecimal(shiftedValue)} readOnly />
        </div>
        <div>
          <Label>Binary</Label>
          <TextBox type="text" value={formatBinary(shiftedValue)} readOnly />
        </div>
      </Row>

      <Handle type="source" position={Position.Top} id="output-out-top" />
      <Handle type="source" position={Position.Left} id="output-out-left" />
      <Handle type="source" position={Position.Right} id="output-out-right" />
      <Handle type="source" position={Position.Bottom} id="output-out-bottom" />
    </NodeContainer>
  );
};

export default memo(ShiftNode);
