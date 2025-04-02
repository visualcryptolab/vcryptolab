import Node from "./NodeModel";

class XORNodeModel extends NodeModel {
  constructor(id, inputs = []) {
    super(id, inputs);
  }

  getOutput() {
    const value = this.inputs.reduce((acc, node) => acc ^ node.getOutput().value, 0);
    return { value, format: value.toString() };
  }
}

export default XORNodeModel;
