import NodeModel from "./NodeModel";

export const ALGORITHM_TYPES = {
  RSA: "RSA",
  ElGamal: "Decimal",
};


class KeyNodeModel extends NodeModel {
  constructor(id) {
    super(id, []);
    this.algorithm = undefined;
    this.publicKey = null;
    this.privateKey = null;    
  }

  
}

export default KeyNodeModel;
