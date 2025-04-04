import NodeModel from "./NodeModel";
import RSAPublicKey from "./RSAPublicKey";
import RSAPrivateKey from "./RSAPrivateKey";

export const ALGORITHM_TYPES = {
  RSA: "RSA",
  ElGamal: "Decimal",
};


class KeyNodeModel extends NodeModel {
  constructor(id) {
    super(id, []);
    this.algorithm = undefined;
    this.publicKey = new RSAPublicKey();
    this.privateKey = new RSAPrivateKey();    
  }

  
}

export default KeyNodeModel;
