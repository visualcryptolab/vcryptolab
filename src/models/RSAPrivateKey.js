import PrivateKey from "./PrivateKey";
import { ALGORITHM_TYPES } from "./KeyNodeModel";


class RSAPrivateKey extends PrivateKey {
  constructor() {
    super(ALGORITHM_TYPES.RSA);
    this.d = null;
    this.n = null;    
  }

  
}

export default RSAPrivateKey;
