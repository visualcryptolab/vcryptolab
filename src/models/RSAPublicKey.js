import PublicKey from "./PublicKey";
import { ALGORITHM_TYPES } from "./KeyNodeModel";


class RSAPublicKey extends PublicKey {
  constructor() {
    super(ALGORITHM_TYPES.RSA);
    this.e = null;
    this.n = null;    
  }

  
}

export default RSAPublicKey;
