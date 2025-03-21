/* global BigInt */

import React from "react";
import { toast } from "react-toastify";

class RSAPrivateKey {
  constructor(d, n) {
    this.d = d;
    this.n = n;
  }
}

export default RSAPrivateKey;
