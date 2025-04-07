/* global BigInt */

import React from "react";
import { toast } from "react-toastify";
//import RSAPublicKey from "./RSAPublicKey";
import RSAPublicKey from "../../../models/RSAPublicKey";

class RSAAlgorithm {
  constructor(setParams) {
    this.setParams = setParams;
    this.params = {};
  }

  getInputs(params) {
    const hasKeys = params.pubKey && params.privKey;
    params.hasKeys = hasKeys;
    if (hasKeys) {
      const pubKeyN = params.pubKey[1];
      const privKeyN = params.privKey[1];
      if (pubKeyN !== privKeyN) {
        toast.error(
          "Error: Public Key and Private Key do not have the same 'n' value.",
          {
            position: "top-right",
            autoClose: 2000,
            hideProgressBar: false,
            closeOnClick: true,
            pauseOnHover: true,
            draggable: true,
            progress: undefined,
          }
        );
        return;
      }

      params.e = params.pubKey[0];
      params.n = params.pubKey[1];
      params.d = params.privKey[0];
    }
    return (
      <div>
        {!hasKeys && (
          <>
            <label>
              p:
              <input
                type="number"
                value={params.p || ""}
                onChange={(e) => this.handleInputChange(e, "p", params)}
                onBlur={() => this.validateParams("p", params)}
              />
            </label>
            <label>
              q:
              <input
                type="number"
                value={params.q || ""}
                onChange={(e) => this.handleInputChange(e, "q", params)}
                onBlur={() => this.validateParams("q", params)}
              />
            </label>
            <label>
              e:
              <input
                type="number"
                value={params.e || ""}
                onChange={(e) => this.handleInputChange(e, "e", params)}
                onBlur={() => this.validateParams("e", params)}
              />
            </label>
            <label>
              n:
              <input type="number" value={params.n || ""} readOnly />
            </label>
            <label>
              d:
              <input type="number" value={params.d || ""} readOnly />
            </label>
          </>
        )}
        <div>
          <label>
            Public Key:
            <input
              type="text"
              value={
                hasKeys
                  ? `(${params.pubKey[0]}, ${params.pubKey[1]})`
                  : params.d && params.n
                  ? `(${params.e}, ${params.n})`
                  : ""
              }
              readOnly
            />
          </label>
        </div>
        <div>
          <label>
            Private Key:
            <input
              type="text"
              value={
                hasKeys
                  ? `(${params.privKey[0]}, ${params.privKey[1]})`
                  : params.d && params.n
                  ? `(${params.d}, ${params.n})`
                  : ""
              }
              readOnly
            />
          </label>
        </div>
      </div>
    );
  }

  handleInputChange(e, key, params) {
    const value = e.target.value;
    if (value === "") {
      this.setParams({ ...params, [key]: "" });
    } else {
      const numValue = Number(value);
      if (!isNaN(numValue)) {
        this.setParams({ ...params, [key]: numValue });
      }
    }
  }

  validateParams(key, params) {
    const { p, q, e } = params;

    if (key === "p" && p && !this.isPrime(p)) {
      const recommendedP = this.getRandomPrime();
      toast.clearWaitingQueue();
      toast.dismiss();
      toast.error(`p must be a prime number. For example ${recommendedP}.`);
    }

    if (key === "q" && q && !this.isPrime(q)) {
      const recommendedQ = this.getRandomPrime();
      toast.clearWaitingQueue();
      toast.dismiss();
      toast.error(`q must be a prime number. For example ${recommendedQ}.`);
    }

    if (key === "e" && e) {
      const phi = (params.p - 1) * (params.q - 1);
      if (e <= 1 || e >= phi || this.gcd(e, phi) !== 1) {
        const recommendedE = this.getRandomCoprime(phi);
        toast.clearWaitingQueue();
        toast.dismiss();
        toast.error(
          `e must be greater than 1, less than ${phi}, and coprime with ${phi}. For example ${recommendedE}.`
        );
      }
    }
  }

  encrypt(message, encryptionKey) {
    
    //if (message !== undefined && encryptionKey !== undefined && encryptionKey.e !== undefined && encryptionKey.n !== undefined) {
    if (message && typeof message === "number" && encryptionKey?.e && encryptionKey?.n) {
      //console.log(message);
      //console.log(encryptionKey);
      const messageBI = BigInt(message);
      const result = this.modExp(messageBI, BigInt(encryptionKey.e), BigInt(encryptionKey.n));
      console.log(result);
      return result.toString();
    } else {
      //TO CHANGE: Raise exception
      return "Message: " + message + " - Key: " + encryptionKey;
    }
  }

  decrypt(cyphertext, decryptionKey) {
    //if (cyphertext !== undefined && decryptionKey !== undefined && decryptionKey.d !== undefined && decryptionKey.n !== undefined) {
    if (cyphertext && typeof cyphertext === "number" && decryptionKey?.d && decryptionKey?.n) {
      //console.log(cyphertext);
      //console.log(decryptionKey);
      const messageBI = BigInt(cyphertext);
      const result = this.modExp(messageBI, BigInt(decryptionKey.d), BigInt(decryptionKey.n));
      return result.toString();
    } else {
      //TO CHANGE: Raise exception
      return "Message: " + cyphertext + " - Key: " + decryptionKey;
    }
  }

  /* Old function when the parameters where listed here and not group. 
  encrypt(params) {
    const { hasKeys, p, q, e, input } = params;
    let newParams = { ...params };
    if (!hasKeys) {
      if (!p) {
        return;
      }

      if (!this.isPrime(p)) {
        return;
      }

      if (!q) {
        return;
      }

      if (!this.isPrime(q)) {
        return;
      }

      newParams.n = p * q;
      const phi = (p - 1) * (q - 1);
      newParams.phi = phi;

      if (!e) {
        return;
      }

      if (e <= 1 || e >= phi || this.gcd(e, phi) !== 1) {
        return;
      }

      newParams.d = this.modInverse(e, phi);

      if (newParams.d === null || newParams.d === undefined) {
        toast.clearWaitingQueue();
        toast.dismiss();
        toast.error(
          "Failed to calculate the modular inverse. Please check the values of p, q, and e."
        );
        return;
      }
      newParams.e = e;
      newParams.kpub = `(${newParams.e}, ${newParams.n})`;
      newParams.kpriv = `(${newParams.d}, ${newParams.n})`;

      this.setParams(newParams);
    }
    else{
      newParams.n = params.privKey[1];
      newParams.e = params.pubKey[0];
    }

    if (input !== undefined) {
      console.log(newParams);
      const message = BigInt(input);
      const result = this.modExp(message, BigInt(newParams.e), BigInt(newParams.n));
      return result.toString();
    }
  }

  decrypt(params) {
    const { p, q, e, input } = params;
    let newParams = { ...params };

    if (!p || !this.isPrime(p) || !q || !this.isPrime(q)) {
      return;
    }

    if (!q) {
      return;
    }

    if (!this.isPrime(q)) {
      return;
    }

    newParams.n = p * q;
    const phi = (p - 1) * (q - 1);
    newParams.phi = phi;

    if (!e || e <= 1 || e >= phi || this.gcd(e, phi) !== 1) {
      return;
    }

    newParams.d = this.modInverse(e, phi);

    if (newParams.d === null || newParams.d === undefined) {
      toast.clearWaitingQueue();
      toast.dismiss();
      toast.error(
        "Failed to calculate the modular inverse. Please check the values of p, q, and e."
      );
      return;
    }
    newParams.kpub = `(${e}, ${newParams.n})`;
    newParams.kpriv = `(${newParams.d}, ${newParams.n})`;

    this.setParams(newParams);

    if (input !== undefined) {
      const message = BigInt(input);
      const result = this.modExp(
        message,
        BigInt(newParams.d),
        BigInt(newParams.n)
      );
      return result.toString();
    }
  }*/

  modExp(base, exp, mod) {
    let result = BigInt(1);
    base = base % mod;
    while (exp > 0) {
      if (exp % BigInt(2) === BigInt(1)) {
        result = (result * base) % mod;
      }
      base = (base * base) % mod;
      exp = exp / BigInt(2);
    }
    return result;
  }

  isPrime(num) {
    if (num <= 1) return false;
    if (num <= 3) return true;
    if (num % 2 === 0 || num % 3 === 0) return false;
    for (let i = 5; i * i <= num; i += 6) {
      if (num % i === 0 || num % (i + 2) === 0) return false;
    }
    return true;
  }

  getRandomPrime() {
    let prime;
    do {
      prime = Math.floor(Math.random() * 100) + 2; // Generate a random number between 2 and 101
    } while (!this.isPrime(prime));
    return prime;
  }

  getRandomCoprime(phi) {
    let coprime;
    do {
      coprime = Math.floor(Math.random() * (phi - 2)) + 2; // Generate a random number between 2 and phi-1
    } while (this.gcd(coprime, phi) !== 1);
    return coprime;
  }

  gcd(a, b) {
    while (b !== 0) {
      [a, b] = [b, a % b];
    }
    return a;
  }

  modInverse(e, phi) {
    let m0 = phi,
      t,
      q;
    let x0 = 0,
      x1 = 1;

    if (phi === 1) return 0;

    while (e > 1) {
      // q is quotient
      q = Math.floor(e / phi);
      t = phi;

      // phi is remainder now, process same as Euclid's algo
      phi = e % phi;
      e = t;
      t = x0;

      x0 = x1 - q * x0;
      x1 = t;
    }

    // Make x1 positive
    if (x1 < 0) x1 += m0;

    return x1;
  }
}

export default RSAAlgorithm;
