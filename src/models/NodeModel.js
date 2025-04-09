import CryptoJS from "crypto-js";
import DataWrapper from "./DataWrapper";

class NodeModel {
    constructor(id, inputs = []) {
      this.id = id;
      this.inputs = inputs;
      this.data = new DataWrapper();
      this.hash = '';
      this.generateHash();
    }

    // Function to serialize the object into a JSON string
    serialize() {/*
      return JSON.stringify({
        id: this.id,
      });*/
      return JSON.stringify(this, null, 2);
    }
  
    generateHash() {
      const serialized = this.serialize(); 
      const hash = CryptoJS.SHA256(serialized); 
      this.hash = hash.toString(CryptoJS.enc.Hex); 
    }
  }

  //prova
  
  export default NodeModel;
  