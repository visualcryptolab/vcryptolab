# VisualCryptoLab Examples

This directory contains example projects that demonstrate various cryptographic protocols and concepts implemented using VisualCryptoLab. You can import these `.json` files directly into the application to see them in action.

## Available Examples

### Block Cipher Modes
- **CBC.json (Cipher Block Chaining):** Demonstrates the CBC mode of operation, where each block of plaintext is XORed with the previous ciphertext block before being encrypted. This example visualizes the chaining mechanism.
- **CBC-prep.json:** A preparatory or simplified setup for understanding the components required for CBC mode.
- **CFB.json (Cipher Feedback):** Demonstrates the CFB mode, which turns a block cipher into a self-synchronizing stream cipher. It shows how the previous ciphertext is encrypted and then XORed with the plaintext.

### Asymmetric Cryptography (RSA)
- **IS - Simple RSA - Enc-Dec example.json:** A complete walkthrough of RSA encryption and decryption using small numbers ("Textbook RSA"). It likely includes key generation, encryption of a message, and decryption back to the original plaintext.
- **IS - Simple RSA - Signature.json:** Demonstrates digital signatures using RSA. shows how a message hash is "signed" (encrypted) with a private key and verified with the corresponding public key.

### Data Structures & Hashing
- **Merkle tree.json:** Visualizes a Merkle Tree (hash tree), showing how leaf nodes (data blocks) are hashed and combined pairwise up to a single root hash. This is fundamental for verifying data integrity in distributed systems like blockchains.

## How to Use
1. Download the `.json` file of the example you want to explore.
2. Open VisualCryptoLab.
3. Click the **"Import JSON"** button (Upload icon) in the toolbar.
4. Select the downloaded file.
5. The project will load onto the canvas, allowing you to inspect the connections and data flow.
