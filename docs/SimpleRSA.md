# 🔑 Simple RSA Algorithm: Key Generation, Encryption, and Digital Signature

The **Simple RSA** algorithm is a public-key cryptosystem that provides **confidentiality** (through encryption and decryption) and **authenticity** and **integrity** (through digital signature). It uses a key pair: a **Public Key ($PK$)** which is shared, and a **Private Key ($SK$)** which is kept secret.

---

## 🗝️ Key-Pair Generation

Any entity, for example $B$, wishing to participate in the system must generate its key pair $\langle PK_B, SK_B \rangle$.

1.  **Choose Primes ($p, q$):** $B$ chooses two distinct **large prime numbers** $p$ and $q$ of similar size.
    * *Example:* $p=281$, $q=167$.
2.  **Compute $n$ and $\phi(n)$:**
    * Calculate the **modulus** $n$: $n = p \cdot q$.
    * Calculate **Euler's totient function** $\phi(n)$: $\phi(n) = (p-1)(q-1)$.
    * *Example:* $n = 281 \cdot 167 = 46927$. $\phi(n) = (280)(166) = 46480$.
3.  **Choose Public Exponent ($e$):** $B$ selects an integer $e$ such that $1 < e < \phi(n)$ and the **greatest common divisor** between $e$ and $\phi(n)$ is $1$ ($\mbox{gcd}(e, \phi(n)) = 1$).
    * *Example:* $e = 39423$.
4.  **Compute Private Exponent ($d$):** $B$ calculates the multiplicative inverse of $e$ modulo $\phi(n)$. This value is $d$, which satisfies the equation $e \cdot d \bmod \phi(n) = 1$.
    * *Example:* $d = 26767$.
5.  **Define Key Pair:**
    * **Public Key:** $PK_B = (n, e)$. This is made public.
    * **Private Key:** $SK_B = d$. This is kept secret.
    * *Example:* $PK_B = (46927, 39423)$, $SK_B = 26767$.

---

## 🔒 Encryption (Confidentiality)

The sender, for example $A$, uses the receiver's ($B$'s) **public key** to encrypt a message.

1.  **Message ($m$):** $A$ has the message $m$ to send, ensuring that $m < n_B$.
    * *Example:* $m=16346$.
2.  **Calculate Ciphertext ($c$):** $A$ computes the **ciphertext ($c$)** using $B$'s public key ($PK_B = (n_B, e_B)$):
    $$c = E_{PK_B}(m) = m^{e_B} \bmod n_B$$
    * *Example:* $c = 16346^{39423} \bmod 46927 = 21166$.
3.  **Send:** $A$ sends the ciphertext $c$ to $B$.

---

## 🔓 Decryption (Message Retrieval)

The receiver, $B$, uses their **private key** to recover the original message.

1.  **Receive:** $B$ receives the ciphertext $c$ from $A$.
    * *Example:* $c = 21166$.
2.  **Calculate Message ($m$):** $B$ computes the original message $m$ using their private key ($SK_B = d_B$):
    $$m = D_{SK_B}(c) = c^{d_B} \bmod n_B$$
    * Since $c = m^{e_B} \bmod n_B$, the decryption is $m = (m^{e_B})^{d_B} \bmod n_B$.
    * *Example:* $m = 21166^{26767} \bmod 46927 = 16346$.

---

## ✍️ Digital Signature (Authenticity and Integrity)

The mathematical property of RSA ($E_{PK}(D_{SK}(m)) = m$) allows the keys to be used in reverse to create and verify a **digital signature**, ensuring the message originates from the signer and has not been altered.

### Signature Creation

The signer, for example $A$, uses their **private key** ($SK_A=d_A$) to "decrypt" the message (or a *hash* of the message) and generate the signature $s$.

1.  **Message to Sign ($m$):** $A$ has the message $m$.
    * *Example:* $m=16346$ (`YES`).
2.  **Calculate Signature ($s$):** $A$ applies their private key to the message $m$:
    $$s = D_{SK_A}(m) = m^{d_A} \bmod n_A$$
    * *Example:* Using $PK_A=(34121, 15775)$ and $SK_A=26623$: $s = 16346^{26623} \bmod 34121 = 20904$.
3.  **Send:** $A$ sends the pair **(message, signature)**: $(m, s)$.

### Signature Verification

Any receiver, for example $B$, uses the signer's **public key** ($PK_A = (n_A, e_A)$) to verify the signature.

1.  **Verification Calculation:** $B$ applies $A$'s public key to the signature $s$:
    $$m' = E_{PK_A}(s) = s^{e_A} \bmod n_A$$
    * *Example:* $m' = 20904^{15775} \bmod 34121 = 16346$.
2.  **Comparison:** $B$ compares the result $m'$ with the original message $m$.
    * If $m' = m$, the **signature is valid** (the message was signed by $A$ and has not been altered).
    * If $m' \neq m$, the signature is invalid.
    * *Example:* $16346 = 16346$. The signature is valid.
