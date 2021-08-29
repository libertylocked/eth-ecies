eth-ecies
---
ECIES encrypt/decrypt library for Ethereum

# Usage

## Encrypt
```javascript
const ecies = require("eth-ecies");
let plaintext = new Buffer(`{foo:"bar",baz:42}`);
let encryptedMsg = ecies.encrypt(ethPubKey, plaintext);
// encrypted message is a 113+ byte buffer
```

## Decrypt
```javascript
const ecies = require("eth-ecies");
let plaintext = ecies.decrypt(ethPrivKey, encryptedMsg);
```

# Notes
To derive the public key from a private key, you can use `ethereumjs-util` module

# Security
The ECIES implementation uses **fixed Diffie-Hellman** (*ephemeral-static*) key exchange and provides no *Perfect Forward Secrecy (PFS)*. AES-256-CBC HMAC-SHA256 is used as AEAD algorithm.
