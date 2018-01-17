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
- To derive the public key from a private key, you can use `ethereumjs-util` module
