eth-ecies
---
ECIES encrypt/decrypt library for Ethereum

# Usage

## Encrypt
```javascript
const ecies = require("eth-ecies");
let plaintext = new Buffer(`{foo:"bar",baz:42}`);
let encryptedMsg = ecies.encrypt(ethPubKey, plaintext);
```

## Decrypt
```javascript
const ecies = require("eth-ecies");
let plaintext = ecies.decrypt(ethPrivKey, encryptedMsg);
```
