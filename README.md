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
The ECIES implementation uses **fixed Diffie-Hellman** (*ephemeral-static*) key exchange and provides no *Perfect Forward Secrecy (PFS)*. A quick rundown of the implementation [can be found here](https://github.com/libertylocked/eth-ecies/issues/3#issuecomment-424928493)

## Appropriate use cases of this library
- Encrypted file storage
- Encrypted emails (where forward secrecy is not desirable, e.g. being able to read past emails)

## Inappropriate use cases
- Instant messaging for casual conversations
