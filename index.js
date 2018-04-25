/**
 * ECIES encrypt/decrypt with Ethereum keys
 * Modified from https://github.com/vhpoet/simple-ecies/blob/master/index.js
 */
"use strict"

const Crypto = require("crypto");
const EC = require("elliptic").ec;
const ec = new EC("secp256k1");

/**
 * AES-256 CBC encrypt
 * @param {Buffer} iv
 * @param {Buffer} key
 * @param {Buffer} plaintext
 * @returns {Buffer} ciphertext
 */
const AES256CbcEncrypt = (iv, key, plaintext) => {
  const cipher = Crypto.createCipheriv("aes-256-cbc", key, iv);
  const firstChunk = cipher.update(plaintext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

/**
 * AES-256 CBC decrypt
 * @param {Buffer} iv
 * @param {Buffer} key
 * @param {Buffer} ciphertext
 * @returns {Buffer} plaintext
 */
const AES256CbcDecrypt = (iv, key, ciphertext) => {
  const cipher = Crypto.createDecipheriv("aes-256-cbc", key, iv);
  const firstChunk = cipher.update(ciphertext);
  const secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

/**
 * Compares if two buffers are equal
 * @param {Buffer} b1
 * @param {Buffer} b2
 * @returns {boolean} true if the buffers are equal
 */
const BufferEqual = (b1, b2) => {
  if (b1.length !== b2.length) {
    return false;
  }
  let res = 0;
  for (let i = 0; i < b1.length; i++) {
    res |= b1[i] ^ b2[i];
  }
  return res === 0;
}

/**
 * ECIES encrypt
 * @param {Buffer} pubKeyTo Ethereum pub key, 64 bytes
 * @param {Buffer} plaintext Plaintext to be encrypted
 * @param {?{?iv: Buffer, ?ephemPrivKey: Buffer}} opts
 * optional iv (16 bytes) and ephem key (32 bytes)
 * @returns {Buffer} Encrypted message, serialized, 113+ bytes
 */
const Encrypt = (pubKeyTo, plaintext, opts) => {
  opts = opts || {};
  const ephemPrivKey = ec.keyFromPrivate(
    opts.ephemPrivKey || Crypto.randomBytes(32));
  const ephemPubKey = ephemPrivKey.getPublic();
  const ephemPubKeyEncoded = Buffer.from(ephemPubKey.encode());
  // Every EC public key begins with the 0x04 prefix before giving
  // the location of the two point on the curve
  const px = ephemPrivKey.derive(ec.keyFromPublic(
    Buffer.concat([Buffer.from([0x04]), pubKeyTo])).getPublic());
  const hash = Crypto.createHash("sha512").update(px.toBuffer()).digest();
  const iv = opts.iv || Crypto.randomBytes(16);
  const encryptionKey = hash.slice(0, 32);
  const macKey = hash.slice(32);
  const ciphertext = AES256CbcEncrypt(iv, encryptionKey, plaintext);
  const dataToMac = Buffer.concat([iv, ephemPubKeyEncoded, ciphertext]);
  const mac = Crypto.createHmac("sha256", macKey).update(dataToMac).digest();
  const serializedCiphertext = Buffer.concat([
    iv, // 16 bytes
    ephemPubKeyEncoded, // 65 bytes
    mac, // 32 bytes
    ciphertext,
  ])
  return serializedCiphertext;
}

/**
 * ECIES decrypt
 * @param {Buffer} privKey Ethereum private key, 32 bytes
 * @param {Buffer} encrypted Encrypted message, serialized, 113+ bytes
 * @returns {Buffer} plaintext
 */
const Decrypt = (privKey, encrypted) => {
  // read iv, ephemPubKey, mac, ciphertext from encrypted message
  const iv = encrypted.slice(0, 16)
  const ephemPubKeyEncoded = encrypted.slice(16, 81);
  const mac = encrypted.slice(81, 113);
  const ciphertext = encrypted.slice(113);
  const ephemPubKey = ec.keyFromPublic(ephemPubKeyEncoded).getPublic();

  const px = ec.keyFromPrivate(privKey).derive(ephemPubKey);
  const hash = Crypto.createHash("sha512").update(px.toBuffer()).digest();
  const encryptionKey = hash.slice(0, 32);
  const macKey = hash.slice(32);
  const dataToMac = Buffer.concat([iv, ephemPubKeyEncoded, ciphertext]);
  const computedMac = Crypto.createHmac("sha256", macKey).update(dataToMac).digest();
  // verify mac
  if (!BufferEqual(computedMac, mac)) {
    throw new Error("MAC mismatch");
  }
  const plaintext = AES256CbcDecrypt(iv, encryptionKey, ciphertext);
  return plaintext;
}

module.exports = {
  encrypt: Encrypt,
  decrypt: Decrypt,
};
