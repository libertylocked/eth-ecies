"use strict"
const ecies = require("../index");

const assert = require('chai').assert;
const expect = require('chai').expect;
const crypto = require("crypto");
const eutil = require("ethereumjs-util");

describe("ECIES", () => {
  describe("encrypt", () => {
    it("should encrypt a message without error", () => {
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const encrypted = ecies.encrypt(pubKey, `foo`);
      assert.isAtLeast(encrypted.length, 113);
    });

    it("should throw an error if priv key is given", () => {
      const privKey = crypto.randomBytes(32);
      expect(() => ecies.encrypt(privKey, "foo"))
        .to.throw('Unknown point format');
    });

    it("should accept provided IV and ephem key", () => {
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const iv = crypto.randomBytes(16);
      const ephemPrivKey = crypto.randomBytes(32);
      // append 0x04 prefix to the EC key
      const ephemPubKey = Buffer.concat([Buffer.from([0x04]),
        eutil.privateToPublic(ephemPrivKey)]);
      const encrypted = ecies.encrypt(pubKey, `foo`, {
        iv,
        ephemPrivKey,
      })
      assert.deepEqual(iv, encrypted.slice(0, 16));
      assert.deepEqual(ephemPubKey, encrypted.slice(16, 81));
    })
  });

  describe("roundtrip", () => {
    it("should return the same plaintext after roundtrip", () => {
      const plaintext = new Buffer("spam");
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const encrypted = ecies.encrypt(pubKey, plaintext);
      const decrypted = ecies.decrypt(privKey, encrypted);
      assert.deepEqual(decrypted, plaintext);
    });

    it("should only decrypt if correct priv key is given", () => {
      const plaintext = new Buffer("spam");
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const fakePrivKey = crypto.randomBytes(32);
      const decrypted = ecies.encrypt(pubKey, plaintext);
      assert.notDeepEqual(decrypted, plaintext);
    });

    it("should detect ciphertext changes thru MAC", () => {
      const plaintext = new Buffer("spam");
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const encrypted = ecies.encrypt(pubKey, plaintext);
      const modifiedEncrypted = new Buffer(encrypted.byteLength);
      encrypted.copy(modifiedEncrypted, 0, 0, 113);
      expect(() => ecies.decrypt(privKey, modifiedEncrypted))
        .to.throw('MAC mismatch');
    })

    it("should be able to encrypt and decrypt a longer message (1024 bytes)", () => {
      const plaintext = crypto.randomBytes(1024);
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const encrypted = ecies.encrypt(pubKey, plaintext);
      const decrypted = ecies.decrypt(privKey, encrypted);
      assert.deepEqual(decrypted, plaintext);
    })

    it("should decrypt with provided iv and ephem key", () => {
      const plaintext = new Buffer("spam");
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const iv = crypto.randomBytes(16);
      const ephemPrivKey = crypto.randomBytes(32);
      const encrypted = ecies.encrypt(pubKey, plaintext, {
        iv,
        ephemPrivKey,
      });
      const decrypted = ecies.decrypt(privKey, encrypted);
      assert.deepEqual(decrypted, plaintext);
    })
  })
});
