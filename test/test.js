"use strict"
const ecies = require("../index");

const assert = require('chai').assert;
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
      try {
        ecies.encrypt(privKey, "foo")
        assert.fail("encryption should not work when a priv key is given");
      } catch (err) {
        // ok
      }
    });
  });

  describe("roundtrip", () => {
    it("should return the same plaintext after roundtrip", () => {
      const plaintext = new Buffer("spam");
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const encrypted = ecies.encrypt(pubKey, plaintext);
      const decrypted = ecies.decrypt(privKey, encrypted);
      assert.equal(decrypted.toString(), plaintext.toString());
    });

    it("should only decrypt if correct priv key is given", () => {
      const plaintext = new Buffer("spam");
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const fakePrivKey = crypto.randomBytes(32);
      try {
        ecies.encrypt(pubKey, plaintext)
        assert.fail("decryption should not work for incorrect priv key");
      } catch (err) {
        // ok
      }
    });

    it("should be able to encrypt and decrypt a longer message (1024 bytes)", () => {
      const plaintext = crypto.randomBytes(1024);
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const encrypted = ecies.encrypt(pubKey, plaintext);
      const decrypted = ecies.decrypt(privKey, encrypted);
      assert.equal(decrypted.toString(), plaintext.toString());
    })
  })
});
