"use strict"
const ecies = require("../index");

const assert = require('chai').assert;
const crypto = require("crypto");
const eutil = require("ethereumjs-util");

describe("ECIES", () => {
  describe("encrypt", () => {
    it("should encrypt a message without error", async () => {
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const encrypted = await ecies.encrypt(pubKey, `foo`);
      assert.isAtLeast(encrypted.length, 113);
    });

    it("should throw an error if priv key is given", () => {
      const privKey = crypto.randomBytes(32);
      return ecies.encrypt(privKey, "foo")
      .then(() => {
        assert.fail("did not throw error when a priv key is given");
      })
      .catch((err) => {
        // ok
      })
    });
  });

  describe("roundtrip", () => {
    it("should return the same plaintext after roundtrip", async () => {
      const plaintext = new Buffer("spam");
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const encrypted = await ecies.encrypt(pubKey, plaintext);
      const decrypted = await ecies.decrypt(privKey, encrypted);
      assert.equal(decrypted.toString(), plaintext.toString());
    });

    it("should only decrypt if correct priv key is given", () => {
      const plaintext = new Buffer("spam");
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const fakePrivKey = crypto.randomBytes(32);
      return ecies.encrypt(pubKey, plaintext)
      .then((encrypted) => {
        return ecies.decrypt(fakePrivKey, encrypted);
      })
      .then(() => {
        assert.fail("decryption should not work");
      })
      .catch((err) => {
        // ok
      })
    });

    it("should be able to encrypt and decrypt a longer message (1024 bytes)", async () => {
      const plaintext = crypto.randomBytes(1024);
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const encrypted = await ecies.encrypt(pubKey, plaintext);
      const decrypted = await ecies.decrypt(privKey, encrypted);
      assert.equal(decrypted.toString(), plaintext.toString());
    })
  })
});
