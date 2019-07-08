'use strict';

const { assert } = require('chai');
const { expect } = require('chai');
const crypto = require('crypto');
const eutil = require('ethereumjs-util');
const ecies = require('../index');

describe('ECIES', () => {
  describe('encrypt', () => {
    it('should encrypt a message without error', () => {
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const encrypted = ecies.encrypt(pubKey, 'foo');
      assert.isAtLeast(encrypted.length, 113);
    });

    it('should throw an error if priv key is given', () => {
      const privKey = crypto.randomBytes(32);
      expect(() => ecies.encrypt(privKey, 'foo'))
        .to.throw('Unknown point format');
    });

    it('should accept provided IV and ephem key', () => {
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const iv = crypto.randomBytes(16);
      const ephemPrivKey = crypto.randomBytes(32);
      // append 0x04 prefix to the EC key
      const ephemPubKey = Buffer.concat([Buffer.from([0x04]),
        eutil.privateToPublic(ephemPrivKey)]);
      const encrypted = ecies.encrypt(pubKey, 'foo', {
        iv,
        ephemPrivKey,
      });
      assert.deepEqual(ephemPubKey, encrypted.slice(0, 65));
      assert.deepEqual(iv, encrypted.slice(65, 81));
    });
  });

  describe('roundtrip', () => {
    it('should return the same plaintext after roundtrip', () => {
      const plaintext = Buffer.from('spam');
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const encrypted = ecies.encrypt(pubKey, plaintext);
      const decrypted = ecies.decrypt(privKey, encrypted);
      assert.deepEqual(decrypted, plaintext);
    });

    it('should only decrypt if correct priv key is given', () => {
      const plaintext = Buffer.from('spam');
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const decrypted = ecies.encrypt(pubKey, plaintext);
      assert.notDeepEqual(decrypted, plaintext);
    });

    it('should detect ciphertext changes thru MAC', () => {
      const plaintext = Buffer.from('spam');
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const encrypted = ecies.encrypt(pubKey, plaintext);
      const modifiedEncrypted = Buffer.alloc(encrypted.byteLength);
      encrypted.copy(modifiedEncrypted, 0, 0, 113);
      expect(() => ecies.decrypt(privKey, modifiedEncrypted))
        .to.throw('MAC mismatch');
    });

    it('should be able to encrypt and decrypt a longer message (1024 bytes)', () => {
      const plaintext = crypto.randomBytes(1024);
      const privKey = crypto.randomBytes(32);
      const pubKey = eutil.privateToPublic(privKey);
      const encrypted = ecies.encrypt(pubKey, plaintext);
      const decrypted = ecies.decrypt(privKey, encrypted);
      assert.deepEqual(decrypted, plaintext);
    });

    it('should decrypt with provided iv and ephem key', () => {
      const plaintext = Buffer.from('spam');
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
    });

    it('should be same as go-ethereum encrypted result', () => {
      const plaintext = Buffer.from('Hello, world.');
      const privKey = Buffer.from('d0b043b4c5d657670778242d82d68a29d25d7d711127d17b8e299f156dad361a', 'hex');
      const pubKey = eutil.privateToPublic(privKey);

      const ephemPrivKey = Buffer.from('1f264057916c537739c9a0581914c72cf986abb64d63265929356bc760777749', 'hex');
      const iv = Buffer.from('cb3de3aeef5c4b46465e8057a1c71b94', 'hex');
      const opt = { ephemPrivKey, iv };
      const encrypted = ecies.encrypt(pubKey, plaintext, opt);
      const expectedResult = Buffer.from('0420642e5c476a6c0d631b0990c9b1691cf717c0ccb0bdc9fab4a9ffc83784b1c7a8324f30f860fa080ac03bfab2e9e20e8c1eb71e29c7cecee3214501f1096692cb3de3aeef5c4b46465e8057a1c71b947690c3817cb949a4acb38071ad3c9e2eaca126730e6bd7506cf94e27fac82bbf1090bd491c5060466cb91a5da9', 'hex');
      assert.deepEqual(expectedResult.toString('hex'), encrypted.toString('hex'));
    });
  });
});
