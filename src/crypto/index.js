const forge = require('node-forge');
const {
  pqPrimeFactorization,
  bytesToHex,
  bytesFromHex
} = require('../primeFactorization');
const BI = require('leemon');
const { decrypt } = require('./aes_ige');

const bytesToSHA1 = (bytes, returnHex = false) => {
  const str = String.fromCharCode(...bytes);
  const hex = forge.md.sha1.create().update(str).digest().toHex();
  return bytesFromHex(hex);
};

const TL_RSA = (data, keyStr) => {
  const bigData = new forge.jsbn.BigInteger(data);
  const publicKey = forge.pki.publicKeyFromPem(keyStr);
  const enc = bigData.modPow(publicKey.e, publicKey.n);
  const bytes = bytesFromHex(enc.toString(16));
  return bytes;
};

const decryptAES = (bytes, key, iv) => {
  return decrypt(bytes, key, iv);
};

module.exports = {
  bytesToSHA1,
  TL_RSA,
  decryptAES
};