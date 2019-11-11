const forge = require('node-forge');
const {
  pqPrimeFactorization,
  bytesToHex,
  bytesFromHex
} = require('../primeFactorization');
const BI = require('leemon');
const { encrypt, decrypt } = require('./aes_ige');

const bytesToSHA1 = (bytes, returnHex = false) => {
  const str = String.fromCharCode(...bytes);
  const hex = forge.md.sha1.create().update(str).digest().toHex();
  return bytesFromHex(hex);
};

const bytesToSHA256 = (bytes, returnHex = false) => {
  const str = String.fromCharCode(...bytes);
  const hex = forge.md.sha256.create().update(str).digest().toHex();
  return bytesFromHex(hex);
};

const TL_RSA = (data, keyStr) => {
  const bigData = new forge.jsbn.BigInteger(data);
  const publicKey = forge.pki.publicKeyFromPem(keyStr);
  const enc = bigData.modPow(publicKey.e, publicKey.n);
  const bytes = bytesFromHex(enc.toString(16));
  return bytes;
};

const makeG_B = (g, b, p) => {
  return modPow(g, b, p);
};

const makeAuthKey = (g_a, b, p) => {
  return modPow(g_a, b, p);
};

const modPow = (baseNum, exponent, modulus) => {
  const xBigInt = BI.str2bigInt(bytesToHex(baseNum), 16);
  const yBigInt = BI.str2bigInt(bytesToHex(exponent), 16);
  const mBigInt = BI.str2bigInt(bytesToHex(modulus), 16);
  const resBigInt = BI.powMod(xBigInt, yBigInt, mBigInt);
  const BIb = bytesFromHex(BI.bigInt2str(resBigInt, 16));
  return BIb;

  // const bigB = new forge.jsbn.BigInteger(baseNum.slice(0).reverse());
  // const bigE = new forge.jsbn.BigInteger(exponent.slice(0).reverse());
  // const bigM = new forge.jsbn.BigInteger(modulus.slice(0).reverse());
  // const res = bigB.modPow(bigE, bigM);
  // const bytes = bytesFromHex(res.toString(16));
  // return bytes;
};

const decryptAES = (bytes, key, iv) => {
  return decrypt(bytes, key, iv);
};

const encryptAES = (bytes, key, iv) => {
  return encrypt(bytes, key, iv);
};

module.exports = {
  bytesToSHA1,
  bytesToSHA256,
  TL_RSA,
  decryptAES,
  encryptAES,
  makeG_B,
  makeAuthKey
};