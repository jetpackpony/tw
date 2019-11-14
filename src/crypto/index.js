const { sha1, sha256 } = require('crypto-hash');
const aesjs = require('aes-js');
const forge = require('node-forge');
const {
  pqPrimeFactorization,
  bytesToHex,
  bytesFromHex
} = require('../primeFactorization');
const BI = require('leemon');
const AES_IGE = require('./aes_ige');

const bytesToSHA1 = async (bytes, returnHex = false) => {
  return new Uint8Array(await sha1(bytes, { outputFormat: "buffer" }));
};

const bytesToSHA256 = async (bytes, returnHex = false) => {
  return new Uint8Array(await sha256(bytes, { outputFormat: "buffer" }));
};

const TL_RSA = async (data, keyStr) => {
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

const modPow = async (baseNum, exponent, modulus) => {
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

const decryptAES = async (bytes, key, iv) => {
  return AES_IGE.decrypt(bytes, key, iv);
};

const encryptAES = async (bytes, key, iv) => {
  return AES_IGE.encrypt(bytes, key, iv);
};

const encryptAES_CTR = async (bytes, key, iv) => {
  const cipher = forge.cipher.createCipher('AES-CTR', forge.util.createBuffer(key));
  cipher.start({ iv: forge.util.createBuffer(iv) });
  cipher.update(forge.util.createBuffer(bytes));
  cipher.finish();
  const res = Uint8Array.from(bytesFromHex(cipher.output.toHex()));
  return res;
};

const decryptAES_CTR  = async (bytes, key, iv) => {
  var decipher = forge.cipher.createDecipher('AES-CTR', forge.util.createBuffer(key));
  decipher.start({ iv: forge.util.createBuffer(iv) });
  decipher.update(forge.util.createBuffer(bytes));
  if (!decipher.finish()) {
    throw("Failed to decrypt");
  }
  return Uint8Array.from(bytesFromHex(decipher.output.toHex()));
};

const makeEncryptorAES_CTR = async (key, iv) => {
  var aesCtr = new aesjs.ModeOfOperation.ctr(key, iv);
  return {
    encrypt: async (bytes) => aesCtr.encrypt(bytes)
  };
};

const makeDecryptorAES_CTR = async (key, iv) => {
  const aesCtr = new aesjs.ModeOfOperation.ctr(key, iv);
  return {
    decrypt: async (bytes) => aesCtr.decrypt(bytes)
  };
};

module.exports = {
  bytesToSHA1,
  bytesToSHA256,
  TL_RSA,
  decryptAES,
  encryptAES,
  encryptAES_CTR,
  decryptAES_CTR,
  makeG_B,
  makeAuthKey,
  makeEncryptorAES_CTR,
  makeDecryptorAES_CTR,
  modPow
};