import sha1 from './sha1';
const bigInt = require('big-integer');
const randomBytes = require('randombytes');
const aesjs = require('aes-js');
const forge = require('node-forge');
const AES_IGE = require('./aes_ige');
const { hexToBytes, bytesToHex, concatUint8, getWindow } = require('../utils');

const bytesToSHA1 = async (bytes) => {
  const res = sha1(bytes);
  return res;
};

const bytesToSHA256 = async (bytes) => {
  const w = getWindow();
  const res = new Uint8Array(await w.crypto.subtle.digest("SHA-256", bytes));
  return res;
};

const TL_RSA = async (data, key) => {
  const exp = hexToBytes(key.exp);
  const mod = hexToBytes(key.mod);
  const bytes = new Uint8Array(await modPow(data, exp, mod));
  return bytes;
};

const makeG_B = (g, b, p) => {
  return modPow(g, b, p);
};

const makeAuthKey = (g_a, b, p) => {
  return modPow(g_a, b, p);
};

const modPow = async (baseNum, exponent, modulus) => {
  const base = bigInt(bytesToHex(baseNum), 16);
  const exp = bigInt(bytesToHex(exponent), 16);
  const mod = bigInt(bytesToHex(modulus), 16);
  const res = base.modPow(exp, mod);
  const bytes = hexToBytes(res.toString(16));
  return bytes;

  // const xBigInt = BI.str2bigInt(bytesToHex(baseNum), 16);
  // const yBigInt = BI.str2bigInt(bytesToHex(exponent), 16);
  // const mBigInt = BI.str2bigInt(bytesToHex(modulus), 16);
  // const resBigInt = BI.powMod(xBigInt, yBigInt, mBigInt);
  // const BIb = hexToBytes(BI.bigInt2str(resBigInt, 16));
  // return BIb;
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
  const res = Uint8Array.from(hexToBytes(cipher.output.toHex()));
  return res;
};

const decryptAES_CTR  = async (bytes, key, iv) => {
  var decipher = forge.cipher.createDecipher('AES-CTR', forge.util.createBuffer(key));
  decipher.start({ iv: forge.util.createBuffer(iv) });
  decipher.update(forge.util.createBuffer(bytes));
  if (!decipher.finish()) {
    throw("Failed to decrypt");
  }
  return Uint8Array.from(hexToBytes(decipher.output.toHex()));
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

const getRandomBytes = async (number) => {
  return randomBytes(number);
};

const makeTmpAESKeys = async (newNonce, serverNonce) => {
  const newNoncePlusServer = await bytesToSHA1(concatUint8([newNonce, serverNonce]));
  const serverPlusNewNonce = await bytesToSHA1(concatUint8([serverNonce, newNonce]));
  const newNoncePlusNewNonce = await bytesToSHA1(concatUint8([newNonce, newNonce]));

  const tmp_aes_key = concatUint8([newNoncePlusServer, serverPlusNewNonce.slice(0, 12)]);
  const tmp_aes_iv = concatUint8([
    concatUint8([serverPlusNewNonce.slice(12, 20), newNoncePlusNewNonce]),
    newNonce.slice(0, 4)
  ]);

  return [tmp_aes_key, tmp_aes_iv];
}; 

const generateMsgKey = async (authKey, messageBytes, x) => {
  // msg_key_large = SHA256(substr(auth_key, 88 + x, 32) + plaintext + random_padding);
  const msg_key_large = await bytesToSHA256(
    concatUint8([authKey.slice(88 + x, 88 + x + 32), messageBytes])
  );
  // msg_key = substr(msg_key_large, 8, 16);
  const msg_key = msg_key_large.slice(8, 24);

  return msg_key;
};

const getEncryptionParams = async ({
  authKey,
  messageBytes,
  inputMsgKey,
  isOutgoingMsg = true
}) => {
  const x = isOutgoingMsg ? 0 : 8;

  const msg_key =
    (inputMsgKey)
      ? inputMsgKey
      : await generateMsgKey(authKey, messageBytes, x);

  // sha256_a = SHA256(msg_key + substr(auth_key, x, 36));
  const sha256_a = await bytesToSHA256(
    concatUint8([msg_key, authKey.slice(x, x + 36)])
  );

  // sha256_b = SHA256(substr(auth_key, 40 + x, 36) + msg_key);
  const sha256_b = await bytesToSHA256(
    concatUint8([authKey.slice(40 + x, 40 + x + 36), msg_key])
  );

  // aes_key = substr(sha256_a, 0, 8) + substr(sha256_b, 8, 16) + substr(sha256_a, 24, 8);
  const aes_key = concatUint8([
    sha256_a.slice(0, 8),
    sha256_b.slice(8, 24),
    sha256_a.slice(24, 32)
  ]);

  // aes_iv = substr(sha256_b, 0, 8) + substr(sha256_a, 8, 16) + substr(sha256_b, 24, 8);
  const aes_iv = concatUint8([
    sha256_b.slice(0, 8),
    sha256_a.slice(8, 24),
    sha256_b.slice(24, 32)
  ]);

  return {
    msg_key,
    aes_key,
    aes_iv
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
  modPow,
  getRandomBytes,
  makeTmpAESKeys,
  getEncryptionParams
};