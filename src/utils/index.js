const bigInt = require('big-integer');
const { bytesToSHA1, bytesToSHA256 } = require("../crypto");
const { pqPrimeFactorization } = require("../primeFactorization");

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

const concatUint8 = (listOfArrays) => {
  const len = listOfArrays.reduce((sum, arr) => {
    sum += arr.length;
    return sum;
  }, 0);
  const uint8 = new Uint8Array(new ArrayBuffer(len));
  let offset = 0;
  listOfArrays.forEach((arr) => {
    uint8.set(arr, offset);
    offset += arr.length;
  });
  return uint8;
};

const xorArrays = (arr1, arr2) => {
  const res = new Uint8Array(new ArrayBuffer(arr1.length));
	for (let i = 0; i < arr1.length; i++) {
    res[i] = arr1[i] ^ arr2[i];
  }
  return res;
};

const serializeString = (bytes) => {
  const len = bytes.length;
  let header = [];
  if (len <= 253) {
    header.push(len);
  } else {
    header.push(254);
    header.push(len & 0xff);
    header.push((len >> 8) & 0xff);
    header.push((len >> 16) & 0xff);
  }
  const padNum = 4 - ((header.length + bytes.length) % 4);
  let padding = [];
  if (padNum > 0 && padNum < 4) {
    padding = (new Array(padNum)).fill(0);
  }
  const buf = new ArrayBuffer(header.length + bytes.length + padding.length);
  const uint8 = new Uint8Array(buf);
  uint8.set(header, 0);
  uint8.set(bytes, header.length);
  uint8.set(padding, header.length + bytes.length);
  return uint8;
};

const unserializeString = (bytes) => {
  const len = bytes[0];
  let content;
  if (len === 254) {
    const realLen = bytes[1] * 1 + bytes[2] * 256 + bytes[3] * 4096;
    content = bytes.slice(4, 4 + realLen);
  } else {
    content = bytes.slice(1, 1 + len);
  }
  return content;
};

const pow2to32 = bigInt("4294967296");
const makeMsgIdHex = async (date = false) => {
  if (!date) date = Math.floor(new Date() / 1000);
  const unixTime = bigInt(date);
  const msg_id = unixTime.multiply(pow2to32);
  return msg_id.toString(16);
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

const bytesToInt = (bytes, littleEndian = true) => {
  let input = bytes.slice(0);
  if (Array.isArray(input)) {
    input = Uint8Array.from(input);
  }
  if (littleEndian) {
    input.reverse();
  }
  const view = new DataView(input.buffer);
  return view.getInt32(0);
};

const intToBytes = (num, size = 4, littleEndian = true) => {
  const arr = new ArrayBuffer(size);
  const view = new DataView(arr);
  switch (size) {
    case 4:
      view.setUint32(0, num, littleEndian);
      break;
  }
  return new Uint8Array(arr);
};

const primeFactorization = async (bytes) => {
  return pqPrimeFactorization(bytes);
};

module.exports = {
  concatUint8,
  makeTmpAESKeys,
  xorArrays,
  serializeString,
  unserializeString,
  makeMsgIdHex,
  getEncryptionParams,
  bytesToInt,
  intToBytes,
  primeFactorization
};