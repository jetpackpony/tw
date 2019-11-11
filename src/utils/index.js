const BI = require('leemon');
const { bytesToSHA1, bytesToSHA256 } = require("../crypto");
const pow2to32 = BI.str2bigInt("4294967296", 10, 1);

const makeTmpAESKeys = (newNonce, serverNonce) => {
  const newNoncePlusServer = bytesToSHA1(concatUint8([newNonce, serverNonce]));
  const serverPlusNewNonce = bytesToSHA1(concatUint8([serverNonce, newNonce]));
  const newNoncePlusNewNonce = bytesToSHA1(concatUint8([newNonce, newNonce]));

  const tmp_aes_key = Uint8Array.from(newNoncePlusServer.concat(serverPlusNewNonce.slice(0, 12)));
  const tmp_aes_iv = concatUint8([
    Uint8Array.from(serverPlusNewNonce.slice(12, 20).concat(newNoncePlusNewNonce)),
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

const makeMsgIdHex = () => {
  const unixTime = BI.int2bigInt(Math.floor(new Date() / 1000), 32, 1);
  const msg_id = BI.mult(unixTime, pow2to32);
  return BI.bigInt2str(msg_id, 16);
};

const generateMsgKey = (authKey, messageBytes, x) => {
  // msg_key_large = SHA256(substr(auth_key, 88 + x, 32) + plaintext + random_padding);
  const msg_key_large = bytesToSHA256(
    concatUint8([authKey.slice(88 + x, 88 + x + 32), messageBytes])
  );
  // msg_key = substr(msg_key_large, 8, 16);
  const msg_key = Uint8Array.from(msg_key_large.slice(8, 24));

  return msg_key;
};

const getEncryptionParams = ({
  authKey,
  messageBytes,
  inputMsgKey,
  isOutgoingMsg = true
}) => {
  const x = isOutgoingMsg ? 0 : 8;

  const msg_key =
    (inputMsgKey)
      ? inputMsgKey
      : generateMsgKey(authKey, messageBytes, x);

  // sha256_a = SHA256(msg_key + substr(auth_key, x, 36));
  const sha256_a = bytesToSHA256(
    concatUint8([msg_key, authKey.slice(x, x + 36)])
  );

  // sha256_b = SHA256(substr(auth_key, 40 + x, 36) + msg_key);
  const sha256_b = bytesToSHA256(
    concatUint8([authKey.slice(40 + x, 40 + x + 36), msg_key])
  );

  // aes_key = substr(sha256_a, 0, 8) + substr(sha256_b, 8, 16) + substr(sha256_a, 24, 8);
  const aes_key = Uint8Array.from(
    sha256_a.slice(0, 8)
      .concat(sha256_b.slice(8, 24))
      .concat(sha256_a.slice(24, 32))
  );

  // aes_iv = substr(sha256_b, 0, 8) + substr(sha256_a, 8, 16) + substr(sha256_b, 24, 8);
  const aes_iv = Uint8Array.from(
    sha256_b.slice(0, 8)
      .concat(sha256_a.slice(8, 24))
      .concat(sha256_b.slice(24, 32))
  );

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

module.exports = {
  makeTmpAESKeys,
  xorArrays,
  serializeString,
  unserializeString,
  makeMsgIdHex,
  getEncryptionParams,
  bytesToInt
};