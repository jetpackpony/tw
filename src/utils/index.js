const bigInt = require('big-integer');
const { factorize } = require("./primeFactorization");

const getWindow = () => {
  if (typeof self !== 'undefined') return self;
  if (typeof window !== 'undefined') return window;
  if (typeof global !== 'undefined') return global;
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

const isEqualUint8 = (arr1, arr2) => {
  if (arr1.constructor !== arr2.constructor) return false;
  if (arr1.length !== arr2.length) return false;
  for (let i = 0; i < arr1.length; i++) {
    if (arr1[i] !== arr2[i]) return false;
  }
  return true;
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
  const n = bigInt(bytesToHex(bytes), 16);
  const res = factorize(n);
  return res.map((v) => hexToBytes(v.toString(16)));
};

const bytesToHex = (bytes = []) => {
  const arr = [];
  for (let i = 0; i < bytes.length; i++) {
    arr.push((bytes[i] < 16 ? '0' : '') + (bytes[i] || 0).toString(16));
  }
  return arr.join('')
};

const hexToBytes = (hexString) => {
  const len = hexString.length;
  let start = 0;
  const bytes = [];

  if (hexString.length % 2 !== 0) {
    bytes.push(parseInt(hexString.charAt(0), 16));
    start++;
  }

  for (let i = start; i < len; i += 2) {
    bytes.push(parseInt(hexString.substr(i, 2), 16));
  }

  return bytes
};

// Returns the number of padding bytes you need to add
// for length to be divisible by mod
const numberToPadToLengthDevidedBy = (mod, length) => {
  let lenDiff = mod - length % mod;
  return (lenDiff <= 0 || lenDiff >= mod) ? 0 : lenDiff;
};


module.exports = {
  concatUint8,
  isEqualUint8,
  xorArrays,
  serializeString,
  unserializeString,
  makeMsgIdHex,
  bytesToInt,
  intToBytes,
  primeFactorization,
  bytesToHex,
  hexToBytes,
  getWindow,
  numberToPadToLengthDevidedBy
};