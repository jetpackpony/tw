const { concatUint8 } = require('../utils');
const randomBytes = require('randombytes');
const { bytesToHex, bytesFromHex } = require("../primeFactorization");
const {
  encryptAES_CTR,
  decryptAES_CTR,
  bytesToSHA256
} = require('../crypto');

class Abridged {
  initialByteSent = false;
  obfuscated = false;
  obfParams = {};
  obfInitPayloadSent = false;

  constructor(obfuscated = false) {
    this.obfuscated = obfuscated;
    if (this.obfuscated) {
      this.obfParams = makeObfuscationParams("efefefef");
    }
  }

  packObfInitPayload() {
    this.obfInitPayloadSent = true;
    return this.obfParams.initPayload;
  }

  packMessage(bytes) {
    if (this.obfuscated && !this.obfInitPayloadSent) {
      throw("Using obfuscated protocol. Before sending messages, need to send init payload first");
    }
    console.log('===> Sending message: ', bytesToHex(bytes));

    const header = [];
    if (!this.initialByteSent && !this.obfuscated) {
      this.initialByteSent = true;
      header.push(0xef);
    }

    const len = bytes.length / 4;
    if (len >= 127) {
      header.push(127);
      header.push(len & 0xff);
      header.push((len >> 8) & 0xff);
      header.push((len >> 16) & 0xff);
    } else {
      header.push(len);
    }
    
    const buf = new ArrayBuffer(header.length + bytes.length);
    let uint8 = new Uint8Array(buf);
    uint8.set(header, 0);
    uint8.set(bytes, header.length);

    if (this.obfuscated) {
      uint8 = encryptAES_CTR(
        uint8,
        this.obfParams.encryptKey,
        this.obfParams.encryptIV
      );
    }

    return uint8;
  }

  unpackMessage(data) {
    let uint8 = new Uint8Array(data);
    if (this.obfuscated) {
      uint8 = decryptAES_CTR(
        uint8,
        this.obfParams.encryptKey,
        this.obfParams.encryptIV
      );
    }

    let len, offset;
    if (uint8[0] === 127) {
      len = uint8[1] * 1 + uint8[2] * 256 + uint8[3] * 4096;
      offset = 4;
    } else {
      len = uint8[0];
      offset = 1;
    }
    const msg = uint8.slice(offset);

    if ((len * 4 + offset) !== data.length) {
      console.log(`Data is corrupt: proclaimed length is ${len}, actual: ${data.length} `);
      return;
    }
    console.log('<=== Recieved message: ', bytesToHex(msg));

    return msg;
  }
}

const badFirstInts = [
  "44414548", "54534f50", "20544547",
  "4954504f", "dddddddd", "eeeeeeee",
];
const makeObfuscationParams = (protocolHeader = "efefefef") => {
  let init;
  while(true) {
    init = concatUint8([
      Uint8Array.from(randomBytes(56)),
      bytesFromHex(protocolHeader),
      Uint8Array.from(randomBytes(4))
    ]);

    if (init[0] === 0xef) {
      continue;
    }
    const firstInt = bytesToHex(init.slice(0, 4));
    if (badFirstInts.includes(firstInt)) {
      continue;
    }

    const secondInt = bytesToHex(init.slice(4, 8));
    if (secondInt === "00000000") {
      continue;
    }

    break;
  }
  const initRev = init.slice(0).reverse();

  let encryptKey = init.slice(8, 40);
  const encryptIV = init.slice(40, 56);

  let decryptKey = initRev.slice(8, 40);
  const decryptIV = initRev.slice(40, 56);

  // encryptKey = bytesToSHA256(encryptKey);
  // decryptKey = bytesToSHA256(decryptKey);

  const encryptedInit = encryptAES_CTR(init, encryptKey, encryptIV);

  const finalInit = concatUint8([
    init.slice(0, 56),
    encryptedInit.slice(56, 64)
  ]);

  return {
    initPayload: finalInit,
    encryptKey,
    encryptIV,
    decryptKey,
    decryptIV
  };
};

module.exports = { Abridged };