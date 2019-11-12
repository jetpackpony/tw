const { concatUint8, intToBytes, bytesToInt } = require('../utils');
const randomBytes = require('randombytes');
const { bytesToHex, bytesFromHex } = require("../primeFactorization");
const {
  encryptAES_CTR,
  decryptAES_CTR,
  bytesToSHA256
} = require('../crypto');

class IntermediatePadded {
  initialByteSent = false;
  obfuscated = false;
  obfParams = {};
  obfInitPayloadSent = false;
  protocolHeader = 0xdddddddd;

  constructor(obfuscated = false) {
    this.obfuscated = obfuscated;
    if (this.obfuscated) {
      this.obfParams = makeObfuscationParams(this.protocolHeader);
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

    let header = [];
    if (!this.initialByteSent && !this.obfuscated) {
      this.initialByteSent = true;
      header = intToBytes(this.protocolHeader);
    }
    
    // Generate 0-15 random bytes
    const padding = randomBytes(Math.round(Math.random() * 15));
    const p = new ArrayBuffer(bytes.length + padding.length);
    let payload = new Uint8Array(p);
    payload.set(bytes, 0);
    payload.set(padding, bytes.length);

    const len = intToBytes(payload.length);
    
    const buf = new ArrayBuffer(header.length + len.length + payload.length);
    let uint8 = new Uint8Array(buf);
    uint8.set(header, 0);
    uint8.set(len, header.length);
    uint8.set(payload, header.length + len.length);

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

    const len = bytesToInt(uint8.slice(0, 4));
    const msg = uint8.slice(4);

    if (len !== uint8.length - 4) {
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
const makeObfuscationParams = (protocolHeader) => {
  let init;
  while(true) {
    init = concatUint8([
      Uint8Array.from(randomBytes(56)),
      intToBytes(protocolHeader),
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

module.exports = { IntermediatePadded };