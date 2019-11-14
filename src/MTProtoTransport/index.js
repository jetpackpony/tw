const { concatUint8, intToBytes, bytesToInt } = require('../utils');
const randomBytes = require('randombytes');
const { bytesToHex, bytesFromHex } = require("../primeFactorization");
const {
  encryptAES_CTR,
  decryptAES_CTR,
  bytesToSHA256,
  makeEncryptorAES_CTR,
  makeDecryptorAES_CTR
} = require('../crypto');

const getRandomBytes = () => {
  return randomBytes(Math.round(Math.random() * 15));
};

class IntermediatePadded {
  initialByteSent = false;
  obfuscated = false;
  obfParams = {};
  protocolHeader = 0xeeeeeeee;
  getRandomBytes = false;

  constructor(obfuscated = false, testing) {
    this.obfuscated = obfuscated;
    this.getRandomBytes = (testing) ? testing.getRandomBytes : getRandomBytes;
    if (this.obfuscated) {
      this.obfParams =
        (testing)
          ? testing.obfParams
          : makeObfuscationParams(this.protocolHeader);
    }
  }

  packObfInitPayload() {
    return this.obfParams.initPayload;
  }

  packMessage(bytes) {
    let header = [];
    if (!this.initialByteSent) {
      if (!this.obfuscated) {
        header = intToBytes(this.protocolHeader);
      } else {
        header = this.packObfInitPayload();
      }
      this.initialByteSent = true;
    }
    
    // Generate 0-15 random bytes
    //const padding = this.getRandomBytes();
    const padding = [];
    const len = intToBytes(bytes.length + padding.length);

    let encrypted = concatUint8([len, bytes, padding]);
    if (this.obfuscated) {
      encrypted = this.obfParams.encryptor.encrypt(encrypted);
    }
    const uint8 = concatUint8([header, encrypted]);

    console.log('===> Sending bytes: ', bytesToHex(uint8));
    return uint8;
  }

  unpackMessage(data) {
    let uint8 = new Uint8Array(data);
    console.log('<=== Recieved bytes: ', bytesToHex(uint8));
    if (this.obfuscated) {
      uint8 = this.obfParams.decryptor.decrypt(uint8);
    }

    const len = bytesToInt(uint8.slice(0, 4));
    const msg = uint8.slice(4);

    if (len !== uint8.length - 4) {
      console.log(`Data is corrupt: proclaimed length is ${len}, actual: ${data.length} `);
      return;
    }

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

  const encryptor = makeEncryptorAES_CTR(encryptKey, encryptIV);
  const decryptor = makeDecryptorAES_CTR(decryptKey, decryptIV);

  const encryptedInit = encryptor.encrypt(init);

  const finalInit = concatUint8([
    init.slice(0, 56),
    encryptedInit.slice(56, 64)
  ]);

  return {
    initPayload: finalInit,
    encryptKey,
    encryptIV,
    decryptKey,
    decryptIV,
    encryptor,
    decryptor
  };
};

module.exports = { IntermediatePadded };