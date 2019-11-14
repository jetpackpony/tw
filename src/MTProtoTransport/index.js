const { bytesToHex, concatUint8, intToBytes, bytesToInt } = require('../utils');
const {
  makeEncryptorAES_CTR,
  makeDecryptorAES_CTR,
  getRandomBytes
} = require('../crypto');

const protocolHeader = 0xeeeeeeee;
const IntermediatePadded = async (obfuscated = false, testing) => {
  let initialByteSent = false;
  let obfParams = {};
  let makeRandomByteString = async () => {
    return await getRandomBytes(Math.round(Math.random() * 15));
  };
  if (testing) {
    makeRandomByteString = testing.getRandomBytes;
  }

  if (obfuscated) {
    obfParams =
      (testing)
        ? testing.obfParams
        : await makeObfuscationParams(protocolHeader);
  }

  const packMessage = async (bytes) => {
    let header = [];
    if (!initialByteSent) {
      if (!obfuscated) {
        header = intToBytes(protocolHeader);
      } else {
        header = obfParams.initPayload;
      }
      initialByteSent = true;
    }
    
    // Generate 0-15 random bytes
    // const padding = await makeRandomByteString();
    const padding = [];
    const len = intToBytes(bytes.length + padding.length);

    let encrypted = concatUint8([len, bytes, padding]);
    if (obfuscated) {
      encrypted = await obfParams.encryptor.encrypt(encrypted);
    }
    const uint8 = concatUint8([header, encrypted]);

    console.log('===> Sending bytes: ', bytesToHex(uint8));
    return uint8;
  }

  const unpackMessage = async (data) => {
    let uint8 = new Uint8Array(data);
    console.log('<=== Recieved bytes: ', bytesToHex(uint8));
    if (obfuscated) {
      uint8 = await obfParams.decryptor.decrypt(uint8);
    }

    const len = bytesToInt(uint8.slice(0, 4));
    const msg = uint8.slice(4);

    if (len !== uint8.length - 4) {
      console.log(`Data is corrupt: proclaimed length is ${len}, actual: ${data.length} `);
      return;
    }

    return msg;
  }

  return {
    packMessage,
    unpackMessage
  }
};

const badFirstInts = [
  "44414548", "54534f50", "20544547",
  "4954504f", "dddddddd", "eeeeeeee",
];
const makeObfuscationParams = async (protocolHeader) => {
  let init;
  while(true) {
    init = concatUint8([
      Uint8Array.from(await getRandomBytes(56)),
      intToBytes(protocolHeader),
      Uint8Array.from(await getRandomBytes(4))
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

  const encryptor = await makeEncryptorAES_CTR(encryptKey, encryptIV);
  const decryptor = await makeDecryptorAES_CTR(decryptKey, decryptIV);

  const encryptedInit = await encryptor.encrypt(init);

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