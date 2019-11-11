const { bytesToSHA1 } = require("../crypto");

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
}

module.exports = { makeTmpAESKeys, xorArrays };