const forge = require('node-forge');
const fs = require('fs');
const { bytesFromHex } = require('../src/primeFactorization');

const keys = fs.readFileSync('./scripts/publicKeys.txt', 'utf8').split("\n\n");

const serializeString = (bytes) => {
  const len = bytes.length;
  let res = [];
  if (len <= 253) {
    res.push(len);
  } else {
    res.push(254);
    res.push(len & 0xff);
    res.push((len >> 8) & 0xff);
    res.push((len >> 16) & 0xff);
  }
  res = res.concat(bytes);
  const padding = 4 - (res.length % 4);
  if (padding > 0 && padding < 4) {
    res = res.concat((new Array(3)).fill(0));
  }
  return res;
};

const keyMap = keys.reduce((acc, k) => {
  const forgeKey = forge.pki.publicKeyFromPem(k);

  let n = forgeKey.n.toString(16);
  let e = forgeKey.e.toString(16);
  const nBytes = bytesFromHex(n);
  const eBytes = bytesFromHex(e);

  const bytes = serializeString(nBytes).concat(serializeString(eBytes))
  const str = String.fromCharCode(...bytes);
  var md = forge.md.sha1.create();
  md.update(str);
  const hex = md.digest().toHex();

  const fingerprint = hex.slice(hex.length - 16, hex.length)
  acc[fingerprint] = k;
  return acc;
}, {})

// "029f4ba16d109296"
// "216be86c022bb4c3"
//console.log("key found: ", keyMap["216be86c022bb4c3"] !== undefined);

fs.writeFileSync('./src/publicKeys.json', JSON.stringify(keyMap, null, 2));
