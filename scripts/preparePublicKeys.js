const forge = require('node-forge');
const fs = require('fs');

const keys = fs.readFileSync('./scripts/publicKeys.txt', 'utf8').split("\n\n");

const keyMap = keys.reduce((acc, k) => {
  const forgeKey = forge.pki.publicKeyFromPem(k);
  const fp = forge.pki.getPublicKeyFingerprint(forgeKey);
  const hex = fp.toHex();

  const fingerprint = hex.slice(hex.length - 16, hex.length)
  acc[fingerprint] = k;
  return acc;
}, {})

fs.writeFileSync('./src/publicKeys.json', JSON.stringify(keyMap, null, 2));
