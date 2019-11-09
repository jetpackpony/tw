const AuthKeyExchange = require('./AuthKeyExchange/AuthKeyExchange');

const exchange = new AuthKeyExchange({
  msg_id_hex: "5DC56EEB00000000",
  nonce: Uint8Array.from([
    90, 172, 101, 29, 227,
    87, 146, 4, 238, 65,
    211, 233, 123, 100, 128,
    77
  ]),
  newNonce: Uint8Array.from([
    186, 201, 84, 119, 46, 134, 167, 51,
    33, 97, 121, 238, 227, 143, 133, 42,
    158, 217, 167, 57, 137, 139, 101, 178,
    34, 177, 165, 48, 27, 187, 226, 55
  ])
});
const msg = exchange.makeNextMessage();
console.log(msg);

const resPQraw = "0,0,0,0,0,0,0,0,1,212,22,138,3,113,197,93,72,0,0,0,99,36,22,5,90,172,101,29,227,87,146,4,238,65,211,233,123,100,128,77,105,122,225,214,89,178,179,217,219,165,88,49,169,121,44,206,8,39,207,141,171,26,62,32,49,0,0,0,21,196,181,28,2,0,0,0,2,159,75,161,109,16,146,150,33,107,232,108,2,43,180,195";
const resPQ = Uint8Array.from(resPQraw.split(","));

exchange.processMessage(resPQ);

const msg1 = exchange.makeNextMessage();
console.log(msg1);

