const AuthKeyExchange = require('./AuthKeyExchange/AuthKeyExchange');

const exchange = new AuthKeyExchange({
  msg_id_hex: "5DC46F8100000000",
  nonceHex: "BC246436A584D818E1A38DCBC6B2316C"
});
const msg = exchange.makeNextMessage();
console.log(msg);

const resPQraw = "23,0,0,0,0,0,0,0,0,1,220,58,204,129,111,196,93,72,0,0,0,99,36,22,5,188,36,100,54,165,132,216,24,225,163,141,203,198,178,49,108,191,151,60,83,178,36,255,203,212,216,196,111,143,228,115,25,8,26,42,125,254,123,207,176,159,0,0,0,21,196,181,28,2,0,0,0,2,159,75,161,109,16,146,150,33,107,232,108,2,43,180,195";
const resPQ = Uint8Array.from(resPQraw.split(","));

exchange.processMessage(resPQ);

const msg1 = exchange.makeNextMessage();
console.log(msg1);

