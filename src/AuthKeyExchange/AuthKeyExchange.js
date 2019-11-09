const BI = require('leemon');
const {
  pqPrimeFactorization,
  bytesToHex,
  bytesFromHex
} = require('../primeFactorization');
const pow2to32 = BI.str2bigInt("4294967296", 10, 1);
const { MessageBuilder } = require('../MessageBuilder');
const randomBytes = require('randombytes');
const publicKeys = require('../publicKeys.json');
const { bytesToSHA1, TL_RSA } = require("../crypto");

const parseUnencryptedMessage = (msg) => {
  const res = {
    auth_key_id: msg.slice(0, 8).reverse(),
    id: msg.slice(8, 16).reverse(),
    length: msg.slice(16, 20).reverse(),
    type: bytesToHex(msg.slice(20, 24).reverse()),
    data: msg.slice(24)
  };

  switch(res.type) {
    // resPQ
    case "05162463":
      res.data = parseResPQ(res.data);
      return res;
    default:
      console.log(`Message type was: ${res.type}. Couldn't handle`);
  }
};

const parseResPQ = (msg) => {
  const res = {
    nonce: msg.slice(0, 16),
    server_nonce: msg.slice(16, 32),
    pq: msg.slice(32, 44),
    //vector: msg.slice(44, 48),
    count: msg.slice(48, 52).reverse(),
    fingerprints: []
  };

  for(let i = 52; i < msg.length; i += 8) {
    res.fingerprints.push(msg.slice(i, i + 8));
  }

  console.log("Parsed: ", {
    nonce: bytesToHex(res.nonce),
    server_nonce: bytesToHex(res.server_nonce),
    pq: bytesToHex(res.pq),
    fingerprints: res.fingerprints.map(bytesToHex)
  });

  return res;
};

const getPublicKey = (fingerprints) => {
  //return [fingerPrint, key];
  for(let i = 0; i < fingerprints.length; i++) {
    const hexFP = bytesToHex(fingerprints[i]);
    if (publicKeys[hexFP]) {
      return [fingerprints[i], publicKeys[hexFP]];
    }
  }
  return [null, null];
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


class AuthKeyExchange {
  isComplete = false;
  outgoingMsgs = [];
  incomingMsgs = [];

  nonce;
  newNonce;
  msg_id_hex;

  constructor({ nonce, newNonce, msg_id_hex }) {
    if (nonce) {
      this.nonce = nonce;
    }
    if (newNonce) {
      this.newNonce = newNonce;
    }
    if (msg_id_hex) {
      this.msg_id_hex = msg_id_hex;
    }
  }

  makeInitialMessage() {
    const builder = new MessageBuilder();

    // auth_key_id
    builder.addValueToMsg(Array(8).fill(0));

    // message_id
    if (!this.msg_id_hex) {
      const unixTime = BI.int2bigInt(Math.floor(new Date() / 1000), 32, 1);
      const msg_id = BI.mult(unixTime, pow2to32);
      this.msg_id_hex = BI.bigInt2str(msg_id, 16);
    }
    console.log("msg_id_hex", this.msg_id_hex);
    builder.addStrToMsg(this.msg_id_hex, true);

    // message_length
    builder.addValueToMsg(20, 4, true);

    // %(req_pq)
    //builder.addValueToMsg(0x60469778, 4, true);
    builder.addValueToMsg(0xbe7e8ef1, 4, true);

    // nonce
    this.nonce = this.nonce || new Uint8Array(randomBytes(16));
    console.log("nonce", this.nonce);
    builder.addValueToMsg(this.nonce);

    return builder.getBytes();
  }

  processMessage(msg) {
    const parsed = parseUnencryptedMessage(msg);

    ///////////
    // should check the message here
    /////////
    this.incomingMsgs.push(parsed);
  }

  makeNextMessage() {
    if (this.outgoingMsgs.length === 0) {
      const msg = this.makeInitialMessage();
      this.outgoingMsgs.push(msg);
      return msg;
    }
    const lastMsg = this.incomingMsgs[this.incomingMsgs.length - 1];

    switch (lastMsg.type) {
      // resPQ
      case "05162463":
        const msg = this.makeReqDHParamsMsg(lastMsg);
        this.outgoingMsgs.push(msg);
        this.isComplete = true;
        return msg;
      default:
        console.log(`Message type was: ${res.type}. Couldn't build next request`);
    }
  }

  makeReqDHParamsMsg(lastMsg) {
    const pq = pqPrimeFactorization(lastMsg.data.pq.slice(1, 9));

    // generate new_nonce
    this.newNonce = this.newNonce || new Uint8Array(randomBytes(32));
    console.log("newNonce", this.newNonce);

    // generate p_q_inner_data
    const innerData = this.makePQInnerData(lastMsg, pq[0], pq[1]);

    // find the server public key that corresponds to a fingerprint
    const [fingerPrint, key] = getPublicKey(lastMsg.data.fingerprints);
    if (!fingerPrint) {
      console.error("Couldn't find any public key for fingerprint:", lastMsg.data.fingerprints);
      return;
    }

    // build data_with_hash
    const dataWithHash = this.buildDataWithHash(innerData);

    // encrypt data_with_hash
    const encData = TL_RSA(dataWithHash, key);

    return this.buildReqDHParams(lastMsg.data.server_nonce, pq[0], pq[1], fingerPrint, encData);
  }

  buildDataWithHash(innerData) {
    const dataBuilder = new MessageBuilder();
    dataBuilder.addValueToMsg(0); // this is a leading zero byte so that fucking RSA works omg jesus christ documentation sucks balls
    dataBuilder.addValueToMsg(bytesToSHA1(innerData));
    dataBuilder.addValueToMsg(innerData);
    dataBuilder.padMessageToLength(256, true);
    return dataBuilder.getBytes();
  }

  buildReqDHParams(serverNonce, p, q, fingerPrint, encData) {
    const builder = new MessageBuilder();

    // auth_key_id
    builder.addValueToMsg(Array(8).fill(0));

    // message_id
    if (!this.msg_id_hex) {
      const unixTime = BI.int2bigInt(Math.floor(new Date() / 1000), 32, 1);
      const msg_id = BI.mult(unixTime, pow2to32);
      this.msg_id_hex = BI.bigInt2str(msg_id, 16);
    }
    builder.addStrToMsg(this.msg_id_hex, true);

    // message_length
    builder.addValueToMsg(320, 4, true);

    // %(req_DH_params)
    builder.addValueToMsg(0xd712e4be, 4, true);

    // nonces
    builder.addValueToMsg(this.nonce);
    builder.addValueToMsg(serverNonce);

    // p with padding
    builder.addValueToMsg(4);
    builder.addValueToMsg(p);
    builder.addValueToMsg([0, 0, 0]);

    // q with padding
    builder.addValueToMsg(4);
    builder.addValueToMsg(q);
    builder.addValueToMsg([0, 0, 0]);

    // public_key_fingerprint
    builder.addValueToMsg(fingerPrint);

    // encrypted data
    builder.addValueToMsg([254, 0, 1, 0]);
    builder.addValueToMsg(encData);

    return builder.getBytes();
  }

  makePQInnerData(msg, p, q) {
    const builder = new MessageBuilder();

    // p_q_inner_data constructor
    builder.addValueToMsg(0x83c95aec, 4, true);

    // pq
    builder.addValueToMsg(msg.data.pq);
    
    // p with padding
    builder.addValueToMsg(4);
    builder.addValueToMsg(p);
    builder.addValueToMsg([0, 0, 0]);

    // q with padding
    builder.addValueToMsg(4);
    builder.addValueToMsg(q);
    builder.addValueToMsg([0, 0, 0]);

    // nonces
    builder.addValueToMsg(this.nonce);
    builder.addValueToMsg(msg.data.server_nonce);
    builder.addValueToMsg(this.newNonce);

    const bytes = builder.getBytes();
    return bytes;
  }
}

module.exports = AuthKeyExchange;