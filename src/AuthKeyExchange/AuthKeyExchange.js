const BI = require('leemon');
const {
  pqPrimeFactorization,
  bytesToHex,
  bytesFromHex
} = require('../primeFactorization');
const pow2to32 = BI.str2bigInt("4294967296", 10, 1);
const { MessageBuilder } = require('../MessageBuilder');
const randomBytes = require('randombytes');

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
    nonce: msg.slice(0, 16).reverse(),
    server_nonce: msg.slice(16, 32).reverse(),
    pq: msg.slice(32, 44),
    //vector: msg.slice(44, 48),
    count: msg.slice(48, 52).reverse(),
    fingerprints: []
  };

  for(let i = 52; i < msg.length; i += 8) {
    res.fingerprints.push(msg.slice(i, i + 8));
  }

  return res;
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

    // envelope header
    builder.addValueToMsg(0xef);

    // env length
    builder.addValueToMsg(40 / 4);

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
    const newRes = new Uint8Array(msg.slice(1));
    const parsed = parseUnencryptedMessage(newRes);
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
        const msg = this.buildReqDHParams(lastMsg);
        this.outgoingMsgs.push(msg);
        return msg;
      default:
        console.log(`Message type was: ${res.type}. Couldn't build next request`);
    }
  }

  buildReqDHParams(lastMsg) {
    const pq = pqPrimeFactorization(lastMsg.data.pq.slice(1, 9));

    // generate new_nonce
    this.newNonce = this.newNonce || new Uint8Array(randomBytes(32));
    console.log("newNonce", this.newNonce);

    // generate p_q_inner_data
    const innerData = this.makePQInnerData(lastMsg, pq[0], pq[1]);

    // find the server public key that corresponds to a fingerprint

    // encrypt innerData with that public key
    // build req_DH_params bytes

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

    console.log('test');
    return builder.getBytes();
  }
}

module.exports = AuthKeyExchange;