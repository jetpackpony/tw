const { MessageBuilder } = require('../MessageBuilder');
const publicKeys = require('../publicKeys.json');
const {
  makeTmpAESKeys,
  bytesToSHA1,
  TL_RSA,
  decryptAES,
  encryptAES,
  makeG_B,
  makeAuthKey,
  getRandomBytes
} = require("../crypto");
const {
  bytesToHex,
  xorArrays,
  makeMsgIdHex,
  primeFactorization
} = require("../utils");


const decryptDHAnswer = async (encAnswer, key, iv) => {
  // decrypt
  const decrypted = await decryptAES(encAnswer, key, iv);

  // extract sha1 and padding
  const sha = decrypted.slice(0, 20);
  const msg = decrypted.slice(20, 584);

  // check against sha1
  const calcSHA = await bytesToSHA1(msg);
  if (bytesToHex(calcSHA) !== bytesToHex(sha)) {
    throw ("decrypted DH answer didn't pass SHA test");
  }

  return msg;
}


const getPublicKey = (fingerprints) => {
  //return [fingerPrint, key];
  for (let i = 0; i < fingerprints.length; i++) {
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

const unserializeString = (bytes) => {
  const len = bytes[0];
  let content;
  if (len === 254) {
    const realLen = bytes[1] * 1 + bytes[2] * 256 + bytes[3] * 4096;
    content = bytes.slice(4, 4 + realLen);
  } else {
    content = bytes.slice(1, 1 + len);
  }
  return content;
};

class AuthKeyExchange {
  static decryptDHAnswer = decryptDHAnswer;

  isComplete = false;
  outgoingMsgs = [];
  incomingMsgs = [];

  nonce;
  newNonce;
  msg_id_hex;
  b;

  retryId = 0;

  constructor({ nonce, newNonce, msg_id_hex, b }) {
    if (nonce) {
      this.nonce = nonce;
    }
    if (newNonce) {
      this.newNonce = newNonce;
    }
    if (msg_id_hex) {
      this.msg_id_hex = msg_id_hex;
    }
    if (b) {
      this.b = b;
    }
  }

  async parseUnencryptedMessage(msg) {
    const res = {
      auth_key_id: msg.slice(0, 8).reverse(),
      id: msg.slice(8, 16).reverse(),
      length: msg.slice(16, 20).reverse(),
      type: bytesToHex(msg.slice(20, 24).reverse()),
      data: msg.slice(24)
    };

    switch (res.type) {
      // resPQ
      case "05162463":
        res.data = await this.parseResPQ(res.data);
        return res;
      // server_DH_params_ok
      case "d0e8075c":
        res.data = await this.parseServerDHParams(res.data);
        return res;
      // server_DH_params_fail
      case "79cb045d":
        console.log(`server_DH_params_fail Recieved!`);
        return;
      // dh_gen_ok
      case "3bcbf734":
        res.data = await this.parseDHGenOK(res.data);
        this.isComplete = true;
        return res;
      default:
        console.log(`Message type was: ${res.type}. Couldn't handle`);
    }
  }

  parseResPQ(msg) {
    const res = {
      nonce: msg.slice(0, 16),
      server_nonce: msg.slice(16, 32),
      pq: msg.slice(32, 44),
      //vector: msg.slice(44, 48),
      count: msg.slice(48, 52).reverse(),
      fingerprints: []
    };

    for (let i = 52; i < msg.length; i += 8) {
      res.fingerprints.push(msg.slice(i, i + 8));
    }

    console.log("Parsed: ", {
      nonce: bytesToHex(res.nonce),
      server_nonce: bytesToHex(res.server_nonce),
      pq: bytesToHex(res.pq),
      fingerprints: res.fingerprints.map(bytesToHex)
    });

    return res;
  }

  async parseServerDHParams(msg) {
    const res = {
      nonce: msg.slice(0, 16),
      server_nonce: msg.slice(16, 32),
      encrypted_answer: unserializeString(msg.slice(32))
    };
    // generate tmp keys
    const [key, iv] = await makeTmpAESKeys(this.newNonce, res.server_nonce);
    const answer = await decryptDHAnswer(res.encrypted_answer, key, iv);
    this.tmp_aes_key = key;
    this.tmp_aes_iv = iv;

    const out = {
      nonce: res.nonce,
      server_nonce: res.server_nonce,
      server_DH_inner_data: answer.slice(0, 4).reverse(),
      nonce: answer.slice(4, 20),
      server_nonce: answer.slice(20, 36),
      g: answer.slice(36, 40).reverse(),
      dh_prime: unserializeString(answer.slice(40, 300)),
      g_a : unserializeString(answer.slice(300, 560)),
      server_time: answer.slice(560, 564).reverse(),
    };
    return out;
  }

  parseDHGenOK(msg) {
    const res = {
      nonce: msg.slice(0, 16),
      server_nonce: msg.slice(16, 32),
      new_nonce_hash1: msg.slice(32, 48)
    };
    return res;
  }

  async completeAuth() {
    console.log();
    const paramsMsg = this.incomingMsgs[this.incomingMsgs.length - 2];
    const g_a = paramsMsg.data.g_a;
    const dh_prime = paramsMsg.data.dh_prime;
    const authKey = Uint8Array.from(await makeAuthKey(g_a, this.b, dh_prime));
    const salt = xorArrays(this.newNonce.slice(0, 8), paramsMsg.data.server_nonce.slice(0, 8));
    const auth_key_id = (await bytesToSHA1(authKey)).slice(-8);
    return {
      authKey,
      serverTime: paramsMsg.data.server_time,
      salt,
      auth_key_id
    };
  }

  async makeInitialMessage() {
    const builder = new MessageBuilder();

    // auth_key_id
    builder.addValueToMsg(Array(8).fill(0));

    // message_id
    if (!this.msg_id_hex) {
      this.msg_id_hex = await makeMsgIdHex();
    }
    console.log("msg_id_hex", this.msg_id_hex);
    builder.addStrToMsg(this.msg_id_hex, true);

    // message_length
    builder.addValueToMsg(20, 4, true);

    // %(req_pq_multi)
    //builder.addValueToMsg(0x60469778, 4, true);
    builder.addValueToMsg(0xbe7e8ef1, 4, true);

    // nonce
    this.nonce = this.nonce || new Uint8Array(await getRandomBytes(16));
    console.log("===> nonce generated: ", bytesToHex(this.nonce));
    builder.addValueToMsg(this.nonce);

    return builder.getBytes();
  }

  async processMessage(msg) {
    const parsed = await this.parseUnencryptedMessage(msg);

    ///////////
    // should check the message here
    /////////
    this.incomingMsgs.push(parsed);
  }

  async makeNextMessage() {
    if (this.outgoingMsgs.length === 0) {
      const msg = await this.makeInitialMessage();
      this.outgoingMsgs.push(msg);
      return msg;
    }
    const lastMsg = this.incomingMsgs[this.incomingMsgs.length - 1];

    switch (lastMsg.type) {
      // resPQ
      case "05162463":
        const msg = await this.makeReqDHParamsMsg(lastMsg);
        this.outgoingMsgs.push(msg);
        return msg;
      // server_DH_params_ok
      case "d0e8075c":
        this.checkDHParams(lastMsg);
        const dhMsg = await this.setClientDHParamsMsg(lastMsg);
        this.outgoingMsgs.push(dhMsg);
        return dhMsg;
      default:
        throw(`Message type was: ${lastMsg.type}. Couldn't build next request`);
    }
  }

  checkDHParams(lastMsg) {
    // https://core.telegram.org/mtproto/auth_key step 5

  }

  async setClientDHParamsMsg(lastMsg) {
    this.b = this.b || new Uint8Array(await getRandomBytes(256));
    console.log("===> B generated: ", bytesToHex(this.b))
    const g_b = await makeG_B(lastMsg.data.g, this.b, lastMsg.data.dh_prime);
    const innerData = this.buildClientDHInnerData(lastMsg.data.server_nonce, g_b);
    const dataWithHash = await this.buildClientDHInnerDataWithHash(innerData);
    const encrypted = await encryptAES(dataWithHash, this.tmp_aes_key, this.tmp_aes_iv);
    const msg = await this.buildSetClientDHParams(lastMsg.data.server_nonce, encrypted);
    return msg;
  }

  buildClientDHInnerData(serverNonce, g_b) {
    const builder = new MessageBuilder();

    // p_q_inner_data constructor
    builder.addValueToMsg(0x6643b654, 4, true);

    // nonces
    builder.addValueToMsg(this.nonce);
    builder.addValueToMsg(serverNonce);

    // retryId
    builder.addValueToMsg(this.retryId, 8, true);

    // g_b
    builder.addValueToMsg(serializeString(g_b));

    return builder.getBytes();
  }

  async buildClientDHInnerDataWithHash(innerData) {
    const dataBuilder = new MessageBuilder();
    dataBuilder.addValueToMsg(await bytesToSHA1(innerData));
    dataBuilder.addValueToMsg(innerData);
    await dataBuilder.padMessageToLengthDevidedBy(16, true);
    return dataBuilder.getBytes();
  }

  async buildSetClientDHParams(serverNonce, encryptedData) {
    const builder = new MessageBuilder();

    // auth_key_id
    builder.addValueToMsg(Array(8).fill(0));

    // message_id
    if (!this.msg_id_hex) {
      this.msg_id_hex = await makeMsgIdHex();
    }
    builder.addStrToMsg(this.msg_id_hex, true);

    // message_length
    builder.addValueToMsg(376, 4, true);

    // set_client_DH_params constructor
    builder.addValueToMsg(0xf5045f1f, 4, true);

    // nonces
    builder.addValueToMsg(this.nonce);
    builder.addValueToMsg(serverNonce);

    // data
    builder.addValueToMsg(serializeString(encryptedData));

    return builder.getBytes();
  }

  async makeReqDHParamsMsg(lastMsg) {
    const pq = await primeFactorization(lastMsg.data.pq.slice(1, 9));

    // generate new_nonce
    this.newNonce = this.newNonce || new Uint8Array(await getRandomBytes(32));
    console.log("===> newNonce generated: ", bytesToHex(this.newNonce));

    // generate p_q_inner_data
    const innerData = this.makePQInnerData(lastMsg, pq[0], pq[1]);

    // find the server public key that corresponds to a fingerprint
    const [fingerPrint, key] = getPublicKey(lastMsg.data.fingerprints);
    if (!fingerPrint) {
      console.error("Couldn't find any public key for fingerprint:", lastMsg.data.fingerprints);
      return;
    }

    // build data_with_hash
    const dataWithHash = await this.buildDataWithHash(innerData);

    // encrypt data_with_hash
    const encData = await TL_RSA(dataWithHash, key);

    return await this.buildReqDHParams(lastMsg.data.server_nonce, pq[0], pq[1], fingerPrint, encData);
  }

  async buildDataWithHash(innerData) {
    const dataBuilder = new MessageBuilder();
    dataBuilder.addValueToMsg(0); // this is a leading zero byte so that fucking RSA works omg jesus christ documentation sucks balls
    dataBuilder.addValueToMsg(await bytesToSHA1(innerData));
    dataBuilder.addValueToMsg(innerData);
    await dataBuilder.padMessageToLength(256, true);
    return dataBuilder.getBytes();
  }

  async buildReqDHParams(serverNonce, p, q, fingerPrint, encData) {
    const builder = new MessageBuilder();

    // auth_key_id
    builder.addValueToMsg(Array(8).fill(0));

    // message_id
    if (!this.msg_id_hex) {
      this.msg_id_hex = await makeMsgIdHex();
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