import { setItem, getItem } from '../storage';

const { MessageBuilder } = require('../MessageBuilder');
const {
  hexToBytes,
  bytesToHex,
  serializeString,
  makeMsgIdHex,
  bytesToInt
} = require('../utils');
const {
  encryptAES,
  decryptAES,
  getRandomBytes,
  getEncryptionParams
} = require('../crypto');

// Client will store all messages and
class Client {
  messagesToAcknowledge = [];
  pendingReply = {};
  constructor({ apiId, apiHash, sendMsg }) {
    this.apiId = apiId;
    this.apiHash = apiHash;
    this.sendMsg = sendMsg;
    const authResult = JSON.parse(getItem("authResult"));
    this.authResult = Object.keys(authResult).reduce((acc, k) => {
      acc[k] = Uint8Array.from(Object.values(authResult[k]));
      return acc;
    }, {});
  }

  subToResponse(msgId, resolve, reject) {
    this.pendingReply[msgId] = { resolve, reject };
  }

  async msgRecieved(msg) {
    const decrypted = await this.decryptMsg(msg);

  }

  async decryptMsg(msg) {
    const res = {
      auth_key_id: msg.slice(0, 8),
      msg_key: msg.slice(8, 24),
      encrypted: msg.slice(24)
    };
    const { msg_key, aes_key, aes_iv } = await getEncryptionParams({
      authKey: this.authResult.authKey,
      inputMsgKey: res.msg_key,
      isOutgoingMsg: false
    });
    const decrypted = await decryptAES(res.encrypted, aes_key, aes_iv);

    res.salt = decrypted.slice(0, 8);
    res.session_id = decrypted.slice(8, 16);
    res.msg_id = decrypted.slice(16, 24);
    res.seq_no = decrypted.slice(24, 28);
    res.msg_length = bytesToInt(decrypted.slice(28, 32));
    res.msg_data = decrypted.slice(32, 32 + res.msg_length);

    const c = bytesToHex(res.msg_data.slice(0, 4).reverse());
    // container
    if (c === "73f1f8dc") {
      res.messages = this.unpackContainer(res.msg_data);

      res.messages.forEach((m) => {
        const c = bytesToHex(m.body.slice(0, 4).reverse());
        // new session created
        if (c === "9ec20908") {
          this.authResult.sessionId = this.sessionId;
          this.authResult.salt = m.body.slice(20, 28)
          setItem('authResult', JSON.stringify(this.authResult, null, 2));
          this.messagesToAcknowledge.push(m.msg_id.slice(0).reverse());
        }
        // pong
        if (c === "347773c5") {
          console.log("PONG!");
        }
      });
    } 

    const head = bytesToHex(res.msg_data.slice(0, 4).reverse());
    // pong
    if (head === "347773c5") {
          console.log("PONG!");
    }

    // acknowledgement
    "62d6b459"

    // RPC response
    "f35c6d01"

    return res;
  }

  resolveReply(msgId, success, data) {
    if (this.pendingReply[msgId]) {
      (success)
        ? this.pendingReply[msgId].resolve(data)
        : this.pendingReply[msgId].reject();
    } else {
      console.log(`Received a reply for msg ${msgId}, but no such message pending. Data: `, data);
    }
  }

  unpackContainer(data) {
    const len = bytesToInt(data.slice(4, 8));
    let rest = data.slice(8);
    const container = [];
    let offset = 0;
    for (let i = 0; i < len; i++) {
      const msg = {
        msg_id: rest.slice(offset, offset + 8),
        seqno: rest.slice(offset + 8, offset + 12),
        length: bytesToInt(rest.slice(offset + 12, offset + 16))
      };
      msg.body = rest.slice(offset + 16, offset + 16 + msg.length);
      container.push(msg);
      offset = offset + 16 + msg.length;
    }

    return container;
  }

  async send(method, params) {
    if (!this.sessionId) {
      this.sessionId = this.authResult.sessionId || new Uint8Array(await getRandomBytes(8));
    }
    switch(method) {
      case "auth.sendCode":
        return this.sendCode(params);
      case "help.getConfig":
        return this.getConfig();
      case "ping":
        return this.ping();
    }
  }

  async sendCode({ phone_number }) {
    const msg = new MessageBuilder();
    
    //api_id: int api_hash: string settings: CodeSettings
    msg.addValueToMsg(0xa677244f, 4, true);

    msg.addValueToMsg(serializeString(phone_number));
    msg.addValueToMsg(this.apiId);
    msg.addValueToMsg(serializeString(this.apiHash));

    const bytes = msg.getBytes();

    //encrypt and send

    await this.sendMsg("hello this is client");
  }

  async getConfig() {
    const b2h = bytesToHex;
    const h2b = hexToBytes;

    //help.getConfig#c4f9186b = Config;
    const plainText = new MessageBuilder();
    plainText.addValueToMsg(0xc4f9186b, 4, true);
    const plainBytes = plainText.getBytes();

    const msg = new MessageBuilder();

    // Salt
    msg.addValueToMsg(this.authResult.salt);

    // Session ID
    msg.addValueToMsg(this.sessionId);

    // Msg Id
    msg.addStrToMsg(await makeMsgIdHex(), true);

    // seq no
    msg.addValueToMsg(1, 4, true);

    // msg length
    msg.addValueToMsg(plainBytes.length, 4, true);

    // msg body
    msg.addValueToMsg(plainBytes);

    // padding
    await msg.padMessageToLengthDevidedBy(16, true, null, 12);

    const bodyBytes = msg.getBytes();
    const { msg_key, aes_key, aes_iv } = await getEncryptionParams({
      authKey: this.authResult.authKey,
      messageBytes: bodyBytes,
      isOutgoingMsg: true
    });

    const encryptedMsg = await encryptAES(bodyBytes, aes_key, aes_iv);

    const final = new MessageBuilder();
    final.addValueToMsg(this.authResult.auth_key_id, 1, true);
    final.addValueToMsg(msg_key, 1, true);
    final.addValueToMsg(encryptedMsg);

    const bytesToSend = final.getBytes();
    
    await this.sendMsg(bytesToSend);
  }

  async ping() {
    const b2h = bytesToHex;
    const h2b = hexToBytes;

    //ping#7abe77ec ping_id:long = Pong;
    const plainText = new MessageBuilder();
    plainText.addValueToMsg(0x7abe77ec, 4, true);
    plainText.addValueToMsg(0, 8, true);
    const plainBytes = plainText.getBytes();

    const msg = new MessageBuilder();

    // Salt
    msg.addValueToMsg(this.authResult.salt);

    // Session ID
    msg.addValueToMsg(this.sessionId);

    // Msg Id
    const msgId = await makeMsgIdHex();
    msg.addStrToMsg(msgId, true);

    // seq no
    msg.addValueToMsg(1, 4, true);

    // msg length
    msg.addValueToMsg(plainBytes.length, 4, true);

    // msg body
    msg.addValueToMsg(plainBytes);

    // padding
    await msg.padMessageToLengthDevidedBy(16, true, null, 12);

    const bodyBytes = msg.getBytes();
    const { msg_key, aes_key, aes_iv } = await getEncryptionParams({
      authKey: this.authResult.authKey,
      messageBytes: bodyBytes,
      isOutgoingMsg: true
    });

    const encryptedMsg = await encryptAES(bodyBytes, aes_key, aes_iv);

    const final = new MessageBuilder();
    final.addValueToMsg(this.authResult.auth_key_id, 1, true);
    final.addValueToMsg(msg_key, 1, true);
    final.addValueToMsg(encryptedMsg);

    const bytesToSend = final.getBytes();

    const p = new Promise((resolve, reject) => {
      this.subToResponse(msgId, resolve, reject);
    });

    await this.sendMsg(bytesToSend);
    return p;
  }

}

module.exports = Client;