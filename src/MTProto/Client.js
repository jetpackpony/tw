const authResult = require('../authResult.json');

// Client will store all messages and
class Client {
  constructor({ apiId, apiHash, sendMsg }) {
    this.apiId = apiId;
    this.apiHash = apiHash;
    this.sendMsg = sendMsg;
  }

  msgRecieved(msg) {
    console.log("<=== Recieved message: ", msg);
  }

  async send(method, params) {
    switch(method) {
      case "auth.sendCode":
        return this.sendCode(params);
    }

  }

  async sendCode({ phone_number }) {
    this.sendMsg("hello this is client");
  }
}

module.exports = Client;