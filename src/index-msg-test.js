const MTproto = require('./MTProto');
const { bytesFromHex } = require('./primeFactorization');

const apiId = "id";
const apiHash = "hash";

const makeFakeSocket = () => {
  const listeners = [];
  let currentResponse = 0;
  const incoming = [
    Uint8Array.from(bytesFromHex("00ff00ff00ff00ff")),
  ];

  const sendMsg = (msg) => {
    console.log("===> Sending message: ", msg);
    listeners.forEach((f) => f(incoming[currentResponse]));
    currentResponse++;
  }
  const addOnMsgListener = (f) => listeners.push(f);

  return {
    sendMsg,
    addOnMsgListener
  };
};

const start = async () => {
  const client = await MTproto({
    apiId, apiHash,
    socket: makeFakeSocket()
  });

  const login = async () => {
    const res = await client.send('auth.sendCode', {
      phone_number: ""
    });

  };

  login();
};

start();