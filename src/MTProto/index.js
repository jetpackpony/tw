import { setItem } from '../storage';

const { IntermediatePadded } = require('../MTProtoTransport');
const Client = require('./Client');
const AuthKeyExchange = require('../AuthKeyExchange/AuthKeyExchange');

// const PROTO = 'ws';
// const HOST = '149.154.167.40';
// const PORT = '80';
// const URI = "apis";
// const SUBPROTO = "binary";
const PROTO = 'wss';
const HOST = 'pluto.web.telegram.org';
const PORT = '443';
const URI = "apiws_test";
const SUBPROTO = "binary";

const makeSocket = async (obfuscated = true) => {
  return new Promise(async (resolve, reject) => {
    const transport = await IntermediatePadded(obfuscated);
    let listeners = [];

    const socket = new WebSocket(`${PROTO}://${HOST}:${PORT}/${URI}`, SUBPROTO);
    socket.binaryType = 'arraybuffer';

    const sendMsg = async (msg) => {
      socket.send(await transport.packMessage(msg));
    };
    const addOnMsgListener = (f) => {
      listeners.push(f);
    };
    const removeOnMsgListener = (f) => {
      if (listeners.includes(f)) {
        listeners = listeners.filter(v => v !== f);
      }
    };

    socket.addEventListener('message', async (event) => {
      const unpacked = await transport.unpackMessage(event.data);
      listeners.forEach((f) => f(unpacked));
    });
    socket.addEventListener('close', async (event) => {
      console.log('Connection closed');
    });
    socket.addEventListener('open', (event) => {
      resolve({
        sendMsg,
        addOnMsgListener,
        removeOnMsgListener
      });
    });
  });
};

const MTProto = ({ apiId, apiHash, socket }) => {
  return new Promise(async (resolve, reject) => {
    const sock = await (
      (socket)
        ? Promise.resolve(socket)
        : makeSocket()
    );

    // authenticating here
    const exchange = new AuthKeyExchange({});

    const onData = async (msg) => {
      try {
        await exchange.processMessage(msg);
        if (!exchange.isComplete) {
          const nextMessage = await exchange.makeNextMessage();
          sock.sendMsg(nextMessage);
        } else {
          sock.removeOnMsgListener(onData);
          const authResult = await exchange.completeAuth();
          setItem('authResult', JSON.stringify(authResult, null, 2));

          // this should be in a separate function which gets called
          // after successful auth
          const client = new Client({ apiId, apiHash, sendMsg: sock.sendMsg });
          const onMsg = client.msgRecieved.bind(client);
          sock.addOnMsgListener(onMsg);

          resolve(client);
        }
      } catch (e) {
        console.log("some error: ", e);
      }
    };

    const msg = await exchange.makeNextMessage();

    sock.addOnMsgListener(onData);
    sock.sendMsg(msg);
  });
};

module.exports = MTProto;