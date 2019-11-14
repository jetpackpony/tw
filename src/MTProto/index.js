const net = require('net');
const { IntermediatePadded } = require('../MTProtoTransport');
const Client = require('./Client');

// const host = '127.0.0.1';
// const port = 3000;
const host = '149.154.167.40';
const port = '443';

const makeSocket = async (obfuscated = true) => {
  return new Promise(async (resolve, reject) => {
    const transport = await IntermediatePadded(obfuscated);
    const listeners = [];

    const socket = new net.Socket();
    const sendMsg = async (msg) => {
      socket.write(await transport.packMessage(msg));
    };
    const addOnMsgListener = (f) => {
      listeners.push(f);
    };

    socket.on('data', async (data) => {
      const unpacked = await transport.unpackMessage(data);
      listeners.forEach((f) => f(unpacked));
    });
    socket.on('close', function () {
      console.log('Connection closed');
    });
    socket.connect(port, host, () => {
      resolve({
        sendMsg,
        addOnMsgListener
      });
    });
  });
};

const MTProto = async ({ apiId, apiHash, socket }) => {
  const sock = await(
    (socket)
      ? Promise.resolve(socket)
      : makeSocket()
  );
  const client = new Client({ apiId, apiHash, sendMsg: sock.sendMsg });
  const onMsg = client.msgRecieved.bind(client);
  sock.addOnMsgListener(onMsg);

  return client;
};

module.exports = MTProto;