const net = require('net');
const { IntermediatePadded } = require('../MTProtoTransport');
const Client = require('./Client');

// const host = '127.0.0.1';
// const port = 3000;
const host = '149.154.167.40';
const port = '443';

const makeSocket = async (obfuscated = true) => {
  return new Promise((resolve, reject) => {
    const transport = new IntermediatePadded(obfuscated);
    const listeners = [];

    const socket = new net.Socket();
    const sendMsg = (msg) => {
      socket.write(transport.packMessage(msg));
    };
    const addOnMsgListener = (f) => {
      listeners.push(f);
    };

    socket.on('data', function (data) {
      const unpacked = transport.unpackMessage(data);
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