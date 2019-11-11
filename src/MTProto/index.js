const net = require('net');
const { Abridged } = require('../MTProtoTransport');
const Client = require('./Client');

// const host = '127.0.0.1';
// const port = 3000;
const host = '149.154.167.40';
const port = '443';

const makeSocket = async () => {
  return new Promise((resolve, reject) => {
    const transport = new Abridged();
    const listeners = [];

    const socket = new net.Socket();
    const sendMsg = (msg) => {
      socket.write(transport.packMessage(m));
    };
    const addOnMsgListener = (f) => {
      listeners.push(f);
    };
    socket.connect(port, host, () => {
      resolve({
        sendMsg,
        addOnMsgListener
      });
    });

    socket.on('data', function (data) {
      listeners.forEach((f) => f(transport.unpackMessage(data)));
    });

    socket.on('close', function () {
      console.log('Connection closed');
    });
  });
};

const MTProto = async ({ apiId, apiHash, socket }) => {
  const sock = await(
    (socket)
      ? Promise.resolve(socket)
      : makeSocket(server, onMsg)
  );
  const client = new Client({ apiId, apiHash, sendMsg: sock.sendMsg });
  const onMsg = client.msgRecieved.bind(client);
  sock.addOnMsgListener(onMsg);

  return client;
};

module.exports = MTProto;