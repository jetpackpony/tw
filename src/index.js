const net = require('net');
const { Abridged } = require('./MTProtoTransport');
const AuthKeyExchange = require('./AuthKeyExchange/AuthKeyExchange');

// const HOST = '127.0.0.1';
// const PORT = 3000;
const HOST = '149.154.167.40';
const PORT = '443';

const transport = new Abridged();
const exchange = new AuthKeyExchange({});
const msg = exchange.makeNextMessage();
const packet = transport.packMessage(msg);

const client = new net.Socket();
client.connect(PORT, HOST, function () {
  client.write(packet);
});

client.on('data', function (data) {
  const msg = transport.unpackMessage(data);

  exchange.processMessage(msg);
  if (!exchange.isComplete) {
    const m = exchange.makeNextMessage();
    const nextMessage = transport.packMessage(m);
    client.write(nextMessage);
  } else {
    client.close();
  }
});

client.on('close', function () {
  console.log('Connection closed');
});
