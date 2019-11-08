const net = require('net');
const AuthKeyExchange = require('./AuthKeyExchange/AuthKeyExchange');

// const HOST = '127.0.0.1';
// const PORT = 3000;
const HOST = '149.154.167.40';
const PORT = '443';

const exchange = new AuthKeyExchange({});
const msg = exchange.makeNextMessage();

const client = new net.Socket();
client.connect(PORT, HOST, function () {
  console.log('CONNECTED TO: ' + HOST + ':' + PORT);

  console.log('sending messgae: ', msg);
  client.write(msg);
});

client.on('data', function (data) {
  console.log('RAW DATA: ', data);
  const d = new Uint8Array(data);
  console.log('DATA: ', d.buffer);
  console.log('str: ', d.toString());

  exchange.processMessage(d);
  if (!exchange.isComplete) {
    const nextMessage = exchange.makeNextMessage();
    //client.write(nextMessage);
  } else {
    client.close();
  }
});

client.on('close', function () {
  console.log('Connection closed');
});
