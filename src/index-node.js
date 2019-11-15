const fs = require('fs');
const net = require('net');
const { IntermediatePadded } = require('./MTProtoTransport');
const AuthKeyExchange = require('./AuthKeyExchange/AuthKeyExchange');

// const HOST = '127.0.0.1';
// const PORT = 3000;
const HOST = '149.154.167.40';
const PORT = '443';

const start = async () => {
  const transport = await IntermediatePadded(true);
  const exchange = new AuthKeyExchange({});
  const msg = await exchange.makeNextMessage();
  const packet = await transport.packMessage(msg);

  const client = new net.Socket();
  client.connect(PORT, HOST, function () {
    client.write(packet);
  });

  client.on('data', async (data) => {
    try {
      const msg = await transport.unpackMessage(data);

      await exchange.processMessage(msg);
      if (!exchange.isComplete) {
        const m = await exchange.makeNextMessage();
        const nextMessage = await transport.packMessage(m);
        client.write(nextMessage);
      } else {
        const authResult = await exchange.completeAuth();
        fs.writeFileSync('./src/authResult.json', JSON.stringify(authResult, null, 2));
        client.destroy();
      }
    } catch(e) {
      console.log("some error: ", e);
    }
  });

  client.on('close', function () {
    console.log('Connection closed');
  });

};

start();