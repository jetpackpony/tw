const W3CWebSocket = require('websocket').w3cwebsocket;
const fs = require('fs');
const net = require('net');
const { IntermediatePadded } = require('./MTProtoTransport');
const AuthKeyExchange = require('./AuthKeyExchange/AuthKeyExchange');

const URI = "ws://149.154.167.40:80/apis_test";
const client = new W3CWebSocket(URI);

const transport = new IntermediatePadded(true);
const exchange = new AuthKeyExchange({});
const msg = exchange.makeNextMessage();
const initPacket = transport.packMessage(msg);
 
client.onerror = function() {
  console.log('Connection Error');
};
 
client.onopen = function() {
  console.log('WebSocket Client Connected');

  // function sendNumber() {
  //   if (client.readyState === client.OPEN) {
  //     var number = Math.round(Math.random() * 0xFFFFFF);
  //     client.send(number.toString());
  //     setTimeout(sendNumber, 1000);
  //   }
  // }
  // sendNumber();

  client.send(initPacket);
};
 
client.onclose = function() {
  console.log('echo-protocol Client Closed');
};
 
client.onmessage = function({ data }) {
  const msg = transport.unpackMessage(data);

  exchange.processMessage(msg);
  if (!exchange.isComplete) {
    const m = exchange.makeNextMessage();
    const nextMessage = transport.packMessage(m);
    client.write(nextMessage);
  } else {
    const authResult = exchange.completeAuth();
    fs.writeFileSync('./src/authResult.json', JSON.stringify(authResult, null, 2));
    client.destroy();
  }
};
