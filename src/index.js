const MTproto = require('./MTProto');

const apiId = "id";
const apiHash = "hash";

const start = async () => {
  const client = await MTproto({
    apiId, apiHash,
    //socket: makeFakeSocket(),
    //msgIds: []
  });

  const ping = async () => {
    const res = await client.send('ping');
    console.log("Got response: ", res);

  };
  const getConfig = async () => {
    const res = await client.send('help.getConfig');
    console.log("Got response: ", res);

  };

  ping();
  //getConfig();
};
start();
