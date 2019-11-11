const MTproto = require('./MTProto');
const { bytesFromHex, bytesToHex } = require('./primeFactorization');

const apiId = "id";
const apiHash = "hash";

const makeFakeSocket = () => {
  const listeners = [];
  let currentResponse = 0;
  const incoming = [
    /* getConfig?
    [
      Uint8Array.from(bytesFromHex("4e4004c35836fb81f72f3ef163201c57818d190a6ed82bc9583b8caa7051e21f33581b971d37f05a2bfd2f953f8b7f001757efcfbf5400586f67a8a6e9c7c9ff772a1234054e9826c9eeb1466a46882aae55be3ebd892f2664d1e518caf05a037a0ba945b6be3e369eb4f20617848a5fa573d5470d38d272e7b06893df30c8b02b942cce2410bc4d49031d146f797a4e0d0053248a776411506df5d5719da02d92327f22be77190f")),
      Uint8Array.from(bytesFromHex("4e4004c35836fb814ba16742ba627e8da136ea7fd95f5248c94caa9633ea7666d88626c4a2d594050314b6ba2075d14e493696bdc23519b8dd991e66970d28919b0fd6de9f1af89546959cf7ce79f8fbbfc9bb3a876c72843da82c7a4fceb2dd3319793429ccdc8af323e83c328828d32b32fd407b8ebd10d4a1811e9aa83e9f4f7d3aad5ec402d4009dec1eeac1a45283a3687069be990f28caf1ce28895941e408db2d77d716b1f4d12994b1fd6fd9007b71dfed9b7629")),
    ]
    */
    /* Ping
    */
    [
      Uint8Array.from(bytesFromHex("630703f11184b0f8e968cdad7ea1e41e49a53265b72369f790ac8a605205183488b42a66edd35b4b2056caded7567363ceb45112c2c70547e4557fb7b2414828cdd53b3d3aa6d31b8de183184b0d994a75dce07a6337eb895c99169983fda86ae3d7b5bd80378b463602405c81f132f0579a0f1ac06af931e7f504459da4ef28c35be5c1dd85ac41e1624c85794dd8882afdc213a2b3db61ad8690d75d64b44f1bbe148d784868cf")),
    ]
  ];

  const sendMsg = (msg) => {
    console.log("===> Sending message: ", bytesToHex(msg));
    incoming[currentResponse].forEach((r) => {
      console.log("<=== Received message: ", bytesToHex(r));
      listeners.forEach((f) => f(r));
    })
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
    socket: makeFakeSocket(),
    //msgIds: []
  });

  const getConfig = async () => {
    const res = await client.send('ping');
    console.log("Got response: ", res);

  };

  getConfig();
};

start();