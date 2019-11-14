
async function main() {

  console.log("main");
}

main()
/*
// const HOST = 'localhost';
// const PORT = 3000;
// const URI = "";
// const SUBPROTO = undefined;
const HOST = '149.154.167.40';
const PORT = '80';
const URI = "apis";
const SUBPROTO = "binary";

async function main() {
  const socket = new WebSocket(`ws://${HOST}:${PORT}/${URI}`, SUBPROTO);
  socket.binaryType = 'arraybuffer';

  // Connection opened
  socket.addEventListener('open', function (event) {
    console.log("Sending...");
    const data = [65,54,166,183,124,145,198,107,10,35,218,150,61,231,32,24,86,94,196,135,5,173,40,124,253,22,127,246,207,81,209,253,70,15,218,109,184,183,136,247,140,100,196,192,64,150,65,6,220,162,153,147,148,156,106,65,202,207,35,142,223,83,216,179,70,200,15,9,80,204,156,131,159,239,60,28,202,28,18,225,123,208,198,56,154,120,111,246,176,157,175,162,34,49,81,215,42,177,59,158,125,43,86,141,231,13,77,188,181,74,212,213,40];
    socket.send(Uint8Array.from(data));
  });


  // Listen for messages
  socket.addEventListener('message', async (event) => {
    const uint8 = new Uint8Array(event.data);
    console.log('Message from server ', uint8);
  });
}

main()
*/