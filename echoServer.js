const net = require('net');
const HOST = '127.0.0.1';
const PORT = 3000;

const server = net.createServer(socket => {
  socket.on('data', (data) => {
    console.log('Echoing: %s', data.toString())
    socket.write(data.toString())
  })
});
server.listen(PORT);
