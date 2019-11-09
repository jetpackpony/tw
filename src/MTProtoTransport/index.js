const { bytesToHex } = require("../primeFactorization");
class Abridged {
  initialByteSent = false;

  packMessage(bytes) {
    console.log('sending message: ', bytesToHex(bytes));

    const header = [];
    if (!this.initialByteSent) {
      this.initialByteSent = true;
      header.push(0xef);
    }

    const len = bytes.length / 4;
    if (len >= 127) {
      header.push(127);
      header.push(len & 0xff);
      header.push((len >> 8) & 0xff);
      header.push((len >> 16) & 0xff);
    } else {
      header.push(len);
    }
    
    const buf = new ArrayBuffer(header.length + bytes.length);
    const uint8 = new Uint8Array(buf);
    uint8.set(header, 0);
    uint8.set(bytes, header.length);


    return uint8;
  }

  unpackMessage(data) {
    const uint8 = new Uint8Array(data);
    console.log('data str: ', uint8.toString());

    let len, offset;
    if (uint8[0] === 127) {
      len = uint8[1] * 1 + uint8[2] * 256 + uint8[3] * 4096;
      offset = 4;
    } else {
      len = uint8[0];
      offset = 1;
    }
    const msg = uint8.slice(offset);

    if ((len * 4 + offset) !== data.length) {
      console.log(`Data is corrupt: proclaimed length is ${len}, actual: ${data.length} `);
      return;
    }
    console.log('message recieved: ', bytesToHex(msg));

    return msg;
  }
}

module.exports = { Abridged };