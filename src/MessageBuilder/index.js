const { bytesFromHex } = require('../primeFactorization');
const randomBytes = require('randombytes');

function numToBytes (num, length, littleEndian = false) {
    const arr = new ArrayBuffer(length);
    const view = new DataView(arr);
    switch(length) {
      case 4:
        view.setUint32(0, num, littleEndian);
        break;
    }
    return Array.from(new Uint8Array(arr));
}

const valueToBytes = (value, length = 1, littleEndian = false) => {
  if (length === 1) {
    return value;
  } else {
    const bytes = numToBytes(value, length, littleEndian);
    return bytes;
  }
};

class MessageBuilder {
  msg = [];

  addBytesToMsg(bytes) {
    this.msg = this.msg.concat(bytes);
  }

  addValueToMsg(value, length = 1, littleEndian = false) {
    let bytes = [];
    if (Array.isArray(value) || value.constructor === Uint8Array) {
      value.forEach((v) => bytes.push(valueToBytes(v, length, littleEndian)));
      bytes = bytes.flat();
    } else {
      bytes = valueToBytes(value, length, littleEndian);
    }
    this.addBytesToMsg(bytes);
    return bytes;
  }

  addStrToMsg(str, littleEndian = false, base = 16) {
    const bytes = bytesFromHex(str);
    if (littleEndian) {
      bytes.reverse();
    }
    this.addBytesToMsg(bytes);
    return bytes;
  }

  getBytes() {
    return new Uint8Array(this.msg);
  }

  padMessageToLength(len, rand = false, val = 0) {
    const lenDiff = len - this.msg.length;
    if (lenDiff <= 0) return;

    const padding = 
      (rand)
        ? new Uint8Array(randomBytes(lenDiff))
        : (new Uint8Array(lenDiff)).fill(val);
    
    this.addValueToMsg(padding);
    return padding;
  }

}

module.exports = { MessageBuilder, numToBytes };