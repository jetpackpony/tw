const { MessageBuilder, numToBytes } = require('./index');
const expect = require('chai').expect;

describe('MessageBuilder', function() {
  describe('addToMsg', function() {
    it('should correctly add hex values', function() {
      const correct = Uint8Array.from([239]);
      const builder = new MessageBuilder();
      builder.addValueToMsg(0xef);
      expect(builder.getBytes()).to.eql(correct);
    });
    it('should correctly add multi-byte hex values', function() {
      const correct = Uint8Array.from([0, 239, 239, 239]);
      const builder = new MessageBuilder();
      builder.addValueToMsg(0xefefef, 4);
      expect(builder.getBytes()).to.eql(correct);
    });
    it('should correctly add int values', function() {
      const correct = Uint8Array.from([33]);
      const builder = new MessageBuilder();
      builder.addValueToMsg(33);
      expect(builder.getBytes()).to.eql(correct);
    });
    it('should correctly add multi-byte int values', function() {
      const correct = Uint8Array.from([0, 1, 40, 223]);
      const builder = new MessageBuilder();
      builder.addValueToMsg(75999, 4);
      expect(builder.getBytes()).to.eql(correct);
    });
    it('should correctly set endianness add', function() {
      const correct = Uint8Array.from([223, 40, 1, 0]);
      const builder = new MessageBuilder();
      builder.addValueToMsg(75999, 4, true);
      expect(builder.getBytes()).to.eql(correct);
    });

    it('should correctly add an array of 1-byte values', function() {
      const correct = Uint8Array.from([22, 33, 11]);
      const builder = new MessageBuilder();
      builder.addValueToMsg([22, 33, 11]);
      expect(builder.getBytes()).to.eql(correct);
    });
    it('should correctly add an array of multi-byte values', function() {
      const correct = Uint8Array.from([0, 1, 40, 223, 0, 1, 62, 36, 0, 239, 239, 239]);
      const builder = new MessageBuilder();
      builder.addValueToMsg([75999, 81444, 0xefefef], 4);
      expect(builder.getBytes()).to.eql(correct);
    });
    it('should correctly set endianness when adding an array', function() {
      const correct = Uint8Array.from([223, 40, 1, 0, 36, 62, 1, 0, 239, 239, 239, 0]);
      const builder = new MessageBuilder();
      builder.addValueToMsg([75999, 81444, 0xefefef], 4, true);
      expect(builder.getBytes()).to.eql(correct);
    });
    it('should correctly add a Uint8Array', function() {
      const correct = Uint8Array.from([0, 1, 40, 223, 0, 1]);
      const builder = new MessageBuilder();
      builder.addValueToMsg(Uint8Array.from([0, 1, 40, 223, 0, 1]));
      expect(builder.getBytes()).to.eql(correct);
    });
  });

  describe('addStrToMsg', function() {
    it('should correctly add hex string', function() {
      const correct = Uint8Array.from([239]);
      const builder = new MessageBuilder();
      builder.addStrToMsg("EF");
      expect(builder.getBytes()).to.eql(correct);
    });
    it('should correctly add multi-byte hex string', function() {
      const correct = Uint8Array.from([239, 239, 0, 239]);
      const builder = new MessageBuilder();
      builder.addStrToMsg("EFEF00EF");
      expect(builder.getBytes()).to.eql(correct);
    });
    it('should correctly set endianness', function() {
      const correct = Uint8Array.from([239, 0, 239, 239]);
      const builder = new MessageBuilder();
      builder.addStrToMsg("efef00ef", true);
      expect(builder.getBytes()).to.eql(correct);
    });
    it('should correctly set endianness', function() {
      const correct = Uint8Array.from([ 0, 0, 0, 0, 129, 111, 196, 93]);
      const builder = new MessageBuilder();
      builder.addStrToMsg("5DC46F8100000000", true);
      expect(builder.getBytes()).to.eql(correct);
    });
  });
});

describe('numToBytes', function () {
  it('should return correct bytes for 1-byte stuff', function () {
    const correct = [0, 0, 0, 33];
    const res = numToBytes(33, 4);
    expect(res).to.eql(correct);
  });
  it('should return correct bytes for multi-byte stuff', function () {
    const correct = [0, 1, 40, 223];
    const res = numToBytes(75999, 4);
    expect(res).to.eql(correct);
  });
  it('should return correct endianness', function () {
    const correct = [223, 40, 1, 0];
    const res = numToBytes(75999, 4, true);
    expect(res).to.eql(correct);
  });
  it('should return correct bytes for 1-byte hex stuff', function () {
    const correct = [0, 0, 0, 239];
    const res = numToBytes(0xef, 4);
    expect(res).to.eql(correct);
  });
  it('should return correct bytes for multi-byte hex stuff', function () {
    const correct = [0, 239, 239, 239];
    const res = numToBytes(0xefefef, 4);
    expect(res).to.eql(correct);
  });
  it('should return correct endianness for hex', function () {
    const correct = [239, 239, 239, 0];
    const res = numToBytes(0xefefef, 4, true);
    expect(res).to.eql(correct);
  });
});
