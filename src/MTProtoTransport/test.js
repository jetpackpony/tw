const expect = require('chai').expect;
const { makeTmpAESKeys } = require("./index");
const { bytesToHex, bytesFromHex } = require('../primeFactorization');
const { IntermediatePadded } = require('../MTProtoTransport');

describe('IntermediatePadded', function () {
  const testing = {
    getRandomBytes: () => (new Uint8Array(5)).fill(3),
    obfParams: {
      initPayload: Uint8Array.from(bytesFromHex("1b2ed5b17c89632e6c964145efdc45f6dba3b35db71979e3ee0c40cbc89eec3f049a1eb2fe8855f4d6080377a68e59c0c5657380c60485a70ee2326bdb5c935b")),
      encryptKey: Uint8Array.from(bytesFromHex("6c964145efdc45f6dba3b35db71979e3ee0c40cbc89eec3f049a1eb2fe8855f4")),
      encryptIV: Uint8Array.from(bytesFromHex("d6080377a68e59c0c5657380c60485a7")),
      decryptKey: Uint8Array.from(bytesFromHex("a78504c6807365c5c0598ea6770308d6f45588feb21e9a043fec9ec8cb400cee")),
      decryptIV: Uint8Array.from(bytesFromHex("e37919b75db3a3dbf645dcef4541966c"))
    }
  };

  describe('without obfuscation', function () {
    it('should build initial request', function () {
      const transport = new IntermediatePadded(false, testing);
      const input = Uint8Array.from(bytesFromHex("311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D"));
      const output = Uint8Array.from(bytesFromHex("dddddddd25000000311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D0303030303"));
      const res = transport.packMessage(input);
      expect(res).to.eql(output);
    });
    it('should build following request', function () {
      const transport = new IntermediatePadded(false, testing);
      const input = Uint8Array.from(bytesFromHex("311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D"));
      const output = Uint8Array.from(bytesFromHex("25000000311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D0303030303"));
      transport.packMessage(input);
      const res = transport.packMessage(input);
      expect(res).to.eql(output);
    });
  });

  describe('with obfuscation', function () {
    it('should build initial request', function () {
      const transport = new IntermediatePadded(true, testing);
      const input = Uint8Array.from(bytesFromHex("311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D"));
      //with length encrypted
      //const output = Uint8Array.from(bytesFromHex("1b2ed5b17c89632e6c964145efdc45f6dba3b35db71979e3ee0c40cbc89eec3f049a1eb2fe8855f4d6080377a68e59c0c5657380c60485a70ee2326bdb5c935b3b0f7c4c5ab9859aef782bbc40c71416c79f642bfec55237657d628cc94f15b06034aead3253389623"));
      //with length non encrypted
      const output = Uint8Array.from(bytesFromHex("1b2ed5b17c89632e6c964145efdc45f6dba3b35db71979e3ee0c40cbc89eec3f049a1eb2fe8855f4d6080377a68e59c0c5657380c60485a70ee2326bdb5c935b250000002f13f99748efa225c6cec3aeed0e913b7fa57dfb30b5253d552059d54fa18d2504fbafe332"));
      const res = transport.packMessage(input);
      expect(res).to.eql(output);
    });
    it('should build following request', function () {
      const transport = new IntermediatePadded(true, testing);
      const input = Uint8Array.from(bytesFromHex("311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D"));
      //with length encrypted
      //const output = Uint8Array.from(bytesFromHex("3b0f7c4c5ab9859aef782bbc40c71416c79f642bfec55237657d628cc94f15b06034aead3253389623"));
      //with length non ecnrypted
      const output = Uint8Array.from(bytesFromHex("250000002f13f99748efa225c6cec3aeed0e913b7fa57dfb30b5253d552059d54fa18d2504fbafe332"));
      transport.packMessage(input);
      const res = transport.packMessage(input);
      expect(res).to.eql(output);
    });
  });
});