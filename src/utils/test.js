const expect = require('chai').expect;
const { makeTmpAESKeys, makeMsgIdHex } = require("./index");
const { bytesToHex, bytesFromHex } = require('../primeFactorization');

describe('utils', function () {
  describe('makeTmpAESKeys', function () {
    it('should make correct keys', async () => {
      const newNonce = Uint8Array.from(bytesFromHex("311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D"));
      const serverNonce = Uint8Array.from(bytesFromHex("A5CF4D33F4A11EA877BA4AA573907330"));

      const [key, iv] = await makeTmpAESKeys(newNonce, serverNonce);

      expect(key).to.eql(Uint8Array.from(bytesFromHex("F011280887C7BB01DF0FC4E17830E0B91FBB8BE4B2267CB985AE25F33B527253")));
      expect(iv).to.eql(Uint8Array.from(bytesFromHex("3212D579EE35452ED23E0D0C92841AA7D31B2E9BDEF2151E80D15860311C85DB")));
    });
  });

  describe('makeMsgIdHex', function () {
    it('should make correct hex', async () => {
      const date = 1573741498;
      const output = "5DCD63BA00000000";
      const res = await makeMsgIdHex(date);
      expect(res).to.eql(output);
    });
  });
});