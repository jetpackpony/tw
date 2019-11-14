const expect = require('chai').expect;
const {
  makeTmpAESKeys,
  makeMsgIdHex,
  primeFactorization
} = require("./index");
const {
  bytesToHex,
  bytesFromHex
} = require('../primeFactorization');

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
      const output = "5dcd63ba00000000";
      const res = await makeMsgIdHex(date);
      expect(res).to.eql(output);
    });
  });

  describe('prime factorization', function () {
    const inputs = [
      [31, 106, 188, 208, 16, 119, 65, 235],
      [48, 226, 5, 1, 122, 19, 99, 249]
    ];
    const outputs = [
      [[86, 24, 183, 195], [93, 106, 82, 185]],
      [[111, 104, 123, 191], [112, 83, 110, 71]]
    ]
    it('should calculate correctly', async () => {
      for (let i = 0; i < inputs.length; i++) {
        const [p, q] = await primeFactorization(inputs[i]);
        expect(p).to.eql(outputs[i][0]);
        expect(q).to.eql(outputs[i][1]);
      }
    });
  });
});