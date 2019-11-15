const expect = require('chai').expect;
const {
  makeMsgIdHex,
  primeFactorization
} = require("./index");

describe('utils', function () {
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
    it('should calculate correctly', async function () {
      // Some browsers take a lot of time to calc this. (Edge in VirtualBox)
      this.timeout(20000);
      for (let i = 0; i < inputs.length; i++) {
        const [p, q] = await primeFactorization(inputs[i]);
        expect(p).to.eql(outputs[i][0]);
        expect(q).to.eql(outputs[i][1]);
      }
    });
  });
});