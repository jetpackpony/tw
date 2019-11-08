const AuthKeyExchange = require('./AuthKeyExchange');
const expect = require('chai').expect;

describe('AuthKeyExchange', function() {
  describe('makeInitialMessage', function() {
    it('should return correct bytes', function() {
      const correct = Uint8Array.from([
        239, 10, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 129, 111, 196, 20, 0,
        0, 0, 241, 142, 126, 190, 188, 36, 100, 54,
        165, 132, 216, 24, 225, 163, 141, 203, 198, 178,
        49, 108
      ]);
      const exchange = new AuthKeyExchange({
        msg_id_hex: "5DC46F8100000000",
        nonceHex: "BC246436A584D818E1A38DCBC6B2316C"
      });
      const msg = exchange.makeInitialMessage();
      console.log('msg: ', msg);
      expect(msg).to.eql(correct);
    });
  });
});