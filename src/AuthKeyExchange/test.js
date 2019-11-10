const AuthKeyExchange = require('./AuthKeyExchange');
const expect = require('chai').expect;

describe('AuthKeyExchange', function() {
  describe('makeInitialMessage', function() {
    it('should return correct bytes', function () {
      const correct = Uint8Array.from([
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 3, 113, 197, 93,
        20, 0, 0, 0,
        241, 142, 126, 190,
        90, 172, 101, 29, 227, 87, 146, 4, 238, 65, 211, 233, 123, 100, 128, 77
      ]);
      const exchange = new AuthKeyExchange({
        msg_id_hex: "5DC5710300000000",
        nonce: Uint8Array.from([
          90, 172, 101, 29, 227,
          87, 146, 4, 238, 65,
          211, 233, 123, 100, 128,
          77
        ])
      });
      const msg = exchange.makeInitialMessage();
      console.log('msg: ', msg);
      expect(msg).to.eql(correct);
    });
  });
});