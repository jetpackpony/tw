const expect = require('chai').expect;
const { makeTmpAESKeys } = require("./index");
const { bytesToHex, bytesFromHex } = require('../primeFactorization');
const { decryptAES } = require('../crypto');
const { encrypt, decrypt } = require('./aes_ige');

describe('AES-IGE', function () {
  const data = [
    {
      encrypted: Uint8Array.from(bytesFromHex("1A8519A6557BE652E9DA8E43DA4EF4453CF456B4CA488AA383C79C98B34797CB")),
      key: Uint8Array.from(bytesFromHex("000102030405060708090A0B0C0D0E0F")),
      iv: Uint8Array.from(bytesFromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")),
      text: Uint8Array.from(bytesFromHex("0000000000000000000000000000000000000000000000000000000000000000")),
    },
    {
      encrypted: Uint8Array.from(bytesFromHex("4C2E204C6574277320686F70652042656E20676F74206974207269676874210A")),
      key: Uint8Array.from(bytesFromHex("5468697320697320616E20696D706C65")),
      iv: Uint8Array.from(bytesFromHex("6D656E746174696F6E206F6620494745206D6F646520666F72204F70656E5353")),
      text: Uint8Array.from(bytesFromHex("99706487A1CDE613BC6DE0B6F24B1C7AA448C8B9C3403E3467A8CAD89340F53B")),
    }
  ];
  it('should decrypt', function () {
    const d = data[0];
    const decrypted = decrypt(d.encrypted, d.key, d.iv);
    expect(decrypted).to.eql(d.text);
  });
  it('should decrypt more', function () {
    const d = data[1];
    const decrypted = decrypt(d.encrypted, d.key, d.iv);
    expect(decrypted).to.eql(d.text);
  });

  it('should encrypt', function () {
    const d = data[0];
    const encrypted = encrypt(d.text, d.key, d.iv);
    expect(encrypted).to.eql(d.encrypted);
  });
  it('should encrypt more', function () {
    const d = data[1];
    const encrypted = encrypt(d.text, d.key, d.iv);
    expect(encrypted).to.eql(d.encrypted);
  });
});

