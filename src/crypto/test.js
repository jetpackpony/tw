const expect = require('chai').expect;
const { makeTmpAESKeys } = require("./index");
const { bytesToHex, bytesFromHex } = require('../primeFactorization');
const { decryptAES, encryptAES_CTR, decryptAES_CTR } = require('../crypto');
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

describe('AES-CTR', function () {
  var keys = [
    '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'
  ];

  var ivs = [
    'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
  ];

  var inputs = [
    '6bc1bee22e409f96e93d7e117393172a' +
    'ae2d8a571e03ac9c9eb76fac45af8e51' +
    '30c81c46a35ce411e5fbc1191a0a52ef' +
    'f69f2445df4f9b17ad2b417be66c3710'
  ];

  var outputs = [
    '601ec313775789a5b7a7f504bbf3d228' +
    'f443e3ca4d62b59aca84e990cacaf5c5' +
    '2b0930daa23de94ce87017ba2d84988d' +
    'dfc9c58db67aada613c2dd08457941a6'
  ];

  const key = Uint8Array.from(bytesFromHex(keys[0]));
  const iv = Uint8Array.from(bytesFromHex(ivs[0]));
  const input = Uint8Array.from(bytesFromHex(inputs[0]));
  const output = Uint8Array.from(bytesFromHex(outputs[0]));

  it('should encrypt', function () {
    const encrypted = encryptAES_CTR(input, key, iv);
    expect(encrypted).to.eql(output);
  });
  it('should decrypt', function () {
    const decrypted = decryptAES_CTR(output, key, iv);
    expect(decrypted).to.eql(input);
  });
});
