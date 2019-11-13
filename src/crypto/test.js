const expect = require('chai').expect;
const { makeTmpAESKeys } = require("./index");
const { bytesToHex, bytesFromHex } = require('../primeFactorization');
const {
  decryptAES,
  encryptAES_CTR,
  decryptAES_CTR,
  makeEncryptorAES_CTR,
  makeDecryptorAES_CTR
} = require('../crypto');
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

describe.only('AES-CTR', function () {
  const input = Uint8Array.from(bytesFromHex("b11a087cdbf4401f2d471ad88a95901adb262d9785fe204da3090f9ff3ae43a697be93f2a3eb103350e8fb5ca14e0ea2fe06658f4e553dcbbc8363372141752d"));

  const encKey = Uint8Array.from(bytesFromHex("2d471ad88a95901adb262d9785fe204da3090f9ff3ae43a697be93f2a3eb1033"));
  const encIV = Uint8Array.from(bytesFromHex("50e8fb5ca14e0ea2fe06658f4e553dcb"));
  const encOut = [
    Uint8Array.from(bytesFromHex('589e5e519d21c34d283604735964587a160cc7e84f4bd964273f975adcf24b964115131c44fb6c4926bc7a32099e67790552eab358cd5205574fcedbdb329e2d')),
    Uint8Array.from(bytesFromHex('3e6122a0bb5783c58b263f58064b65639be9a67b328388d75b53fd62a569db7e82352dcbca3fe86034ba91e668d141b024bace413f70a11af80778e2eca0678c')),
    Uint8Array.from(bytesFromHex('11f25eae2f252570d1def310faec8eb780a0e1af747f7feed16795ebeedb9a845ed3e36550cedce0073f25ed045f33fc5aad6b92a0db6f07e71c3b22fb29c37c'))
  ];
  it('should encrypt', function () {
    const encryptor = makeEncryptorAES_CTR(encKey, encIV);
    expect(encryptor.encrypt(input)).to.eql(encOut[0]);
    expect(encryptor.encrypt(input)).to.eql(encOut[1]);
    expect(encryptor.encrypt(input)).to.eql(encOut[2]);
  });

  const decKey = Uint8Array.from(bytesFromHex("cb3d554e8f6506fea20e4ea15cfbe8503310eba3f293be97a643aef39f0f09a3"));
  const decIV = Uint8Array.from(bytesFromHex("4d20fe85972d26db1a90958ad81a472d"));
  const decOut = [
    Uint8Array.from(bytesFromHex('222fc81cb9c6b02d62d2bd80ad1624ec29cf84f7344aca34a65ff8b70a01fdb7714cba4ec0e75f133be0dbbe73d1a161f37d8ff0b51ce4aafd47b7ff68230eac')),
    Uint8Array.from(bytesFromHex('4717a870866f0e9c86116572b3551fe3c7795c6fd39956e76406a9626ed371f74e5736f730e5e5e778a46749c23bea79b2d3f010aade4ad7f8cc531a334486e5')),
    Uint8Array.from(bytesFromHex('a0e21a7adb895aab57b71a12cdf5bc207da4cdfb2a8c54d67986f9424138b548a23ef56c614e099add61d30e9bf60ed4db52db19431a911440c4339e1570b545'))
  ];
  it('should decrypt', function () {
    const decryptor = makeDecryptorAES_CTR(decKey, decIV);
    expect(decryptor.decrypt(input)).to.eql(decOut[0]);
    expect(decryptor.decrypt(input)).to.eql(decOut[1]);
    expect(decryptor.decrypt(input)).to.eql(decOut[2]);
  });
});
