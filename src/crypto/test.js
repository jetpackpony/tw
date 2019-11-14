const expect = require('chai').expect;
const { makeTmpAESKeys } = require("./index");
const { bytesToHex, bytesFromHex } = require('../primeFactorization');
const {
  modPow,
  makeEncryptorAES_CTR,
  makeDecryptorAES_CTR,
  encryptAES,
  decryptAES
} = require('../crypto');

describe("crypto", () => {
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
    it('should decrypt', async () => {
      const d = data[0];
      const decrypted = await decryptAES(d.encrypted, d.key, d.iv);
      expect(decrypted).to.eql(d.text);
    });
    it('should decrypt more', async () => {
      const d = data[1];
      const decrypted = await decryptAES(d.encrypted, d.key, d.iv);
      expect(decrypted).to.eql(d.text);
    });

    it('should encrypt', async () => {
      const d = data[0];
      const encrypted = await encryptAES(d.text, d.key, d.iv);
      expect(encrypted).to.eql(d.encrypted);
    });
    it('should encrypt more', async () => {
      const d = data[1];
      const encrypted = await encryptAES(d.text, d.key, d.iv);
      expect(encrypted).to.eql(d.encrypted);
    });
  });

  describe('AES-CTR', function () {
    const input = Uint8Array.from(bytesFromHex("b11a087cdbf4401f2d471ad88a95901adb262d9785fe204da3090f9ff3ae43a697be93f2a3eb103350e8fb5ca14e0ea2fe06658f4e553dcbbc8363372141752d"));

    const encKey = Uint8Array.from(bytesFromHex("2d471ad88a95901adb262d9785fe204da3090f9ff3ae43a697be93f2a3eb1033"));
    const encIV = Uint8Array.from(bytesFromHex("50e8fb5ca14e0ea2fe06658f4e553dcb"));
    const encOut = [
      Uint8Array.from(bytesFromHex('589e5e519d21c34d283604735964587a160cc7e84f4bd964273f975adcf24b964115131c44fb6c4926bc7a32099e67790552eab358cd5205574fcedbdb329e2d')),
      Uint8Array.from(bytesFromHex('3e6122a0bb5783c58b263f58064b65639be9a67b328388d75b53fd62a569db7e82352dcbca3fe86034ba91e668d141b024bace413f70a11af80778e2eca0678c')),
      Uint8Array.from(bytesFromHex('11f25eae2f252570d1def310faec8eb780a0e1af747f7feed16795ebeedb9a845ed3e36550cedce0073f25ed045f33fc5aad6b92a0db6f07e71c3b22fb29c37c'))
    ];
    it('should encrypt', async () => {
      const encryptor = await makeEncryptorAES_CTR(encKey, encIV);
      expect(await encryptor.encrypt(input)).to.eql(encOut[0]);
      expect(await encryptor.encrypt(input)).to.eql(encOut[1]);
      expect(await encryptor.encrypt(input)).to.eql(encOut[2]);
    });

    const decKey = Uint8Array.from(bytesFromHex("cb3d554e8f6506fea20e4ea15cfbe8503310eba3f293be97a643aef39f0f09a3"));
    const decIV = Uint8Array.from(bytesFromHex("4d20fe85972d26db1a90958ad81a472d"));
    const decOut = [
      Uint8Array.from(bytesFromHex('222fc81cb9c6b02d62d2bd80ad1624ec29cf84f7344aca34a65ff8b70a01fdb7714cba4ec0e75f133be0dbbe73d1a161f37d8ff0b51ce4aafd47b7ff68230eac')),
      Uint8Array.from(bytesFromHex('4717a870866f0e9c86116572b3551fe3c7795c6fd39956e76406a9626ed371f74e5736f730e5e5e778a46749c23bea79b2d3f010aade4ad7f8cc531a334486e5')),
      Uint8Array.from(bytesFromHex('a0e21a7adb895aab57b71a12cdf5bc207da4cdfb2a8c54d67986f9424138b548a23ef56c614e099add61d30e9bf60ed4db52db19431a911440c4339e1570b545'))
    ];
    it('should decrypt', async () => {
      const decryptor = await makeDecryptorAES_CTR(decKey, decIV);
      expect(await decryptor.decrypt(input)).to.eql(decOut[0]);
      expect(await decryptor.decrypt(input)).to.eql(decOut[1]);
      expect(await decryptor.decrypt(input)).to.eql(decOut[2]);
    });
  });

  describe("modPow", () => {
    const bases = [
      Uint8Array.from([0, 0, 0, 3]),
      Uint8Array.from([0, 0, 0, 3]),
      Uint8Array.from([0, 0, 0, 3]),
    ];
    const exps = [
      Uint8Array.from([158, 140, 151, 110, 175, 224, 232, 181, 193, 191, 121, 24, 158, 89, 154, 150, 225, 96, 24, 85, 40, 127, 13, 238, 64, 238, 235, 7, 142, 146, 224, 133, 63, 98, 65, 203, 104, 219, 224, 221, 58, 135, 233, 216, 244, 25, 165, 111, 103, 206, 66, 208, 96, 214, 151, 10, 133, 139, 171, 51, 119, 45, 131, 41, 196, 47, 218, 209, 129, 13, 237, 244, 80, 22, 180, 108, 188, 198, 21, 4, 134, 35, 228, 242, 138, 33, 133, 170, 28, 128, 112, 213, 203, 205, 145, 232, 199, 75, 48, 187, 245, 138, 195, 215, 188, 106, 189, 9, 216, 137, 254, 38, 199, 58, 118, 166, 175, 14, 240, 63, 232, 185, 168, 253, 75, 110, 226, 191, 68, 98, 29, 200, 72, 135, 213, 166, 73, 28, 102, 111, 108, 3, 251, 211, 185, 174, 175, 129, 240, 143, 162, 77, 223, 4, 175, 31, 230, 190, 171, 91, 140, 161, 176, 1, 97, 224, 143, 187, 45, 253, 167, 60, 32, 57, 5, 83, 44, 199, 235, 135, 233, 254, 242, 173, 224, 76, 182, 203, 54, 107, 227, 178, 193, 114, 203, 4, 69, 99, 59, 123, 160, 7, 111, 200, 62, 179, 241, 81, 120, 68, 93, 131, 231, 36, 166, 82, 19, 18, 17, 165, 64, 166, 93, 103, 48, 143, 131, 57, 186, 182, 184, 181, 55, 241, 251, 85, 110, 60, 58, 183, 93, 75, 51, 240, 101, 36, 105, 154, 240, 204, 148, 9, 240, 207, 73, 118]),
      Uint8Array.from([215, 223, 170, 144, 38, 192, 157, 239, 42, 253, 206, 151, 254, 33, 48, 191, 60, 238, 200, 1, 212, 206, 125, 7, 19, 170, 10, 10, 138, 133, 181, 128, 216, 59, 28, 66, 25, 204, 244, 38, 235, 136, 196, 14, 225, 234, 174, 227, 163, 240, 88, 55, 171, 55, 138, 205, 75, 130, 46, 241, 60, 250, 57, 166, 120, 107, 81, 54, 99, 163, 2, 64, 42, 46, 100, 193, 88, 102, 153, 88, 42, 31, 182, 17, 221, 37, 178, 217, 47, 141, 148, 146, 36, 143, 241, 211, 144, 175, 73, 42, 82, 27, 129, 67, 89, 198, 24, 193, 235, 145, 244, 197, 255, 246, 89, 15, 224, 224, 85, 160, 137, 241, 49, 142, 208, 107, 64, 51, 86, 188, 246, 30, 101, 246, 44, 218, 96, 251, 93, 191, 239, 208, 209, 255, 37, 210, 192, 141, 242, 36, 14, 188, 216, 158, 217, 51, 75, 64, 207, 225, 40, 126, 192, 91, 23, 240, 9, 5, 244, 38, 246, 60, 165, 242, 68, 206, 182, 149, 154, 63, 233, 19, 129, 197, 183, 217, 201, 217, 35, 178, 37, 72, 36, 23, 16, 246, 241, 118, 21, 5, 33, 52, 191, 45, 217, 174, 152, 150, 224, 119, 19, 123, 8, 26, 69, 149, 1, 159, 142, 223, 139, 71, 192, 121, 144, 40, 58, 41, 79, 139, 187, 69, 186, 108, 231, 131, 101, 70, 236, 10, 118, 112, 106, 163, 154, 129, 213, 19, 190, 244, 95, 61, 195, 144, 242, 91]),
      Uint8Array.from([243, 89, 156, 36, 122, 48, 229, 99, 245, 27, 231, 177, 91, 253, 207, 98, 126, 110, 82, 76, 197, 189, 117, 122, 24, 173, 177, 123, 219, 135, 151, 19, 61, 122, 80, 80, 236, 49, 34, 229, 231, 128, 94, 32, 126, 102, 6, 198, 132, 60, 68, 88, 173, 82, 109, 6, 125, 190, 154, 238, 98, 53, 136, 183, 57, 185, 77, 131, 243, 53, 199, 2, 166, 194, 110, 127, 118, 165, 179, 185, 227, 187, 107, 44, 203, 86, 32, 49, 131, 84, 207, 176, 244, 90, 207, 165, 218, 94, 156, 36, 204, 22, 232, 27, 151, 205, 106, 223, 235, 39, 38, 124, 64, 226, 74, 171, 113, 219, 248, 223, 35, 94, 231, 237, 243, 150, 235, 93, 140, 112, 72, 17, 74, 254, 125, 62, 96, 255, 104, 186, 118, 127, 229, 19, 116, 162, 158, 98, 244, 228, 75, 159, 53, 64, 191, 14, 228, 163, 202, 129, 138, 131, 2, 228, 85, 187, 50, 224, 187, 48, 230, 10, 180, 148, 41, 90, 121, 25, 92, 117, 117, 37, 201, 143, 176, 198, 80, 57, 145, 175, 220, 9, 213, 227, 220, 188, 221, 118, 242, 191, 167, 73, 91, 183, 243, 141, 30, 174, 26, 210, 221, 204, 163, 4, 149, 3, 189, 218, 228, 189, 73, 116, 61, 24, 72, 145, 227, 224, 98, 207, 154, 48, 24, 221, 223, 162, 203, 91, 4, 55, 191, 253, 76, 72, 78, 194, 231, 215, 169, 56, 55, 135, 222, 199, 114, 247]),
    ];
    const mods = [
      Uint8Array.from([199, 28, 174, 185, 198, 177, 201, 4, 142, 108, 82, 47, 112, 241, 63, 115, 152, 13, 64, 35, 142, 62, 33, 193, 73, 52, 208, 55, 86, 61, 147, 15, 72, 25, 138, 10, 167, 193, 64, 88, 34, 148, 147, 210, 37, 48, 244, 219, 250, 51, 111, 110, 10, 201, 37, 19, 149, 67, 174, 212, 76, 206, 124, 55, 32, 253, 81, 246, 148, 88, 112, 90, 198, 140, 212, 254, 107, 107, 19, 171, 220, 151, 70, 81, 41, 105, 50, 132, 84, 241, 143, 175, 140, 89, 95, 100, 36, 119, 254, 150, 187, 42, 148, 29, 91, 205, 29, 74, 200, 204, 73, 136, 7, 8, 250, 155, 55, 142, 60, 79, 58, 144, 96, 190, 230, 124, 249, 164, 164, 166, 149, 129, 16, 81, 144, 126, 22, 39, 83, 181, 107, 15, 107, 65, 13, 186, 116, 216, 168, 75, 42, 20, 179, 20, 78, 14, 241, 40, 71, 84, 253, 23, 237, 149, 13, 89, 101, 180, 185, 221, 70, 88, 45, 177, 23, 141, 22, 156, 107, 196, 101, 176, 214, 255, 156, 163, 146, 143, 239, 91, 154, 228, 228, 24, 252, 21, 232, 62, 190, 160, 248, 127, 169, 255, 94, 237, 112, 5, 13, 237, 40, 73, 244, 123, 249, 89, 217, 86, 133, 12, 233, 41, 133, 31, 13, 129, 21, 246, 53, 177, 5, 238, 46, 78, 21, 208, 75, 36, 84, 191, 111, 79, 173, 240, 52, 177, 4, 3, 17, 156, 216, 227, 185, 47, 204, 91]),
      Uint8Array.from([199, 28, 174, 185, 198, 177, 201, 4, 142, 108, 82, 47, 112, 241, 63, 115, 152, 13, 64, 35, 142, 62, 33, 193, 73, 52, 208, 55, 86, 61, 147, 15, 72, 25, 138, 10, 167, 193, 64, 88, 34, 148, 147, 210, 37, 48, 244, 219, 250, 51, 111, 110, 10, 201, 37, 19, 149, 67, 174, 212, 76, 206, 124, 55, 32, 253, 81, 246, 148, 88, 112, 90, 198, 140, 212, 254, 107, 107, 19, 171, 220, 151, 70, 81, 41, 105, 50, 132, 84, 241, 143, 175, 140, 89, 95, 100, 36, 119, 254, 150, 187, 42, 148, 29, 91, 205, 29, 74, 200, 204, 73, 136, 7, 8, 250, 155, 55, 142, 60, 79, 58, 144, 96, 190, 230, 124, 249, 164, 164, 166, 149, 129, 16, 81, 144, 126, 22, 39, 83, 181, 107, 15, 107, 65, 13, 186, 116, 216, 168, 75, 42, 20, 179, 20, 78, 14, 241, 40, 71, 84, 253, 23, 237, 149, 13, 89, 101, 180, 185, 221, 70, 88, 45, 177, 23, 141, 22, 156, 107, 196, 101, 176, 214, 255, 156, 163, 146, 143, 239, 91, 154, 228, 228, 24, 252, 21, 232, 62, 190, 160, 248, 127, 169, 255, 94, 237, 112, 5, 13, 237, 40, 73, 244, 123, 249, 89, 217, 86, 133, 12, 233, 41, 133, 31, 13, 129, 21, 246, 53, 177, 5, 238, 46, 78, 21, 208, 75, 36, 84, 191, 111, 79, 173, 240, 52, 177, 4, 3, 17, 156, 216, 227, 185, 47, 204, 91]),
      Uint8Array.from([199, 28, 174, 185, 198, 177, 201, 4, 142, 108, 82, 47, 112, 241, 63, 115, 152, 13, 64, 35, 142, 62, 33, 193, 73, 52, 208, 55, 86, 61, 147, 15, 72, 25, 138, 10, 167, 193, 64, 88, 34, 148, 147, 210, 37, 48, 244, 219, 250, 51, 111, 110, 10, 201, 37, 19, 149, 67, 174, 212, 76, 206, 124, 55, 32, 253, 81, 246, 148, 88, 112, 90, 198, 140, 212, 254, 107, 107, 19, 171, 220, 151, 70, 81, 41, 105, 50, 132, 84, 241, 143, 175, 140, 89, 95, 100, 36, 119, 254, 150, 187, 42, 148, 29, 91, 205, 29, 74, 200, 204, 73, 136, 7, 8, 250, 155, 55, 142, 60, 79, 58, 144, 96, 190, 230, 124, 249, 164, 164, 166, 149, 129, 16, 81, 144, 126, 22, 39, 83, 181, 107, 15, 107, 65, 13, 186, 116, 216, 168, 75, 42, 20, 179, 20, 78, 14, 241, 40, 71, 84, 253, 23, 237, 149, 13, 89, 101, 180, 185, 221, 70, 88, 45, 177, 23, 141, 22, 156, 107, 196, 101, 176, 214, 255, 156, 163, 146, 143, 239, 91, 154, 228, 228, 24, 252, 21, 232, 62, 190, 160, 248, 127, 169, 255, 94, 237, 112, 5, 13, 237, 40, 73, 244, 123, 249, 89, 217, 86, 133, 12, 233, 41, 133, 31, 13, 129, 21, 246, 53, 177, 5, 238, 46, 78, 21, 208, 75, 36, 84, 191, 111, 79, 173, 240, 52, 177, 4, 3, 17, 156, 216, 227, 185, 47, 204, 91]),
    ];
    const ouputs = [
      Uint8Array.from([42, 8, 212, 126, 244, 152, 209, 94, 105, 77, 206, 250, 229, 37, 92, 208, 105, 41, 179, 137, 19, 143, 125, 87, 27, 149, 8, 95, 153, 131, 109, 178, 109, 50, 190, 227, 33, 132, 129, 134, 79, 12, 139, 115, 121, 38, 91, 75, 224, 105, 213, 252, 248, 204, 158, 171, 191, 77, 240, 242, 214, 61, 137, 57, 245, 118, 232, 33, 145, 145, 74, 245, 170, 182, 54, 62, 145, 32, 57, 164, 75, 79, 213, 105, 143, 38, 108, 97, 171, 136, 17, 188, 182, 232, 196, 252, 75, 172, 185, 113, 107, 24, 130, 76, 40, 225, 110, 172, 39, 130, 6, 247, 166, 223, 203, 174, 133, 83, 204, 108, 217, 171, 228, 67, 246, 127, 93, 75, 216, 95, 160, 255, 56, 8, 226, 184, 28, 87, 28, 239, 105, 85, 51, 48, 97, 209, 65, 184, 197, 23, 69, 114, 176, 21, 250, 117, 216, 250, 219, 77, 68, 12, 194, 167, 118, 94, 175, 59, 132, 199, 138, 49, 128, 129, 169, 92, 129, 80, 210, 198, 209, 157, 211, 230, 52, 113, 124, 214, 60, 164, 15, 93, 116, 27, 65, 173, 156, 112, 195, 200, 50, 20, 227, 43, 77, 71, 49, 222, 106, 146, 45, 158, 95, 22, 99, 195, 243, 206, 62, 109, 164, 238, 75, 223, 106, 193, 228, 111, 224, 215, 50, 227, 248, 219, 61, 105, 167, 254, 0, 111, 140, 139, 180, 69, 143, 237, 34, 223, 136, 217, 115, 126, 209, 172, 110, 103]),
      Uint8Array.from([58, 14, 255, 32, 161, 159, 212, 192, 211, 143, 228, 47, 41, 45, 72, 40, 144, 83, 143, 186, 206, 170, 20, 217, 98, 156, 102, 10, 251, 235, 8, 100, 17, 204, 48, 131, 129, 188, 196, 153, 196, 115, 122, 211, 55, 160, 64, 252, 146, 4, 187, 68, 252, 34, 53, 165, 232, 26, 12, 162, 93, 227, 178, 113, 70, 211, 75, 140, 70, 248, 184, 251, 45, 93, 241, 48, 166, 252, 138, 165, 209, 82, 0, 169, 51, 37, 148, 199, 253, 208, 189, 34, 13, 229, 170, 239, 253, 211, 198, 105, 120, 201, 108, 108, 138, 61, 69, 18, 83, 250, 48, 52, 2, 147, 237, 196, 161, 171, 127, 242, 93, 185, 212, 8, 189, 76, 16, 123, 202, 20, 155, 40, 223, 92, 155, 253, 26, 1, 200, 122, 4, 210, 77, 148, 232, 235, 73, 49, 79, 240, 218, 29, 188, 186, 17, 7, 4, 199, 177, 223, 157, 190, 60, 110, 101, 218, 199, 64, 113, 147, 43, 76, 98, 167, 34, 187, 232, 30, 104, 134, 127, 126, 2, 19, 83, 223, 55, 154, 167, 210, 201, 204, 174, 168, 201, 210, 150, 222, 215, 246, 126, 107, 35, 92, 212, 90, 113, 110, 224, 5, 166, 176, 239, 46, 170, 115, 125, 4, 174, 206, 38, 74, 84, 34, 190, 194, 90, 216, 104, 75, 82, 2, 202, 248, 12, 183, 155, 113, 186, 169, 119, 217, 213, 224, 122, 166, 51, 14, 217, 121, 4, 197, 192, 250, 114, 106]),
      Uint8Array.from([173, 138, 78, 9, 55, 90, 141, 88, 3, 19, 89, 203, 22, 36, 197, 110, 191, 220, 128, 58, 85, 223, 69, 227, 26, 112, 208, 144, 126, 115, 58, 29, 108, 95, 134, 59, 254, 52, 205, 29, 120, 59, 217, 114, 21, 38, 119, 100, 102, 149, 130, 31, 80, 158, 119, 59, 96, 54, 120, 97, 88, 99, 218, 245, 11, 210, 73, 34, 233, 2, 152, 0, 0, 240, 223, 103, 15, 216, 131, 74, 146, 146, 253, 25, 137, 91, 193, 96, 244, 0, 104, 45, 227, 119, 185, 187, 45, 195, 156, 129, 170, 107, 251, 152, 38, 155, 12, 89, 123, 243, 70, 191, 34, 173, 91, 221, 158, 110, 86, 134, 102, 187, 215, 189, 35, 167, 59, 88, 222, 18, 145, 80, 70, 82, 68, 26, 187, 126, 90, 177, 0, 181, 42, 203, 14, 138, 251, 25, 146, 169, 153, 76, 0, 31, 68, 22, 233, 141, 143, 219, 167, 204, 98, 43, 235, 24, 129, 116, 37, 2, 6, 128, 45, 145, 229, 216, 167, 174, 97, 253, 225, 198, 214, 59, 126, 77, 29, 190, 161, 211, 92, 125, 23, 42, 58, 204, 231, 80, 20, 102, 111, 209, 106, 228, 21, 9, 132, 147, 169, 236, 35, 122, 132, 213, 206, 84, 175, 151, 113, 182, 138, 184, 23, 56, 135, 225, 238, 217, 217, 8, 47, 117, 213, 63, 253, 132, 195, 229, 165, 24, 83, 12, 119, 103, 75, 241, 133, 247, 119, 6, 246, 39, 29, 130, 192, 236]),
    ];

    it("should work", async () => {
      for (let i = 0; i < bases.length; i++) {
        const res = await modPow(bases[i], exps[i], mods[i]);
        expect(Uint8Array.from(res)).to.eql(ouputs[i]);
      }
    });
  });
});