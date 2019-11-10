const forge = require('node-forge');
const { bytesFromHex } = require('../primeFactorization');

const encrypt = function(buffer, aesKey, aesIV) {
	return crypt(buffer, aesKey, aesIV, true);
};

const decrypt = function(buffer, aesKey, aesIV) {
	return crypt(buffer, aesKey, aesIV, false);
};

function crypt(buffer, aesKey, aesIV, isEncrypt) {
	const key = forge.util.createBuffer(aesKey);
	var cipher;
	if (isEncrypt) {
		cipher = forge.cipher.createCipher('AES-ECB', key);
		cipher.mode.pad = false;
		cipher.start();
	} else {
		cipher = forge.cipher.createDecipher('AES-ECB', key);
		cipher.mode.unpad = false;
		cipher.start();
	}

	var result = new Uint8Array(new ArrayBuffer(buffer.length));

	var prevTop, prevBottom;

	if (isEncrypt) {
		prevTop = aesIV.slice(0, 16);
		prevBottom = aesIV.slice(16, 32);
	} else {
		prevTop = aesIV.slice(16, 32);
		prevBottom = aesIV.slice(0, 16);
	}

	var current = new Uint8Array(new ArrayBuffer(16));

	for (let offset = 0; offset < buffer.length; offset += 16) {
		current.set(buffer.slice(offset, offset + 16), 0)

		xorBuffer(current, prevTop);

		cipher.update(forge.util.createBuffer(current));
		let crypted = Uint8Array.from(bytesFromHex(cipher.output.toHex().slice(-32)));

		xorBuffer(crypted, prevBottom);

		result.set(crypted, offset);

		prevTop = crypted;
		prevBottom = buffer.slice(offset, offset + 16);
	}
	cipher.finish();
	return result;
}

function xorBuffer(buffer, xor) {
	for (let i = 0; i < buffer.length; i++) {
		buffer[i] = buffer[i] = buffer[i] ^ xor[i];
	}
}

module.exports = { encrypt, decrypt };
