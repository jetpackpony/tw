const aesjs = require('aes-js');
const { bytesFromHex } = require('../primeFactorization');

const encrypt = async (buffer, aesKey, aesIV) => {
	return crypt(buffer, aesKey, aesIV, true);
};

const decrypt = async (buffer, aesKey, aesIV) => {
	return crypt(buffer, aesKey, aesIV, false);
};

function crypt(buffer, aesKey, aesIV, isEncrypt) {
	const cipher = new aesjs.ModeOfOperation.ecb(aesKey);

	const result = new Uint8Array(new ArrayBuffer(buffer.length));
	let prevTop, prevBottom;

	if (isEncrypt) {
		prevTop = aesIV.slice(0, 16);
		prevBottom = aesIV.slice(16, 32);
	} else {
		prevTop = aesIV.slice(16, 32);
		prevBottom = aesIV.slice(0, 16);
	}

	const current = new Uint8Array(new ArrayBuffer(16));

	for (let offset = 0; offset < buffer.length; offset += 16) {
		current.set(buffer.slice(offset, offset + 16), 0)

		xorBuffer(current, prevTop);

		const crypted = (isEncrypt) ? cipher.encrypt(current) : cipher.decrypt(current);

		xorBuffer(crypted, prevBottom);

		result.set(crypted, offset);

		prevTop = crypted;
		prevBottom = buffer.slice(offset, offset + 16);
	}
	return result;
}

function xorBuffer(buffer, xor) {
	for (let i = 0; i < buffer.length; i++) {
		buffer[i] = buffer[i] = buffer[i] ^ xor[i];
	}
}

module.exports = { encrypt, decrypt };
