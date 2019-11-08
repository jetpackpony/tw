const { eGCD_, greater, divide_, str2bigInt, equalsInt,
  isZero, bigInt2str, copy_, copyInt_, rightShift_,
  leftShift_, sub_, add_, powMod, bpe, one } = require('leemon');

const minSize = Math.ceil(64 / bpe) + 1;

function bytesToHex(bytes = []) {
  const arr = []
  for (let i = 0; i < bytes.length; i++) {
    arr.push((bytes[i] < 16 ? '0' : '') + (bytes[i] || 0).toString(16))
  }
  return arr.join('')
}

function bytesFromHex(hexString) {
  const len = hexString.length
  let start = 0
  const bytes = []

  if (hexString.length % 2) {
    bytes.push(parseInt(hexString.charAt(0), 16))
    start++
  }

  for (let i = start; i < len; i += 2) {
    bytes.push(parseInt(hexString.substr(i, 2), 16))
  }

  return bytes
}

function bytesFromLeemonBigInt(bigInt) {
  const str = bigInt2str(bigInt, 16)
  return bytesFromHex(str)
}

function pqPrimeFactorization(pqBytes) {
  // const what = new BigInteger(pqBytes)
  const hex = bytesToHex(pqBytes)
  const lWhat = str2bigInt(hex, 16, minSize)
  const result = pqPrimeLeemon(lWhat)
  return result
}

function nextRandomInt(maxValue) {
  return Math.floor(Math.random() * maxValue)
}

function pqPrimeLeemon(what) {
  let it = 0
  let q, lim
  const a = new Array(minSize)
  const b = new Array(minSize)
  const c = new Array(minSize)
  const g = new Array(minSize)
  const z = new Array(minSize)
  const x = new Array(minSize)
  const y = new Array(minSize)

  for (let i = 0; i < 3; i++) {
    q = (nextRandomInt(128) & 15) + 17
    copyInt_(x, nextRandomInt(1000000000) + 1)
    copy_(y, x)
    lim = 1 << i + 18

    for (let j = 1; j < lim; j++) {
      ++it
      copy_(a, x)
      copy_(b, x)
      copyInt_(c, q)

      while (!isZero(b)) {
        if (b[0] & 1) {
          add_(c, a)
          if (greater(c, what)) {
            sub_(c, what)
          }
        }
        add_(a, a)
        if (greater(a, what)) {
          sub_(a, what)
        }
        rightShift_(b, 1)
      }

      copy_(x, c)
      if (greater(x, y)) {
        copy_(z, x)
        sub_(z, y)
      } else {
        copy_(z, y)
        sub_(z, x)
      }
      eGCD_(z, what, g, a, b)
      if (!equalsInt(g, 1)) {
        break
      }
      if ((j & j - 1) === 0) {
        copy_(y, x)
      }
    }
    if (greater(g, one)) {
      break
    }
  }

  divide_(what, g, x, y)

  const [P, Q] =
    greater(g, x)
      ? [x, g]
      : [g, x]

  // console.log(dT(), 'done', bigInt2str(what, 10), bigInt2str(P, 10), bigInt2str(Q, 10))

  return [bytesFromLeemonBigInt(P), bytesFromLeemonBigInt(Q), it]
}

module.exports = {
  pqPrimeFactorization,
  bytesToHex,
  bytesFromHex
};