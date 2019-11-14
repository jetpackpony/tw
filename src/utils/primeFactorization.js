const bigInt = require('big-integer');

const rand = (min, max) => {
  return Math.floor(Math.random() * (max - min) + min);
};

// Input is bigInt already
const factorize = (n) => {
  if (n.mod(2).toJSNumber() === 0) return 2;

  let y = bigInt(rand(1, 1000));
  let c = bigInt(rand(1, 1000));
  let m = bigInt(rand(1, 1000));

  let g = bigInt(1);
  let r = bigInt(1);
  let q = bigInt(1);

  let x = bigInt(0);
  let ys = bigInt(0);

  while(g.eq(1)) {
    x = y;
    for (let i = bigInt(1); i.compare(r) <= 0; i = i.next()) {
      y = y.square().mod(n).add(c).mod(n);
    }
    k = bigInt(0);

    while(k.compare(r) < 0 && g.eq(1)) {
      ys = y;
      let mrkMin = bigInt.min(m, r.minus(k));
      for (let i = bigInt(1); i.compare(mrkMin) <= 0; i = i.next()) {
        y = y.square().mod(n).add(c).mod(n);
        q = q.multiply(x.minus(y).abs()).mod(n);
      }
      g = bigInt.gcd(q, n);
      k = k.add(m);
    }
    r = r.multiply(2);
  }

  if (g.eq(n)) {
    while(true) {
      ys = ys.square().mod(n).add(c).mod(n);
      g = bigInt.gcd(x.minus(ys).abs(), n);
      if (g.compare(1) > 0) {
        break;
      }
    }
  }

  const o = n.divide(g);
  return (g.compare(o) < 0) ? [g, o] : [o, g];
};

module.exports = { factorize };