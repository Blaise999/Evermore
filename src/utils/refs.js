function randomDigits(n = 8) {
  let out = "";
  for (let i = 0; i < n; i++) out += Math.floor(Math.random() * 10);
  return out;
}

function randomBase32(n = 10) {
  const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  let s = "";
  for (let i = 0; i < n; i++) s += alphabet[Math.floor(Math.random() * alphabet.length)];
  return s;
}

function makeHospitalId() {
  // EVR-XXXXXXXX
  return `EVR-${randomDigits(8)}`;
}

function makeRequestRef(prefix = "PMT") {
  // PMT-XXXX-XXXX-XXXX
  const a = randomBase32(4);
  const b = randomBase32(4);
  const c = randomBase32(4);
  return `${prefix}-${a}-${b}-${c}`;
}

module.exports = { makeHospitalId, makeRequestRef };
