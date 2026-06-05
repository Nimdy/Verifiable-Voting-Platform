// Randomized soundness smoke-test for the cryptographic core. Not a substitute
// for a formal audit — but it catches the obvious ways ZK proofs go wrong
// (forgeable proofs, malleable proofs, wrong tallies). Run: npm run selftest

import { G, N, ZERO, mod, mul, randScalar } from './group.js';
import {
  addCiphertexts, combinePublicKey, decryptionShare, discreteLog, encrypt, trusteeKeygen,
} from './elgamal.js';
import { proveBit, verifyBit, proveDecryption, verifyDecryption } from './proofs.js';

let pass = 0;
let fail = 0;
const check = (cond: boolean, msg: string): void => {
  if (cond) pass++;
  else { fail++; console.log('  ❌ FAIL:', msg); }
};
const bit = (): 0 | 1 => (Math.random() < 0.5 ? 0 : 1);

const trustees = [1, 2, 3].map((i) => trusteeKeygen(i, randScalar()));
const h = combinePublicKey(trustees.map((t) => t.pub));

// 1. Every honest 0/1 ballot verifies.
for (let i = 0; i < 300; i++) {
  const m = bit();
  const r = randScalar();
  const ct = encrypt(h, BigInt(m), r);
  check(verifyBit(h, ct, proveBit(h, ct, m, r)), 'honest 0/1 ballot must verify');
}

// 2. Out-of-range votes can NEVER be passed off as 0 or 1 (anti-stuffing).
for (let i = 0; i < 300; i++) {
  const m = BigInt(2 + Math.floor(Math.random() * 1000));
  const r = randScalar();
  const ct = encrypt(h, m, r);
  check(!verifyBit(h, ct, proveBit(h, ct, 0, r)), 'illegal vote faked as 0 must fail');
  check(!verifyBit(h, ct, proveBit(h, ct, 1, r)), 'illegal vote faked as 1 must fail');
}

// 3. Any single-bit mutation of a valid proof must break it (non-malleability).
for (let i = 0; i < 200; i++) {
  const m = bit();
  const r = randScalar();
  const ct = encrypt(h, BigInt(m), r);
  const p = proveBit(h, ct, m, r);
  check(!verifyBit(h, ct, { ...p, s0: mod(p.s0 + 1n, N) }), 'mutated s0 must fail');
  check(!verifyBit(h, ct, { ...p, c0: mod(p.c0 + 1n, N) }), 'mutated c0 must fail');
  check(!verifyBit(h, ct, { ...p, T1g: p.T1g.add(G) }), 'mutated commitment must fail');
  // Non-canonical scalar encodings (≥ N) must now be rejected (was malleable).
  check(!verifyBit(h, ct, { ...p, c0: p.c0 + N }), 'non-canonical c0 (+N) must be rejected');
  check(!verifyBit(h, ct, { ...p, s1: p.s1 + N }), 'non-canonical s1 (+N) must be rejected');
}

// 4. Homomorphic tally equals the plaintext sum, for random electorates/trustees.
for (let trial = 0; trial < 100; trial++) {
  const n = 1 + Math.floor(Math.random() * 5);
  const ts = Array.from({ length: n }, (_, i) => trusteeKeygen(i + 1, randScalar()));
  const pk = combinePublicKey(ts.map((t) => t.pub));
  const k = 1 + Math.floor(Math.random() * 12);
  const votes = Array.from({ length: k }, () => bit());
  const cts = votes.map((v) => encrypt(pk, BigInt(v), randScalar()));
  const agg = addCiphertexts(cts);
  const D = ts.map((t) => decryptionShare(agg.a, t.secret)).reduce((acc, s) => acc.add(s), ZERO);
  const tally = discreteLog(agg.b.subtract(D), k);
  check(tally === votes.filter((v) => v === 1).length, `tally mismatch (trial ${trial})`);
}

// 5. Decryption proofs: honest verifies; wrong share or forged proof rejected.
for (let i = 0; i < 200; i++) {
  const x = randScalar();
  const pub = mul(G, x);
  const a = mul(G, randScalar());
  const share = mul(a, x);
  check(verifyDecryption(a, pub, share, proveDecryption(a, pub, share, x)), 'honest decryption verifies');
  const wrong = share.add(G);
  check(!verifyDecryption(a, pub, wrong, proveDecryption(a, pub, wrong, x)), 'cannot prove a wrong share');
}

console.log(`\nself-test: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
