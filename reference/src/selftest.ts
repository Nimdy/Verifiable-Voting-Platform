// Randomized soundness smoke-test for the cryptographic core. Not a substitute
// for a formal audit — but it catches the obvious ways ZK proofs go wrong
// (forgeable proofs, malleable proofs, wrong tallies). Run: npm run selftest

import { G, N, ZERO, mod, mul, randScalar, scalarTo32, invMod } from './group.js';
import {
  addCiphertexts, combinePublicKey, decryptionShare, discreteLog, encrypt, trusteeKeygen,
} from './elgamal.js';
import {
  proveBit, verifyBit, proveDecryption, verifyDecryption, proveSumOne, verifySumOne,
} from './proofs.js';
import { issueCredential, sign, verifySig } from './credentials.js';
import {
  setupKeys, runElection, encryptSelection, auditSelection, type Voter,
} from './election.js';
import { dkg, combineShares, verificationKeyAt } from './threshold.js';
import { newSession, prepareBallot, challengeBallot, castBallot } from './session.js';
import { verifyTranscript } from './verify.js';

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

// 6. Credential signatures: honest verifies; wrong message, wrong key, and any mutation rejected.
for (let i = 0; i < 200; i++) {
  const cred = issueCredential();
  const msg = scalarTo32(randScalar());
  const sig = sign(cred.secret, msg);
  check(verifySig(cred.pub, msg, sig), 'honest signature verifies');
  check(!verifySig(cred.pub, scalarTo32(randScalar()), sig), 'signature over wrong message rejected');
  check(!verifySig(issueCredential().pub, msg, sig), 'signature under wrong key rejected');
  check(!verifySig(cred.pub, msg, { R: sig.R, s: mod(sig.s + 1n, N) }), 'mutated s rejected');
  check(!verifySig(cred.pub, msg, { R: sig.R.add(G), s: sig.s }), 'mutated R rejected');
}

// 7. Multi-candidate selections: honest verifies; over/under-votes and tampering rejected.
for (let i = 0; i < 150; i++) {
  const K = 2 + Math.floor(Math.random() * 5); // 2..6 candidates
  const choice = Math.floor(Math.random() * K);
  const { selection, randomness } = encryptSelection(h, choice, K);
  const bitsOk = selection.enc.every((ct, j) => verifyBit(h, ct, selection.bitProofs[j]!));
  check(bitsOk, 'all candidate bit-proofs verify');
  check(verifySumOne(h, addCiphertexts(selection.enc), selection.sumProof), 'exactly-one proof verifies');
  check(auditSelection(h, selection, randomness, choice), 'Benaloh audit passes for the real choice');
  check(!auditSelection(h, selection, randomness, (choice + 1) % K), 'Benaloh audit fails for a different choice');

  // Overvote: select two candidates → sum is 2 → exactly-one proof must fail.
  const enc = [], rs: bigint[] = [];
  for (let j = 0; j < K; j++) {
    const v: 0 | 1 = j < 2 ? 1 : 0;
    const r = randScalar();
    enc.push(encrypt(h, BigInt(v), r)); rs.push(r);
  }
  const R = rs.reduce((a, b) => mod(a + b, N), 0n);
  check(!verifySumOne(h, addCiphertexts(enc), proveSumOne(h, addCiphertexts(enc), R)), 'overvote (sum=2) rejected');

  // Undervote: select none → sum is 0 → exactly-one proof must fail.
  const z = Array.from({ length: K }, () => { const r = randScalar(); return { ct: encrypt(h, 0n, r), r }; });
  const Rz = z.reduce((a, b) => mod(a + b.r, N), 0n);
  check(!verifySumOne(h, addCiphertexts(z.map((x) => x.ct)), proveSumOne(h, addCiphertexts(z.map((x) => x.ct)), Rz)), 'undervote (sum=0) rejected');

  // Mutated exactly-one proof rejected.
  const sp = selection.sumProof;
  check(!verifySumOne(h, addCiphertexts(selection.enc), { ...sp, s: mod(sp.s + 1n, N) }), 'mutated sum proof rejected');
}

// 8. End-to-end multi-candidate elections verify and report the true counts.
for (let trial = 0; trial < 20; trial++) {
  const K = 2 + Math.floor(Math.random() * 4);
  const candidates = Array.from({ length: K }, (_, j) => `c${j}`);
  const nVoters = 1 + Math.floor(Math.random() * 10);
  const n = 1 + Math.floor(Math.random() * 4);
  const k = 1 + Math.floor(Math.random() * n);
  const keys = setupKeys(n, k);
  const roll = Array.from({ length: nVoters }, () => issueCredential());
  const choices = Array.from({ length: nVoters }, () => Math.floor(Math.random() * K));
  const voters: Voter[] = roll.map((credential, i) => ({ credential, choice: choices[i]! }));
  const t = runElection('c', candidates, voters, keys, roll.map((c) => c.pub));
  const r = verifyTranscript(t);
  check(r.ok, `end-to-end election verifies (trial ${trial})`);
  const expected = candidates.map((_, j) => choices.filter((c) => c === j).length);
  check(JSON.stringify(t.results) === JSON.stringify(expected), `tallies match plaintext (trial ${trial})`);
}

// 9. Verifier robustness: malformed transcripts REJECT (never throw); audits check proofs; range guards.
{
  const K = 3;
  const cands = ['a', 'b', 'c'];
  const keys = setupKeys(3, 2);
  const roll = [issueCredential(), issueCredential(), issueCredential()];
  const voters: Voter[] = roll.map((credential, i) => ({ credential, choice: i % K }));
  const base = runElection('e', cands, voters, keys, roll.map((c) => c.pub));

  const noThrow = (fn: () => boolean): boolean | 'threw' => { try { return fn(); } catch { return 'threw'; } };

  check(noThrow(() => verifyTranscript({ ...base, aggregates: base.aggregates.slice(0, K - 1) }).ok) === false,
    'verifier rejects truncated aggregates without throwing');

  const shortBallots = base.ballots.map((b, i) => i === 0
    ? { ...b, selection: { ...b.selection, enc: b.selection.enc.slice(0, K - 1), bitProofs: b.selection.bitProofs.slice(0, K - 1) } }
    : b);
  check(noThrow(() => verifyTranscript({ ...base, ballots: shortBallots }).ok) === false,
    'verifier rejects a short ballot (K mismatch) without throwing');

  check(noThrow(() => verifyTranscript({ ...base, decShares: base.decShares.map((d) => ({ ...d, shares: d.shares.slice(0, 1) })) }).ok) === false,
    'verifier rejects truncated decryption shares without throwing');

  let rangeThrew = false;
  try { encryptSelection(base.publicKey, 99, K); } catch { rangeThrew = true; }
  check(rangeThrew, 'encryptSelection rejects an out-of-range choice');

  const good = encryptSelection(base.publicKey, 1, K);
  check(auditSelection(base.publicKey, good.selection, good.randomness, 1), 'audit passes for a fully valid ballot');
  const corrupt = { ...good.selection, bitProofs: good.selection.bitProofs.map((p, j) => (j === 0 ? { ...p, s0: mod(p.s0 + 1n, N) } : p)) };
  check(!auditSelection(base.publicKey, corrupt, good.randomness, 1), 'audit fails when a bit proof is invalid');

  const oor = { ...base, decShares: base.decShares.map((d, i) => (i === 0 ? { ...d, trusteeIndex: 999 } : d)) };
  check(noThrow(() => verifyTranscript(oor).ok) === false, 'verifier rejects an out-of-range trustee index');

  let invThrew = false;
  try { invMod(0n); } catch { invThrew = true; }
  check(invThrew, 'invMod(0) throws');
}

// 10. Threshold k-of-n: ANY k of n trustees decrypt; fewer than k cannot; verification
//     keys recompute from the public commitments.
for (let trial = 0; trial < 40; trial++) {
  const n = 2 + Math.floor(Math.random() * 4); // 2..5
  const k = 1 + Math.floor(Math.random() * n); // 1..n
  const keys = dkg(n, k);
  const m = BigInt(Math.floor(Math.random() * 5));
  const ct = encrypt(keys.publicKey, m, randScalar());
  const idx = keys.trustees.map((t) => t.index);
  const shuffled = [...idx].sort(() => Math.random() - 0.5);

  // verification keys recompute from commitments
  for (const tr of keys.trustees) {
    check(verificationKeyAt(keys.commitments, tr.index).equals(tr.verificationKey), 'verification key recomputed from commitments');
  }

  // any k of n decrypt correctly
  const pick = (set: number[]) => set.map((i) => {
    const tr = keys.trustees.find((t) => t.index === i)!;
    return { index: i, d: decryptionShare(ct.a, tr.share) };
  });
  const Dk = combineShares(pick(shuffled.slice(0, k)));
  let dec = -1; try { dec = discreteLog(ct.b.subtract(Dk), 5); } catch { /* not found */ }
  check(dec === Number(m), `any ${k} of ${n} trustees decrypt correctly (trial ${trial})`);

  // fewer than k must NOT recover the plaintext
  if (k > 1) {
    const Dless = combineShares(pick(shuffled.slice(0, k - 1)));
    let decLess = -1; try { decLess = discreteLog(ct.b.subtract(Dless), 5); } catch { decLess = -1; }
    check(decLess !== Number(m), `${k - 1} of ${n} trustees do NOT recover the plaintext (trial ${trial})`);
  }
}

// 11. Cast-or-challenge (Benaloh) session: spoiled ballots can't be cast; audits catch a lying device.
{
  const K = 3;
  const s = newSession();
  const p = prepareBallot(h, 1, K);
  check(challengeBallot(s, h, p, 1), 'challenge audits an honest ballot');
  let blocked = false; try { castBallot(s, p); } catch { blocked = true; }
  check(blocked, 'cannot cast a spoiled (challenged) ballot');
  const p2 = prepareBallot(h, 1, K);
  check(castBallot(s, p2) === p2.selection, 'a fresh ballot casts');
  let dup = false; try { castBallot(s, p2); } catch { dup = true; }
  check(dup, 'cannot cast the same ballot twice');
  const lying = prepareBallot(h, 0, K); // device secretly encrypted candidate 0
  check(!challengeBallot(newSession(), h, lying, 1), 'audit catches a device that encrypted a different candidate');
}

console.log(`\nself-test: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
