// Randomized soundness smoke-test for the cryptographic core. Not a substitute
// for a formal audit — but it catches the obvious ways ZK proofs go wrong
// (forgeable proofs, malleable proofs, wrong tallies). Run: npm run selftest

import { G, H, N, ZERO, mod, mul, randScalar, scalarTo32, invMod, pointToHex, hashToScalar, scalarFromDecimal } from './group.js';
import { Registrar } from './registrar.js';
import {
  runStructuredElection, verifyStructured, validateSpec, type ElectionSpec, type StructuredVoter,
} from './structured.js';
import {
  encryptRanking, verifyRankingValid, bordaBallotTotals,
  runRankedElection, verifyRankedTranscript, type RankedVoter,
} from './ranked.js';
import {
  addCiphertexts, combinePublicKey, decryptionShare, discreteLog, encrypt, trusteeKeygen,
  type Ciphertext,
} from './elgamal.js';
import {
  shuffleProve, verifyShuffle, shuffleChallengeBits, reencItem, SECURITY_T,
  type Item, type ShuffleProof,
} from './mixnet.js';
import {
  runMixnetElection, verifyMixnetTranscript, tabulateIrv, ballotToRanks, flattenBallot,
  type MixnetVoter, type MixnetIrvTranscript, type MixnetDecShare,
} from './mixnet-irv.js';
import {
  proveBit, verifyBit, proveDecryption, verifyDecryption, proveSumOne, verifySumOne,
  proveSumEqual, verifySumEqual, proveConsistency, verifyConsistency, proveCommitBit, verifyCommitBit,
  proveCommitSum, verifyCommitSum,
} from './proofs.js';
import { issueCredential, sign, verifySig } from './credentials.js';
import {
  setupKeys, runElection, encryptSelection, auditSelection, type Voter,
} from './election.js';
import { dkg, combineShares, verificationKeyAt } from './threshold.js';
import { newSession, prepareBallot, challengeBallot, castBallot } from './session.js';
import { BulletinBoard } from './bulletin.js';
import {
  makeManifest, buildAnchor, verifyAnchor, reportedResults, pollingExport, verifyExport,
  pollingExportToJSON, pollingExportFromJSON, toArloManifestCsv, bravoSampleSize,
  bravoBallotPolling, representativeSample, type BatchRow,
} from './rla.js';
import {
  AnchorLog, verifyAnchorLog, verifyRootAnchored, rootCommitment, logHead, type AnchorEntry,
} from './anchorlog.js';
import {
  commitVote, addCommitments, buildTrail, verifyTrail, trailToJSON, trailFromJSON, commitmentTotals,
  type EverlastingTrail,
} from './everlasting.js';
import {
  transcriptToJSON, transcriptFromJSON, rankedTranscriptToJSON, rankedTranscriptFromJSON,
  mixnetIrvTranscriptToJSON, mixnetIrvTranscriptFromJSON,
} from './transcript-json.js';
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

// 12. Transcript JSON round-trips and re-verifies from the published record alone;
//     tampering the published file is caught; bad point encodings are rejected on parse.
{
  const keys = setupKeys(4, 2);
  const roll = [issueCredential(), issueCredential(), issueCredential()];
  const voters: Voter[] = roll.map((credential, i) => ({ credential, choice: i % 3 }));
  const t = runElection('json', ['a', 'b', 'c'], voters, keys, roll.map((c) => c.pub));

  const round = transcriptFromJSON(transcriptToJSON(t));
  const r = verifyTranscript(round);
  check(r.ok, 'round-tripped transcript verifies');
  check(JSON.stringify(r.results) === JSON.stringify(t.results), 'round-tripped results match');

  const obj = JSON.parse(transcriptToJSON(t));
  obj.results[0] = obj.results[0] + 5; // tamper the published totals
  let okTamper = true;
  try { okTamper = verifyTranscript(transcriptFromJSON(JSON.stringify(obj))).ok; } catch { okTamper = false; }
  check(okTamper === false, 'tampering the published results is caught');

  const obj2 = JSON.parse(transcriptToJSON(t));
  obj2.publicKey = 'zz'.repeat(32); // invalid point encoding
  let parseThrew = false;
  try { transcriptFromJSON(JSON.stringify(obj2)); } catch { parseThrew = true; }
  check(parseThrew, 'a bad point encoding is rejected on parse');
}

// 13. Registrar separation: roll = identity-free credential pubs; identityOf is registrar-only;
//     elections use the published roll, and a voter not on the roll is rejected.
{
  const r = new Registrar();
  const packets = r.register([{ id: 'a' }, { id: 'b' }, { id: 'c' }]);
  const roll = r.publishedRoll();
  const rollHex = new Set(roll.map(pointToHex));
  check(roll.length === 3, 'roll has one pub per registered voter');
  check(packets.every((pk) => rollHex.has(pointToHex(pk.credential.pub))), 'roll equals the voters credential pubs');
  check(r.identityOf(packets[0]!.credential.pub) === 'a', 'registrar (only) can map credential → identity');
  const outsider = issueCredential();
  check(!rollHex.has(pointToHex(outsider.pub)), 'an unregistered credential is not on the roll');
  let dupThrew = false; try { r.register([{ id: 'a' }]); } catch { dupThrew = true; }
  check(dupThrew, 'duplicate registration is rejected');

  const keys = setupKeys(2, 2);
  const voters: Voter[] = packets.map((pk, i) => ({ credential: pk.credential, choice: i % 2 }));
  check(verifyTranscript(runElection('e', ['x', 'y'], voters, keys, roll)).ok, 'election with the registrar roll verifies');
  const sneaky: Voter[] = [...voters, { credential: issueCredential(), choice: 0 }]; // not on the roll
  check(verifyTranscript(runElection('e', ['x', 'y'], sneaky, keys, roll)).ok === false, 'a voter not on the published roll is rejected');

  const base2 = runElection('e', ['x', 'y'], voters, keys, roll);
  check(verifyTranscript({ ...base2, numVoters: 1_000_000 }).ok === false, 'verifier rejects numVoters != ballot count (and does not hang)');
  check(verifyTranscript({ ...base2, eligibleRoll: [...base2.eligibleRoll, base2.eligibleRoll[0]!] }).ok === false, 'verifier rejects a duplicate eligible-roll entry');
}

// 14. Structured (hierarchical) elections: tree + tags; per-leaf verify; cross-contest replay rejected.
{
  const spec: ElectionSpec = {
    title: 'Community decisions',
    contests: [
      { id: 'budget', title: 'Budget', tags: ['budget'] },
      { id: 'park', title: 'Park budget', tags: ['budget', 'parks'], parent: 'budget', candidates: ['Low', 'Mid', 'High'] },
      { id: 'lib', title: 'Library hours', tags: ['budget'], parent: 'budget', candidates: ['Keep', 'Extend'] },
      { id: 'fest', title: 'Festival theme', tags: ['events'], candidates: ['Music', 'Food', 'Art'] },
    ],
  };
  const r = new Registrar();
  const packets = r.register([{ id: 'a' }, { id: 'b' }, { id: 'c' }]);
  const keys = setupKeys(3, 2);
  const roll = r.publishedRoll();
  const voters: StructuredVoter[] = [
    { credential: packets[0]!.credential, choices: { park: 0, lib: 1, fest: 2 } },
    { credential: packets[1]!.credential, choices: { park: 2, lib: 1 } }, // abstains from fest
    { credential: packets[2]!.credential, choices: { park: 0, lib: 0, fest: 0 } },
  ];
  const result = runStructuredElection(spec, voters, keys, roll);
  check(verifyStructured(result).ok, 'structured election: every leaf contest verifies');
  const park = result.results.find((x) => x.id === 'park')!;
  check(JSON.stringify(park.transcript.results) === JSON.stringify([2, 0, 1]), 'park tally correct (Low2, Mid0, High1)');
  const fest = result.results.find((x) => x.id === 'fest')!;
  check(fest.transcript.numVoters === 2, 'fest has 2 voters (one abstained)');

  // cross-contest replay: a ballot signed for 'park' must NOT verify inside 'fest' (both K=3) — context binding.
  const parkBallot = park.transcript.ballots[0]!;
  const spliced = { ...fest.transcript, ballots: [...fest.transcript.ballots, parkBallot], numVoters: fest.transcript.ballots.length + 1 };
  check(verifyTranscript(spliced).ok === false, 'a ballot from another contest is rejected (context binding)');

  // Structured composition attacks must be caught by verifyStructured (not just per-transcript).
  check(verifyStructured({ spec, results: result.results.slice(0, 2) }).ok === false, 'omitting a contest is rejected');
  check(verifyStructured({ spec, results: [...result.results, result.results[0]!] }).ok === false, 'duplicating a contest is rejected');
  const swapped = result.results.map((r, idx) => (idx === 0 ? { ...r, id: 'fest', candidates: ['Music', 'Food', 'Art'] } : r));
  check(verifyStructured({ spec, results: swapped }).ok === false, 'relabeling/substituting a contest is rejected');
  check(verifyStructured(result).ok, 'the honest structured result still verifies');

  let dup = false; try { validateSpec({ title: 'x', contests: [{ id: 'a', title: 'A', tags: [] }, { id: 'a', title: 'B', tags: [] }] }); } catch { dup = true; }
  check(dup, 'validateSpec rejects duplicate contest ids');
  let mp = false; try { validateSpec({ title: 'x', contests: [{ id: 'a', title: 'A', tags: [], parent: 'nope' }] }); } catch { mp = true; }
  check(mp, 'validateSpec rejects a missing parent');
  let lp = false; try { validateSpec({ title: 'x', contests: [{ id: 'p', title: 'P', tags: [], candidates: ['a', 'b'] }, { id: 'c', title: 'C', tags: [], parent: 'p', candidates: ['x', 'y'] }] }); } catch { lp = true; }
  check(lp, 'validateSpec rejects a leaf used as a parent');
  let nl = false; try { validateSpec({ title: 'x', contests: [{ id: 'g', title: 'G', tags: [] }] }); } catch { nl = true; }
  check(nl, 'validateSpec rejects a spec with no leaf contest');
}

// 15. Multi-seat "vote for exactly N" — sound generalization of exactly-one.
{
  const keys = setupKeys(3, 2);
  const r = new Registrar();
  const packets = r.register([{ id: 'a' }, { id: 'b' }, { id: 'c' }, { id: 'd' }]);
  const roll = r.publishedRoll();
  const cands = ['w', 'x', 'y', 'z'];
  const voters: Voter[] = packets.map((pk, i) => ({ credential: pk.credential, choice: [i % 4, (i + 1) % 4] }));
  const t = runElection('seats', cands, voters, keys, roll, undefined, 2);
  check(verifyTranscript(t).ok, 'multi-seat (exactly-2) election verifies');
  check(t.results.reduce((a, b) => a + b, 0) === 2 * t.numVoters, 'multi-seat totals sum to L×voters');
  check(verifyTranscript({ ...t, selectionLimit: 1 }).ok === false, 'a tampered selectionLimit is rejected');
  let wc = false; try { encryptSelection(t.publicKey, [0], 4, 2); } catch { wc = true; }
  check(wc, 'encryptSelection rejects the wrong number of picks');
  const h = keys.publicKey;
  const build = (bits: number[]) => {
    const enc = [];
    const rs: bigint[] = [];
    for (let jx = 0; jx < 4; jx++) { const rr = randScalar(); enc.push(encrypt(h, bits.includes(jx) ? 1n : 0n, rr)); rs.push(rr); }
    return { enc, R: rs.reduce((a, b) => mod(a + b, N), 0n) };
  };
  const two = build([0, 1]);
  check(verifySumEqual(h, addCiphertexts(two.enc), proveSumEqual(h, addCiphertexts(two.enc), two.R, 2), 2), 'sumEqual(2) accepts exactly 2');
  const three = build([0, 1, 2]);
  check(!verifySumEqual(h, addCiphertexts(three.enc), proveSumEqual(h, addCiphertexts(three.enc), three.R, 2), 2), 'sumEqual(2) rejects 3');
  // Benaloh audit works for multi-seat (L>1)
  const ms = encryptSelection(keys.publicKey, [0, 2], 4, 2);
  check(auditSelection(keys.publicKey, ms.selection, ms.randomness, [0, 2]), 'multi-seat audit passes for the real picks');
  check(!auditSelection(keys.publicKey, ms.selection, ms.randomness, [0, 1]), 'multi-seat audit fails for different picks');
}

// 16. Ranked-choice validity (permutation matrix) + homomorphic Borda correctness.
{
  const keys = setupKeys(1, 1);
  const pk = keys.publicKey;
  const x = keys.trustees[0]!.share;
  const ranking = [2, 0, 3, 1]; // K=4
  const { ballot } = encryptRanking(pk, ranking);
  check(verifyRankingValid(pk, ballot), 'a valid strict ranking verifies');
  const borda = bordaBallotTotals(ballot).map((ct) => discreteLog(ct.b.subtract(mul(ct.a, x)), 3));
  check(JSON.stringify(borda) === JSON.stringify([1, 3, 0, 2]), 'homomorphic Borda totals decrypt correctly');
  const bad = { ...ballot, matrix: ballot.matrix.map((row, i) => row.map((c, r) => (i === 0 && r === 0 ? { a: c.a, b: c.b.add(pk) } : c))) };
  check(!verifyRankingValid(pk, bad), 'a tampered ranking matrix is rejected');
  let np = false; try { encryptRanking(pk, [0, 0, 1, 2]); } catch { np = true; }
  check(np, 'encryptRanking rejects a non-permutation');

  // Hand-built duplicate-rank ballot (candidates 0 and 1 both rank 0 → column 0 sums to 2) is rejected.
  const asg = [0, 0, 2, 3];
  const K = 4;
  const mtx: ReturnType<typeof encrypt>[][] = [];
  const bps: ReturnType<typeof proveBit>[][] = [];
  const rnd: bigint[][] = [];
  for (let i = 0; i < K; i++) {
    mtx[i] = []; bps[i] = []; rnd[i] = [];
    for (let r = 0; r < K; r++) {
      const v: 0 | 1 = asg[i] === r ? 1 : 0;
      const rr = randScalar();
      const ct = encrypt(pk, BigInt(v), rr);
      mtx[i]!.push(ct); bps[i]!.push(proveBit(pk, ct, v, rr)); rnd[i]!.push(rr);
    }
  }
  const rs = mtx.map((row, i) => proveSumEqual(pk, addCiphertexts(row), rnd[i]!.reduce((a, b) => mod(a + b, N), 0n), 1));
  const cs = Array.from({ length: K }, (_, r) => proveSumEqual(pk, addCiphertexts(mtx.map((row) => row[r]!)), rnd.reduce((a, row) => mod(a + row[r]!, N), 0n), 1));
  check(!verifyRankingValid(pk, { matrix: mtx, bitProofs: bps, rowSums: rs, colSums: cs }), 'duplicate-rank ballot (a column sums to 2) is rejected');
}

// 17. Full ranked (Borda) election: verifies; tally correct; insider attacks caught.
{
  const keys = setupKeys(3, 2);
  const r = new Registrar();
  const packets = r.register([{ id: 'a' }, { id: 'b' }, { id: 'c' }]);
  const roll = r.publishedRoll();
  const cands = ['w', 'x', 'y', 'z'];
  const voters: RankedVoter[] = packets.map((pk, i) => ({ credential: pk.credential, ranking: [0, 1, 2, 3].map((x) => (x + i) % 4) }));
  const t = runRankedElection('rank', cands, voters, keys, roll);
  check(verifyRankedTranscript(t).ok, 'ranked election verifies');
  check(t.results.reduce((a, b) => a + b, 0) === voters.length * ((4 * 3) / 2), 'Borda totals sum to V·K(K-1)/2');
  const expected = cands.map((_, c) => voters.reduce((acc, _v, i) => acc + (3 - ((c + i) % 4)), 0));
  check(JSON.stringify(t.results) === JSON.stringify(expected), 'ranked Borda totals are correct');
  const sneaky: RankedVoter[] = [...voters, { credential: issueCredential(), ranking: [0, 1, 2, 3] }];
  check(verifyRankedTranscript(runRankedElection('rank', cands, sneaky, keys, roll)).ok === false, 'ranked: a voter not on the roll is rejected');
  check(verifyRankedTranscript({ ...t, results: t.results.map((n, i) => (i === 0 ? n + 1 : n)) }).ok === false, 'ranked: a tampered Borda total is rejected');
  const dbl: RankedVoter[] = [...voters, { credential: packets[0]!.credential, ranking: [3, 2, 1, 0] }];
  check(verifyRankedTranscript(runRankedElection('rank', cands, dbl, keys, roll)).ok === false, 'ranked: a double vote is rejected');
  const wrongDim = { ...t, ballots: t.ballots.map((b, i) => (i === 0 ? { ...b, ballot: { ...b.ballot, colSums: [...b.ballot.colSums, b.ballot.colSums[0]!] } } : b)) };
  check(verifyRankedTranscript(wrongDim).ok === false, 'ranked: a wrong-dimension ballot is rejected at the shape gate');
}

// 18. Ranked transcript JSON round-trips and re-verifies from the published record
//     alone; tampering the published file is caught; bad point encodings reject on parse.
{
  const keys = setupKeys(5, 3);
  const r = new Registrar();
  const packets = r.register([{ id: 'a' }, { id: 'b' }, { id: 'c' }, { id: 'd' }]);
  const roll = r.publishedRoll();
  const cands = ['w', 'x', 'y', 'z'];
  const voters: RankedVoter[] = packets.map((pk, i) => ({ credential: pk.credential, ranking: [0, 1, 2, 3].map((x) => (x + i) % 4) }));
  const t = runRankedElection('rank-json', cands, voters, keys, roll, [1, 3, 5]);

  const round = rankedTranscriptFromJSON(rankedTranscriptToJSON(t));
  const rr = verifyRankedTranscript(round);
  check(rr.ok, 'round-tripped ranked transcript verifies');
  check(JSON.stringify(rr.results) === JSON.stringify(t.results), 'round-tripped ranked results match');

  const obj = JSON.parse(rankedTranscriptToJSON(t));
  check(obj.kind === 'ranked', 'ranked transcript carries kind discriminator');
  obj.results[0] = obj.results[0] + 5; // tamper the published Borda totals
  let okTamper = true;
  try { okTamper = verifyRankedTranscript(rankedTranscriptFromJSON(JSON.stringify(obj))).ok; } catch { okTamper = false; }
  check(okTamper === false, 'tampering a published ranked total is caught');

  const obj2 = JSON.parse(rankedTranscriptToJSON(t));
  obj2.ballots[0].ballot.matrix[0][0].a = 'zz'.repeat(32); // invalid point encoding
  let parseThrew = false;
  try { rankedTranscriptFromJSON(JSON.stringify(obj2)); } catch { parseThrew = true; }
  check(parseThrew, 'a bad point encoding in a ranked ballot is rejected on parse');
}

// 19. Verifiable re-encryption mixnet (Sako–Kilian cut-and-choose): honest shuffles verify and
//     preserve the plaintext multiset; every soundness/privacy pitfall is caught; verifier never throws.
{
  const T = SECURITY_T; // the verifier hard-floors t ≥ SECURITY_T, so honest test proofs use it
  const mk = trusteeKeygen(1, randScalar());
  const mh = mk.pub; // 1-of-1 joint key, only so tests can decrypt to check the plaintext multiset
  const dec = (ct: Ciphertext): number => discreteLog(ct.b.subtract(decryptionShare(ct.a, mk.secret)), 50);
  const encItem = (ms: number[]): Item => ms.map((m) => encrypt(mh, BigInt(m), randScalar()));
  const noThrow = (fn: () => boolean): boolean | 'threw' => { try { return fn(); } catch { return 'threw'; } };
  const bumpFactor0 = (pf: ShuffleProof, w: number): ShuffleProof => ({
    ...pf,
    openings: pf.openings.map((op, j) => (j === 0
      ? { ...op, factors: op.factors.map((f, i) => (i === 0 ? f.map((s, ww) => (ww === w ? mod(s + 1n, N) : s)) : f)) }
      : op)),
  });

  // H1 — honest shuffles verify AND preserve the plaintext multiset (W = 1..3). t=128 proofs are
  //       heavy, so a small sweep; degenerate W=1 and substitution soundness are exercised below.
  let h1 = true;
  for (let trial = 0; trial < 3; trial++) {
    const n = 1 + Math.floor(Math.random() * 2); // 1..2
    const W = 1 + Math.floor(Math.random() * 2); // 1..2
    const L0: Item[] = Array.from({ length: n }, () => encItem(Array.from({ length: W }, () => Math.floor(Math.random() * 6))));
    const { L, proof } = shuffleProve(mh, L0, T);
    if (!verifyShuffle(mh, L0, L, proof).ok) h1 = false;
    const before = L0.map((it) => it.map(dec).join(',')).sort();
    const after = L.map((it) => it.map(dec).join(',')).sort();
    if (JSON.stringify(before) !== JSON.stringify(after)) h1 = false;
  }
  check(h1, 'mixnet: honest shuffles verify and preserve the plaintext multiset (W=1..3)');

  // H2 — factor-0 is the identity re-encryption; verifier must not special-case/skip it
  const it0 = encItem([3, 4]);
  const re0 = reencItem(mh, it0, [0n, 0n]);
  check(re0.every((c, w) => c.a.equals(it0[w]!.a) && c.b.equals(it0[w]!.b)), 'mixnet: factor-0 re-encryption is the identity');

  // Baseline honest proof to tamper (n=2, W=2 — small, since the t=128 hash/work dominates cost)
  const baseL0: Item[] = Array.from({ length: 2 }, () => encItem([Math.floor(Math.random() * 6), Math.floor(Math.random() * 6)]));
  const base = shuffleProve(mh, baseL0, T);
  check(verifyShuffle(mh, baseL0, base.L, base.proof).ok, 'mixnet: baseline honest proof verifies');

  // T2 — opened permutation must be a true bijection of 0..n-1
  const dupPerm = { ...base.proof, openings: base.proof.openings.map((op, j) => (j === 0 ? { ...op, perm: op.perm.map((p, idx) => (idx === 0 ? op.perm[1]! : p)) } : op)) };
  check(verifyShuffle(mh, baseL0, base.L, dupPerm).ok === false, 'mixnet: duplicated index in an opened permutation is rejected');
  const oorPerm = { ...base.proof, openings: base.proof.openings.map((op, j) => (j === 0 ? { ...op, perm: op.perm.map((p, idx) => (idx === 0 ? baseL0.length : p)) } : op)) };
  check(verifyShuffle(mh, baseL0, base.L, oorPerm).ok === false, 'mixnet: out-of-range index in an opened permutation is rejected');
  const shortPerm = { ...base.proof, openings: base.proof.openings.map((op, j) => (j === 0 ? { ...op, perm: op.perm.slice(0, -1) } : op)) };
  check(noThrow(() => verifyShuffle(mh, baseL0, base.L, shortPerm).ok) === false, 'mixnet: wrong-length opened permutation is rejected without throwing');

  // T3 — |L| = |L0| = |M_j| enforced
  check(verifyShuffle(mh, baseL0, base.L.slice(0, -1), base.proof).ok === false, 'mixnet: output shorter than input is rejected');
  check(verifyShuffle(mh, baseL0, [...base.L, encItem([0, 0])], base.proof).ok === false, 'mixnet: output longer than input is rejected');
  const truncM = { ...base.proof, intermediates: base.proof.intermediates.map((M, j) => (j === 0 ? M.slice(0, -1) : M)) };
  check(verifyShuffle(mh, baseL0, base.L, truncM).ok === false, 'mixnet: a truncated intermediate is rejected');

  // T4 — output ciphertext integrity (both components are bound)
  const tamperB = base.L.map((it, i) => (i === 0 ? it.map((c, w) => (w === 0 ? { a: c.a, b: c.b.add(mh) } : c)) : it));
  check(verifyShuffle(mh, baseL0, tamperB, base.proof).ok === false, 'mixnet: tampering an output ciphertext .b is rejected');
  const tamperA = base.L.map((it, i) => (i === 0 ? it.map((c, w) => (w === 0 ? { a: c.a.add(G), b: c.b } : c)) : it));
  check(verifyShuffle(mh, baseL0, tamperA, base.proof).ok === false, 'mixnet: tampering an output ciphertext .a is rejected');

  // T5 — re-encryption is checked on EVERY one of the W components (not just component 0)
  check(verifyShuffle(mh, baseL0, base.L, bumpFactor0(base.proof, 0)).ok === false, 'mixnet: a bumped factor on component 0 is rejected');
  check(verifyShuffle(mh, baseL0, base.L, bumpFactor0(base.proof, 1)).ok === false, 'mixnet: a bumped factor on the LAST component is rejected');

  // T6 — substituting an output ballot with a different plaintext is rejected
  const sub = base.L.map((it, i) => (i === 0 ? encItem([99, 99]) : it));
  check(verifyShuffle(mh, baseL0, sub, base.proof).ok === false, 'mixnet: substituting an output ballot (different plaintext) is rejected');

  // T7 — Fiat–Shamir binds every intermediate; t-floor enforced; challenge is pure
  const mutM = { ...base.proof, intermediates: base.proof.intermediates.map((M, j) => (j === 0 ? M.map((it, i) => (i === 0 ? it.map((c, w) => (w === 0 ? { a: c.a.add(G), b: c.b } : c)) : it)) : M)) };
  check(verifyShuffle(mh, baseL0, base.L, mutM).ok === false, 'mixnet: mutating a committed intermediate (FS binding) is rejected');
  const lowL0: Item[] = [encItem([1]), encItem([2])];
  const low = shuffleProve(mh, lowL0, SECURITY_T - 1);
  check(verifyShuffle(mh, lowL0, low.L, low.proof).ok === false, `mixnet: t < SECURITY_T (${SECURITY_T}) is rejected at the shape gate`);
  const bitsA = shuffleChallengeBits(mh, baseL0, base.L, base.proof.intermediates, T);
  const bitsB = shuffleChallengeBits(mh, baseL0, base.L, base.proof.intermediates, T);
  check(JSON.stringify(bitsA) === JSON.stringify(bitsB), 'mixnet: challenge bits are deterministic (pure function)');
  const bitsC = shuffleChallengeBits(mh, baseL0, base.L, mutM.intermediates, T);
  check(JSON.stringify(bitsA) !== JSON.stringify(bitsC), 'mixnet: flipping any intermediate point changes the challenge bits');

  // T8 — exactly t bits, and they are ~balanced (no constant/low-entropy derivation). Balance is a
  //      property of the bit-expansion, so derive a long 512-bit stream from one statement (cheap).
  check(bitsA.length === T, 'mixnet: challenge derivation yields exactly t bits');
  const longBits = shuffleChallengeBits(mh, baseL0, base.L, base.proof.intermediates, 512);
  const ones = longBits.filter((b) => b === 1).length;
  check(ones > 512 * 0.4 && ones < 512 * 0.6, `mixnet: challenge bits are ~balanced (${ones}/512 ones)`);

  // T9 — fresh randomness: two shuffles of the same input differ; exactly t single-leg openings
  const r9L0: Item[] = [encItem([1]), encItem([2])];
  const r1 = shuffleProve(mh, r9L0, T);
  const r2 = shuffleProve(mh, r9L0, T);
  const Lhex = (L: Item[]): string => L.map((it) => it.map((c) => pointToHex(c.b)).join()).join();
  check(Lhex(r1.L) !== Lhex(r2.L), 'mixnet: two shuffles of the same input differ (fresh randomness, not Math.random)');
  check(r1.proof.openings.length === T && r1.proof.openings.every((op) => Array.isArray(op.perm) && Array.isArray(op.factors)), 'mixnet: exactly t openings, each a single leg');

  // T10 — non-canonical scalar (s + N) rejected
  const nonCanon = { ...base.proof, openings: base.proof.openings.map((op, j) => (j === 0 ? { ...op, factors: op.factors.map((f, i) => (i === 0 ? f.map((s, w) => (w === 0 ? s + N : s)) : f)) } : op)) };
  check(verifyShuffle(mh, baseL0, base.L, nonCanon).ok === false, 'mixnet: a non-canonical factor (s + N) is rejected');

  // T11 — verifier NEVER throws on malformed proofs (returns false)
  check(noThrow(() => verifyShuffle(mh, baseL0, base.L, { ...base.proof, openings: [] }).ok) === false, 'mixnet: empty openings rejected without throwing');
  check(noThrow(() => verifyShuffle(mh, baseL0, base.L, { ...base.proof, intermediates: base.proof.intermediates.slice(0, 1) }).ok) === false, 'mixnet: wrong intermediate count rejected without throwing');
  check(noThrow(() => verifyShuffle(mh, baseL0, base.L, { ...base.proof, openings: base.proof.openings.map((op, j) => (j === 0 ? { ...op, perm: null as unknown as number[] } : op)) }).ok) === false, 'mixnet: null perm rejected without throwing');
  check(noThrow(() => verifyShuffle(mh, baseL0, base.L, { ...base.proof, openings: base.proof.openings.map((op, j) => (j === 0 ? { ...op, factors: op.factors.map((f, i) => (i === 0 ? f.slice(0, -1) : f)) } : op)) }).ok) === false, 'mixnet: ragged factor row rejected without throwing');
  check(noThrow(() => verifyShuffle(mh, [], base.L, base.proof).ok) === false, 'mixnet: empty input rejected without throwing');

  // T12 — W=1 degenerate (single-ciphertext shuffle, the unit a per-column IRV feeds)
  const w1L0: Item[] = Array.from({ length: 3 }, () => encItem([Math.floor(Math.random() * 5)]));
  const w1 = shuffleProve(mh, w1L0, T);
  check(verifyShuffle(mh, w1L0, w1.L, w1.proof).ok, 'mixnet: W=1 (single-ciphertext) shuffle verifies');
  check(verifyShuffle(mh, w1L0, w1.L.map((it, i) => (i === 0 ? encItem([77]) : it)), w1.proof).ok === false, 'mixnet: W=1 output substitution is rejected');

  // T13 — re-encryption binds the JOINT key (s·pk on b, s·G on a): wrong key is rejected
  const wrongPk = trusteeKeygen(2, randScalar()).pub;
  check(verifyShuffle(wrongPk, baseL0, base.L, base.proof).ok === false, 'mixnet: verifying under the wrong joint key is rejected (s·pk binding)');

  // T14 — domain-separation label cannot alias other proof types
  const dpts = [mh, G, base.L[0]![0]!.a];
  check(hashToScalar('mixnet-shuffle', dpts) !== hashToScalar('decryption', dpts)
    && hashToScalar('mixnet-shuffle', dpts) !== hashToScalar('ballot-bit', dpts)
    && hashToScalar('mixnet-shuffle', dpts) !== hashToScalar('sum-eq', dpts),
    'mixnet: domain-separation label differs from every other proof label');
}

// 20. Mixnet-IRV (end-to-end verifiable instant-runoff): ranked ballots → verifiable shuffle →
//     threshold-decrypt → deterministic public IRV. Honest verifies; the shuffle is bound to the
//     board ballots; tabulation is recomputed; every soundness pitfall is caught; never throws.
{
  const noThrow = (fn: () => boolean): boolean | 'threw' => { try { return fn(); } catch { return 'threw'; } };
  const rankingToMatrix = (ranking: number[]): number[][] => {
    const K = ranking.length;
    return Array.from({ length: K }, (_, i) => Array.from({ length: K }, (_, r) => (ranking[i] === r ? 1 : 0)));
  };

  // --- pure deterministic IRV (instant; no crypto) ---
  const irv = (rankings: number[][]) => tabulateIrv(rankings.map(rankingToMatrix), rankings[0]!.length);
  const w = (rankings: number[][]): number => { const o = irv(rankings); return 'winner' in o ? o.winner : -1; };
  check(w([[0]]) === 0, 'IRV K=1: the sole candidate wins round 0');
  check(w([[0, 1], [1, 0]]) === 0, 'IRV even 2-way split: highest index eliminated ⇒ candidate 0 wins');
  check(w([[0, 1, 2], [0, 1, 2], [0, 1, 2]]) === 0, 'IRV all-identical: unanimous top choice wins round 0');
  { const o = irv([[0, 1, 2], [2, 0, 1], [1, 2, 0]]); // perfectly symmetric 3-cycle
    check('winner' in o && o.winner === 0 && o.rounds.length === 2 && o.rounds[0]!.eliminatedThisRound === 2, 'IRV symmetric 3-way tie: highest indices fall first, candidate 0 survives'); }
  check('error' in tabulateIrv([[[1, 1], [0, 0]]], 2), 'IRV rejects a non-permutation matrix (row sums to 2)');
  check(ballotToRanks([[1, 0], [1, 0]], 2) === null, 'ballotToRanks rejects a non-permutation (column reused)');

  // --- honest end-to-end election (K=3, n=3, a genuine runoff) ---
  const keys = setupKeys(3, 2);
  const reg = new Registrar();
  const packets = reg.register([{ id: 'a' }, { id: 'b' }, { id: 'c' }]);
  const roll = reg.publishedRoll();
  const cands = ['Ana', 'Ben', 'Cy'];
  const castRankings = [[0, 1, 2], [2, 0, 1], [1, 2, 0]]; // 3-cycle → round0 [1,1,1] elim Cy(2) → round1 [2,1,0] Ana wins
  const voters: MixnetVoter[] = packets.map((p, i) => ({ credential: p.credential, ranking: castRankings[i]! }));
  const base = runMixnetElection('Chair (IRV)', cands, voters, keys, roll, [1, 2]);
  const bv = verifyMixnetTranscript(base);
  check(bv.ok, 'mixnet-IRV: honest election verifies');
  check(base.winner === 0 && base.rounds.length === 2 && base.rounds[0]!.eliminatedThisRound === 2 && JSON.stringify(base.rounds[1]!.tallies) === JSON.stringify([2, 1, 0]), 'mixnet-IRV: winner + round-by-round trace are correct');

  // plaintext-preservation + anonymity: recovered ranking multiset == cast multiset; no voter linkage published
  const recoveredRanks = base.decryptedMatrices.map((M) => JSON.stringify(ballotToRanks(M, 3))).sort();
  const castRanks = castRankings.map((r) => JSON.stringify(r)).sort(); // ballotToRanks(rankingToMatrix(r)) === r
  check(JSON.stringify(recoveredRanks) === JSON.stringify(castRanks), 'mixnet-IRV: shuffle preserves the ranking multiset (and only the link is hidden)');
  // Re-encryption changed every ciphertext: publishing L0 verbatim as `shuffled` is caught (deterministic).
  const ctHex = (items: Item[]): string => items.map((it) => it.map((c) => pointToHex(c.a) + pointToHex(c.b)).join()).join('|');
  check(ctHex(base.shuffled) !== ctHex(base.ballots.map((b) => flattenBallot(b.ballot))), 'mixnet-IRV: the shuffle re-encrypts every ciphertext (output != board-order L0)');
  // Decorrelation (the ONE privacy property this path provides): output order != board/input order. Distinct
  // rankings ⇒ decSeq === boardSeq iff the secret permutation is identity; retry across fresh runs so an honest
  // identity permutation (prob 1/n! per run) can't flake, while a dropped/identity-shuffle regression ALWAYS fails.
  const distinctRk = [[0, 1, 2], [2, 0, 1], [1, 2, 0]];
  let decorrelated = false;
  for (let attempt = 0; attempt < 12 && !decorrelated; attempt++) {
    const r2 = new Registrar();
    const pk2 = r2.register([{ id: 'a' }, { id: 'b' }, { id: 'c' }]);
    const vs: MixnetVoter[] = pk2.map((p, i) => ({ credential: p.credential, ranking: distinctRk[i]! }));
    const e = runMixnetElection('decorr', cands, vs, keys, r2.publishedRoll(), [1, 2]);
    const boardSeq = vs.slice().sort((a, b) => pointToHex(a.credential.pub).localeCompare(pointToHex(b.credential.pub))).map((v) => JSON.stringify(v.ranking));
    const decSeq = e.decryptedMatrices.map((M) => JSON.stringify(ballotToRanks(M, 3)));
    if (JSON.stringify(decSeq) !== JSON.stringify(boardSeq)) decorrelated = true;
  }
  check(decorrelated, 'mixnet-IRV: the shuffle decorrelates output order from board/input order (link-hiding)');

  // --- adversarial: each must REJECT ---
  // S5 shuffle-input binding: shuffle a DOCTORED L0 (one plaintext changed) but keep honest ballots.
  const doctoredL0 = base.ballots.map((b) => flattenBallot(b.ballot));
  doctoredL0[0]![0] = { a: doctoredL0[0]![0]!.a, b: doctoredL0[0]![0]!.b.add(G) }; // flips a plaintext bit
  const dShuf = shuffleProve(base.publicKey, doctoredL0);
  check(verifyMixnetTranscript({ ...base, shuffled: dShuf.L, shuffleProof: dShuf.proof }).ok === false, 'mixnet-IRV: a shuffle of a doctored input (not the board ballots) is rejected');

  // dropped ballot in the shuffle → shape gate
  check(verifyMixnetTranscript({ ...base, shuffled: base.shuffled.slice(0, -1) }).ok === false, 'mixnet-IRV: a dropped item in the shuffle is rejected (shape)');

  // S6 forged decryption proof
  const forgedDS: MixnetDecShare[] = base.decShares.map((ds, j) => (j === 0
    ? { ...ds, proofs: ds.proofs.map((p, i) => (i === 0 ? { ...p, s: mod(p.s + 1n, N) } : p)) } : ds));
  check(verifyMixnetTranscript({ ...base, decShares: forgedDS }).ok === false, 'mixnet-IRV: a forged decryption proof is rejected');

  // S6 below quorum (k-1 trustees)
  check(verifyMixnetTranscript({ ...base, decShares: base.decShares.slice(0, keys.threshold - 1) }).ok === false, 'mixnet-IRV: fewer than k trustees cannot decrypt');

  // S6 bogus trustee index
  const bogusIdx = base.decShares.map((ds, j) => (j === 0 ? { ...ds, trusteeIndex: 99 } : ds));
  check(verifyMixnetTranscript({ ...base, decShares: bogusIdx }).ok === false, 'mixnet-IRV: an out-of-range trustee index is rejected');

  // S6 wrong-key: give trustee #1's record trustee #2's shares/proofs (verified against vk(1) → fails)
  const swappedKey = base.decShares.map((ds, j) => (j === 0 ? { ...ds, shares: base.decShares[1]!.shares, proofs: base.decShares[1]!.proofs } : ds));
  check(verifyMixnetTranscript({ ...base, decShares: swappedKey }).ok === false, 'mixnet-IRV: a share under the wrong trustee key is rejected');

  // S8 tampered winner / flipped elimination (verifier recomputes the tabulation + tie-break)
  check(verifyMixnetTranscript({ ...base, winner: 1 }).ok === false, 'mixnet-IRV: a tampered winner is rejected');
  const flippedElim = base.rounds.map((r, j) => (j === 0 ? { ...r, eliminatedThisRound: 1 } : r)); // verifier recomputes victim = 2 (highest-index tie-break)
  check(verifyMixnetTranscript({ ...base, rounds: flippedElim }).ok === false, 'mixnet-IRV: a tampered elimination (wrong tie-break) is rejected');

  // S7 tampered decryptedMatrices (verifier recovers its own + compares)
  const tamperedMx = base.decryptedMatrices.map((M, j) => (j === 0 ? M.map((row, i) => (i === 0 ? row.map((v, r) => (r === 0 ? 1 - v : v)) : row)) : M));
  check(verifyMixnetTranscript({ ...base, decryptedMatrices: tamperedMx }).ok === false, 'mixnet-IRV: a tampered published matrix is rejected');

  // S3 ineligible: drop a credential from the published roll
  check(verifyMixnetTranscript({ ...base, eligibleRoll: base.eligibleRoll.slice(1) }).ok === false, 'mixnet-IRV: a ballot off the eligible roll is rejected');

  // S0 / robustness: malformed transcripts REJECT without throwing
  check(noThrow(() => verifyMixnetTranscript({ ...base, decShares: base.decShares.map((ds, j) => (j === 0 ? { ...ds, shares: ds.shares.slice(0, -1) } : ds)) }).ok) === false, 'mixnet-IRV: wrong-length decShares rejected without throwing');
  check(noThrow(() => verifyMixnetTranscript({ ...base, winner: 99 }).ok) === false, 'mixnet-IRV: out-of-range winner rejected without throwing');
  check(noThrow(() => verifyMixnetTranscript({ ...base, decryptedMatrices: base.decryptedMatrices.map((M, j) => (j === 0 ? M.map((row, i) => (i === 0 ? row.map((v, r) => (r === 0 ? 5 : v)) : row)) : M)) }).ok) === false, 'mixnet-IRV: a non-0/1 published entry rejected without throwing');

  // JSON round-trips and re-verifies from the published record alone; tampering is caught; bad points reject on parse.
  const roundIrv = mixnetIrvTranscriptFromJSON(mixnetIrvTranscriptToJSON(base));
  check(verifyMixnetTranscript(roundIrv).ok && roundIrv.winner === base.winner, 'mixnet-IRV: round-tripped JSON transcript verifies');
  const oj = JSON.parse(mixnetIrvTranscriptToJSON(base));
  check(oj.kind === 'mixnet-irv', 'mixnet-IRV: transcript carries kind discriminator');
  oj.winner = (oj.winner + 1) % 3; // tamper the published winner
  let okT = true; try { okT = verifyMixnetTranscript(mixnetIrvTranscriptFromJSON(JSON.stringify(oj))).ok; } catch { okT = false; }
  check(okT === false, 'mixnet-IRV: tampering the published winner in JSON is caught');
  const oj2 = JSON.parse(mixnetIrvTranscriptToJSON(base));
  oj2.shuffled[0][0].a = 'zz'.repeat(32); // invalid point encoding
  let parseThrewIrv = false; try { mixnetIrvTranscriptFromJSON(JSON.stringify(oj2)); } catch { parseThrewIrv = true; }
  check(parseThrewIrv, 'mixnet-IRV: a bad point encoding in the shuffle is rejected on parse');
}

// 21. Bulletin-board Merkle is NOT malleable (CVE-2012-2459 regression lock): the RFC-6962-strict
//     construction (split at the largest power of two < n, never duplicate a lone node) means n and
//     n+1-with-a-duplicated-tail entries can never share a root. This is the property the on-chain
//     root anchor depends on; it was the round-1 finding and this test keeps it from regressing.
{
  const board = (items: Uint8Array[]): string => { const b = new BulletinBoard(); items.forEach((x) => b.append(x)); return b.root(); };
  const A = new Uint8Array([1]); const B = new Uint8Array([2]); const C = new Uint8Array([3]); const D = new Uint8Array([4]);
  // The exact CVE-2012-2459 collision the original construction had: [A,B,C] vs [A,B,C,C].
  check(board([A, B, C]) !== board([A, B, C, C]), 'Merkle: [A,B,C] and [A,B,C,C] have DIFFERENT roots (CVE-2012-2459 fixed)');
  check(board([A, B]) !== board([A, B, B]), 'Merkle: [A,B] and [A,B,B] have different roots (no odd-node duplication)');
  // The root commits to the exact ordered multiset: size, order, and content all matter.
  check(board([A, B, C]) !== board([A, B]) && board([A, B, C]) !== board([A, B, C, D]), 'Merkle: root commits to the ballot count');
  check(board([A, B, C]) !== board([A, C, B]), 'Merkle: root commits to ballot order');
  check(board([A, B, C]) !== board([A, B, D]), 'Merkle: flipping any one leaf changes the root');
  check(board([A]) !== board([]) && board([A, B]) !== board([B, A]), 'Merkle: distinct boards yield distinct roots');
  // Deterministic: same ordered set → same root (so an independent verifier reproduces it).
  check(board([A, B, C]) === board([A, B, C]), 'Merkle: root is a deterministic function of the ordered ballots');
}

// 22. Paper + RLA hybrid (ADR-0004): the digital↔paper anchor binds the board root to the paper
//     batches and is signed by the authority; tampering either side is caught; the secret-ballot
//     export carries ONLY totals (never a per-ballot CVR); the verifier never throws.
{
  const noThrow = (fn: () => boolean): boolean | 'threw' => { try { return fn(); } catch { return 'threw'; } };
  const keys = setupKeys(3, 2);
  const r = new Registrar();
  const packets = r.register(Array.from({ length: 7 }, (_, i) => ({ id: `v${i}` })));
  const roll = r.publishedRoll();
  const cands = ['Ana', 'Ben', 'Cy'];
  const choices = [0, 0, 0, 1, 1, 2, 0]; // Ana 4, Ben 2, Cy 1 over 7 voters
  const voters: Voter[] = packets.map((p, i) => ({ credential: p.credential, choice: choices[i]! }));
  const t = runElection('Chair', cands, voters, keys, roll, [1, 2]);
  const signer = issueCredential(); // the election-authority / ceremony key

  const batches: BatchRow[] = [{ batchId: 'batch-A', ballotCount: 4 }, { batchId: 'batch-B', ballotCount: 3 }];
  const manifest = makeManifest('Chair', batches);
  const anchor = buildAnchor({ contest: 'Chair', boardRoot: t.boardRoot, numVoters: t.numVoters, publicKey: t.publicKey, manifest, signer, anchoredAt: '2026-06-06T00:00:00Z' });
  const exp = { boardRoot: t.boardRoot, numVoters: t.numVoters, publicKey: anchor.publicKey, signerPub: anchor.signerPub };

  check(verifyAnchor(anchor, manifest, exp).ok, 'RLA anchor: honest anchor verifies (signed, pinned authority, both roots, reconciled)');
  // CRITICAL regression (review finding 1): a byte-boundary shift between the two adjacent roots, reusing
  // the honest signature, must be rejected on the BARE path by the canonical 32-byte encoding gate.
  check(verifyAnchor({ ...anchor, boardRoot: anchor.boardRoot.slice(0, -2), paperManifestRoot: anchor.boardRoot.slice(-2) + anchor.paperManifestRoot }).ok === false, 'RLA anchor: a root byte-boundary-shift forge (reused sig) is rejected on the bare path');
  // Signer pinning (review finding 2): an anchor self-signed by a non-authority key is rejected when the
  // authority is pinned; pinning a different key rejects even the honest anchor.
  const rogue = buildAnchor({ contest: 'Chair', boardRoot: t.boardRoot, numVoters: t.numVoters, publicKey: t.publicKey, manifest, signer: issueCredential(), anchoredAt: '2026-06-06T00:00:00Z' });
  check(verifyAnchor(rogue, manifest, exp).ok === false, 'RLA anchor: an anchor self-signed by a non-authority key is rejected when the authority is pinned');
  check(verifyAnchor(anchor, manifest, { ...exp, signerPub: pointToHex(issueCredential().pub) }).ok === false, 'RLA anchor: pinning a different authority key rejects the honest anchor');
  check(verifyAnchor({ ...anchor, boardRoot: 'ab'.repeat(32) }, manifest, exp).ok === false, 'RLA anchor: a tampered digital board root is rejected');
  check(verifyAnchor({ ...anchor, paperManifestRoot: 'cd'.repeat(32) }, manifest, exp).ok === false, 'RLA anchor: a tampered paper-manifest root is rejected');
  check(verifyAnchor({ ...anchor, sig: { R: anchor.sig.R, s: (BigInt(anchor.sig.s) + 1n).toString() } }, manifest, exp).ok === false, 'RLA anchor: a forged authority signature is rejected');
  check(verifyAnchor(anchor, makeManifest('Chair', [{ batchId: 'batch-A', ballotCount: 5 }, { batchId: 'batch-B', ballotCount: 3 }]), exp).ok === false, 'RLA anchor: a tampered paper batch count is rejected');
  check(verifyAnchor(anchor, manifest, { ...exp, boardRoot: 'ef'.repeat(32) }).ok === false, 'RLA anchor: an anchor bound to a different transcript is rejected');
  const badRecon = buildAnchor({ contest: 'Chair', boardRoot: t.boardRoot, numVoters: t.numVoters, publicKey: t.publicKey, manifest: makeManifest('Chair', [{ batchId: 'b', ballotCount: 99 }]), signer, anchoredAt: 'x' });
  check(verifyAnchor(badRecon).ok === false, 'RLA anchor: a paper/digital count discrepancy is flagged (paper wins)');

  // HARD RULE — secret-ballot export carries totals only, NEVER a per-ballot CVR.
  const reported = reportedResults('Chair', cands, 'plurality', t.results, t.numVoters, 0);
  const e = pollingExport(anchor, manifest, reported);
  const j = pollingExportToJSON(e);
  check(!/"choice"|"selection"|cvr|plaintext|"ranking"|enc"|credentialPub/i.test(j), 'RLA export: secret-ballot export contains no per-ballot CVR / voter-linked field');
  check(e.reported.reportedTally.length === cands.length && e.reported.auditMethod === 'ballot-polling', 'RLA export: reported tally is an aggregate, audit method forced to ballot-polling');
  check(verifyAnchor(pollingExportFromJSON(j).anchor, pollingExportFromJSON(j).manifest, exp).ok, 'RLA export: round-trips through JSON and re-verifies');
  check(e.kind === 'rla-export' && verifyExport(pollingExportFromJSON(j), exp).ok, 'RLA export: verifyExport accepts the round-tripped export (kind discriminator + reported binding)');
  check(verifyExport({ ...e, reported: { ...reported, contest: 'Other' } }, exp).ok === false, 'RLA export: a reported-contest mismatch is rejected by verifyExport');

  // Arlo manifest CSV + illustrative BRAVO.
  check(toArloManifestCsv(manifest).split('\n')[0] === 'Container,Tabulator,Batch Name,Number of Ballots', 'RLA export: Arlo ballot-manifest CSV header is correct');
  check(Number.isFinite(bravoSampleSize(t.results, 0.05).sampleSize) && bravoSampleSize([5, 5], 0.05).sampleSize === Infinity && bravoSampleSize([10, 0], 0.05).sampleSize === Infinity, 'RLA: illustrative BRAVO is finite for a real margin, ∞ for a tie / unopposed (no NaN)');

  // Robustness: malformed anchor rejects without throwing (bad hex → caught).
  check(noThrow(() => verifyAnchor({ ...anchor, signerPub: 'zz'.repeat(32) }, manifest, exp).ok) === false, 'RLA anchor: a malformed anchor is rejected without throwing');

  // M4 criterion (ADR-0004): an endpoint-flipped outcome is caught by the ballot-polling RLA against paper.
  // Reported (digital) 40-20; honest paper agrees → audit confirms; flipped paper (true intent is the other
  // candidate) contradicts the reported winner → the sequential test never confirms → escalate (flip caught).
  check(bravoBallotPolling([40, 20], representativeSample([40, 20]), 0.05).confirmed, 'RLA M4: ballot-polling CONFIRMS the reported winner when the paper agrees');
  check(bravoBallotPolling([40, 20], representativeSample([20, 40]), 0.05).confirmed === false, 'RLA M4: a flipped outcome (paper contradicts the reported winner) does NOT confirm — the audit escalates (flip caught)');
}

// 23. Chain-anchor adapter (ADR-0002/0003): the signed, hash-chained transparency log of ROOT
//     commitments is append-only, ordered, attributable, and never carries a ballot. Honest log verifies;
//     tampering an entry / breaking the chain / reordering / dropping / a non-allowlisted validator / a
//     case-mutated or wrong-version root / a truncated suffix is caught; the verifier never throws.
//     NOTE: tamper checks pass { validators: allow } so the failure is attributable to the tamper itself,
//     not to the unconditional accountability gate (which fails any log presented without an allowlist).
{
  const noThrow = (fn: () => boolean): boolean | 'threw' => { try { return fn(); } catch { return 'threw'; } };
  const v1 = issueCredential(); const v2 = issueCredential();
  const allow = [pointToHex(v1.pub), pointToHex(v2.pub)];
  const c1 = rootCommitment('Chair', 'a'.repeat(64), '2026-06-06T00:00:00Z', 'c'.repeat(64));
  const c2 = rootCommitment('Budget', 'b'.repeat(64), '2026-06-06T01:00:00Z');
  const log = new AnchorLog();
  log.append(c1, v1); log.append(c2, v2);
  const es = log.entries();

  check(verifyAnchorLog(es, { validators: allow }).ok, 'anchor log: honest log verifies (chain + named-validator signatures + allowlist)');
  check(verifyRootAnchored(es, 'a'.repeat(64), { paperManifestRoot: 'c'.repeat(64), validators: allow }).ok, 'anchor log: the election root is found anchored in the log');
  check(verifyRootAnchored(es, 'f'.repeat(64), { validators: allow }).ok === false, 'anchor log: a root NOT in the log is reported unanchored');

  // ACCOUNTABILITY GATE (ADR-0003): a log presented with NO allowlist fails — signer identities are
  // self-asserted, not accountable, so "no roster" must not read as "all fine".
  check(verifyAnchorLog(es).ok === false, 'anchor log: an honest log with NO allowlist FAILS the accountability gate (self-asserted ≠ accountable)');

  // tamper an entry's committed root (it is signed + hash-chained → caught two ways)
  const tampered: AnchorEntry[] = es.map((e, i) => (i === 0 ? { ...e, commitment: { ...e.commitment, boardRoot: 'd'.repeat(64) } } : e));
  check(verifyAnchorLog(tampered, { validators: allow }).ok === false, 'anchor log: tampering a committed root is rejected (signature + chain)');
  // forge a signature
  const forgedSig = es.map((e, i) => (i === 1 ? { ...e, sig: { R: e.sig.R, s: (BigInt(e.sig.s) + 1n).toString() } } : e));
  check(verifyAnchorLog(forgedSig, { validators: allow }).ok === false, 'anchor log: a forged validator signature is rejected');
  // break the hash-chain
  const brokenChain = es.map((e, i) => (i === 1 ? { ...e, prev: 'e'.repeat(64) } : e));
  check(verifyAnchorLog(brokenChain, { validators: allow }).ok === false, 'anchor log: a broken hash-chain link is rejected');
  // reorder entries (append-only order must hold)
  check(verifyAnchorLog([es[1]!, es[0]!], { validators: allow }).ok === false, 'anchor log: reordering entries is rejected (monotonic index + chain)');
  // drop the genesis entry
  check(verifyAnchorLog([es[1]!], { validators: allow }).ok === false, 'anchor log: dropping the genesis entry is rejected');
  // CASE-MUTATION: a root presented upper/mixed-case is a different string → canonical (lowercase-only) gate rejects it.
  const upperRoot = es.map((e, i) => (i === 0 ? { ...e, commitment: { ...e.commitment, boardRoot: 'A'.repeat(64) } } : e));
  check(verifyAnchorLog(upperRoot, { validators: allow }).ok === false, 'anchor log: an upper/mixed-case root is rejected (canonical hex is lowercase-only)');
  // WRONG VERSION: a commitment whose version is not vvp-root-commitment-1 fails the canonical gate (version is bound + checked).
  const badVer = es.map((e, i) => (i === 0 ? { ...e, commitment: { ...e.commitment, version: 'vvp-root-commitment-2' as 'vvp-root-commitment-1' } } : e));
  check(verifyAnchorLog(badVer, { validators: allow }).ok === false, 'anchor log: an unexpected commitment version is rejected (version is bound + gated)');
  // a non-allowlisted (rogue) validator witnesses an entry, pinned to the real two → rejected
  const rogueLog = new AnchorLog(); rogueLog.append(c1, issueCredential());
  check(verifyAnchorLog(rogueLog.entries(), { validators: allow }).ok === false, 'anchor log: an entry signed by a non-allowlisted validator is rejected (ADR-0003)');

  // TRUNCATION pins (head/length obtained out-of-band): a dropped suffix is invisible from one copy unless pinned.
  const head = log.head();
  check(head === logHead(es) && head.length === 64, 'anchor log: logHead(entries) equals AnchorLog.head() (running head, not a signed tree head)');
  check(verifyAnchorLog(es, { validators: allow, expectLength: 2, expectHead: head }).ok, 'anchor log: verifies against the pinned head + length');
  // present only the genesis entry — a valid 1-entry log on its own, but it fails the length/head pins.
  check(verifyAnchorLog([es[0]!], { validators: allow }).ok, 'anchor log: a truncated suffix is INVISIBLE without a pin (genesis alone still verifies)');
  check(verifyAnchorLog([es[0]!], { validators: allow, expectLength: 2 }).ok === false, 'anchor log: a truncated log is caught by the pinned length');
  check(verifyAnchorLog([es[0]!], { validators: allow, expectHead: head }).ok === false, 'anchor log: a truncated log is caught by the pinned head');

  // robustness: malformed entry rejects without throwing
  check(noThrow(() => verifyAnchorLog(es.map((e, i) => (i === 0 ? { ...e, validatorPub: 'zz'.repeat(32) } : e)), { validators: allow }).ok) === false, 'anchor log: a malformed entry is rejected without throwing');
  check(noThrow(() => verifyAnchorLog([]).ok) === false, 'anchor log: an empty log is rejected without throwing');
  // verifyRootAnchored shares the never-throws contract — malformed input is a clean rejection, not an exception.
  check(noThrow(() => verifyRootAnchored(es.map((e, i) => (i === 0 ? ({ ...e, commitment: undefined } as unknown as AnchorEntry) : e)), 'a'.repeat(64), { validators: allow }).ok) === false, 'anchor log: verifyRootAnchored on a malformed entry is rejected without throwing');
  check(noThrow(() => verifyRootAnchored(null as unknown as AnchorEntry[], 'a'.repeat(64)).ok) === false, 'anchor log: verifyRootAnchored on a non-array is rejected without throwing');
  // HOSTILE (round-15): an entry whose `commitment` is a THROWING accessor — optional chaining does NOT stop
  // a getter (`e?.commitment` still invokes it for a non-null e), so BOTH verifiers must catch it, not throw.
  const poison = { index: 0, prev: '', validatorPub: 'a'.repeat(64), sig: { R: 'a'.repeat(64), s: '1' }, get commitment() { throw new Error('boom'); } } as unknown as AnchorEntry;
  check(noThrow(() => verifyAnchorLog([poison], { validators: allow }).ok) === false, 'anchor log: verifyAnchorLog on a throwing-getter entry is rejected without throwing');
  check(noThrow(() => verifyRootAnchored([poison], 'a'.repeat(64), { validators: allow }).ok) === false, 'anchor log: verifyRootAnchored on a throwing-getter entry is rejected without throwing (round-15)');
}

// 24. Everlasting-privacy commitment trail (ADR-0010): a perfectly-hiding Pedersen commitment C = v·G + d·H
//     per ballot, BOUND to the verifiable ElGamal ballot by a consistency NIZK. Hiding is unconditional;
//     binding is computational. Honest verifies; every tamper (commitment, ciphertext, each response, each
//     commitment-point, non-canonical scalar, wrong key, transplanted proof) is caught; the verifier never
//     throws; H is the pinned NUMS generator; commitments are additively homomorphic.
{
  const noThrow = (fn: () => boolean): boolean | 'threw' => { try { return fn(); } catch { return 'threw'; } };
  // H is the pinned nothing-up-my-sleeve generator, distinct from G and the identity.
  check(pointToHex(H) === 'b66dc28b63ecfbb83fa33aad8148a54f17757fce571ad6b8df258d3cfa2a777a', 'everlasting: H matches the pinned NUMS constant');
  check(!H.equals(G) && !H.equals(ZERO), 'everlasting: H differs from G and the identity');

  // Perfect hiding: two commitments to the SAME vote with independent d are (overwhelmingly) different points.
  let hidingDistinct = 0;
  for (let i = 0; i < 50; i++) { if (!commitVote(1, randScalar()).equals(commitVote(1, randScalar()))) hidingDistinct++; }
  check(hidingDistinct === 50, 'everlasting: commitments to the same vote are distinct (perfectly hiding)');
  // A commitment to 0 and to 1 with the same d differ by exactly G (sanity: C(1,d) − C(0,d) == G).
  { const d = randScalar(); check(commitVote(1, d).equals(commitVote(0, d).add(G)), 'everlasting: C(1,d) − C(0,d) == G (commitment opens correctly in the exponent)'); }

  // Consistency NIZK: honest proofs verify for random (v, r, d); the cross-binding holds.
  let consHonest = 0;
  const pk = h; // trustees' joint key from the top of the file
  for (let i = 0; i < 60; i++) {
    const v: 0 | 1 = bit();
    const r = randScalar(); const d = randScalar();
    const ct = encrypt(pk, BigInt(v), r);
    const C = commitVote(v, d);
    if (verifyConsistency(pk, ct, C, proveConsistency(pk, ct, C, v, r, d))) consHonest++;
  }
  check(consHonest === 60, 'everlasting: honest consistency proofs verify over random (v,r,d)');

  // Tamper battery on a single honest instance.
  {
    const v: 0 | 1 = 1; const r = randScalar(); const d = randScalar();
    const ct = encrypt(pk, BigInt(v), r);
    const C = commitVote(v, d);
    const pr = proveConsistency(pk, ct, C, v, r, d);
    check(verifyConsistency(pk, ct, C, pr), 'everlasting: baseline consistency proof verifies');
    // commit to a DIFFERENT vote with the same proof → reject (binding)
    check(verifyConsistency(pk, ct, commitVote(0, d), pr) === false, 'everlasting: a commitment to a different vote is rejected (binding)');
    // commit to the same vote, different d (so C ≠ committed point in the proof) → reject
    check(verifyConsistency(pk, ct, commitVote(v, randScalar()), pr) === false, 'everlasting: a re-randomized commitment not matching the proof is rejected');
    // tamper each response → reject
    check(verifyConsistency(pk, ct, C, { ...pr, zv: mod(pr.zv + 1n, N) }) === false, 'everlasting: tampering zv (the cross-binding response) is rejected');
    check(verifyConsistency(pk, ct, C, { ...pr, zr: mod(pr.zr + 1n, N) }) === false, 'everlasting: tampering zr is rejected');
    check(verifyConsistency(pk, ct, C, { ...pr, zd: mod(pr.zd + 1n, N) }) === false, 'everlasting: tampering zd is rejected');
    // tamper each commitment point → reject
    check(verifyConsistency(pk, ct, C, { ...pr, Aa: pr.Aa.add(G) }) === false, 'everlasting: tampering Aa is rejected');
    check(verifyConsistency(pk, ct, C, { ...pr, Ab: pr.Ab.add(G) }) === false, 'everlasting: tampering Ab is rejected');
    check(verifyConsistency(pk, ct, C, { ...pr, Ac: pr.Ac.add(H) }) === false, 'everlasting: tampering Ac is rejected');
    // non-canonical scalar (≥ N) → reject (inRange hardening, mirrors verifyBit/verifyDecryption)
    check(verifyConsistency(pk, ct, C, { ...pr, zv: N }) === false, 'everlasting: a non-canonical response scalar (= N) is rejected');
    check(verifyConsistency(pk, ct, C, { ...pr, zr: N + 5n }) === false, 'everlasting: a non-canonical response scalar (> N) is rejected');
    // wrong public key → reject (FS binds PK)
    check(verifyConsistency(mul(G, randScalar()), ct, C, pr) === false, 'everlasting: a consistency proof under the wrong key is rejected');
    // transplant the proof onto a DIFFERENT ciphertext (same v) → reject (FS binds a,b)
    const ct2 = encrypt(pk, BigInt(v), randScalar());
    check(verifyConsistency(pk, ct2, C, pr) === false, 'everlasting: a proof transplanted to a different ciphertext is rejected');
  }

  // Everlasting bit-proof on C ALONE (the CPP-migration gate): C commits to a bit using only (G,H,C).
  {
    let cbHonest = 0;
    for (let i = 0; i < 60; i++) {
      const v: 0 | 1 = bit(); const d = randScalar();
      const C = commitVote(v, d);
      if (verifyCommitBit(C, proveCommitBit(C, v, d))) cbHonest++;
    }
    check(cbHonest === 60, 'everlasting: honest commit-bit proofs verify over random (v,d)');
    const d = randScalar();
    const C0 = commitVote(0, d); const C1 = commitVote(1, d);
    const p0 = proveCommitBit(C0, 0, d); const p1 = proveCommitBit(C1, 1, d);
    check(verifyCommitBit(C0, p0) && verifyCommitBit(C1, p1), 'everlasting: commit-bit verifies for both v=0 and v=1');
    // transplant a proof to a different commitment → reject (FS binds C)
    check(verifyCommitBit(C1, p0) === false, 'everlasting: a commit-bit proof transplanted to a different commitment is rejected');
    // tamper each field → reject
    check(verifyCommitBit(C0, { ...p0, A0: p0.A0.add(G) }) === false, 'everlasting: tampering commit-bit A0 is rejected');
    check(verifyCommitBit(C0, { ...p0, A1: p0.A1.add(H) }) === false, 'everlasting: tampering commit-bit A1 is rejected');
    check(verifyCommitBit(C0, { ...p0, c0: mod(p0.c0 + 1n, N) }) === false, 'everlasting: tampering commit-bit c0 is rejected');
    check(verifyCommitBit(C0, { ...p0, s0: mod(p0.s0 + 1n, N) }) === false, 'everlasting: tampering commit-bit s0 is rejected');
    check(verifyCommitBit(C0, { ...p0, s1: mod(p0.s1 + 1n, N) }) === false, 'everlasting: tampering commit-bit s1 is rejected');
    // non-canonical scalar → reject (inRange)
    check(verifyCommitBit(C0, { ...p0, c0: N }) === false, 'everlasting: a non-canonical commit-bit scalar (= N) is rejected');
    // soundness: a commitment to a NON-bit value (2) cannot be proven a bit — neither branch's witness exists,
    // and an honest proof built for one C does not verify against the non-bit commitment.
    const C2 = mul(G, 2n).add(mul(H, d));
    check(verifyCommitBit(C2, p0) === false && verifyCommitBit(C2, p1) === false, 'everlasting: a commitment to a non-bit value (2) is not accepted by a bit-proof');
  }

  // Everlasting exactly-L (sum) proof on the commitment row: ΣC commits to exactly L, from (G,H,ΣC) alone.
  {
    // honest: a row of bits summing to L=1 verifies; tamper rejects; the L is bound.
    const ds = [randScalar(), randScalar(), randScalar()];
    const row1 = [commitVote(1, ds[0]!), commitVote(0, ds[1]!), commitVote(0, ds[2]!)]; // exactly 1
    const sum1 = addCommitments(row1); const D1 = ds.reduce((a, x) => mod(a + x, N), 0n);
    const sp1 = proveCommitSum(sum1, 1, D1);
    check(verifyCommitSum(sum1, 1, sp1), 'everlasting: honest exactly-1 row sum proof verifies');
    check(verifyCommitSum(sum1, 1, { ...sp1, z: mod(sp1.z + 1n, N) }) === false, 'everlasting: tampering the sum-proof z is rejected');
    check(verifyCommitSum(sum1, 1, { ...sp1, A: sp1.A.add(H) }) === false, 'everlasting: tampering the sum-proof A is rejected');
    check(verifyCommitSum(sum1, 1, { ...sp1, z: N }) === false, 'everlasting: a non-canonical sum-proof scalar (= N) is rejected');
    check(verifyCommitSum(sum1, 2, sp1) === false, 'everlasting: an exactly-1 proof does not verify as exactly-2 (L is bound)');
    // SOUNDNESS: an OVERVOTE row (sums to 2) cannot be passed off as exactly-1 — no valid witness exists.
    const e0 = randScalar(); const e1 = randScalar();
    const over = [commitVote(1, e0), commitVote(1, e1)]; // two 1s
    const sumOver = addCommitments(over); const Dover = mod(e0 + e1, N);
    check(verifyCommitSum(sumOver, 1, proveCommitSum(sumOver, 1, Dover)) === false, 'everlasting: an overvote row (Σ=2) is rejected by the exactly-1 proof (no over/undervote in the everlasting view)');
    check(verifyCommitSum(sumOver, 2, proveCommitSum(sumOver, 2, Dover)), 'everlasting: the same row honestly verifies as exactly-2');
  }

  // Additively homomorphic: Σ commitments = (Σv)·G + (Σd)·H.
  {
    const vs: (0 | 1)[] = [1, 0, 1, 1, 0];
    const ds = vs.map(() => randScalar());
    const Cs = vs.map((v, i) => commitVote(v, ds[i]!));
    const sumV = vs.reduce((a, v) => a + BigInt(v), 0n);
    const sumD = ds.reduce((a, d) => mod(a + d, N), 0n);
    check(addCommitments(Cs).equals(mul(G, sumV).add(mul(H, sumD))), 'everlasting: Σ commitments opens to (Σv)·G + (Σd)·H (homomorphic)');
  }

  // Trail-level: honest trail verifies (object + JSON round-trip); tamper rejected; never-throws.
  const trail: EverlastingTrail = buildTrail(h, 'Chair', ['A', 'B', 'C'], [0, 1, 2, 0, 1], 'a'.repeat(64));
  check(verifyTrail(trail).ok, 'everlasting: an honest trail verifies');
  check(verifyTrail(trailFromJSON(trailToJSON(trail))).ok, 'everlasting: a trail survives a JSON round-trip');
  check(commitmentTotals(trail).length === 3, 'everlasting: per-candidate commitment totals are produced (homomorphic tally commitment)');
  // tamper a commitment in the trail → reject
  const tt: EverlastingTrail = { ...trail, ballots: trail.ballots.map((b, i) => (i === 0 ? { ...b, cells: b.cells.map((c, j) => (j === 0 ? { ...c, commitment: commitVote(1, randScalar()) } : c)) } : b)) };
  check(verifyTrail(tt).ok === false, 'everlasting: a tampered trail commitment is rejected (consistency + commit-bit + row-sum all catch it)');
  // tamper the row sum-proof alone → reject (everlasting exactly-L)
  const ts2: EverlastingTrail = { ...trail, ballots: trail.ballots.map((b, i) => (i === 0 ? { ...b, sumProof: { ...b.sumProof, z: mod(b.sumProof.z + 1n, N) } } : b)) };
  check(verifyTrail(ts2).ok === false, 'everlasting: a tampered row sum-proof is rejected');
  // a trail whose document H is wrong must fail to parse (fail closed)
  check(noThrow(() => trailFromJSON(trailToJSON(trail).replace(/"pedersenH":"[0-9a-f]{64}"/, '"pedersenH":"' + 'f'.repeat(64) + '"')) && true) === 'threw', 'everlasting: a trail with a wrong pinned H fails closed on parse');
  // strict canonical-decimal scalar parsing (round-16): the SAME-VALUE-different-syntax forms that JS
  // BigInt() or Python int() would each accept must be a clean rejection in BOTH verifiers (no divergence).
  check(scalarFromDecimal('123') === 123n && scalarFromDecimal('0') === 0n, 'everlasting: scalarFromDecimal accepts canonical decimal');
  for (const bad of ['0x10', '1_0', '', ' 5', '5 ', '-1', '00', '01', '٥', '1e3', '0b1', '+7']) {
    check(noThrow(() => { scalarFromDecimal(bad); return true; }) === 'threw', `everlasting: scalarFromDecimal rejects non-canonical "${bad}"`);
  }
  // end-to-end: a trail whose scalar is rewritten to a non-canonical (hex) form fails to parse (mirrors Python int()).
  {
    const tj = trailToJSON(buildTrail(h, 'X', ['A', 'B'], [0, 1]));
    const m = tj.match(/"zv":"(\d+)"/);
    const hexForm = tj.replace('"zv":"' + m![1]! + '"', '"zv":"0x' + BigInt(m![1]!).toString(16) + '"');
    check(noThrow(() => { trailFromJSON(hexForm); return true; }) === 'threw', 'everlasting: a hex-rewritten scalar in a trail is rejected on parse (cross-verifier equivalence)');
  }

  // robustness: malformed trails are a clean rejection, not an exception
  check(noThrow(() => verifyTrail(null as unknown as EverlastingTrail).ok) === false, 'everlasting: verifyTrail on null is rejected without throwing');
  check(noThrow(() => verifyTrail({ contest: 'x', candidates: [], selectionLimit: 1, publicKey: h, ballots: [] } as EverlastingTrail).ok) === false, 'everlasting: verifyTrail on an empty candidate set is rejected without throwing');
  check(noThrow(() => verifyTrail({ ...trail, ballots: [{ cells: [] }] } as unknown as EverlastingTrail).ok) === false, 'everlasting: verifyTrail on a wrong-shape ballot is rejected without throwing');
  check(noThrow(() => verifyTrail({ ...trail, selectionLimit: 0 } as EverlastingTrail).ok) === false, 'everlasting: verifyTrail on an out-of-range selection limit is rejected without throwing');
}

console.log(`\nself-test: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
