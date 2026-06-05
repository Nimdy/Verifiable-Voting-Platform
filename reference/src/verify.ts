// The INDEPENDENT VERIFIER — the thing that makes the system trustless.
//
// It takes only the public transcript and rechecks EVERYTHING from scratch,
// trusting nothing about who produced it. If any insider altered a ballot, voted
// without an eligible credential, voted twice, cast an invalid/multi selection,
// faked a decryption, decrypted with too few trustees, or lied about a candidate's
// total, at least one check below fails — and it ALWAYS returns a verdict (never
// throws), even for malformed input. In production this is re-implemented in a
// different language by a different team so a single bug cannot hide itself.

import { addCiphertexts, discreteLog } from './elgamal.js';
import { verifyBit, verifyDecryption, verifySumOne } from './proofs.js';
import { verificationKeyAt, combineShares } from './threshold.js';
import { verifySig } from './credentials.js';
import { ZERO, type Point } from './group.js';
import { signingBytes, boardBytes, electionContext } from './codec.js';
import { BulletinBoard } from './bulletin.js';
import type { Transcript, Selection } from './election.js';

export interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface VerifyResult {
  ok: boolean;
  checks: Check[];
  results: number[] | null;
}

const hx = (p: Point): string =>
  Array.from(p.toRawBytes()).map((x) => x.toString(16).padStart(2, '0')).join('');

/** A selection is valid iff it has exactly K columns, each a 0/1 bit, and exactly one is selected. */
function selectionValid(pk: Point, sel: Selection, K: number): boolean {
  if (sel.enc.length !== K || sel.bitProofs.length !== K) return false;
  for (let j = 0; j < K; j++) {
    if (!verifyBit(pk, sel.enc[j]!, sel.bitProofs[j]!)) return false;
  }
  return verifySumOne(pk, addCiphertexts(sel.enc), sel.sumProof);
}

export function verifyTranscript(t: Transcript): VerifyResult {
  try {
    return verifyInner(t);
  } catch (err) {
    return {
      ok: false,
      results: null,
      checks: [{ name: 'Transcript is well-formed (no exception during verification)', ok: false, detail: String(err) }],
    };
  }
}

function verifyInner(t: Transcript): VerifyResult {
  const checks: Check[] = [];
  const K = t.candidates.length;
  const k = t.threshold;

  // 0. Shape gate — every per-candidate array has exactly K entries, commitments has
  //    exactly k. REJECT (never pad) on mismatch so no later loop indexes past the end.
  const shapeOk =
    K > 0 && Number.isInteger(k) && k >= 1 &&
    Number.isInteger(t.trustees) && t.trustees >= k &&
    // numVoters must equal the number of ballots — it is otherwise an attacker-controlled
    // field used as the discrete-log bound and tally-sum target (denial-of-verification / a
    // self-consistent sum check). Pinning it to ballots.length closes both.
    Number.isInteger(t.numVoters) && t.numVoters === t.ballots.length &&
    t.commitments.length === k &&
    t.aggregates.length === K && t.results.length === K &&
    t.ballots.every((b) => b.selection.enc.length === K && b.selection.bitProofs.length === K) &&
    t.decShares.every((ds) => ds.shares.length === K && ds.proofs.length === K);
  checks.push({ name: 'Transcript shape: K-length arrays and k commitments', ok: shapeOk });
  if (!shapeOk) return { ok: false, checks, results: null };

  // A trustee index is valid only if it is a registered trustee (1..n).
  const idxOk = (i: number): boolean => Number.isInteger(i) && i >= 1 && i <= t.trustees;

  const ctx = electionContext(t.contest, t.publicKey, t.candidates);

  // 1. Joint public key is exactly commitment C₀ of the threshold key.
  checks.push({ name: 'Joint public key = commitment C₀ (threshold key)', ok: t.commitments[0]!.equals(t.publicKey) });

  // 2. Bulletin-board Merkle root commits to exactly these ballots, in order.
  const board = new BulletinBoard();
  for (const b of t.ballots) board.append(boardBytes(ctx, b.credentialPub, b.selection, b.sig));
  const rootOk = board.root() === t.boardRoot;
  checks.push({
    name: 'Bulletin-board Merkle root matches the published ballots',
    ok: rootOk,
    detail: rootOk ? undefined : `recomputed ${board.root().slice(0, 16)}… ≠ published ${t.boardRoot.slice(0, 16)}…`,
  });

  // 3. Every ballot is signed by an ELIGIBLE credential, and no credential votes twice.
  const eligible = new Set(t.eligibleRoll.map(hx));
  checks.push({
    name: 'Eligible roll has no duplicate credentials',
    ok: eligible.size === t.eligibleRoll.length,
    detail: eligible.size === t.eligibleRoll.length ? undefined : `${t.eligibleRoll.length - eligible.size} duplicate(s)`,
  });
  const seen = new Set<string>();
  let ineligible = 0, badSig = 0, duplicate = 0;
  for (const b of t.ballots) {
    const key = hx(b.credentialPub);
    if (!eligible.has(key)) ineligible++;
    if (!verifySig(b.credentialPub, signingBytes(ctx, b.selection), b.sig)) badSig++;
    if (seen.has(key)) duplicate++;
    seen.add(key);
  }
  checks.push({
    name: 'Every ballot is signed by an eligible voter credential',
    ok: ineligible === 0 && badSig === 0,
    detail: ineligible === 0 && badSig === 0
      ? `${t.ballots.length}/${t.ballots.length} signed by the roll`
      : `${ineligible} ineligible, ${badSig} bad signature(s)`,
  });
  checks.push({
    name: 'No credential voted more than once (single-use nullifier)',
    ok: duplicate === 0,
    detail: duplicate === 0 ? undefined : `${duplicate} double vote(s) detected`,
  });

  // 4. Every ballot selects exactly one candidate (each ciphertext a 0/1 bit; sum == 1).
  let invalid = 0;
  for (const b of t.ballots) if (!selectionValid(t.publicKey, b.selection, K)) invalid++;
  checks.push({
    name: 'Every ballot selects exactly one candidate (zero-knowledge)',
    ok: invalid === 0,
    detail: invalid === 0 ? `${t.ballots.length}/${t.ballots.length} valid` : `${invalid} INVALID ballot(s)`,
  });

  // 5. Each candidate aggregate is the honest homomorphic sum of that column.
  let aggBad = 0;
  for (let j = 0; j < K; j++) {
    const agg = addCiphertexts(t.ballots.map((b) => b.selection.enc[j]!));
    const claimed = t.aggregates[j]!;
    if (!agg.a.equals(claimed.a) || !agg.b.equals(claimed.b)) aggBad++;
  }
  checks.push({ name: 'Each candidate aggregate = homomorphic sum of its column', ok: aggBad === 0 });

  // 6. A quorum of ≥ k DISTINCT trustees, each with a provably-correct decryption share
  //    against the verification key recomputed from the public commitments.
  const indices = t.decShares.map((ds) => ds.trusteeIndex);
  const distinct = new Set(indices).size === indices.length;
  const allRegistered = indices.every(idxOk);
  checks.push({
    name: `Decryption quorum: ≥ ${k} distinct registered trustees (1..${t.trustees})`,
    ok: distinct && allRegistered && t.decShares.length >= k,
    detail: `${t.decShares.length} trustee(s), threshold ${k}`,
  });

  let badShares = 0;
  for (const ds of t.decShares) {
    if (!idxOk(ds.trusteeIndex)) { badShares += K; continue; } // never feed a bogus index to point arithmetic
    const pub = verificationKeyAt(t.commitments, ds.trusteeIndex);
    for (let j = 0; j < K; j++) {
      if (!verifyDecryption(t.aggregates[j]!.a, pub, ds.shares[j]!, ds.proofs[j]!)) badShares++;
    }
  }
  checks.push({
    name: 'Every trustee decryption share is provably honest',
    ok: badShares === 0,
    detail: badShares === 0 ? `${t.decShares.length}×${K} proven` : `${badShares} BAD share(s)`,
  });

  // 7. Each published candidate total is the true Lagrange-combined decryption.
  let tallyBad = 0;
  const results: number[] = [];
  const validShares = t.decShares.filter((ds) => idxOk(ds.trusteeIndex)); // bogus indices excluded from interpolation
  for (let j = 0; j < K; j++) {
    const combined = combineShares(validShares.map((ds) => ({ index: ds.trusteeIndex, d: ds.shares[j]! })));
    try {
      const n = discreteLog(t.aggregates[j]!.b.subtract(combined), t.ballots.length);
      results.push(n);
      if (n !== t.results[j]) tallyBad++;
    } catch {
      results.push(-1);
      tallyBad++;
    }
  }
  const sumOk = results.reduce((a, b) => a + b, 0) === t.numVoters;
  checks.push({
    name: 'Published per-candidate totals equal the decrypted aggregates',
    ok: tallyBad === 0 && sumOk,
    detail: tallyBad === 0 && sumOk ? `Σ = ${t.numVoters}` : `${tallyBad} mismatch, Σ=${results.reduce((a, b) => a + b, 0)}`,
  });

  return { ok: checks.every((c) => c.ok), checks, results: tallyBad === 0 ? results : null };
}
