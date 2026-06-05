// The INDEPENDENT VERIFIER — the thing that makes the system trustless.
//
// It takes only the public transcript and rechecks EVERYTHING from scratch,
// trusting nothing about who produced it. If any insider altered a ballot, voted
// without an eligible credential, voted twice, cast an invalid/multi selection,
// faked a decryption, or lied about a candidate's total, at least one check below
// fails — and it ALWAYS returns a verdict (never throws) even for malformed input.
// In production this is re-implemented in a different language by a different team
// so a single bug cannot hide itself.

import { addCiphertexts, combinePublicKey, discreteLog } from './elgamal.js';
import { verifyBit, verifyDecryption, verifySumOne } from './proofs.js';
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
    // The trust root must always emit a verdict, even for adversarial/malformed input.
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

  // 0. Shape gate — every per-candidate array must have exactly K entries. REJECT (never pad)
  //    on mismatch, so no later loop can index past the end.
  const shapeOk =
    K > 0 &&
    t.aggregates.length === K &&
    t.results.length === K &&
    t.ballots.every((b) => b.selection.enc.length === K && b.selection.bitProofs.length === K) &&
    t.decShares.every((ds) => ds.shares.length === K && ds.proofs.length === K);
  checks.push({ name: 'Transcript shape: every ballot/aggregate/share has exactly K entries', ok: shapeOk });
  if (!shapeOk) return { ok: false, checks, results: null };

  const ctx = electionContext(t.contest, t.publicKey, t.candidates);

  // 1. Joint public key is exactly the combination of the published trustee keys.
  const h = combinePublicKey(t.trusteePubs.map((p) => p.pub));
  checks.push({ name: 'Joint public key = combination of trustee keys', ok: h.equals(t.publicKey) });

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

  // 6. Every trustee decryption share (for every candidate) is provably correct.
  let badShares = 0;
  for (const ds of t.decShares) {
    const pub = t.trusteePubs.find((p) => p.index === ds.trusteeIndex)?.pub;
    if (!pub) { badShares++; continue; }
    for (let j = 0; j < K; j++) {
      if (!verifyDecryption(t.aggregates[j]!.a, pub, ds.shares[j]!, ds.proofs[j]!)) badShares++;
    }
  }
  checks.push({
    name: 'Every trustee decryption share is provably honest',
    ok: badShares === 0,
    detail: badShares === 0 ? `${t.decShares.length}×${K} proven` : `${badShares} BAD share(s)`,
  });

  // 7. Each published candidate total is the true decryption of its aggregate.
  let tallyBad = 0;
  const results: number[] = [];
  for (let j = 0; j < K; j++) {
    const combined = t.decShares.reduce<Point>((acc, ds) => acc.add(ds.shares[j]!), ZERO);
    try {
      const n = discreteLog(t.aggregates[j]!.b.subtract(combined), t.numVoters);
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
