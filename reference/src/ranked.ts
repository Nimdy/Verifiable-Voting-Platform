// Ranked-choice ballots — validity via a PERMUTATION-MATRIX proof (increment 1 of #49).
//
// A strict ranking of K candidates is a K×K matrix M of encrypted bits where M[i][r] = 1 iff
// candidate i is given rank r (0 = best). It is a valid ranking iff:
//   • every entry is a 0/1 bit            (reuses the audited disjunctive Chaum–Pedersen proof)
//   • every ROW sums to 1                 (each candidate gets exactly one rank)
//   • every COLUMN sums to 1              (each rank goes to exactly one candidate)
// Rows-and-columns-sum-to-1 over 0/1 entries ⇒ a permutation matrix ⇒ a valid strict ranking.
// No new cryptographic primitive is invented — this composes proveBit + the exactly-L sum proof.
//
// It also exposes the homomorphic BORDA aggregation: candidate i's per-ballot score is
// Σ_r (K-1-r)·M[i][r] (a public-weight linear combination of verified ciphertexts), which can be
// summed across ballots and threshold-decrypted to per-candidate Borda totals WITHOUT a mixnet.
// (Full ranked elections — transcript, threshold tally, the independent Python verifier, UI —
// and IRV-style elimination via a verifiable mixnet are the next increments, tracked in #49.)

import { concatBytes } from '@noble/hashes/utils';
import { encrypt, addCiphertexts, decryptionShare, discreteLog, type Ciphertext } from './elgamal.js';
import {
  proveBit, verifyBit, proveSumEqual, verifySumEqual, proveDecryption, verifyDecryption,
  type BitProof, type SumProof, type DecProof,
} from './proofs.js';
import { randScalar, mul, mod, N, ZERO, scalarTo32, pointToHex, type Point } from './group.js';
import { combineShares, verificationKeyAt, type KeySetup } from './threshold.js';
import { sign, verifySig, type Credential, type Signature } from './credentials.js';
import { electionContext } from './codec.js';
import { BulletinBoard } from './bulletin.js';
import type { Check, VerifyResult } from './verify.js';

export interface RankedBallot {
  matrix: Ciphertext[][]; // matrix[candidate][rank]
  bitProofs: BitProof[][];
  rowSums: SumProof[]; // row i (candidate i) sums to 1
  colSums: SumProof[]; // col r (rank r) sums to 1
}

/**
 * Encrypt a strict ranking. `ranking[i]` is the rank (0 = best … K-1 = worst) assigned to
 * candidate i and must be a permutation of 0..K-1.
 */
export function encryptRanking(pk: Point, ranking: number[]): { ballot: RankedBallot; randomness: bigint[][] } {
  const K = ranking.length;
  if (new Set(ranking).size !== K || ranking.some((r) => !Number.isInteger(r) || r < 0 || r >= K)) {
    throw new Error('ranking must be a permutation of 0..K-1');
  }
  const matrix: Ciphertext[][] = [];
  const bitProofs: BitProof[][] = [];
  const randomness: bigint[][] = [];
  for (let i = 0; i < K; i++) {
    matrix[i] = []; bitProofs[i] = []; randomness[i] = [];
    for (let r = 0; r < K; r++) {
      const v: 0 | 1 = ranking[i] === r ? 1 : 0;
      const rr = randScalar();
      const ct = encrypt(pk, BigInt(v), rr);
      matrix[i]!.push(ct);
      bitProofs[i]!.push(proveBit(pk, ct, v, rr));
      randomness[i]!.push(rr);
    }
  }
  const rowSums: SumProof[] = [];
  for (let i = 0; i < K; i++) {
    const R = randomness[i]!.reduce((a, b) => mod(a + b, N), 0n);
    rowSums.push(proveSumEqual(pk, addCiphertexts(matrix[i]!), R, 1));
  }
  const colSums: SumProof[] = [];
  for (let r = 0; r < K; r++) {
    const col = matrix.map((row) => row[r]!);
    const R = randomness.reduce((a, row) => mod(a + row[r]!, N), 0n);
    colSums.push(proveSumEqual(pk, addCiphertexts(col), R, 1));
  }
  return { ballot: { matrix, bitProofs, rowSums, colSums }, randomness };
}

/** A ranked ballot is valid iff it is a K×K permutation matrix (bits + every row & column sum to 1). */
export function verifyRankingValid(pk: Point, b: RankedBallot): boolean {
  const K = b.matrix.length;
  if (K === 0 || b.bitProofs.length !== K || b.rowSums.length !== K || b.colSums.length !== K) return false;
  for (let i = 0; i < K; i++) {
    if (b.matrix[i]!.length !== K || b.bitProofs[i]!.length !== K) return false;
    for (let r = 0; r < K; r++) {
      if (!verifyBit(pk, b.matrix[i]![r]!, b.bitProofs[i]![r]!)) return false;
    }
  }
  for (let i = 0; i < K; i++) {
    if (!verifySumEqual(pk, addCiphertexts(b.matrix[i]!), b.rowSums[i]!, 1)) return false;
  }
  for (let r = 0; r < K; r++) {
    const col = b.matrix.map((row) => row[r]!);
    if (!verifySumEqual(pk, addCiphertexts(col), b.colSums[r]!, 1)) return false;
  }
  return true;
}

/**
 * Per-candidate homomorphic Borda score for one ballot: candidate i → Σ_r (K-1-r)·M[i][r].
 * PRECONDITION: the ballot must already have passed verifyRankingValid — this does not re-check it.
 * Per-ballot scores lie in [0, K-1]; summed across V ballots they reach [0, (K-1)·V], so a future
 * threshold tally must size its discrete-log bound as (K-1)·numVoters.
 */
export function bordaBallotTotals(b: RankedBallot): Ciphertext[] {
  const K = b.matrix.length;
  return b.matrix.map((row) => {
    let acc: Ciphertext = { a: ZERO, b: ZERO };
    for (let r = 0; r < K; r++) {
      const w = BigInt(K - 1 - r);
      acc = { a: acc.a.add(mul(row[r]!.a, w)), b: acc.b.add(mul(row[r]!.b, w)) };
    }
    return acc;
  });
}

// ---------------------------------------------------------------------------
// Full ranked (Borda) election: signed ranked ballots on a public board, then a
// k-of-n threshold decryption of the per-candidate Borda aggregates. Reuses the
// credential/nullifier/threshold infrastructure; tally is mixnet-free (homomorphic
// Borda). (IRV-style elimination still needs a verifiable mixnet — #49.)
// ---------------------------------------------------------------------------

function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
function bitBytes(p: BitProof): Uint8Array {
  return concatBytes(
    p.T0g.toRawBytes(), p.T0h.toRawBytes(), p.T1g.toRawBytes(), p.T1h.toRawBytes(),
    scalarTo32(p.c0), scalarTo32(p.c1), scalarTo32(p.s0), scalarTo32(p.s1),
  );
}
function sumBytes(p: SumProof): Uint8Array {
  return concatBytes(p.Tg.toRawBytes(), p.Th.toRawBytes(), scalarTo32(p.c), scalarTo32(p.s));
}

/** Canonical bytes a voter signs for a ranked ballot (matrix + all proofs), bound to the election ctx. */
export function rankedSigningBytes(ctx: Uint8Array, b: RankedBallot): Uint8Array {
  const parts: Uint8Array[] = [ctx, u32(b.matrix.length)];
  for (let i = 0; i < b.matrix.length; i++) {
    for (let r = 0; r < b.matrix.length; r++) {
      parts.push(b.matrix[i]![r]!.a.toRawBytes(), b.matrix[i]![r]!.b.toRawBytes(), bitBytes(b.bitProofs[i]![r]!));
    }
  }
  for (let i = 0; i < b.matrix.length; i++) parts.push(sumBytes(b.rowSums[i]!));
  for (let r = 0; r < b.matrix.length; r++) parts.push(sumBytes(b.colSums[r]!));
  return concatBytes(...parts);
}

function rankedBoardBytes(ctx: Uint8Array, credPub: Point, b: RankedBallot, sig: Signature): Uint8Array {
  return concatBytes(credPub.toRawBytes(), rankedSigningBytes(ctx, b), sig.R.toRawBytes(), scalarTo32(sig.s));
}

export interface RankedVoter {
  credential: Credential;
  ranking: number[];
}

export interface RankedBallotEntry {
  voter: string;
  credentialPub: Point;
  ballot: RankedBallot;
  sig: Signature;
}

export interface RankedDecShare {
  trusteeIndex: number;
  shares: Point[]; // one per candidate (for that candidate's Borda aggregate)
  proofs: DecProof[];
}

export interface RankedTranscript {
  contest: string;
  candidates: string[];
  numVoters: number;
  eligibleRoll: Point[];
  publicKey: Point;
  commitments: Point[];
  trustees: number;
  threshold: number;
  ballots: RankedBallotEntry[];
  boardRoot: string;
  bordaAggregates: Ciphertext[]; // per candidate
  decShares: RankedDecShare[];
  results: number[]; // per-candidate Borda totals
}

/** Run a full ranked (Borda) election; trustee secrets stay with the caller. */
export function runRankedElection(
  contest: string,
  candidates: string[],
  voters: RankedVoter[],
  keys: KeySetup,
  eligibleRoll: Point[],
  participants?: number[],
): RankedTranscript {
  const K = candidates.length;
  const pk = keys.publicKey;
  const ctx = electionContext(contest, pk, candidates);

  const prepared = voters.map((v) => {
    if (v.ranking.length !== K) throw new Error('ranking length must equal candidate count');
    const { ballot } = encryptRanking(pk, v.ranking);
    const sig = sign(v.credential.secret, rankedSigningBytes(ctx, ballot));
    return { credentialPub: v.credential.pub, ballot, sig };
  });
  prepared.sort((a, b) => pointToHex(a.credentialPub).localeCompare(pointToHex(b.credentialPub)));
  const board = new BulletinBoard();
  const ballots: RankedBallotEntry[] = prepared.map((e, i) => {
    board.append(rankedBoardBytes(ctx, e.credentialPub, e.ballot, e.sig));
    return { voter: `ballot-${i + 1}`, credentialPub: e.credentialPub, ballot: e.ballot, sig: e.sig };
  });

  const perBallot = ballots.map((b) => bordaBallotTotals(b.ballot));
  const bordaAggregates = Array.from({ length: K }, (_, i) =>
    perBallot.reduce<Ciphertext>((acc, pb) => ({ a: acc.a.add(pb[i]!.a), b: acc.b.add(pb[i]!.b) }), { a: ZERO, b: ZERO }));

  const subset = participants ?? keys.trustees.slice(0, keys.threshold).map((t) => t.index);
  const participating = keys.trustees.filter((t) => subset.includes(t.index));
  const decShares: RankedDecShare[] = participating.map((t) => {
    const shares = bordaAggregates.map((agg) => decryptionShare(agg.a, t.share));
    const proofs = bordaAggregates.map((agg, i) => proveDecryption(agg.a, t.verificationKey, shares[i]!, t.share));
    return { trusteeIndex: t.index, shares, proofs };
  });

  const maxBorda = (K - 1) * voters.length;
  const results = bordaAggregates.map((agg, i) => {
    const combined = combineShares(decShares.map((ds) => ({ index: ds.trusteeIndex, d: ds.shares[i]! })));
    return discreteLog(agg.b.subtract(combined), maxBorda);
  });

  return {
    contest, candidates, numVoters: voters.length, eligibleRoll, publicKey: pk,
    commitments: keys.commitments, trustees: keys.trustees.length, threshold: keys.threshold,
    ballots, boardRoot: board.root(), bordaAggregates, decShares, results,
  };
}

/** Verify a ranked election trustlessly (always returns a verdict, never throws). */
export function verifyRankedTranscript(t: RankedTranscript): VerifyResult {
  try {
    return verifyRankedInner(t);
  } catch (err) {
    return { ok: false, results: null, checks: [{ name: 'Transcript is well-formed (no exception)', ok: false, detail: String(err) }] };
  }
}

function verifyRankedInner(t: RankedTranscript): VerifyResult {
  const checks: Check[] = [];
  const K = t.candidates.length;
  const k = t.threshold;
  const shapeOk =
    K > 0 && Number.isInteger(k) && k >= 1 && Number.isInteger(t.trustees) && t.trustees >= k &&
    Number.isInteger(t.numVoters) && t.numVoters === t.ballots.length &&
    t.commitments.length === k && t.bordaAggregates.length === K && t.results.length === K &&
    t.decShares.every((ds) => ds.shares.length === K && ds.proofs.length === K) &&
    // every ranked ballot must be exactly K×K (reject wrong-dimension ballots up front, not downstream)
    t.ballots.every((b) =>
      b.ballot.matrix.length === K && b.ballot.matrix.every((row) => row.length === K) &&
      b.ballot.bitProofs.length === K && b.ballot.bitProofs.every((row) => row.length === K) &&
      b.ballot.rowSums.length === K && b.ballot.colSums.length === K);
  checks.push({ name: 'Transcript shape: K aggregates, k commitments, numVoters = ballots', ok: shapeOk });
  if (!shapeOk) return { ok: false, checks, results: null };

  const idxOk = (i: number): boolean => Number.isInteger(i) && i >= 1 && i <= t.trustees;
  const ctx = electionContext(t.contest, t.publicKey, t.candidates);
  checks.push({ name: 'Joint public key = commitment C₀', ok: t.commitments[0]!.equals(t.publicKey) });

  const board = new BulletinBoard();
  for (const b of t.ballots) board.append(rankedBoardBytes(ctx, b.credentialPub, b.ballot, b.sig));
  checks.push({ name: 'Bulletin-board Merkle root matches the published ballots', ok: board.root() === t.boardRoot });

  const eligible = new Set(t.eligibleRoll.map(pointToHex));
  checks.push({ name: 'Eligible roll has no duplicate credentials', ok: eligible.size === t.eligibleRoll.length });
  const seen = new Set<string>();
  let inelig = 0, badSig = 0, dup = 0;
  for (const b of t.ballots) {
    const key = pointToHex(b.credentialPub);
    if (!eligible.has(key)) inelig++;
    if (!verifySig(b.credentialPub, rankedSigningBytes(ctx, b.ballot), b.sig)) badSig++;
    if (seen.has(key)) dup++;
    seen.add(key);
  }
  checks.push({ name: 'Every ballot is signed by an eligible voter credential', ok: inelig === 0 && badSig === 0, detail: inelig === 0 && badSig === 0 ? undefined : `${inelig} ineligible, ${badSig} bad sig` });
  checks.push({ name: 'No credential voted more than once (single-use nullifier)', ok: dup === 0 });

  let invalid = 0;
  for (const b of t.ballots) if (!verifyRankingValid(t.publicKey, b.ballot)) invalid++;
  checks.push({ name: 'Every ballot is a valid strict ranking (permutation matrix)', ok: invalid === 0, detail: invalid === 0 ? `${t.ballots.length}/${t.ballots.length} valid` : `${invalid} INVALID` });

  let aggBad = 0;
  for (let i = 0; i < K; i++) {
    const agg = t.ballots
      .map((b) => bordaBallotTotals(b.ballot)[i]!)
      .reduce<Ciphertext>((acc, ct) => ({ a: acc.a.add(ct.a), b: acc.b.add(ct.b) }), { a: ZERO, b: ZERO });
    if (!agg.a.equals(t.bordaAggregates[i]!.a) || !agg.b.equals(t.bordaAggregates[i]!.b)) aggBad++;
  }
  checks.push({ name: 'Borda aggregates = homomorphic Borda sum of the ballots', ok: aggBad === 0 });

  const indices = t.decShares.map((d) => d.trusteeIndex);
  checks.push({
    name: `Decryption quorum: ≥ ${k} distinct registered trustees (1..${t.trustees})`,
    ok: new Set(indices).size === indices.length && indices.every(idxOk) && t.decShares.length >= k,
  });
  let badShares = 0;
  for (const ds of t.decShares) {
    if (!idxOk(ds.trusteeIndex)) { badShares += K; continue; }
    const pub = verificationKeyAt(t.commitments, ds.trusteeIndex);
    for (let i = 0; i < K; i++) if (!verifyDecryption(t.bordaAggregates[i]!.a, pub, ds.shares[i]!, ds.proofs[i]!)) badShares++;
  }
  checks.push({ name: 'Every trustee decryption share is provably honest', ok: badShares === 0 });

  const valid = t.decShares.filter((ds) => idxOk(ds.trusteeIndex));
  const maxBorda = (K - 1) * t.numVoters;
  let tallyBad = 0;
  const results: number[] = [];
  for (let i = 0; i < K; i++) {
    const combined = combineShares(valid.map((ds) => ({ index: ds.trusteeIndex, d: ds.shares[i]! })));
    try {
      const n = discreteLog(t.bordaAggregates[i]!.b.subtract(combined), maxBorda);
      results.push(n);
      if (n !== t.results[i]) tallyBad++;
    } catch {
      results.push(-1);
      tallyBad++;
    }
  }
  const expectedSum = t.numVoters * (K * (K - 1) / 2); // each ballot distributes 0+1+…+(K-1) Borda points
  const sumOk = results.reduce((a, b) => a + b, 0) === expectedSum;
  checks.push({ name: 'Borda totals equal the decrypted aggregates', ok: tallyBad === 0 && sumOk, detail: `Σ = ${expectedSum}` });

  return { ok: checks.every((c) => c.ok), checks, results: tallyBad === 0 ? results : null };
}
