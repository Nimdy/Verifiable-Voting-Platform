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

import { encrypt, addCiphertexts, type Ciphertext } from './elgamal.js';
import {
  proveBit, verifyBit, proveSumEqual, verifySumEqual, type BitProof, type SumProof,
} from './proofs.js';
import { randScalar, mul, mod, N, ZERO, type Point } from './group.js';

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
