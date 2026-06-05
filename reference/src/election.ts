// Orchestrates one end-to-end multi-candidate election and produces a PUBLIC
// TRANSCRIPT. A ballot selects exactly one of K candidates, encrypted as K
// 0/1 ciphertexts (one per candidate) with a bit proof each, plus one
// "exactly-one-selected" proof. The key is k-of-n threshold-shared, so any k
// trustees can decrypt the per-candidate TOTALS — and no fewer can decrypt anything.

import {
  encrypt, addCiphertexts, decryptionShare, discreteLog, type Ciphertext,
} from './elgamal.js';
import {
  proveBit, verifyBit, proveDecryption, proveSumOne, verifySumOne,
  type BitProof, type DecProof, type SumProof,
} from './proofs.js';
import { randScalar, mul, mod, N, ZERO, type Point } from './group.js';
import { dkg, combineShares, type KeySetup, type TrusteeShare } from './threshold.js';
import { sign, type Credential, type Signature } from './credentials.js';
import { signingBytes, boardBytes, electionContext } from './codec.js';
import { BulletinBoard } from './bulletin.js';

/** An encrypted contest selection: one ciphertext + bit proof per candidate, plus a sum=1 proof. */
export interface Selection {
  enc: Ciphertext[];
  bitProofs: BitProof[];
  sumProof: SumProof;
}

/** One voter: their (pseudonymous) credential and the candidate index they chose. */
export interface Voter {
  credential: Credential;
  choice: number;
}

export interface BallotEntry {
  voter: string; // display label only — never linked to identity in a real deployment
  credentialPub: Point; // eligible credential that signed this ballot (also the nullifier)
  selection: Selection;
  sig: Signature;
}

export interface DecShareEntry {
  trusteeIndex: number;
  shares: Point[]; // one per candidate (for that candidate's aggregate)
  proofs: DecProof[];
}

export interface Transcript {
  contest: string;
  candidates: string[];
  numVoters: number;
  eligibleRoll: Point[];
  publicKey: Point;
  commitments: Point[]; // Feldman commitments; verifier recomputes each trustee's verification key
  trustees: number; // n — number of registered trustees (valid indices are 1..n)
  threshold: number; // k — minimum trustees required to decrypt
  ballots: BallotEntry[];
  boardRoot: string;
  aggregates: Ciphertext[]; // per candidate
  decShares: DecShareEntry[]; // from a participating subset of size ≥ threshold
  results: number[]; // votes per candidate (sums to numVoters)
}

/** Generate a k-of-n threshold key (any k of n trustees can decrypt). */
export function setupKeys(n: number, k: number): KeySetup {
  return dkg(n, k);
}

/**
 * Encrypt a voter's choice as K bit-ciphertexts + proofs + an exactly-one proof.
 * Returns the selection and the per-candidate randomness (kept secret; only used
 * by the cast-or-challenge "audit my ballot" flow — see auditSelection).
 */
export function encryptSelection(
  pk: Point,
  choice: number,
  numCandidates: number,
): { selection: Selection; randomness: bigint[] } {
  if (!Number.isInteger(choice) || choice < 0 || choice >= numCandidates) {
    throw new Error(`choice ${choice} out of range [0, ${numCandidates})`);
  }
  const enc: Ciphertext[] = [];
  const bitProofs: BitProof[] = [];
  const randomness: bigint[] = [];
  for (let j = 0; j < numCandidates; j++) {
    const v: 0 | 1 = j === choice ? 1 : 0;
    const r = randScalar();
    const ct = encrypt(pk, BigInt(v), r);
    enc.push(ct);
    bitProofs.push(proveBit(pk, ct, v, r));
    randomness.push(r);
  }
  const R = randomness.reduce((acc, r) => mod(acc + r, N), 0n);
  const sumProof = proveSumOne(pk, addCiphertexts(enc), R);
  return { selection: { enc, bitProofs, sumProof }, randomness };
}

/**
 * Cast-as-intended (Benaloh) audit: recompute the selection from revealed
 * randomness, confirm it encodes exactly `choice`, AND verify the attached proofs
 * (so a successful audit attests a fully castable ballot). A spoiled ballot is then
 * discarded and the voter re-votes, so a cheating device cannot predict an audit.
 */
export function auditSelection(pk: Point, sel: Selection, randomness: bigint[], choice: number): boolean {
  if (randomness.length !== sel.enc.length) return false;
  if (!Number.isInteger(choice) || choice < 0 || choice >= sel.enc.length) return false;
  for (let j = 0; j < sel.enc.length; j++) {
    const v: 0 | 1 = j === choice ? 1 : 0;
    const expected = encrypt(pk, BigInt(v), randomness[j]!);
    if (!expected.a.equals(sel.enc[j]!.a) || !expected.b.equals(sel.enc[j]!.b)) return false;
  }
  for (let j = 0; j < sel.enc.length; j++) {
    if (!verifyBit(pk, sel.enc[j]!, sel.bitProofs[j]!)) return false;
  }
  return verifySumOne(pk, addCiphertexts(sel.enc), sel.sumProof);
}

/**
 * Run a multi-candidate election. Each voter signs their encrypted selection with
 * their credential; `eligibleRoll` is the published set of credential public keys
 * allowed to vote. `participants` chooses which trustees perform the decryption
 * (defaults to the first `threshold` trustees, demonstrating that k of n suffice).
 */
export function runElection(
  contest: string,
  candidates: string[],
  voters: Voter[],
  keys: KeySetup,
  eligibleRoll: Point[],
  participants?: number[],
): Transcript {
  const K = candidates.length;
  const publicKey = keys.publicKey;
  const ctx = electionContext(contest, publicKey, candidates);

  // --- voters encrypt locally, prove validity, and SIGN with their credential ---
  const board = new BulletinBoard();
  const ballots: BallotEntry[] = voters.map((v, i) => {
    const { selection } = encryptSelection(publicKey, v.choice, K);
    const sig = sign(v.credential.secret, signingBytes(ctx, selection));
    board.append(boardBytes(ctx, v.credential.pub, selection, sig));
    return { voter: `voter-${i + 1}`, credentialPub: v.credential.pub, selection, sig };
  });

  // --- homomorphically aggregate per candidate; only TOTALS are ever decrypted ---
  const aggregates = Array.from({ length: K }, (_, j) =>
    addCiphertexts(ballots.map((b) => b.selection.enc[j]!)));

  // --- a participating subset (≥ threshold) of trustees decrypts each aggregate ---
  const subset = participants ?? keys.trustees.slice(0, keys.threshold).map((t) => t.index);
  const participating = keys.trustees.filter((t) => subset.includes(t.index));
  const decShares: DecShareEntry[] = participating.map((t) => {
    const shares = aggregates.map((agg) => decryptionShare(agg.a, t.share));
    const proofs = aggregates.map((agg, j) => proveDecryption(agg.a, t.verificationKey, shares[j]!, t.share));
    return { trusteeIndex: t.index, shares, proofs };
  });

  // --- Lagrange-combine the shares per candidate (recovers a^x, x never reconstructed) ---
  const results = aggregates.map((agg, j) => {
    const combined = combineShares(decShares.map((ds) => ({ index: ds.trusteeIndex, d: ds.shares[j]! })));
    return discreteLog(agg.b.subtract(combined), voters.length);
  });

  return {
    contest, candidates, numVoters: voters.length, eligibleRoll, publicKey,
    commitments: keys.commitments, trustees: keys.trustees.length, threshold: keys.threshold,
    ballots, boardRoot: board.root(), aggregates, decShares, results,
  };
}

/** A single trustee attempting to decrypt one candidate ciphertext alone — to show it can't. */
export function singleTrusteeAttempt(ct: Ciphertext, trustee: TrusteeShare, max: number): number | null {
  const partial = ct.b.subtract(mul(ct.a, trustee.share));
  try {
    return discreteLog(partial, max);
  } catch {
    return null;
  }
}
