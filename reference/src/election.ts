// Orchestrates one end-to-end multi-candidate election and produces a PUBLIC
// TRANSCRIPT. A ballot selects exactly one of K candidates, encrypted as K
// 0/1 ciphertexts (one per candidate) with a bit proof each, plus one
// "exactly-one-selected" proof. Only the per-candidate TOTALS are ever decrypted.

import {
  combinePublicKey, encrypt, addCiphertexts, decryptionShare, discreteLog,
  trusteeKeygen, type Ciphertext, type TrusteeKey,
} from './elgamal.js';
import {
  proveBit, verifyBit, proveDecryption, proveSumOne, verifySumOne,
  type BitProof, type DecProof, type SumProof,
} from './proofs.js';
import { randScalar, mul, mod, N, ZERO, type Point } from './group.js';
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
  trusteePubs: { index: number; pub: Point }[];
  publicKey: Point;
  ballots: BallotEntry[];
  boardRoot: string;
  aggregates: Ciphertext[]; // per candidate
  decShares: DecShareEntry[]; // per trustee
  results: number[]; // votes per candidate (sums to numVoters)
}

/** Create n trustees with fresh random secret-key shares. */
export function setupTrustees(n: number): TrusteeKey[] {
  return Array.from({ length: n }, (_, i) => trusteeKeygen(i + 1, randScalar()));
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
 * randomness and confirm it encodes exactly `choice`. A spoiled ballot is then
 * discarded and the voter re-votes — so a cheating device cannot know in advance
 * whether it will be audited.
 */
export function auditSelection(pk: Point, sel: Selection, randomness: bigint[], choice: number): boolean {
  if (randomness.length !== sel.enc.length) return false;
  if (!Number.isInteger(choice) || choice < 0 || choice >= sel.enc.length) return false;
  // (a) the ciphertexts open to exactly the claimed choice under the revealed randomness …
  for (let j = 0; j < sel.enc.length; j++) {
    const v: 0 | 1 = j === choice ? 1 : 0;
    const expected = encrypt(pk, BigInt(v), randomness[j]!);
    if (!expected.a.equals(sel.enc[j]!.a) || !expected.b.equals(sel.enc[j]!.b)) return false;
  }
  // (b) … AND the attached proofs are valid, so a successful audit attests a fully castable ballot.
  for (let j = 0; j < sel.enc.length; j++) {
    if (!verifyBit(pk, sel.enc[j]!, sel.bitProofs[j]!)) return false;
  }
  return verifySumOne(pk, addCiphertexts(sel.enc), sel.sumProof);
}

/**
 * Run a multi-candidate election. Each voter signs their encrypted selection with
 * their credential; `eligibleRoll` is the published set of credential public keys
 * allowed to vote. Returns the public transcript (trustee secrets stay with caller).
 */
export function runElection(
  contest: string,
  candidates: string[],
  voters: Voter[],
  trustees: TrusteeKey[],
  eligibleRoll: Point[],
): Transcript {
  const K = candidates.length;
  const trusteePubs = trustees.map((t) => ({ index: t.index, pub: t.pub }));
  const publicKey = combinePublicKey(trustees.map((t) => t.pub));

  // --- voters encrypt locally, prove validity, and SIGN with their credential ---
  const ctx = electionContext(contest, publicKey, candidates);
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

  // --- each trustee proves it decrypted each candidate aggregate honestly ---
  const decShares: DecShareEntry[] = trustees.map((t) => {
    const shares = aggregates.map((agg) => decryptionShare(agg.a, t.secret));
    const proofs = aggregates.map((agg, j) => proveDecryption(agg.a, t.pub, shares[j]!, t.secret));
    return { trusteeIndex: t.index, shares, proofs };
  });

  // --- combine shares per candidate and read off each total (held by NO single party) ---
  const results = aggregates.map((agg, j) => {
    const combined = decShares.reduce<Point>((acc, ds) => acc.add(ds.shares[j]!), ZERO);
    return discreteLog(agg.b.subtract(combined), voters.length);
  });

  return {
    contest, candidates, numVoters: voters.length, eligibleRoll, trusteePubs, publicKey,
    ballots, boardRoot: board.root(), aggregates, decShares, results,
  };
}

/** A single trustee attempting to decrypt one candidate ciphertext alone — to show it can't. */
export function singleTrusteeAttempt(ct: Ciphertext, trustee: TrusteeKey, max: number): number | null {
  const partial = ct.b.subtract(mul(ct.a, trustee.secret));
  try {
    return discreteLog(partial, max);
  } catch {
    return null;
  }
}
