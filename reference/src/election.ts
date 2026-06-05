// Orchestrates one end-to-end election and produces a PUBLIC TRANSCRIPT.
//
// The transcript is everything the world gets to see. It contains NO secret
// keys and NO individual plaintext votes — only encrypted ballots, their
// validity proofs, the Merkle root, and the trustees' proven decryption of the
// aggregate. Anyone can re-verify it (see verify.ts) trusting only the math.

import {
  combinePublicKey, encrypt, addCiphertexts, decryptionShare, discreteLog,
  trusteeKeygen, type Ciphertext, type TrusteeKey,
} from './elgamal.js';
import { proveBit, proveDecryption, type BitProof, type DecProof } from './proofs.js';
import { randScalar, mul, ZERO, type Point } from './group.js';
import { serializeBallot } from './codec.js';
import { BulletinBoard } from './bulletin.js';

export interface BallotEntry {
  voter: string; // a label only — never linked to identity in a real deployment
  ct: Ciphertext;
  proof: BitProof;
}

export interface DecShareEntry {
  trusteeIndex: number;
  share: Point;
  proof: DecProof;
}

export interface Transcript {
  contest: string;
  options: [string, string]; // [option for 0, option for 1]
  numVoters: number;
  trusteePubs: { index: number; pub: Point }[];
  publicKey: Point;
  ballots: BallotEntry[];
  boardRoot: string;
  aggregate: Ciphertext;
  decShares: DecShareEntry[];
  claimedTally: number; // number of "1" votes the authority claims
}

/** Create n trustees with fresh random secret-key shares. */
export function setupTrustees(n: number): TrusteeKey[] {
  return Array.from({ length: n }, (_, i) => trusteeKeygen(i + 1, randScalar()));
}

/**
 * Run a yes/no (0/1) election over `votes`, using `trustees` for the joint key
 * and threshold decryption. Returns the public transcript. Trustee secrets stay
 * with the caller and are never placed in the transcript.
 */
export function runElection(
  contest: string,
  options: [string, string],
  votes: (0 | 1)[],
  trustees: TrusteeKey[],
): Transcript {
  const trusteePubs = trustees.map((t) => ({ index: t.index, pub: t.pub }));
  const publicKey = combinePublicKey(trustees.map((t) => t.pub));

  // --- voters encrypt locally and attach a validity proof ---
  const board = new BulletinBoard();
  const ballots: BallotEntry[] = votes.map((v, i) => {
    const r = randScalar();
    const ct = encrypt(publicKey, BigInt(v), r);
    const proof = proveBit(publicKey, ct, v, r);
    board.append(serializeBallot(ct, proof));
    return { voter: `voter-${i + 1}`, ct, proof };
  });

  // --- homomorphically aggregate; only the TOTAL will ever be decrypted ---
  const aggregate = addCiphertexts(ballots.map((b) => b.ct));

  // --- each trustee proves it decrypted the aggregate honestly ---
  const decShares: DecShareEntry[] = trustees.map((t) => {
    const share = decryptionShare(aggregate.a, t.secret);
    const proof = proveDecryption(aggregate.a, t.pub, share, t.secret);
    return { trusteeIndex: t.index, share, proof };
  });

  // --- combine shares and read off the tally (held by NO single party) ---
  const combined = decShares.reduce<Point>((acc, s) => acc.add(s.share), ZERO);
  const messagePoint = aggregate.b.subtract(combined); // = g^{Σ votes}
  const claimedTally = discreteLog(messagePoint, votes.length);

  return {
    contest, options, numVoters: votes.length, trusteePubs, publicKey,
    ballots, boardRoot: board.root(), aggregate, decShares, claimedTally,
  };
}

/** A single trustee attempting to decrypt one ballot alone — to show it can't. */
export function singleTrusteeAttempt(ct: Ciphertext, trustee: TrusteeKey, max: number): number | null {
  // The best a lone trustee can do is apply its own share; the message is still
  // masked by every OTHER trustee's secret, so the discrete log won't be found.
  const partial = ct.b.subtract(mul(ct.a, trustee.secret));
  try {
    return discreteLog(partial, max);
  } catch {
    return null;
  }
}
