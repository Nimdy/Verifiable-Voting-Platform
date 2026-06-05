// Orchestrates one end-to-end election and produces a PUBLIC TRANSCRIPT.
//
// The transcript is everything the world gets to see. It contains NO secret
// keys and NO individual plaintext votes — only the eligible-credential roll,
// encrypted ballots with their validity proofs and credential signatures, the
// Merkle root, and the trustees' proven decryption of the aggregate. Anyone can
// re-verify it (see verify.ts) trusting only the math.

import {
  combinePublicKey, encrypt, addCiphertexts, decryptionShare, discreteLog,
  trusteeKeygen, type Ciphertext, type TrusteeKey,
} from './elgamal.js';
import { proveBit, proveDecryption, type BitProof, type DecProof } from './proofs.js';
import { randScalar, mul, ZERO, type Point } from './group.js';
import { sign, type Credential, type Signature } from './credentials.js';
import { signingBytes, boardBytes } from './codec.js';
import { BulletinBoard } from './bulletin.js';

/** One voter: their (pseudonymous) credential and their choice. */
export interface Voter {
  credential: Credential;
  vote: 0 | 1;
}

export interface BallotEntry {
  voter: string; // a display label only — never linked to identity in a real deployment
  credentialPub: Point; // the eligible credential that signed this ballot (also the nullifier)
  ct: Ciphertext;
  proof: BitProof;
  sig: Signature;
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
  eligibleRoll: Point[]; // published set of eligible credential public keys
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
 * Run a yes/no (0/1) election. Each voter signs their encrypted ballot with their
 * credential; `eligibleRoll` is the published set of credential public keys allowed
 * to vote. Returns the public transcript (trustee secrets stay with the caller).
 */
export function runElection(
  contest: string,
  options: [string, string],
  voters: Voter[],
  trustees: TrusteeKey[],
  eligibleRoll: Point[],
): Transcript {
  const trusteePubs = trustees.map((t) => ({ index: t.index, pub: t.pub }));
  const publicKey = combinePublicKey(trustees.map((t) => t.pub));

  // --- voters encrypt locally, attach a validity proof, and SIGN with their credential ---
  const board = new BulletinBoard();
  const ballots: BallotEntry[] = voters.map((v, i) => {
    const r = randScalar();
    const ct = encrypt(publicKey, BigInt(v.vote), r);
    const proof = proveBit(publicKey, ct, v.vote, r);
    const sig = sign(v.credential.secret, signingBytes(ct, proof));
    board.append(boardBytes(v.credential.pub, ct, proof, sig));
    return { voter: `voter-${i + 1}`, credentialPub: v.credential.pub, ct, proof, sig };
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
  const claimedTally = discreteLog(messagePoint, voters.length);

  return {
    contest, options, numVoters: voters.length, eligibleRoll, trusteePubs, publicKey,
    ballots, boardRoot: board.root(), aggregate, decShares, claimedTally,
  };
}

/** A single trustee attempting to decrypt one ballot alone — to show it can't. */
export function singleTrusteeAttempt(ct: Ciphertext, trustee: TrusteeKey, max: number): number | null {
  const partial = ct.b.subtract(mul(ct.a, trustee.secret));
  try {
    return discreteLog(partial, max);
  } catch {
    return null;
  }
}
