// Thin UI wrapper over the EXACT audited protocol from ../reference.
// No crypto is reimplemented here — we only orchestrate and format.
import {
  setupTrustees, runElection, verifyTranscript,
  issueCredential, sign, encrypt, proveBit, verifyBit, randScalar,
  signingBytes, boardBytes, BulletinBoard,
  type Transcript, type VerifyResult, type TrusteeKey, type Voter, type Credential,
  type BallotEntry, type Point,
} from '@engine';

export type { Transcript, VerifyResult, TrusteeKey, Voter };

const OPTIONS: [string, string] = ['No', 'Yes'];
const toHex = (b: Uint8Array): string =>
  Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');

export const makeTrustees = (n: number): TrusteeKey[] => setupTrustees(n);

/** Each cast registers a fresh eligible voter credential + their choice. */
export const newVoter = (vote: 0 | 1): Voter => ({ credential: issueCredential(), vote });

export const tally = (question: string, voters: Voter[], trustees: TrusteeKey[]): Transcript =>
  runElection(question, OPTIONS, voters, trustees, voters.map((v) => v.credential.pub));

export const verify = (t: Transcript): VerifyResult => verifyTranscript(t);

export const ballotCipher = (t: Transcript, i: number): string => {
  const b = t.ballots[i];
  return b ? toHex(b.ct.b.toRawBytes()) : '';
};
export const yesCount = (t: Transcript): number => t.claimedTally;
export const noCount = (t: Transcript): number => t.numVoters - t.claimedTally;

// ---- helpers to forge ballots for the "try to cheat" panel -----------------
function makeBallot(cred: Credential, vote: 0 | 1, pk: Point, label: string): BallotEntry {
  const r = randScalar();
  const ct = encrypt(pk, BigInt(vote), r);
  const proof = proveBit(pk, ct, vote, r);
  const sig = sign(cred.secret, signingBytes(ct, proof));
  return { voter: label, credentialPub: cred.pub, ct, proof, sig };
}
function rootOf(ballots: BallotEntry[]): string {
  const board = new BulletinBoard();
  for (const b of ballots) board.append(boardBytes(b.credentialPub, b.ct, b.proof, b.sig));
  return board.root();
}

// ---- insider attacks -------------------------------------------------------

/** An admin secretly flips a stored ballot. */
export const tamperBallot = (t: Transcript): Transcript => ({
  ...t,
  ballots: t.ballots.map((b, i) =>
    i === 0 ? { ...b, ct: { a: b.ct.a, b: b.ct.b.add(t.publicKey) } } : b),
});

/** A corrupt authority lies about the result. */
export const rigResult = (t: Transcript): Transcript => ({
  ...t,
  claimedTally: t.claimedTally === t.numVoters ? 0 : t.numVoters,
});

/** Voter #1 tries to vote a second time with the same credential. */
export const doubleVote = (t: Transcript, voters: Voter[]): Transcript => {
  const ballots = [...t.ballots, makeBallot(voters[0]!.credential, 1, t.publicKey, 'voter-1-again')];
  return { ...t, ballots, boardRoot: rootOf(ballots) };
};

/** Someone not on the roll forges a credential and votes. */
export const ineligibleVote = (t: Transcript): Transcript => {
  const ballots = [...t.ballots, makeBallot(issueCredential(), 1, t.publicKey, 'gate-crasher')];
  return { ...t, ballots, boardRoot: rootOf(ballots) };
};

/** A voter tries to stuff an out-of-range vote ("10"). Returns whether it was accepted. */
export const stuffingAccepted = (t: Transcript): boolean => {
  const r = randScalar();
  const ct = encrypt(t.publicKey, 10n, r);
  return verifyBit(t.publicKey, ct, proveBit(t.publicKey, ct, 1, r));
};
