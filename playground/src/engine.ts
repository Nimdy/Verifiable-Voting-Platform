// Thin UI wrapper over the EXACT audited protocol from ../reference.
// No crypto is reimplemented here — we only orchestrate and format.
import {
  setupTrustees, runElection, verifyTranscript, encryptSelection, auditSelection,
  issueCredential, sign, encrypt, proveBit, proveSumOne, addCiphertexts, randScalar, mod, N,
  signingBytes, boardBytes, electionContext, BulletinBoard,
  type Transcript, type VerifyResult, type TrusteeKey, type Voter, type Credential,
  type BallotEntry, type Selection, type Point,
} from '@engine';

export type { Transcript, VerifyResult, TrusteeKey, Voter, Credential };

const toHex = (b: Uint8Array): string =>
  Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');

export const makeTrustees = (n: number): TrusteeKey[] => setupTrustees(n);
export const issueSpare = (): Credential => issueCredential();
export const newVoter = (choice: number): Voter => ({ credential: issueCredential(), choice });

export const tally = (
  contest: string,
  candidates: string[],
  voters: Voter[],
  trustees: TrusteeKey[],
  extraEligible: Point[],
): Transcript =>
  runElection(contest, candidates, voters, trustees, [...voters.map((v) => v.credential.pub), ...extraEligible]);

export const verify = (t: Transcript): VerifyResult => verifyTranscript(t);

export const ballotCipher = (t: Transcript, i: number): string => {
  const b = t.ballots[i];
  return b ? toHex(b.selection.enc[0]!.b.toRawBytes()) : '';
};

/** Cast-as-intended check: a device that encrypted `deviceChoice` is audited against `expected`. */
export const auditCheck = (t: Transcript, deviceChoice: number, expected: number): boolean => {
  const { selection, randomness } = encryptSelection(t.publicKey, deviceChoice, t.candidates.length);
  return auditSelection(t.publicKey, selection, randomness, expected);
};

// ---- forging helpers for the "try to cheat" panel --------------------------
const ctxOf = (t: Transcript): Uint8Array => electionContext(t.contest, t.publicKey, t.candidates);

function makeBallot(ctx: Uint8Array, cred: Credential, selection: Selection, label: string): BallotEntry {
  return { voter: label, credentialPub: cred.pub, selection, sig: sign(cred.secret, signingBytes(ctx, selection)) };
}
function rootOf(ctx: Uint8Array, ballots: BallotEntry[]): string {
  const board = new BulletinBoard();
  for (const b of ballots) board.append(boardBytes(ctx, b.credentialPub, b.selection, b.sig));
  return board.root();
}
function overvoteSelection(pk: Point, K: number): Selection {
  const enc = [], bitProofs = [], rs: bigint[] = [];
  for (let j = 0; j < K; j++) {
    const v: 0 | 1 = j < 2 ? 1 : 0;
    const r = randScalar();
    const ct = encrypt(pk, BigInt(v), r);
    enc.push(ct); bitProofs.push(proveBit(pk, ct, v, r)); rs.push(r);
  }
  const R = rs.reduce((a, b) => mod(a + b, N), 0n);
  return { enc, bitProofs, sumProof: proveSumOne(pk, addCiphertexts(enc), R) };
}

export const tamperBallot = (t: Transcript): Transcript => ({
  ...t,
  ballots: t.ballots.map((b, i) =>
    i === 0
      ? { ...b, selection: { ...b.selection, enc: b.selection.enc.map((c, j) => (j === 0 ? { a: c.a, b: c.b.add(t.publicKey) } : c)) } }
      : b),
});
export const rigResult = (t: Transcript): Transcript => ({ ...t, results: t.results.map((n, j) => (j === 0 ? n + 2 : n)) });
export const doubleVote = (t: Transcript, voters: Voter[]): Transcript => {
  const ctx = ctxOf(t);
  const bs = [...t.ballots, makeBallot(ctx, voters[0]!.credential, encryptSelection(t.publicKey, 0, t.candidates.length).selection, 'voter-1-again')];
  return { ...t, ballots: bs, boardRoot: rootOf(ctx, bs) };
};
export const ineligibleVote = (t: Transcript): Transcript => {
  const ctx = ctxOf(t);
  const bs = [...t.ballots, makeBallot(ctx, issueCredential(), encryptSelection(t.publicKey, 0, t.candidates.length).selection, 'gate-crasher')];
  return { ...t, ballots: bs, boardRoot: rootOf(ctx, bs) };
};
export const overvote = (t: Transcript, spare: Credential): Transcript => {
  const ctx = ctxOf(t);
  const bs = [...t.ballots, makeBallot(ctx, spare, overvoteSelection(t.publicKey, t.candidates.length), 'overvoter')];
  return { ...t, ballots: bs, boardRoot: rootOf(ctx, bs) };
};
