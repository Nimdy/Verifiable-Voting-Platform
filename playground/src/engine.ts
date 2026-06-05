// Thin UI wrapper over the EXACT audited protocol from ../reference.
// No crypto is reimplemented here — we only orchestrate and format.
import {
  setupTrustees, runElection, verifyTranscript, encrypt, proveBit, verifyBit, randScalar,
  type Transcript, type VerifyResult, type TrusteeKey,
} from '@engine';

export type { Transcript, VerifyResult, TrusteeKey };

const toHex = (b: Uint8Array): string =>
  Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');

export const makeTrustees = (n: number): TrusteeKey[] => setupTrustees(n);

export const tally = (
  question: string,
  options: [string, string],
  votes: (0 | 1)[],
  trustees: TrusteeKey[],
): Transcript => runElection(question, options, votes, trustees);

export const verify = (t: Transcript): VerifyResult => verifyTranscript(t);

/** The encrypted ballot as the public sees it (truncated hex of the b component). */
export const ballotCipher = (t: Transcript, i: number): string => {
  const b = t.ballots[i];
  return b ? toHex(b.ct.b.toRawBytes()) : '';
};

export const yesCount = (t: Transcript): number => t.claimedTally;
export const noCount = (t: Transcript): number => t.numVoters - t.claimedTally;

// ---- insider attacks (for the "try to cheat" panel) -----------------------

/** An admin secretly flips a stored ballot. */
export const tamperBallot = (t: Transcript, idx: number): Transcript => ({
  ...t,
  ballots: t.ballots.map((b, i) =>
    i === idx ? { ...b, ct: { a: b.ct.a, b: b.ct.b.add(t.publicKey) } } : b),
});

/** A corrupt authority lies about the result. */
export const rigResult = (t: Transcript): Transcript => ({
  ...t,
  claimedTally: t.claimedTally === t.numVoters ? 0 : t.numVoters,
});

/** A voter tries to stuff an out-of-range vote ("10"). Returns whether it was accepted. */
export const stuffingAccepted = (t: Transcript): boolean => {
  const r = randScalar();
  const ct = encrypt(t.publicKey, 10n, r);
  const proof = proveBit(t.publicKey, ct, 1, r); // lie: claim it's a "1"
  return verifyBit(t.publicKey, ct, proof);
};
