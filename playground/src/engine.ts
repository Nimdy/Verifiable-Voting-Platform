// Thin UI wrapper over the EXACT audited protocol from ../reference.
// No crypto is reimplemented here — we only orchestrate and format.
import {
  setupKeys, runElection, verifyTranscript, encryptSelection, auditSelection,
  issueCredential, sign, encrypt, proveBit, proveSumOne, proveSumEqual, addCiphertexts, randScalar, mod, N,
  signingBytes, boardBytes, electionContext, BulletinBoard, Registrar,
  type Transcript, type VerifyResult, type KeySetup, type Voter, type Credential,
  type VoterCredential, type BallotEntry, type Selection, type Point,
  runStructuredElection, verifyStructured, childrenOf, allTags, isLeaf, leafContests,
  type ElectionSpec, type ElectionResult, type ContestSpec, type StructuredVoter,
  encryptRanking, verifyRankingValid, verifyBit, verifySumEqual, runRankedElection, verifyRankedTranscript,
  type RankedBallot, type RankedTranscript, type RankedVoter, type Ciphertext, type BitProof,
  runMixnetElection, verifyMixnetTranscript, ballotToRanks, SECURITY_T,
  type MixnetVoter, type MixnetIrvTranscript, type IrvRound,
} from '@engine';

export type { Transcript, VerifyResult, KeySetup, Voter, Credential };

/** 3 trustees; ANY 2 can decrypt (survives one offline/malicious trustee). */
export const TRUSTEES = 3;
export const THRESHOLD = 2;

const toHex = (b: Uint8Array): string =>
  Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');

export const makeKeys = (): KeySetup => setupKeys(TRUSTEES, THRESHOLD);
export const issueSpare = (): Credential => issueCredential();
export const newVoter = (choice: number): Voter => ({ credential: issueCredential(), choice });

export const tally = (
  contest: string,
  candidates: string[],
  voters: Voter[],
  keys: KeySetup,
  extraEligible: Point[],
): Transcript =>
  runElection(contest, candidates, voters, keys, [...voters.map((v) => v.credential.pub), ...extraEligible]);

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

// ---- lifecycle walkthrough scenario (real artifacts, revealed step by step) -
export const hexShort = (h: string, n = 14): string => (h.length > n ? h.slice(0, n) + '…' : h);
export const ptShort = (p: Point, n = 14): string => hexShort(toHex(p.toRawBytes()), n);

export interface Scenario {
  contest: string;
  candidates: string[];
  keys: KeySetup;
  registrar: Registrar;
  packets: VoterCredential[];
  voters: Voter[];
  spare: Credential; // an eligible-but-unused credential (for the overvote demo)
  transcript: Transcript;
}

/** Build one complete election with all the real intermediate artifacts the walkthrough reveals. */
export function buildScenario(): Scenario {
  const contest = 'Best team lunch? 🍽️';
  const candidates = ['🌮 Tacos', '🍕 Pizza', '🍣 Sushi', '🥗 Salad'];
  const keys = setupKeys(5, 3); // 5 trustees, any 3 decrypt
  const registrar = new Registrar();
  const packets = registrar.register(Array.from({ length: 8 }, (_, i) => ({ id: `citizen-${i + 1}` })));
  const choices = [0, 1, 0, 2, 0, 3, 1]; // 7 of 8 registered actually vote
  const voters: Voter[] = choices.map((choice, i) => ({ credential: packets[i]!.credential, choice }));
  const spare = packets[7]!.credential; // registered but did not vote
  const transcript = runElection(contest, candidates, voters, keys, registrar.publishedRoll(), [1, 3, 5]);
  return { contest, candidates, keys, registrar, packets, voters, spare, transcript };
}

// ---- structured (hierarchical, tagged) ballot scenario for the drill-down UI -
export { childrenOf, allTags, isLeaf, leafContests, verifyStructured };
export type { ElectionSpec, ElectionResult, ContestSpec };

export interface BallotScenario {
  spec: ElectionSpec;
  result: ElectionResult;
  ok: boolean;
  verified: Set<string>; // ids of contests that verified
}

export function buildBallotScenario(): BallotScenario {
  const spec: ElectionSpec = {
    title: 'Community decisions',
    contests: [
      { id: 'gov', title: '🏛️ Governance', tags: ['governance'] },
      { id: 'chair', title: 'Board chair', tags: ['governance', 'leadership'], parent: 'gov', candidates: ['Ada', 'Grace', 'Alan'] },
      { id: 'cadence', title: 'Meeting cadence', tags: ['governance'], parent: 'gov', candidates: ['Weekly', 'Biweekly', 'Monthly'] },
      { id: 'budget', title: '💸 Budget', tags: ['budget'] },
      { id: 'park', title: 'Park budget', tags: ['budget', 'parks'], parent: 'budget', candidates: ['Low', 'Mid', 'High'] },
      { id: 'lib', title: 'Library hours', tags: ['budget'], parent: 'budget', candidates: ['Keep', 'Extend'] },
      { id: 'fest', title: '🎉 Festival theme', tags: ['events'], candidates: ['Music', 'Food', 'Art'] },
    ],
  };
  const keys = setupKeys(5, 3);
  const reg = new Registrar();
  const packets = reg.register(Array.from({ length: 6 }, (_, i) => ({ id: `m-${i + 1}` })));
  const roll = reg.publishedRoll();
  const leaves = leafContests(spec);
  const voters: StructuredVoter[] = packets.map((pk, i) => {
    const choices: Record<string, number> = {};
    for (const c of leaves) {
      if ((i + c.id.length) % 4 !== 0) choices[c.id] = (i + c.title.length) % c.candidates!.length; // most vote; some abstain
    }
    return { credential: pk.credential, choices };
  });
  const result = runStructuredElection(spec, voters, keys, roll);
  const v = verifyStructured(result);
  return { spec, result, ok: v.ok, verified: new Set(v.perContest.filter((p) => p.result.ok).map((p) => p.id)) };
}

// ---- ranked-choice (Borda) — thin wrappers over the reference ranked engine ----
// No crypto is reimplemented: every helper calls the EXACT ranked primitives from
// reference/src/ranked.ts (encryptRanking / verifyRankingValid / runRankedElection /
// verifyRankedTranscript) and proofs.ts (verifyBit / verifySumEqual). This is the BORDA
// path — no mixnet, only per-candidate point totals are decrypted (never reveals a ballot).
// True IRV elimination (which instead reveals the anonymized ranking multiset) is the
// separate mixnet path below: see runIrv / verifyIrv and the Instant-runoff tab.
export type { RankedBallot, RankedTranscript, RankedVoter };

export const newRankedVoter = (ranking: number[]): RankedVoter => ({ credential: issueCredential(), ranking });

/** Mirrors `tally()`: roll = the voters' own credentials + any spare eligible creds. */
export const rankedTally = (
  contest: string,
  candidates: string[],
  voters: RankedVoter[],
  keys: KeySetup,
  extraEligible: Point[],
): RankedTranscript =>
  runRankedElection(contest, candidates, voters, keys, [...voters.map((v) => v.credential.pub), ...extraEligible]);

export const verifyRanked = (t: RankedTranscript): VerifyResult => verifyRankedTranscript(t);

/** Build ONE real local ballot (the K×K ciphertext matrix + all ZK proofs) from a ranking. */
export const buildRankedBallot = (pk: Point, ranking: number[]): RankedBallot => encryptRanking(pk, ranking).ballot;

/** Truncated ciphertext hex for a single grid cell (hover tooltip: "this is real encryption"). */
export const cellCipher = (b: RankedBallot, cand: number, rank: number): string =>
  hexShort(toHex(b.matrix[cand]![rank]!.b.toRawBytes()), 20);

export interface GridVerdict {
  cells: boolean[][];                    // cells[candidate][rank] — real disjunctive bit-proof result
  rows: { sum: number; ok: boolean }[];  // each candidate gets exactly one rank
  cols: { sum: number; ok: boolean }[];  // each rank goes to exactly one candidate
  overall: boolean;
}

/**
 * Drive the live grid badges by running the REAL primitives per cell / row / column.
 * The pass/fail booleans are 100% the actual verifier (verifyBit / verifySumEqual /
 * verifyRankingValid). Only the displayed Σ number is cosmetic — it defaults to 1, or
 * uses the caller-supplied true sums for the forged-ballot demo.
 */
export const verifyGrid = (
  pk: Point,
  b: RankedBallot,
  trueSums?: { rows: number[]; cols: number[] },
): GridVerdict => {
  const K = b.matrix.length;
  const cells = b.matrix.map((row, i) => row.map((ct, r) => verifyBit(pk, ct, b.bitProofs[i]![r]!)));
  const rows = b.matrix.map((row, i) => ({
    sum: trueSums?.rows[i] ?? 1,
    ok: verifySumEqual(pk, addCiphertexts(row), b.rowSums[i]!, 1),
  }));
  const cols = Array.from({ length: K }, (_, r) => ({
    sum: trueSums?.cols[r] ?? 1,
    ok: verifySumEqual(pk, addCiphertexts(b.matrix.map((row) => row[r]!)), b.colSums[r]!, 1),
  }));
  return { cells, rows, cols, overall: verifyRankingValid(pk, b) };
};

/**
 * SOUNDNESS demo — forge a GENUINELY invalid (non-permutation) ranked ballot, bypassing
 * encryptRanking's permutation guard, built from the SAME primitives as overvoteSelection.
 * Candidates 0 AND 1 both get rank 0, so column 0 truly sums to 2 and column 1 to 0. Every
 * cell is still a real 0/1 bit and every row still sums to 1, but the real verifySumEqual(…,1)
 * rejects columns 0 and 1 honestly — nothing is hardcoded.
 */
export const forgeInvalidBallot = (
  pk: Point,
  K: number,
): { ballot: RankedBallot; trueSums: { rows: number[]; cols: number[] } } => {
  const rank = [0, 0, 2, 3].slice(0, K); // candidate i → rank[i]; deliberately NOT a permutation
  const matrix: Ciphertext[][] = [];
  const bitProofs: BitProof[][] = [];
  const rnd: bigint[][] = [];
  for (let i = 0; i < K; i++) {
    matrix[i] = []; bitProofs[i] = []; rnd[i] = [];
    for (let r = 0; r < K; r++) {
      const v: 0 | 1 = rank[i] === r ? 1 : 0;
      const rr = randScalar();
      const ct = encrypt(pk, BigInt(v), rr);
      matrix[i]!.push(ct); bitProofs[i]!.push(proveBit(pk, ct, v, rr)); rnd[i]!.push(rr);
    }
  }
  const rowSums = matrix.map((row, i) => proveSumEqual(pk, addCiphertexts(row), rnd[i]!.reduce((a, b) => mod(a + b, N), 0n), 1));
  const colSums = Array.from({ length: K }, (_, r) =>
    proveSumEqual(pk, addCiphertexts(matrix.map((row) => row[r]!)), rnd.reduce((a, row) => mod(a + row[r]!, N), 0n), 1));
  const trueRows = Array.from({ length: K }, () => 1); // each candidate still has exactly one rank
  const trueCols = Array.from({ length: K }, (_, r) => rank.filter((x) => x === r).length); // [2,0,1,1]
  return { ballot: { matrix, bitProofs, rowSums, colSums }, trueSums: { rows: trueRows, cols: trueCols } };
};

// ---- ranked-choice IRV (mixnet) — thin wrappers over the audited mixnet-irv engine -----------
// No crypto is reimplemented: every helper calls the EXACT primitives from reference/src/mixnet-irv.ts
// (runMixnetElection / verifyMixnetTranscript). HONEST SCOPE: mixnet-IRV reveals the anonymized
// ranking multiset and hides only the voter↔ballot link (computational, DDH) — weaker than Borda.
export type { MixnetVoter, MixnetIrvTranscript, IrvRound };
export { ballotToRanks, SECURITY_T };

export const newMixnetVoter = (ranking: number[]): MixnetVoter => ({ credential: issueCredential(), ranking });

/** Mirrors tally()/rankedTally(): roll = the voters' own credentials + any spare eligible creds. */
export const runIrv = (
  contest: string,
  candidates: string[],
  voters: MixnetVoter[],
  keys: KeySetup,
  extraEligible: Point[],
): MixnetIrvTranscript =>
  runMixnetElection(contest, candidates, voters, keys, [...voters.map((v) => v.credential.pub), ...extraEligible]);

export const verifyIrv = (t: MixnetIrvTranscript): VerifyResult => verifyMixnetTranscript(t);

/** A short credential pub for the "board order" column (links to a person only via the registrar). */
export const credShort = (t: MixnetIrvTranscript, i: number): string => {
  const b = t.ballots[i];
  return b ? ptShort(b.credentialPub, 10) : '';
};

/** A short ciphertext sample for a shuffled item — DELIBERATELY carries no identity (that's the point). */
export const itemSampleHex = (t: MixnetIrvTranscript, item: number): string => {
  const it = t.shuffled[item];
  return it && it[0] ? hexShort(toHex(it[0]!.b.toRawBytes()), 12) : '';
};
