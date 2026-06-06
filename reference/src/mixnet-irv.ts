// End-to-end verifiable INSTANT-RUNOFF (IRV) election, composed entirely from already-audited
// primitives — NO new cryptography:
//
//   1. BALLOT   — the K×K permutation-matrix ranked ballot (ranked.ts), signed onto an RFC-6962
//                 board with a single-use nullifier; its validity (a true strict ranking) is proven
//                 PRE-shuffle by the audited verifyRankingValid.
//   2. ANONYMIZE— flatten each ballot's matrix to an Item (Ciphertext[K·K]) and SHUFFLE all ballots
//                 through the verifiable re-encryption mixnet (mixnet.ts), breaking the voter↔ballot link.
//   3. REVEAL   — k-of-n threshold-decrypt every entry of every SHUFFLED matrix → cleartext
//                 permutation matrices, now unlinkable to voters.
//   4. TABULATE — deterministic public IRV (round-by-round elimination/transfer) over the revealed
//                 rankings; the verifier re-runs the identical tabulation.
//
// ─── PRIVACY MODEL — READ THIS ───────────────────────────────────────────────────────────────────
// Mixnet-IRV REVEALS THE FULL MULTISET OF CLEARTEXT RANKINGS. IRV's round-by-round elimination needs
// the actual rankings, so after the mix every ballot's complete strict ordering is published in the
// clear (the n decrypted K×K matrices). This path does NOT keep your ranking secret. The mixnet hides
// ONLY which voter cast which ranking — the voter↔ballot link — and that hiding is COMPUTATIONAL,
// under DDH on ristretto255 + the Fiat–Shamir/ROM assumption.
//
// This is STRICTLY WEAKER than the homomorphic Borda path (ranked.ts), which never reveals any
// individual ballot — only per-candidate Borda totals are ever decrypted. If per-ballot secrecy
// matters, use the Borda path, not mixnet-IRV. With small electorates, or any voter whose full
// ranking is unique/rare, revealing the ranking multiset is WEAKLY DE-ANONYMIZING (a pattern /
// "Italian" attack): mixnet-IRV provides NO coercion-resistance and NO receipt-freeness. UI/README
// copy MUST NOT claim "your ranking stays secret" for the IRV path — only "which voter cast which
// ranking is hidden" is true.
//
// PRE-AUDIT, like the rest of the engine: not independently audited; Fisher–Yates / scalar-mul are
// not constant-time (out of scope for a reference engine). Cost is O(n·K²) ElGamal decryptions +
// O(n·K²) Chaum–Pedersen verifications + an O(SECURITY_T·n·K²) shuffle proof — fine for a reference
// engine, not production-scale.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

import { decryptionShare, discreteLog, type Ciphertext } from './elgamal.js';
import { proveDecryption, verifyDecryption, type DecProof } from './proofs.js';
import { combineShares, verificationKeyAt, type KeySetup } from './threshold.js';
import { shuffleProve, verifyShuffle, SECURITY_T, type Item, type ShuffleProof } from './mixnet.js';
import {
  encryptRanking, verifyRankingValid, rankedSigningBytes, rankedBoardBytes,
  type RankedBallot, type RankedBallotEntry,
} from './ranked.js';
import { sign, verifySig, type Credential } from './credentials.js';
import { electionContext } from './codec.js';
import { BulletinBoard } from './bulletin.js';
import { pointToHex, type Point } from './group.js';
import type { Check, VerifyResult } from './verify.js';

export interface MixnetVoter {
  credential: Credential;
  ranking: number[]; // a permutation of 0..K-1 (full strict ranking; 0 = best)
}

/**
 * One trustee's decryption contribution for the WHOLE shuffled output: one share + one proof per
 * entry of every shuffled matrix, in the flattened entryIdx(item,i,r) order. Mirrors RankedDecShare
 * scaled to n·K·K.
 */
export interface MixnetDecShare {
  trusteeIndex: number; // 1-based; must be a registered trustee
  shares: Point[]; // length n·K·K; shares[idx] = decryptionShare(shuffled[item][i*K+r].a, x_trustee)
  proofs: DecProof[]; // length n·K·K; proofs[idx] proves shares[idx] honest for that entry's `a`
}

/** One IRV round, recomputed identically by prover and verifier (integer-only). */
export interface IrvRound {
  eliminated: number[]; // candidates eliminated BEFORE this round (ascending); [] for round 0
  tallies: number[]; // length K; first-preference count among non-eliminated candidates (eliminated → 0)
  eliminatedThisRound: number | null; // candidate dropped at END of this round, or null if a winner was declared
  winner: number | null; // candidate index if a strict majority / last-standing this round, else null
}

export interface MixnetIrvTranscript {
  contest: string;
  candidates: string[]; // length K
  numVoters: number; // pinned: MUST equal ballots.length
  eligibleRoll: Point[];
  publicKey: Point; // = commitments[0]
  commitments: Point[]; // Feldman C₀..C_{k-1}; length === threshold
  trustees: number; // n
  threshold: number; // k
  ballots: RankedBallotEntry[]; // ranked.ts type verbatim
  boardRoot: string; // RFC-6962 root over rankedBoardBytes(ctx, credPub, ballot, sig), board order
  shuffled: Item[]; // = L (shuffle OUTPUT); n re-encrypted flattened matrices, each Item length K·K
  shuffleProof: ShuffleProof; // proves `shuffled` is a re-enc shuffle of the RE-DERIVED L0; proof.t ≥ SECURITY_T
  decShares: MixnetDecShare[]; // ≥ k trustees; each .shares/.proofs length n·K·K in entryIdx order
  decryptedMatrices: number[][][]; // n matrices, each K×K of 0/1
  rounds: IrvRound[]; // full round-by-round trace (recomputed + matched by verifier)
  winner: number; // final IRV winner candidate index
}
// NOTE: there is intentionally NO `L0` field, NO `K` field (K = candidates.length), and NO per-voter
// linkage into `shuffled` — that linkage is exactly what the mixnet destroys.

// ── the ONE flatten/index convention (prover, share-gen, recovery, and verifier all call these) ──
/** Row-major flatten of a ranked ballot's matrix into a shuffle item: for i, for r → matrix[i][r]. */
export function flattenBallot(b: RankedBallot): Item {
  const K = b.matrix.length;
  const out: Ciphertext[] = [];
  for (let i = 0; i < K; i++) for (let r = 0; r < K; r++) out.push(b.matrix[i]![r]!);
  return out;
}
/** Inverse of flattenBallot: item[i*K + r] → matrix[i][r]. */
export function unflattenMatrix(item: Item, K: number): Ciphertext[][] {
  const m: Ciphertext[][] = [];
  for (let i = 0; i < K; i++) { const row: Ciphertext[] = []; for (let r = 0; r < K; r++) row.push(item[i * K + r]!); m.push(row); }
  return m;
}
/** Flattened decryption-share index: ((item·K)+i)·K + r — item-major, then candidate row i, then rank col r. */
export function entryIdx(item: number, i: number, r: number, K: number): number {
  return ((item * K) + i) * K + r;
}

type IrvResult = { rounds: IrvRound[]; winner: number } | { error: string };

/**
 * Read a decrypted 0/1 matrix as a ranking vector: rankOf[i] = the unique column with a 1 in row i.
 * Returns null (never throws) unless the matrix is a genuine permutation (every row exactly one 1,
 * every column used exactly once, all entries in {0,1}).
 */
export function ballotToRanks(matrix: number[][], K: number): number[] | null {
  if (matrix.length !== K) return null;
  const rankOf = new Array<number>(K);
  const colUsed = new Array<boolean>(K).fill(false);
  for (let i = 0; i < K; i++) {
    const row = matrix[i]!;
    if (row.length !== K) return null;
    let ones = 0;
    let col = -1;
    for (let r = 0; r < K; r++) {
      const v = row[r]!;
      if (v !== 0 && v !== 1) return null;
      if (v === 1) { ones++; col = r; }
    }
    if (ones !== 1 || colUsed[col]!) return null;
    colUsed[col] = true;
    rankOf[i] = col;
  }
  return rankOf;
}

/**
 * Fully deterministic public IRV tabulation, shared verbatim by prover and verifier. Integer counts
 * only — no floats, no division. Majority is strict (2·tally > n). One elimination per round with a
 * full re-count; tie-break = eliminate the FEWEST-first-preference candidate, ties broken by HIGHEST
 * candidate index (data-independent, reproducible from public data alone). Full strict K-rankings
 * never exhaust, so the active denominator is permanently n.
 */
export function tabulateIrv(decrypted: number[][][], K: number): IrvResult {
  const rankMatrix: number[][] = [];
  for (let b = 0; b < decrypted.length; b++) {
    const ranks = ballotToRanks(decrypted[b]!, K);
    if (ranks === null) return { error: `ballot ${b} is not a permutation matrix` };
    rankMatrix.push(ranks);
  }
  const n = rankMatrix.length;
  const eliminated = new Array<boolean>(K).fill(false);
  const rounds: IrvRound[] = [];
  let alive = K;
  for (let round = 0; round < K; round++) {
    const elimSnapshot = eliminated.map((e, c) => (e ? c : -1)).filter((c) => c >= 0);
    const tally = new Array<number>(K).fill(0);
    for (const rankOf of rankMatrix) {
      let best = -1;
      let bestRank = K;
      for (let c = 0; c < K; c++) if (!eliminated[c] && rankOf[c]! < bestRank) { bestRank = rankOf[c]!; best = c; }
      tally[best]! += 1;
    }
    if (tally.reduce((a, x) => a + x, 0) !== n) return { error: `round ${round}: active total != n` };
    let winner = -1;
    for (let c = 0; c < K; c++) if (!eliminated[c] && 2 * tally[c]! > n) { winner = c; break; }
    if (winner !== -1 || alive === 1) {
      if (winner === -1) for (let c = 0; c < K; c++) if (!eliminated[c]) { winner = c; break; } // last-one-standing
      rounds.push({ eliminated: elimSnapshot, tallies: tally, eliminatedThisRound: null, winner });
      return { rounds, winner };
    }
    let mn = Infinity;
    for (let c = 0; c < K; c++) if (!eliminated[c] && tally[c]! < mn) mn = tally[c]!;
    let victim = -1;
    for (let c = 0; c < K; c++) if (!eliminated[c] && tally[c]! === mn) victim = c; // ascending scan + overwrite ⇒ HIGHEST index
    rounds.push({ eliminated: elimSnapshot, tallies: tally, eliminatedThisRound: victim, winner: null });
    eliminated[victim] = true;
    alive--;
  }
  return { error: 'IRV did not terminate within K rounds (impossible for valid input)' };
}

/** Run a full mixnet-IRV election; trustee secrets stay with the caller. */
export function runMixnetElection(
  contest: string,
  candidates: string[],
  voters: MixnetVoter[],
  keys: KeySetup,
  eligibleRoll: Point[],
  participants?: number[],
): MixnetIrvTranscript {
  const K = candidates.length;
  const pk = keys.publicKey;
  const ctx = electionContext(contest, pk, candidates);

  const prepared = voters.map((v) => {
    if (v.ranking.length !== K) throw new Error('ranking length must equal candidate count');
    const { ballot } = encryptRanking(pk, v.ranking); // throws on a non-permutation ranking
    const sig = sign(v.credential.secret, rankedSigningBytes(ctx, ballot));
    return { credentialPub: v.credential.pub, ballot, sig };
  });
  prepared.sort((a, b) => pointToHex(a.credentialPub).localeCompare(pointToHex(b.credentialPub)));

  const board = new BulletinBoard();
  const ballots: RankedBallotEntry[] = prepared.map((e, i) => {
    board.append(rankedBoardBytes(ctx, e.credentialPub, e.ballot, e.sig));
    return { voter: `ballot-${i + 1}`, credentialPub: e.credentialPub, ballot: e.ballot, sig: e.sig };
  });

  const L0 = ballots.map((b) => flattenBallot(b.ballot)); // SAME (sorted) order as the board
  const { L, proof } = shuffleProve(pk, L0); // t defaults to SECURITY_T
  const n = ballots.length;

  const subset = participants ?? keys.trustees.slice(0, keys.threshold).map((t) => t.index);
  const participating = keys.trustees.filter((t) => subset.includes(t.index));
  const decShares: MixnetDecShare[] = participating.map((tr) => {
    const shares: Point[] = [];
    const proofs: DecProof[] = [];
    for (let item = 0; item < n; item++) {
      for (let i = 0; i < K; i++) {
        for (let r = 0; r < K; r++) {
          const a = L[item]![i * K + r]!.a;
          const d = decryptionShare(a, tr.share);
          shares.push(d);
          proofs.push(proveDecryption(a, tr.verificationKey, d, tr.share));
        }
      }
    }
    return { trusteeIndex: tr.index, shares, proofs };
  });

  const decryptedMatrices: number[][][] = [];
  for (let item = 0; item < n; item++) {
    const M: number[][] = [];
    for (let i = 0; i < K; i++) {
      const row: number[] = [];
      for (let r = 0; r < K; r++) {
        const idx = entryIdx(item, i, r, K);
        const combined = combineShares(decShares.map((ds) => ({ index: ds.trusteeIndex, d: ds.shares[idx]! })));
        row.push(discreteLog(L[item]![i * K + r]!.b.subtract(combined), 1)); // entries are single bits g^0/g^1
      }
      M.push(row);
    }
    decryptedMatrices.push(M);
  }

  const out = tabulateIrv(decryptedMatrices, K);
  if ('error' in out) throw new Error(out.error);

  return {
    contest, candidates, numVoters: voters.length, eligibleRoll, publicKey: pk,
    commitments: keys.commitments, trustees: keys.trustees.length, threshold: keys.threshold,
    ballots, boardRoot: board.root(), shuffled: L, shuffleProof: proof, decShares,
    decryptedMatrices, rounds: out.rounds, winner: out.winner,
  };
}

/** Verify a mixnet-IRV election trustlessly (always returns a verdict, never throws). */
export function verifyMixnetTranscript(t: MixnetIrvTranscript): VerifyResult {
  try {
    return verifyMixnetInner(t);
  } catch (err) {
    return { ok: false, results: null, checks: [{ name: 'Transcript is well-formed (no exception)', ok: false, detail: String(err) }] };
  }
}

function verifyMixnetInner(t: MixnetIrvTranscript): VerifyResult {
  const checks: Check[] = [];
  const K = t.candidates.length;
  const k = t.threshold;
  const n = t.ballots.length;
  const W = K * K;
  const nKK = n * K * K;
  const idxOk = (i: number): boolean => Number.isInteger(i) && i >= 1 && i <= t.trustees;

  // S0 — shape gate
  const shapeOk =
    K > 0 && Number.isInteger(k) && k >= 1 && Number.isInteger(t.trustees) && t.trustees >= k &&
    t.commitments.length === k && Number.isInteger(t.numVoters) && t.numVoters === n && n >= 1 &&
    t.ballots.every((b) =>
      b.ballot.matrix.length === K && b.ballot.matrix.every((row) => row.length === K) &&
      b.ballot.bitProofs.length === K && b.ballot.bitProofs.every((row) => row.length === K) &&
      b.ballot.rowSums.length === K && b.ballot.colSums.length === K) &&
    Array.isArray(t.shuffled) && t.shuffled.length === n && t.shuffled.every((it) => Array.isArray(it) && it.length === W) &&
    Array.isArray(t.decShares) && t.decShares.every((ds) => Array.isArray(ds.shares) && ds.shares.length === nKK && Array.isArray(ds.proofs) && ds.proofs.length === nKK) &&
    Array.isArray(t.decryptedMatrices) && t.decryptedMatrices.length === n &&
    t.decryptedMatrices.every((M) => M.length === K && M.every((row) => row.length === K && row.every((v) => v === 0 || v === 1))) &&
    Array.isArray(t.rounds) && t.rounds.length >= 1 && Number.isInteger(t.winner) && t.winner >= 0 && t.winner < K;
  checks.push({ name: 'Transcript shape: K×K ballots, n flattened items of width K², n·K² shares, well-formed rounds', ok: shapeOk });
  if (!shapeOk) return { ok: false, checks, results: null };

  // S1 — joint key
  checks.push({ name: 'Joint public key = commitment C₀', ok: t.commitments[0]!.equals(t.publicKey) });

  // S2 — bulletin board
  const ctx = electionContext(t.contest, t.publicKey, t.candidates);
  const board = new BulletinBoard();
  for (const b of t.ballots) board.append(rankedBoardBytes(ctx, b.credentialPub, b.ballot, b.sig));
  checks.push({ name: 'Bulletin-board Merkle root matches the published ballots', ok: board.root() === t.boardRoot });

  // S3 — eligibility + nullifier
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

  // S4 — pre-shuffle validity
  let invalid = 0;
  for (const b of t.ballots) if (!verifyRankingValid(t.publicKey, b.ballot)) invalid++;
  checks.push({ name: 'Every ballot is a valid strict ranking (permutation matrix)', ok: invalid === 0 });

  // S5 — RE-DERIVE L0 from the validated ballots (never trust a published L0) + verify the shuffle
  const L0 = t.ballots.map((b) => flattenBallot(b.ballot));
  checks.push({ name: 'Shuffle proof meets the SECURITY_T floor', ok: Number.isInteger(t.shuffleProof.t) && t.shuffleProof.t >= SECURITY_T });
  const sr = verifyShuffle(t.publicKey, L0, t.shuffled, t.shuffleProof);
  checks.push({ name: 'Shuffle is a proven re-encryption permutation of the board ballots (L0 re-derived, not trusted)', ok: sr.ok });

  // S6 — quorum + per-entry decryption proofs (read `a` from shuffled, never from the proof)
  const indices = t.decShares.map((d) => d.trusteeIndex);
  checks.push({
    name: `Decryption quorum: ≥ ${k} distinct registered trustees (1..${t.trustees})`,
    ok: new Set(indices).size === indices.length && indices.every(idxOk) && t.decShares.length >= k,
  });
  let badShares = 0;
  for (const ds of t.decShares) {
    if (!idxOk(ds.trusteeIndex)) { badShares += nKK; continue; }
    const pub = verificationKeyAt(t.commitments, ds.trusteeIndex);
    for (let item = 0; item < n; item++) {
      for (let i = 0; i < K; i++) {
        for (let r = 0; r < K; r++) {
          const a = t.shuffled[item]![i * K + r]!.a;
          const idx = entryIdx(item, i, r, K);
          if (!verifyDecryption(a, pub, ds.shares[idx]!, ds.proofs[idx]!)) badShares++;
        }
      }
    }
  }
  checks.push({ name: 'Every trustee decryption share is provably honest', ok: badShares === 0 });

  // S7 — recover the matrices ourselves + defensive permutation re-check
  const valid = t.decShares.filter((ds) => idxOk(ds.trusteeIndex));
  const recovered: number[][][] = [];
  let recoverBad = 0, fieldMismatch = 0;
  for (let item = 0; item < n; item++) {
    const M: number[][] = [];
    for (let i = 0; i < K; i++) {
      const row: number[] = [];
      for (let r = 0; r < K; r++) {
        const idx = entryIdx(item, i, r, K);
        const combined = combineShares(valid.map((ds) => ({ index: ds.trusteeIndex, d: ds.shares[idx]! })));
        let bit = -1;
        try { bit = discreteLog(t.shuffled[item]![i * K + r]!.b.subtract(combined), 1); } catch { recoverBad++; bit = -1; }
        row.push(bit);
        if (bit !== t.decryptedMatrices[item]![i]![r]) fieldMismatch++;
      }
      M.push(row);
    }
    recovered.push(M);
  }
  checks.push({ name: 'Recovered entries match the published decrypted matrices', ok: recoverBad === 0 && fieldMismatch === 0 });
  let nonPerm = 0;
  for (const M of recovered) {
    for (let i = 0; i < K; i++) { let s = 0; for (let r = 0; r < K; r++) s += M[i]![r]!; if (s !== 1) nonPerm++; }
    for (let r = 0; r < K; r++) { let s = 0; for (let i = 0; i < K; i++) s += M[i]![r]!; if (s !== 1) nonPerm++; }
  }
  checks.push({ name: 'Every recovered matrix is a permutation (every row & column sums to 1)', ok: nonPerm === 0 });

  // S8 — re-run IRV over the verifier's OWN recovered matrices and match the published trace
  const out = tabulateIrv(recovered, K);
  let irvOk = false;
  let round0: number[] | null = null;
  if (!('error' in out)) {
    const same =
      out.rounds.length === t.rounds.length &&
      out.rounds.every((R, j) => {
        const T = t.rounds[j]!;
        return JSON.stringify(R.eliminated) === JSON.stringify(T.eliminated) &&
          JSON.stringify(R.tallies) === JSON.stringify(T.tallies) &&
          R.eliminatedThisRound === T.eliminatedThisRound && R.winner === T.winner;
      }) &&
      out.winner === t.winner;
    irvOk = recoverBad === 0 && nonPerm === 0 && same;
    if (irvOk) round0 = out.rounds[0]!.tallies.slice();
  }
  checks.push({ name: 'IRV tabulation is correct and deterministic (recomputed over recovered matrices)', ok: irvOk });

  const allOk = checks.every((c) => c.ok);
  return { ok: allOk, checks, results: allOk ? round0 : null };
}
