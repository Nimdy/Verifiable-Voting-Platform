// Selene-style verifiable trackers with coercion-MITIGATION (ADR-0011) — REDUCED-BUT-HONEST variant.
//
// WHAT THIS IS. After the election, the board publishes, in cleartext, a shuffled list of (tracker, vote)
// rows. Each voter privately recovers her own tracker — a group POINT — using only her trapdoor key, finds
// that exact point among the public rows, and reads her own vote. That is TRANSPARENT INDIVIDUAL
// VERIFIABILITY with no per-voter zero-knowledge proof to interpret. The pairing of trackers to votes is a
// verifiable re-encryption shuffle (mixnet.ts, Sako–Kilian, 2⁻¹²⁸) of the committed board, threshold-
// decrypted with Chaum–Pedersen correctness proofs (threshold.ts) — so the rows are UNIVERSALLY verifiable.
//
// THE COERCION-MITIGATION MECHANISM (Ryan–Rønne–Iovino 2016). The voter's tracker reaches her through a
// deferred notification Notif = (a, β) = (r·G, T + r·pk) toward her dual public key pk = x·G. She recovers
// T = β − x·a. Under coercion she fabricates a FAKE ephemeral opening a' = x⁻¹·(β − T′) that points the SAME
// notification at ANY palatable posted row T′, while her key x and published pk = x·G are NEVER repudiated —
// so a coercer (lacking x and the untappable channel) cannot tell the fake opening from the real one.
// Equivocation is on the EPHEMERAL opening, NEVER the key: a fake key tk′ would be publicly falsified by
// pk = x·G, which is why this is the only sound form.
//
// HONEST SCOPE — coercion MITIGATION, NOT coercion RESISTANCE (read before claiming anything):
//   • This is STRICTLY WEAKER than JCJ/Civitas. There are no fake credentials. It does NOT defend a
//     coerced-AT-CAST-TIME adversary, a device that is controlled or observed at cast OR retrieval time,
//     an adversary who observes the untappable channel, or one who returns after results post and watches
//     the retrieval. The dominant residual attack is the "Italian"/forced-instruction attack: the FULL
//     (tracker, vote) multiset is public, so a coercer who demands a specific rare ballot verifies it
//     directly from the board — no tracker needed.
//   • In THIS proof-of-concept the trapdoor key x is generated in-process (like the simulated DKG), and
//     tracker assignment is in-process. So the coercion-mitigation property is CRYPTOGRAPHICALLY
//     DEMONSTRATED but NOT OPERATIVE as a deployment guarantee: it additionally requires VOTER-CONTRIBUTED
//     x over an untappable channel, DISTRIBUTED tracker assignment (no single party learns voter↔tracker),
//     and an eager coercion-free retrieval window. Until those land (M3+), treat this as transparent
//     individual verifiability + a coercion-mitigation MECHANISM DEMO, not a guarantee.
//   • Integrity is classical (DDH/ROM); not post-quantum. The posted rows are computationally private
//     (only the Pedersen tracker commitment Com is perfectly hiding). Turnout is not hidden (pk is public).
//   • A voter who sees the WRONG vote has only a NON-transferable personal complaint (a known Selene limit).
//
// Pre-audit; not for binding government use. See ADR-0011 and docs/CRYPTO_REVIEW.md.

import {
  G, H, N, ZERO, mul, mod, invMod, randScalar, pointToHex, pointFromHex, scalarFromDecimal, scalarTo32, type Point,
} from './group.js';
import { decryptionShare, discreteLog, type Ciphertext } from './elgamal.js';
import {
  proveBit, verifyBit, proveSumOne, verifySumOne, proveDecryption, verifyDecryption,
  proveTrackerConsistency, verifyTrackerConsistency,
  type BitProof, type SumProof, type DecProof, type TrackerConsistencyProof,
} from './proofs.js';
import { combineShares, verificationKeyAt, type KeySetup } from './threshold.js';
import { shuffleProve, verifyShuffle, type Item, type ShuffleProof, SECURITY_T } from './mixnet.js';
import { sign, verifySig, type Credential, type Signature } from './credentials.js';
import { electionContext } from './codec.js';
import { BulletinBoard } from './bulletin.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import type { Check, VerifyResult } from './verify.js';

// --- primitives ------------------------------------------------------------

/** ElGamal of a POINT message T under joint key pk: (r·G, T + r·pk). (elgamal.encrypt is the scalar-message form.) */
export function pointEncrypt(pk: Point, T: Point, r: bigint): Ciphertext {
  return { a: mul(G, r), b: T.add(mul(pk, r)) };
}

/** A voter's trapdoor (dual) keypair. In a deployment x is VOTER-CONTRIBUTED over an untappable channel. */
export function trapdoorKeygen(): { x: bigint; pk: Point } {
  const x = randScalar();
  return { x, pk: mul(G, x) };
}

/** Perfectly-hiding Pedersen commitment to a tracker POINT T: Com = T + d·H. */
export function trackerCommit(T: Point, d: bigint): Point {
  return T.add(mul(H, d));
}

/** The deferred notification toward the voter's key pk: (a, β) = (r·G, T + r·pk). Delivered off-board. */
export interface Notification { a: Point; beta: Point; }
export function makeNotification(T: Point, pk: Point, r: bigint): Notification {
  return { a: mul(G, r), beta: T.add(mul(pk, r)) };
}

/** Honest retrieval: T = β − x·a, using the voter's trapdoor key x. */
export function retrieveTracker(notif: Notification, x: bigint): Point {
  return notif.beta.subtract(mul(notif.a, x));
}

/**
 * Coercion equivocation: a FAKE ephemeral opening a′ such that retrieveTracker({a:a′, beta}, x) === T′,
 * for ANY chosen posted tracker point T′. a′ = x⁻¹·(β − T′). The key x (and pk = x·G) are unchanged, so the
 * fake opening is indistinguishable from the real one to a coercer lacking x. Voter-side ONLY — never on the board.
 */
export function fakeOpening(notif: Notification, x: bigint, Tprime: Point): Point {
  return mul(notif.beta.subtract(Tprime), invMod(x));
}

// --- election artifacts ----------------------------------------------------

export interface SeleneVoter { credential: Credential; choice: number; }

/** The vote column: one ciphertext + bit proof per candidate, plus a sum=1 proof (reuses the plurality shape). */
export interface SeleneSelection { enc: Ciphertext[]; bitProofs: BitProof[]; sumProof: SumProof; }

export interface SeleneBallotEntry {
  voter: string; // display label only
  credentialPub: Point; // eligible credential that signed this ballot
  trapdoorPub: Point; // pk = x·G — the voter's dual key (published)
  encTracker: Ciphertext; // ET = pointEncrypt(PK, T, ρ)
  trackerCommitment: Point; // Com = T + d·H (perfectly hiding)
  trackerProof: TrackerConsistencyProof; // binds Com to the same T that ET encrypts
  selection: SeleneSelection; // the encrypted vote + validity proofs
  sig: Signature;
}

export interface SeleneDecShare { trusteeIndex: number; shares: Point[]; proofs: DecProof[]; }

export interface SeleneTranscript {
  contest: string;
  candidates: string[];
  numVoters: number;
  eligibleRoll: Point[];
  publicKey: Point;
  commitments: Point[]; // Feldman commitments
  trustees: number;
  threshold: number;
  ballots: SeleneBallotEntry[];
  boardRoot: string;
  shuffled: Item[]; // each item is [ET, enc_0, …, enc_{K-1}] (width 1+K) after the verifiable shuffle
  shuffleProof: ShuffleProof;
  decShares: SeleneDecShare[];
  trackerPoints: string[]; // recovered tracker POINT per shuffled row (hex)
  votes: number[]; // recovered candidate index per shuffled row
  results: number[]; // votes per candidate
}

// --- canonical signing/board bytes (length-prefixed; mirrored by the Python verifier) --------------

function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
function bitBytes(p: BitProof): Uint8Array {
  return concatBytes(p.T0g.toRawBytes(), p.T0h.toRawBytes(), p.T1g.toRawBytes(), p.T1h.toRawBytes(),
    scalarTo32(p.c0), scalarTo32(p.c1), scalarTo32(p.s0), scalarTo32(p.s1));
}
function selectionBytes(sel: SeleneSelection): Uint8Array {
  const parts: Uint8Array[] = [u32(sel.enc.length)];
  for (let j = 0; j < sel.enc.length; j++) parts.push(sel.enc[j]!.a.toRawBytes(), sel.enc[j]!.b.toRawBytes(), bitBytes(sel.bitProofs[j]!));
  parts.push(sel.sumProof.Tg.toRawBytes(), sel.sumProof.Th.toRawBytes(), scalarTo32(sel.sumProof.c), scalarTo32(sel.sumProof.s));
  return concatBytes(...parts);
}
/** What the voter signs: context + dual key + encrypted tracker + tracker commitment + the vote selection. */
export function seleneSigningBytes(ctx: Uint8Array, trapdoorPub: Point, ET: Ciphertext, Com: Point, sel: SeleneSelection): Uint8Array {
  return concatBytes(utf8ToBytes('vvp-selene-v1'), ctx, trapdoorPub.toRawBytes(), ET.a.toRawBytes(), ET.b.toRawBytes(), Com.toRawBytes(), selectionBytes(sel));
}
function seleneBoardBytes(ctx: Uint8Array, credentialPub: Point, trapdoorPub: Point, ET: Ciphertext, Com: Point, sel: SeleneSelection, sig: Signature): Uint8Array {
  return concatBytes(credentialPub.toRawBytes(), seleneSigningBytes(ctx, trapdoorPub, ET, Com, sel), sig.R.toRawBytes(), scalarTo32(sig.s));
}

// --- run an election -------------------------------------------------------

function encryptVote(pk: Point, choice: number, K: number): { selection: SeleneSelection; randomness: bigint[] } {
  if (!Number.isInteger(choice) || choice < 0 || choice >= K) throw new Error(`choice ${choice} out of range [0, ${K})`);
  const enc: Ciphertext[] = [];
  const bitProofs: BitProof[] = [];
  const randomness: bigint[] = [];
  for (let j = 0; j < K; j++) {
    const v: 0 | 1 = j === choice ? 1 : 0;
    const r = randScalar();
    const ct: Ciphertext = { a: mul(G, r), b: mul(G, BigInt(v)).add(mul(pk, r)) };
    enc.push(ct); bitProofs.push(proveBit(pk, ct, v, r)); randomness.push(r);
  }
  const R = randomness.reduce((acc, r) => mod(acc + r, N), 0n);
  const aggB = enc.reduce<Ciphertext>((acc, c) => ({ a: acc.a.add(c.a), b: acc.b.add(c.b) }), { a: ZERO, b: ZERO });
  return { selection: { enc, bitProofs, sumProof: proveSumOne(pk, aggB, R) }, randomness };
}

/** Per-voter secrets kept off the board (for the demo's retrieval/equivocation demonstration only). */
export interface SeleneSecret { credentialPub: Point; trapdoorKey: bigint; tracker: Point; notif: Notification; }

export function runSeleneElection(
  contest: string,
  candidates: string[],
  voters: SeleneVoter[],
  keys: KeySetup,
  eligibleRoll: Point[],
  participants?: number[],
): { transcript: SeleneTranscript; secrets: SeleneSecret[] } {
  const K = candidates.length;
  const pk = keys.publicKey;
  const ctx = electionContext(contest, pk, candidates);

  const prepared = voters.map((v) => {
    const { selection } = encryptVote(pk, v.choice, K);
    const td = trapdoorKeygen(); // PoC: in-process. Deployment: voter-contributed over an untappable channel.
    const tnScalar = randScalar();
    const T = mul(G, tnScalar); // tracker POINT (assignment in-process; M4 makes this distributed)
    const rho = randScalar();
    const ET = pointEncrypt(pk, T, rho);
    const d = randScalar();
    const Com = trackerCommit(T, d);
    const trackerProof = proveTrackerConsistency(pk, ET, Com, rho, d);
    const rNotif = randScalar();
    const notif = makeNotification(T, td.pk, rNotif);
    const sig = sign(v.credential.secret, seleneSigningBytes(ctx, td.pk, ET, Com, selection));
    return { credentialPub: v.credential.pub, trapdoorPub: td.pk, ET, Com, trackerProof, selection, sig, x: td.x, T, notif };
  });
  // Publish in credential-sorted order (board position independent of registration/arrival order).
  prepared.sort((a, b) => pointToHex(a.credentialPub).localeCompare(pointToHex(b.credentialPub)));

  const board = new BulletinBoard();
  const ballots: SeleneBallotEntry[] = prepared.map((e, i) => {
    board.append(seleneBoardBytes(ctx, e.credentialPub, e.trapdoorPub, e.ET, e.Com, e.selection, e.sig));
    return { voter: `ballot-${i + 1}`, credentialPub: e.credentialPub, trapdoorPub: e.trapdoorPub, encTracker: e.ET, trackerCommitment: e.Com, trackerProof: e.trackerProof, selection: e.selection, sig: e.sig };
  });
  const secrets: SeleneSecret[] = prepared.map((e) => ({ credentialPub: e.credentialPub, trapdoorKey: e.x, tracker: e.T, notif: e.notif }));

  // Verifiable shuffle of the (tracker, vote) items — breaks the board-position ↔ (tracker,vote) link.
  const W = 1 + K;
  const L0: Item[] = ballots.map((b) => [b.encTracker, ...b.selection.enc]); // width 1+K, same order as the board
  const { L, proof } = shuffleProve(pk, L0);
  const n = ballots.length;

  // Threshold-decrypt every component of every shuffled item.
  const subset = participants ?? keys.trustees.slice(0, keys.threshold).map((t) => t.index);
  const participating = keys.trustees.filter((t) => subset.includes(t.index));
  const decShares: SeleneDecShare[] = participating.map((tr) => {
    const shares: Point[] = [];
    const proofs: DecProof[] = [];
    for (let item = 0; item < n; item++) {
      for (let c = 0; c < W; c++) {
        const a = L[item]![c]!.a;
        const dsh = decryptionShare(a, tr.share);
        shares.push(dsh);
        proofs.push(proveDecryption(a, tr.verificationKey, dsh, tr.share));
      }
    }
    return { trusteeIndex: tr.index, shares, proofs };
  });

  // Recover the cleartext (tracker POINT, vote) rows.
  const trackerPoints: string[] = [];
  const votes: number[] = [];
  for (let item = 0; item < n; item++) {
    const combinedT = combineShares(decShares.map((ds) => ({ index: ds.trusteeIndex, d: ds.shares[item * W + 0]! })));
    trackerPoints.push(pointToHex(L[item]![0]!.b.subtract(combinedT))); // tracker as a POINT (no discreteLog)
    let vote = -1;
    for (let j = 0; j < K; j++) {
      const combined = combineShares(decShares.map((ds) => ({ index: ds.trusteeIndex, d: ds.shares[item * W + 1 + j]! })));
      const bit = discreteLog(L[item]![1 + j]!.b.subtract(combined), 1); // 0/1
      if (bit === 1) vote = j;
    }
    votes.push(vote);
  }
  const results = Array.from({ length: K }, (_, j) => votes.filter((v) => v === j).length);

  const transcript: SeleneTranscript = {
    contest, candidates, numVoters: voters.length, eligibleRoll, publicKey: pk,
    commitments: keys.commitments, trustees: keys.trustees.length, threshold: keys.threshold,
    ballots, boardRoot: board.root(), shuffled: L, shuffleProof: proof, decShares, trackerPoints, votes, results,
  };
  return { transcript, secrets };
}

// --- verify (never throws) -------------------------------------------------

export function verifySeleneTranscript(t: SeleneTranscript): VerifyResult {
  try {
    return verifyInner(t);
  } catch (err) {
    return { ok: false, results: null, checks: [{ name: 'Transcript is well-formed (no exception)', ok: false, detail: String(err) }] };
  }
}

function verifyInner(t: SeleneTranscript): VerifyResult {
  const checks: Check[] = [];
  const K = t.candidates.length;
  const k = t.threshold;
  const n = t.ballots.length;
  const W = 1 + K;
  const nW = n * W;

  const shapeOk =
    K > 0 && Number.isInteger(k) && k >= 1 && Number.isInteger(t.trustees) && t.trustees >= k &&
    t.commitments.length === k && Number.isInteger(t.numVoters) && t.numVoters === n && n >= 1 &&
    t.ballots.every((b) => b.selection.enc.length === K && b.selection.bitProofs.length === K) &&
    Array.isArray(t.shuffled) && t.shuffled.length === n && t.shuffled.every((it) => Array.isArray(it) && it.length === W) &&
    Array.isArray(t.decShares) && t.decShares.every((ds) => ds.shares.length === nW && ds.proofs.length === nW) &&
    Array.isArray(t.trackerPoints) && t.trackerPoints.length === n &&
    Array.isArray(t.votes) && t.votes.length === n && Array.isArray(t.results) && t.results.length === K;
  checks.push({ name: 'Transcript shape: K candidates, n ballots, n items of width 1+K, n·(1+K) shares', ok: shapeOk });
  if (!shapeOk) return { ok: false, checks, results: null };

  // Joint key + bulletin board
  checks.push({ name: 'Joint public key = commitment C₀', ok: t.commitments[0]!.equals(t.publicKey) });
  const ctx = electionContext(t.contest, t.publicKey, t.candidates);
  const board = new BulletinBoard();
  for (const b of t.ballots) board.append(seleneBoardBytes(ctx, b.credentialPub, b.trapdoorPub, b.encTracker, b.trackerCommitment, b.selection, b.sig));
  checks.push({ name: 'Bulletin-board Merkle root matches the published ballots', ok: board.root() === t.boardRoot });

  // Eligibility + one-vote-per-credential
  const eligible = new Set(t.eligibleRoll.map(pointToHex));
  checks.push({ name: 'Eligible roll has no duplicate credentials', ok: eligible.size === t.eligibleRoll.length });
  let inelig = 0, badSig = 0, dup = 0;
  const seen = new Set<string>();
  for (const b of t.ballots) {
    const key = pointToHex(b.credentialPub);
    if (!eligible.has(key)) inelig++;
    if (!verifySig(b.credentialPub, seleneSigningBytes(ctx, b.trapdoorPub, b.encTracker, b.trackerCommitment, b.selection), b.sig)) badSig++;
    if (seen.has(key)) dup++;
    seen.add(key);
  }
  checks.push({ name: 'Every ballot is signed by an eligible, non-duplicate voter credential', ok: inelig === 0 && badSig === 0 && dup === 0, detail: inelig === 0 && badSig === 0 && dup === 0 ? undefined : `${inelig} ineligible, ${badSig} bad sig, ${dup} dup` });

  // Vote validity (each candidate a 0/1 bit + exactly one selected) on the BOARD ballots (pre-shuffle).
  let voteBad = 0;
  for (const b of t.ballots) {
    for (let j = 0; j < K; j++) if (!verifyBit(t.publicKey, b.selection.enc[j]!, b.selection.bitProofs[j]!)) voteBad++;
    const aggB = b.selection.enc.reduce<Ciphertext>((acc, c) => ({ a: acc.a.add(c.a), b: acc.b.add(c.b) }), { a: ZERO, b: ZERO });
    if (!verifySumOne(t.publicKey, aggB, b.selection.sumProof)) voteBad++;
  }
  checks.push({ name: 'Every vote is a valid 1-of-K selection (bit proofs + exactly-one)', ok: voteBad === 0 });

  // Tracker↔commitment consistency: each Com commits to the same tracker its ET encrypts.
  let trkBad = 0;
  for (const b of t.ballots) if (!verifyTrackerConsistency(t.publicKey, b.encTracker, b.trackerCommitment, b.trackerProof)) trkBad++;
  checks.push({ name: 'Every tracker commitment is bound to the same tracker its ciphertext encrypts (consistency NIZK)', ok: trkBad === 0 });

  // The verifiable shuffle: re-derive L0 from the board (never trust a transcript L0), then verifyShuffle.
  const L0: Item[] = t.ballots.map((b) => [b.encTracker, ...b.selection.enc]);
  const sh = verifyShuffle(t.publicKey, L0, t.shuffled, t.shuffleProof);
  checks.push({ name: `Verifiable re-encryption shuffle of the (tracker, vote) pairs (Sako–Kilian, soundness 2⁻${SECURITY_T})`, ok: sh.ok });

  // Threshold decryption proofs + quorum, and recompute the cleartext rows ourselves.
  const idxOk = (i: number): boolean => Number.isInteger(i) && i >= 1 && i <= t.trustees;
  const distinctQuorum = new Set(t.decShares.map((ds) => ds.trusteeIndex));
  const quorumOk = t.decShares.every((ds) => idxOk(ds.trusteeIndex)) && distinctQuorum.size === t.decShares.length && distinctQuorum.size >= k;
  checks.push({ name: `Decryption is by ≥ ${k} distinct registered trustees (quorum)`, ok: quorumOk });

  let decBad = 0;
  let rowMismatch = 0;
  const recomputedTrackers: string[] = [];
  for (let item = 0; item < n && quorumOk; item++) {
    for (let c = 0; c < W; c++) {
      const a = t.shuffled[item]![c]!.a;
      for (const ds of t.decShares) {
        const vk = verificationKeyAt(t.commitments, ds.trusteeIndex);
        if (!verifyDecryption(a, vk, ds.shares[item * W + c]!, ds.proofs[item * W + c]!)) decBad++;
      }
    }
    const combinedT = combineShares(t.decShares.map((ds) => ({ index: ds.trusteeIndex, d: ds.shares[item * W + 0]! })));
    const Tpt = t.shuffled[item]![0]!.b.subtract(combinedT);
    recomputedTrackers.push(pointToHex(Tpt));
    let vote = -1;
    for (let j = 0; j < K; j++) {
      const combined = combineShares(t.decShares.map((ds) => ({ index: ds.trusteeIndex, d: ds.shares[item * W + 1 + j]! })));
      const diff = t.shuffled[item]![1 + j]!.b.subtract(combined);
      const bit = diff.equals(ZERO) ? 0 : diff.equals(G) ? 1 : -1;
      if (bit === 1) vote = j;
      if (bit === -1) rowMismatch++;
    }
    if (pointToHex(Tpt) !== t.trackerPoints[item] || vote !== t.votes[item]) rowMismatch++;
  }
  checks.push({ name: 'Every decryption share carries a valid Chaum–Pedersen proof', ok: decBad === 0 });
  checks.push({ name: 'Published (tracker, vote) rows match our independent threshold decryption', ok: rowMismatch === 0 });

  // Collision-freeness: every recovered tracker point is distinct (a duplicate would let two voters map to one row).
  const distinctTrackers = new Set(t.trackerPoints);
  checks.push({ name: 'All tracker points are distinct (no two voters share a tracker)', ok: distinctTrackers.size === t.trackerPoints.length });

  // Tally matches the recovered votes.
  const tally = Array.from({ length: K }, (_, j) => t.votes.filter((v) => v === j).length);
  const tallyOk = tally.every((v, j) => v === t.results[j]) && t.votes.every((v) => Number.isInteger(v) && v >= 0 && v < K);
  checks.push({ name: 'Announced results equal the count of the recovered votes', ok: tallyOk });

  const ok = checks.every((c) => c.ok);
  return { ok, checks, results: ok ? t.results : null };
}

// --- canonical JSON wire format (self-contained; mirrored by the Python cross-verifier) ------------

/* eslint-disable @typescript-eslint/no-explicit-any */
const P = pointToHex;
const p = pointFromHex;
const S = (x: bigint): string => x.toString();
const s = scalarFromDecimal; // strict canonical-decimal parse (cross-verifier equivalence — see group.ts)

const ctToJ = (c: Ciphertext): any => ({ a: P(c.a), b: P(c.b) });
const ctFromJ = (j: any): Ciphertext => ({ a: p(j.a), b: p(j.b) });
const bitToJ = (b: BitProof): any => ({ T0g: P(b.T0g), T0h: P(b.T0h), T1g: P(b.T1g), T1h: P(b.T1h), c0: S(b.c0), c1: S(b.c1), s0: S(b.s0), s1: S(b.s1) });
const bitFromJ = (j: any): BitProof => ({ T0g: p(j.T0g), T0h: p(j.T0h), T1g: p(j.T1g), T1h: p(j.T1h), c0: s(j.c0), c1: s(j.c1), s0: s(j.s0), s1: s(j.s1) });
const sumToJ = (sp: SumProof): any => ({ Tg: P(sp.Tg), Th: P(sp.Th), c: S(sp.c), s: S(sp.s) });
const sumFromJ = (j: any): SumProof => ({ Tg: p(j.Tg), Th: p(j.Th), c: s(j.c), s: s(j.s) });
const decToJ = (d: DecProof): any => ({ Tg: P(d.Tg), Ta: P(d.Ta), c: S(d.c), s: S(d.s) });
const decFromJ = (j: any): DecProof => ({ Tg: p(j.Tg), Ta: p(j.Ta), c: s(j.c), s: s(j.s) });
const trkToJ = (tp: TrackerConsistencyProof): any => ({ A1: P(tp.A1), A2: P(tp.A2), zr: S(tp.zr), zd: S(tp.zd) });
const trkFromJ = (j: any): TrackerConsistencyProof => ({ A1: p(j.A1), A2: p(j.A2), zr: s(j.zr), zd: s(j.zd) });
const itemToJ = (it: Item): any => it.map(ctToJ);
const itemFromJ = (j: any): Item => j.map(ctFromJ);
const selToJ = (sel: SeleneSelection): any => ({ enc: sel.enc.map(ctToJ), bitProofs: sel.bitProofs.map(bitToJ), sumProof: sumToJ(sel.sumProof) });
const selFromJ = (j: any): SeleneSelection => ({ enc: j.enc.map(ctFromJ), bitProofs: j.bitProofs.map(bitFromJ), sumProof: sumFromJ(j.sumProof) });
const shToJ = (sp: ShuffleProof): any => ({ t: sp.t, intermediates: sp.intermediates.map((m) => m.map(itemToJ)), openings: sp.openings.map((op) => ({ perm: op.perm, factors: op.factors.map((f) => f.map(S)) })) });
const shFromJ = (j: any): ShuffleProof => ({ t: j.t, intermediates: j.intermediates.map((m: any[]) => m.map(itemFromJ)), openings: j.openings.map((op: any) => ({ perm: op.perm, factors: op.factors.map((f: any[]) => f.map(s)) })) });

export function seleneTranscriptToJSON(t: SeleneTranscript): string {
  return JSON.stringify({
    version: 'vvp-selene-transcript-1',
    kind: 'selene',
    contest: t.contest,
    candidates: t.candidates,
    numVoters: t.numVoters,
    eligibleRoll: t.eligibleRoll.map(P),
    publicKey: P(t.publicKey),
    commitments: t.commitments.map(P),
    trustees: t.trustees,
    threshold: t.threshold,
    ballots: t.ballots.map((b) => ({
      voter: b.voter,
      credentialPub: P(b.credentialPub),
      trapdoorPub: P(b.trapdoorPub),
      encTracker: ctToJ(b.encTracker),
      trackerCommitment: P(b.trackerCommitment),
      trackerProof: trkToJ(b.trackerProof),
      selection: selToJ(b.selection),
      sig: { R: P(b.sig.R), s: S(b.sig.s) },
    })),
    boardRoot: t.boardRoot,
    shuffled: t.shuffled.map(itemToJ),
    shuffleProof: shToJ(t.shuffleProof),
    decShares: t.decShares.map((d) => ({ trusteeIndex: d.trusteeIndex, shares: d.shares.map(P), proofs: d.proofs.map(decToJ) })),
    trackerPoints: t.trackerPoints, // hex points
    votes: t.votes, // plain ints
    results: t.results, // plain ints
  }, null, 2);
}

export function seleneTranscriptFromJSON(json: string): SeleneTranscript {
  const j: any = JSON.parse(json);
  if (j.kind !== 'selene' || j.version !== 'vvp-selene-transcript-1') throw new Error('not a vvp-selene-transcript-1 document');
  return {
    contest: j.contest,
    candidates: j.candidates,
    numVoters: j.numVoters,
    eligibleRoll: j.eligibleRoll.map(p),
    publicKey: p(j.publicKey),
    commitments: j.commitments.map(p),
    trustees: j.trustees,
    threshold: j.threshold,
    ballots: j.ballots.map((b: any) => ({
      voter: b.voter,
      credentialPub: p(b.credentialPub),
      trapdoorPub: p(b.trapdoorPub),
      encTracker: ctFromJ(b.encTracker),
      trackerCommitment: p(b.trackerCommitment),
      trackerProof: trkFromJ(b.trackerProof),
      selection: selFromJ(b.selection),
      sig: { R: p(b.sig.R), s: s(b.sig.s) },
    })),
    boardRoot: j.boardRoot,
    shuffled: j.shuffled.map(itemFromJ),
    shuffleProof: shFromJ(j.shuffleProof),
    decShares: j.decShares.map((d: any) => ({ trusteeIndex: d.trusteeIndex, shares: d.shares.map(p), proofs: d.proofs.map(decFromJ) })),
    trackerPoints: j.trackerPoints,
    votes: j.votes,
    results: j.results,
  };
}
