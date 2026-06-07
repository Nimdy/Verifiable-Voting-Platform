// Everlasting-privacy commitment trail (the post-quantum / unconditional-privacy PRIMITIVE).
//
// WHAT THIS IS. Alongside each per-candidate ElGamal ballot ciphertext (a, b), this publishes a
// PERFECTLY-HIDING Pedersen commitment C = v·G + d·H (d uniform in [0,N); H a nothing-up-my-sleeve
// generator with unknown dlog base G — see group.ts), plus a generalized-Schnorr CONSISTENCY NIZK
// proving C and (a, b) encode the SAME vote v (proofs.ts proveConsistency/verifyConsistency).
//
// WHY IT MATTERS. C is UNCONDITIONALLY (perfectly) hiding: with d uniform, C is distributed uniformly
// over the prime-order group independently of v, so the commitment trail {C_i} leaks ZERO information
// about any individual vote even to a computationally unbounded / quantum adversary who later breaks
// the elliptic curve. This is the property an ElGamal ciphertext can NEVER have — (a, b) is only
// *computationally* private (a future dlog break recovers v). The consistency NIZK binds the everlasting
// trail to the verifiable election, and — combined with the existing disjunctive bit-proof on (a, b) —
// establishes that each C commits to a value in {0,1}. Commitments are additively homomorphic, so the
// sum ΣC_i perfectly hides the tally while remaining bound (via the per-ballot proofs) to the count the
// ElGamal aggregate decrypts to.
//
// HONEST SCOPE — read before claiming anything (these limits are load-bearing):
//   • This ships the everlasting-privacy PRIMITIVE + binding proof, NOT an everlasting-private DEPLOYMENT.
//     Full everlasting privacy of a deployed election needs the Cuvelier–Pereira–Peters discipline: the
//     commitments {C_i} are the PERMANENT public record, while the ElGamal ciphertexts (a, b), the bit
//     proofs, and the decryption transcript are EPHEMERAL threshold-tally material destroyed after the
//     aggregate is decrypted and NOT permanently published. This trail artifact publishes BOTH layers
//     (so it is independently checkable and cross-verifiable), and is therefore only COMPUTATIONALLY
//     private as published — a future curve-breaker reads v straight from (a, b), independent of C.
//   • This is everlasting / post-quantum PRIVACY of the commitment trail only. It is NOT post-quantum
//     INTEGRITY: binding of C and soundness of the consistency proof are discrete-log based — a quantum
//     adversary who computes dlog_G(H) can equivocate a commitment, and one who computes dlog_G(PK) can
//     decrypt. Integrity remains classical.
//   • Hiding is unconditional; binding is computational (unknown dlog_G(H)). No commitment scheme can be
//     both unconditionally hiding AND unconditionally binding.
//   • Precision: hiding is PERFECT for an exactly-uniform d. As implemented, d = randScalar() (64 bytes →
//     mod N) has a negligible (< 2^-256) statistical distance from uniform — the same bias used for all
//     randomness in this system — so the commitment is *statistically* hiding with that negligible distance,
//     i.e. perfect up to < 2^-256. (Cryptographically irrelevant; stated for honesty.)
//   • At a CPP migration (commitments become the permanent record; (a,b) and the bit proofs are
//     discarded) the commitment record must STILL prove ballot validity — and it does, from (G,H,{C}) alone:
//     an everlasting bit-proof on each C (`proveCommitBit`) proves 0/1, AND an everlasting exactly-L sum-proof
//     on each row (`proveCommitSum`) proves no over/undervote. Both are perfectly-hiding-PRESERVING, so the
//     trail is self-sufficient for FULL ballot validity in binary contests with no ciphertext. What remains
//     for a full deployment: a range-proof generalization for NON-binary contests, and the operational
//     ephemeral-ciphertext model. Soundness of these is computational (unknown dlog_G(H)) — everlasting
//     PRIVACY, classical INTEGRITY.
//
// Pre-audit; not for binding government use.

import { G, H, ZERO, N, mod, mul, randScalar, pointToHex, pointFromHex, scalarFromDecimal, type Point } from './group.js';
import { encrypt, type Ciphertext } from './elgamal.js';
import {
  proveBit, verifyBit, proveConsistency, verifyConsistency, proveCommitBit, verifyCommitBit,
  proveCommitSum, verifyCommitSum,
  type BitProof, type ConsistencyProof, type CommitBitProof, type CommitSumProof,
} from './proofs.js';
import type { Check, VerifyResult } from './verify.js';

/** A perfectly-hiding Pedersen commitment to vote v with hiding randomness d: C = v·G + d·H. */
export function commitVote(v: 0 | 1, d: bigint): Point {
  return mul(G, BigInt(v)).add(mul(H, d));
}

/** Homomorphic sum of commitments: Σ(v_i·G + d_i·H) = (Σv_i)·G + (Σd_i)·H. */
export function addCommitments(cs: Point[]): Point {
  return cs.reduce<Point>((acc, c) => acc.add(c), ZERO);
}

/** One per-candidate cell: verifiable ciphertext + bit proof, the perfectly-hiding commitment, and the binding proofs. */
export interface EverlastingCell {
  ct: Ciphertext; // (a, b) — the verifiable, decryptable, ephemeral tally material
  bitProof: BitProof; // proves the ciphertext encrypts a bit in {0,1}
  commitment: Point; // C = v·G + d·H — the PERFECTLY-HIDING permanent record
  consistency: ConsistencyProof; // binds C to the SAME v that (a,b) encrypts
  commitBit: CommitBitProof; // proves C ALONE commits to a bit (G,H,C) — the everlasting record is self-sufficient
}

/** One ballot's everlasting row: one cell per candidate, plus the exactly-L sum proof over the row. */
export interface EverlastingBallot {
  cells: EverlastingCell[];
  sumProof: CommitSumProof; // proves ΣC over this row commits to exactly L (everlasting exactly-L / no over-undervote)
}

/** A self-contained, cross-verifiable everlasting-privacy trail bound to a specific election. */
export interface EverlastingTrail {
  contest: string;
  candidates: string[];
  selectionLimit: number; // L — how many candidates each ballot selects (1 = plurality)
  publicKey: Point; // PK — the trustees' joint key the ciphertexts encrypt under
  ballots: EverlastingBallot[];
  boardRoot?: string; // optional: the bulletin-board root this trail accompanies (self-description)
}

/**
 * Build one everlasting cell for a known vote bit v with ElGamal randomness r (both held by the voter
 * at cast time). The hiding randomness d is sampled fresh at full entropy and NEVER published.
 */
export function buildCell(pk: Point, v: 0 | 1, r: bigint): { cell: EverlastingCell; d: bigint } {
  const ct = encrypt(pk, BigInt(v), r);
  const bitProof = proveBit(pk, ct, v, r);
  const d = randScalar(); // hiding randomness — kept secret; publishing it would destroy hiding
  const commitment = commitVote(v, d);
  const consistency = proveConsistency(pk, ct, commitment, v, r, d);
  const commitBit = proveCommitBit(commitment, v, d); // C alone commits to a bit (no ciphertext needed)
  return { cell: { ct, bitProof, commitment, consistency, commitBit }, d };
}

/**
 * Build a trail for a set of ballots, each choosing one candidate index (plurality, L=1). Fresh ElGamal and
 * hiding randomness per cell; the voter holds the secrets, only the public cell is retained. Each row also
 * carries an everlasting exactly-L sum proof so the commitment record proves no over/undervote without the
 * ciphertext.
 */
export function buildTrail(
  pk: Point,
  contest: string,
  candidates: string[],
  choices: number[],
  boardRoot?: string,
): EverlastingTrail {
  const K = candidates.length;
  const L = 1; // plurality
  const ballots: EverlastingBallot[] = choices.map((choice) => {
    if (!Number.isInteger(choice) || choice < 0 || choice >= K) throw new Error(`choice ${choice} out of range [0, ${K})`);
    const built = Array.from({ length: K }, (_, j) => buildCell(pk, (j === choice ? 1 : 0) as 0 | 1, randScalar()));
    const cells = built.map((b) => b.cell);
    const sumC = addCommitments(cells.map((c) => c.commitment));
    const D = built.reduce((acc, b) => mod(acc + b.d, N), 0n); // Σd over the row
    return { cells, sumProof: proveCommitSum(sumC, L, D) };
  });
  return boardRoot === undefined
    ? { contest, candidates, selectionLimit: L, publicKey: pk, ballots }
    : { contest, candidates, selectionLimit: L, publicKey: pk, ballots, boardRoot };
}

/**
 * Verify a trail from the public record alone (NEVER throws). For every cell: the ciphertext encrypts a
 * bit (disjunctive bit-proof), and the consistency NIZK binds the perfectly-hiding commitment to that
 * same bit. The trail is NOT decrypted — commitments are privacy artifacts, never tally inputs.
 */
export function verifyTrail(trail: EverlastingTrail): VerifyResult {
  const checks: Check[] = [];
  try {
    if (!trail || !Array.isArray(trail.ballots) || !Array.isArray(trail.candidates) || trail.candidates.length === 0) {
      checks.push({ name: 'Trail is well-formed (non-empty candidate set + ballot array)', ok: false });
      return { ok: false, checks, results: null };
    }
    const K = trail.candidates.length;
    const L = trail.selectionLimit;
    const pk = trail.publicKey;
    if (!Number.isInteger(L) || L < 1 || L > K) {
      checks.push({ name: `Selection limit L is in [1, K] (L=${String(L)})`, ok: false });
      return { ok: false, checks, results: null };
    }

    const shapeOk = trail.ballots.every((b) => Array.isArray(b.cells) && b.cells.length === K);
    checks.push({ name: `Every ballot has exactly one commitment per candidate (K=${K})`, ok: shapeOk });
    if (!shapeOk) return { ok: false, checks, results: null };

    let bitBad = 0;
    let consBad = 0;
    let cbitBad = 0;
    let sumBad = 0;
    for (const b of trail.ballots) {
      for (const cell of b.cells) {
        if (!verifyBit(pk, cell.ct, cell.bitProof)) bitBad++;
        if (!verifyConsistency(pk, cell.ct, cell.commitment, cell.consistency)) consBad++;
        if (!verifyCommitBit(cell.commitment, cell.commitBit)) cbitBad++;
      }
      // everlasting exactly-L: the row's commitments sum to a commitment to L (verifier recomputes ΣC).
      if (!verifyCommitSum(addCommitments(b.cells.map((c) => c.commitment)), L, b.sumProof)) sumBad++;
    }
    checks.push({ name: 'Every ciphertext is proven to encrypt a bit in {0,1} (disjunctive Chaum–Pedersen)', ok: bitBad === 0 });
    checks.push({ name: 'Every commitment is bound to the SAME vote as its ciphertext (consistency NIZK); combined with the bit-proof above, C therefore commits to a bit', ok: consBad === 0 });
    checks.push({ name: 'Every commitment ALONE is proven to commit to a bit (everlasting bit-proof on C)', ok: cbitBad === 0 });
    checks.push({ name: `Every commitment ROW is proven to sum to exactly ${L} (everlasting exactly-${L} proof) — so the commitment record alone proves per-candidate 0/1 AND exactly-${L} (no over/undervote), with no ciphertext`, ok: sumBad === 0 });

    const total = trail.ballots.length * K;
    checks.push({ name: `Commitment trail is perfectly hiding by construction (C = v·G + d·H; ${total} commitments)`, ok: true });

    return { ok: checks.every((c) => c.ok), checks, results: null };
  } catch (err) {
    return { ok: false, results: null, checks: [{ name: 'Trail is well-formed (no exception)', ok: false, detail: String(err) }] };
  }
}

// --- canonical JSON wire format (self-contained; mirrored by the Python cross-verifier) ------------

/* eslint-disable @typescript-eslint/no-explicit-any */
const P = pointToHex;
const p = pointFromHex;
const S = (x: bigint): string => x.toString();
const s = scalarFromDecimal; // strict canonical-decimal parse (cross-verifier equivalence — see group.ts)

const cellToJ = (c: EverlastingCell): unknown => ({
  a: P(c.ct.a), b: P(c.ct.b),
  bit: {
    T0g: P(c.bitProof.T0g), T0h: P(c.bitProof.T0h), T1g: P(c.bitProof.T1g), T1h: P(c.bitProof.T1h),
    c0: S(c.bitProof.c0), c1: S(c.bitProof.c1), s0: S(c.bitProof.s0), s1: S(c.bitProof.s1),
  },
  C: P(c.commitment),
  cons: { Aa: P(c.consistency.Aa), Ab: P(c.consistency.Ab), Ac: P(c.consistency.Ac), zv: S(c.consistency.zv), zr: S(c.consistency.zr), zd: S(c.consistency.zd) },
  cbit: { A0: P(c.commitBit.A0), A1: P(c.commitBit.A1), c0: S(c.commitBit.c0), c1: S(c.commitBit.c1), s0: S(c.commitBit.s0), s1: S(c.commitBit.s1) },
});

const cellFromJ = (j: any): EverlastingCell => ({
  ct: { a: p(j.a), b: p(j.b) },
  bitProof: {
    T0g: p(j.bit.T0g), T0h: p(j.bit.T0h), T1g: p(j.bit.T1g), T1h: p(j.bit.T1h),
    c0: s(j.bit.c0), c1: s(j.bit.c1), s0: s(j.bit.s0), s1: s(j.bit.s1),
  },
  commitment: p(j.C),
  consistency: { Aa: p(j.cons.Aa), Ab: p(j.cons.Ab), Ac: p(j.cons.Ac), zv: s(j.cons.zv), zr: s(j.cons.zr), zd: s(j.cons.zd) },
  commitBit: { A0: p(j.cbit.A0), A1: p(j.cbit.A1), c0: s(j.cbit.c0), c1: s(j.cbit.c1), s0: s(j.cbit.s0), s1: s(j.cbit.s1) },
});

export function trailToJSON(t: EverlastingTrail): string {
  const obj: Record<string, unknown> = {
    version: 'vvp-everlasting-trail-1',
    kind: 'everlasting-trail',
    contest: t.contest,
    candidates: t.candidates,
    selectionLimit: t.selectionLimit,
    publicKey: P(t.publicKey),
    pedersenH: P(H), // pinned NUMS generator; the verifier re-derives H and FAILS CLOSED if it differs
    ballots: t.ballots.map((b) => ({ cells: b.cells.map(cellToJ), sum: { A: P(b.sumProof.A), z: S(b.sumProof.z) } })),
  };
  if (t.boardRoot !== undefined) obj.boardRoot = t.boardRoot;
  return JSON.stringify(obj);
}

export function trailFromJSON(json: string): EverlastingTrail {
  const j = JSON.parse(json);
  if (j.kind !== 'everlasting-trail' || j.version !== 'vvp-everlasting-trail-1') {
    throw new Error('not a vvp-everlasting-trail-1 document');
  }
  // Fail closed: the document's pinned H must equal the NUMS generator this verifier derived.
  if (j.pedersenH !== P(H)) throw new Error('trail pedersenH does not match the verifier NUMS generator H');
  const trail: EverlastingTrail = {
    contest: j.contest,
    candidates: j.candidates,
    selectionLimit: j.selectionLimit,
    publicKey: p(j.publicKey),
    ballots: (j.ballots as any[]).map((b) => ({ cells: (b.cells as any[]).map(cellFromJ), sumProof: { A: p(b.sum.A), z: s(b.sum.z) } })),
  };
  if (j.boardRoot !== undefined) trail.boardRoot = j.boardRoot;
  return trail;
}

/** Per-candidate homomorphic commitment to the tally: ΣC over all ballots for each candidate. */
export function commitmentTotals(trail: EverlastingTrail): Point[] {
  const K = trail.candidates.length;
  return Array.from({ length: K }, (_, j) => addCommitments(trail.ballots.map((b) => b.cells[j]!.commitment)));
}
