// Canonical JSON serialization of a Transcript.
//
// An election can be published as a single self-contained file that ANYONE can
// re-verify from the public record alone (no shared in-memory state). Every group
// element is validated on parse (pointFromHex throws on a bad encoding), giving the
// deserialization-boundary input validation a networked deployment needs. This is
// also the wire format the independent cross-language verifier (Python) consumes.
//
// Three transcript kinds share these encoders, each with a `kind` discriminator so a reader
// dispatches to the right verifier from the file alone: plurality/multi-seat (`Transcript`,
// version `vvp-transcript-1`), ranked-choice Borda (`RankedTranscript`, `vvp-ranked-transcript-1`),
// and mixnet instant-runoff (`MixnetIrvTranscript`, `vvp-mixnet-irv-transcript-1`).

import { pointToHex, pointFromHex, scalarFromDecimal } from './group.js';
import type { Transcript, Selection } from './election.js';
import type { RankedTranscript, RankedBallot } from './ranked.js';
import type { Ciphertext } from './elgamal.js';
import type { BitProof, SumProof, DecProof } from './proofs.js';
import type { Item, ShuffleProof } from './mixnet.js';
import type { MixnetIrvTranscript, MixnetDecShare } from './mixnet-irv.js';

/* eslint-disable @typescript-eslint/no-explicit-any */

const P = pointToHex;
const p = pointFromHex;
const S = (x: bigint): string => x.toString();
const s = scalarFromDecimal; // strict canonical-decimal parse (cross-verifier equivalence — see group.ts)

// --- shared element encoders (one source of truth for every group element) ---
const ctToJ = (c: Ciphertext): unknown => ({ a: P(c.a), b: P(c.b) });
const ctFromJ = (j: any): Ciphertext => ({ a: p(j.a), b: p(j.b) });

const bitToJ = (bp: BitProof): unknown => ({
  T0g: P(bp.T0g), T0h: P(bp.T0h), T1g: P(bp.T1g), T1h: P(bp.T1h),
  c0: S(bp.c0), c1: S(bp.c1), s0: S(bp.s0), s1: S(bp.s1),
});
const bitFromJ = (j: any): BitProof => ({
  T0g: p(j.T0g), T0h: p(j.T0h), T1g: p(j.T1g), T1h: p(j.T1h),
  c0: s(j.c0), c1: s(j.c1), s0: s(j.s0), s1: s(j.s1),
});

const sumToJ = (sp: SumProof): unknown => ({ Tg: P(sp.Tg), Th: P(sp.Th), c: S(sp.c), s: S(sp.s) });
const sumFromJ = (j: any): SumProof => ({ Tg: p(j.Tg), Th: p(j.Th), c: s(j.c), s: s(j.s) });

const decToJ = (pr: DecProof): unknown => ({ Tg: P(pr.Tg), Ta: P(pr.Ta), c: S(pr.c), s: S(pr.s) });
const decFromJ = (j: any): DecProof => ({ Tg: p(j.Tg), Ta: p(j.Ta), c: s(j.c), s: s(j.s) });

function selToJ(sel: Selection): unknown {
  return {
    enc: sel.enc.map(ctToJ),
    bitProofs: sel.bitProofs.map(bitToJ),
    sumProof: sumToJ(sel.sumProof),
  };
}

function selFromJ(j: any): Selection {
  return {
    enc: j.enc.map(ctFromJ),
    bitProofs: j.bitProofs.map(bitFromJ),
    sumProof: sumFromJ(j.sumProof),
  };
}

export function transcriptToJSON(t: Transcript): string {
  return JSON.stringify({
    version: 'vvp-transcript-1',
    kind: 'plurality',
    contest: t.contest,
    candidates: t.candidates,
    numVoters: t.numVoters,
    selectionLimit: t.selectionLimit,
    eligibleRoll: t.eligibleRoll.map(P),
    publicKey: P(t.publicKey),
    commitments: t.commitments.map(P),
    trustees: t.trustees,
    threshold: t.threshold,
    ballots: t.ballots.map((b) => ({
      voter: b.voter,
      credentialPub: P(b.credentialPub),
      selection: selToJ(b.selection),
      sig: { R: P(b.sig.R), s: S(b.sig.s) },
    })),
    boardRoot: t.boardRoot,
    aggregates: t.aggregates.map(ctToJ),
    decShares: t.decShares.map((d) => ({
      trusteeIndex: d.trusteeIndex,
      shares: d.shares.map(P),
      proofs: d.proofs.map(decToJ),
    })),
    results: t.results,
  }, null, 2);
}

export function transcriptFromJSON(json: string): Transcript {
  const j: any = JSON.parse(json);
  return {
    contest: j.contest,
    candidates: j.candidates,
    numVoters: j.numVoters,
    selectionLimit: j.selectionLimit,
    eligibleRoll: j.eligibleRoll.map(p),
    publicKey: p(j.publicKey),
    commitments: j.commitments.map(p),
    trustees: j.trustees,
    threshold: j.threshold,
    ballots: j.ballots.map((b: any) => ({
      voter: b.voter,
      credentialPub: p(b.credentialPub),
      selection: selFromJ(b.selection),
      sig: { R: p(b.sig.R), s: s(b.sig.s) },
    })),
    boardRoot: j.boardRoot,
    aggregates: j.aggregates.map(ctFromJ),
    decShares: j.decShares.map((d: any) => ({
      trusteeIndex: d.trusteeIndex,
      shares: d.shares.map(p),
      proofs: d.proofs.map(decFromJ),
    })),
    results: j.results,
  };
}

// --- ranked-choice (Borda) transcript --------------------------------------
function rankedBallotToJ(b: RankedBallot): unknown {
  return {
    matrix: b.matrix.map((row) => row.map(ctToJ)),
    bitProofs: b.bitProofs.map((row) => row.map(bitToJ)),
    rowSums: b.rowSums.map(sumToJ),
    colSums: b.colSums.map(sumToJ),
  };
}

function rankedBallotFromJ(j: any): RankedBallot {
  return {
    matrix: j.matrix.map((row: any[]) => row.map(ctFromJ)),
    bitProofs: j.bitProofs.map((row: any[]) => row.map(bitFromJ)),
    rowSums: j.rowSums.map(sumFromJ),
    colSums: j.colSums.map(sumFromJ),
  };
}

export function rankedTranscriptToJSON(t: RankedTranscript): string {
  return JSON.stringify({
    version: 'vvp-ranked-transcript-1',
    kind: 'ranked',
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
      ballot: rankedBallotToJ(b.ballot),
      sig: { R: P(b.sig.R), s: S(b.sig.s) },
    })),
    boardRoot: t.boardRoot,
    bordaAggregates: t.bordaAggregates.map(ctToJ),
    decShares: t.decShares.map((d) => ({
      trusteeIndex: d.trusteeIndex,
      shares: d.shares.map(P),
      proofs: d.proofs.map(decToJ),
    })),
    results: t.results,
  }, null, 2);
}

export function rankedTranscriptFromJSON(json: string): RankedTranscript {
  const j: any = JSON.parse(json);
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
      ballot: rankedBallotFromJ(b.ballot),
      sig: { R: p(b.sig.R), s: s(b.sig.s) },
    })),
    boardRoot: j.boardRoot,
    bordaAggregates: j.bordaAggregates.map(ctFromJ),
    decShares: j.decShares.map((d: any) => ({
      trusteeIndex: d.trusteeIndex,
      shares: d.shares.map(p),
      proofs: d.proofs.map(decFromJ),
    })),
    results: j.results,
  };
}

// --- mixnet instant-runoff (IRV) transcript -------------------------------
const itemToJ = (it: Item): unknown => it.map(ctToJ);
const itemFromJ = (j: any): Item => j.map(ctFromJ);

function shuffleProofToJ(sp: ShuffleProof): unknown {
  return {
    t: sp.t,
    intermediates: sp.intermediates.map((m) => m.map(itemToJ)),
    openings: sp.openings.map((op) => ({ perm: op.perm, factors: op.factors.map((f) => f.map(S)) })),
  };
}
function shuffleProofFromJ(j: any): ShuffleProof {
  return {
    t: j.t,
    intermediates: j.intermediates.map((m: any[]) => m.map(itemFromJ)),
    openings: j.openings.map((op: any) => ({ perm: op.perm, factors: op.factors.map((f: any[]) => f.map(s)) })),
  };
}

const mixnetDecShareToJ = (d: MixnetDecShare): unknown => ({ trusteeIndex: d.trusteeIndex, shares: d.shares.map(P), proofs: d.proofs.map(decToJ) });
const mixnetDecShareFromJ = (j: any): MixnetDecShare => ({ trusteeIndex: j.trusteeIndex, shares: j.shares.map(p), proofs: j.proofs.map(decFromJ) });

export function mixnetIrvTranscriptToJSON(t: MixnetIrvTranscript): string {
  return JSON.stringify({
    version: 'vvp-mixnet-irv-transcript-1',
    kind: 'mixnet-irv',
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
      ballot: rankedBallotToJ(b.ballot),
      sig: { R: P(b.sig.R), s: S(b.sig.s) },
    })),
    boardRoot: t.boardRoot,
    shuffled: t.shuffled.map(itemToJ),
    shuffleProof: shuffleProofToJ(t.shuffleProof),
    decShares: t.decShares.map(mixnetDecShareToJ),
    decryptedMatrices: t.decryptedMatrices, // plain 0/1 ints
    rounds: t.rounds, // plain ints + nulls
    winner: t.winner,
  }, null, 2);
}

export function mixnetIrvTranscriptFromJSON(json: string): MixnetIrvTranscript {
  const j: any = JSON.parse(json);
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
      ballot: rankedBallotFromJ(b.ballot),
      sig: { R: p(b.sig.R), s: s(b.sig.s) },
    })),
    boardRoot: j.boardRoot,
    shuffled: j.shuffled.map(itemFromJ),
    shuffleProof: shuffleProofFromJ(j.shuffleProof),
    decShares: j.decShares.map(mixnetDecShareFromJ),
    decryptedMatrices: j.decryptedMatrices,
    rounds: j.rounds,
    winner: j.winner,
  };
}
