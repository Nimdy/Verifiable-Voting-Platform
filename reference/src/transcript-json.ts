// Canonical JSON serialization of a Transcript.
//
// An election can be published as a single self-contained file that ANYONE can
// re-verify from the public record alone (no shared in-memory state). Every group
// element is validated on parse (pointFromHex throws on a bad encoding), giving the
// deserialization-boundary input validation a networked deployment needs. This is
// also the wire format a future independent cross-language verifier will consume.

import { pointToHex, pointFromHex } from './group.js';
import type { Transcript, Selection } from './election.js';

const P = pointToHex;
const p = pointFromHex;
const S = (x: bigint): string => x.toString();
const s = (x: string): bigint => BigInt(x);

function selToJ(sel: Selection): unknown {
  return {
    enc: sel.enc.map((c) => ({ a: P(c.a), b: P(c.b) })),
    bitProofs: sel.bitProofs.map((bp) => ({
      T0g: P(bp.T0g), T0h: P(bp.T0h), T1g: P(bp.T1g), T1h: P(bp.T1h),
      c0: S(bp.c0), c1: S(bp.c1), s0: S(bp.s0), s1: S(bp.s1),
    })),
    sumProof: { Tg: P(sel.sumProof.Tg), Th: P(sel.sumProof.Th), c: S(sel.sumProof.c), s: S(sel.sumProof.s) },
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function selFromJ(j: any): Selection {
  return {
    enc: j.enc.map((c: any) => ({ a: p(c.a), b: p(c.b) })),
    bitProofs: j.bitProofs.map((bp: any) => ({
      T0g: p(bp.T0g), T0h: p(bp.T0h), T1g: p(bp.T1g), T1h: p(bp.T1h),
      c0: s(bp.c0), c1: s(bp.c1), s0: s(bp.s0), s1: s(bp.s1),
    })),
    sumProof: { Tg: p(j.sumProof.Tg), Th: p(j.sumProof.Th), c: s(j.sumProof.c), s: s(j.sumProof.s) },
  };
}

export function transcriptToJSON(t: Transcript): string {
  return JSON.stringify({
    version: 'vvp-transcript-1',
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
      selection: selToJ(b.selection),
      sig: { R: P(b.sig.R), s: S(b.sig.s) },
    })),
    boardRoot: t.boardRoot,
    aggregates: t.aggregates.map((c) => ({ a: P(c.a), b: P(c.b) })),
    decShares: t.decShares.map((d) => ({
      trusteeIndex: d.trusteeIndex,
      shares: d.shares.map(P),
      proofs: d.proofs.map((pr) => ({ Tg: P(pr.Tg), Ta: P(pr.Ta), c: S(pr.c), s: S(pr.s) })),
    })),
    results: t.results,
  }, null, 2);
}

export function transcriptFromJSON(json: string): Transcript {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
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
      selection: selFromJ(b.selection),
      sig: { R: p(b.sig.R), s: s(b.sig.s) },
    })),
    boardRoot: j.boardRoot,
    aggregates: j.aggregates.map((c: any) => ({ a: p(c.a), b: p(c.b) })),
    decShares: j.decShares.map((d: any) => ({
      trusteeIndex: d.trusteeIndex,
      shares: d.shares.map(p),
      proofs: d.proofs.map((pr: any) => ({ Tg: p(pr.Tg), Ta: p(pr.Ta), c: s(pr.c), s: s(pr.s) })),
    })),
    results: j.results,
  };
}
