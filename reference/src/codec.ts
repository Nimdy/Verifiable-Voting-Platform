// Canonical, deterministic serialization for a multi-candidate selection.
//
//  - electionContext: a domain-separated frame binding the contest, the joint
//                     public key, and the candidate list. Mixed into every
//                     signed ballot so a ballot/signature cannot be replayed
//                     into a different election or contest.
//  - signingBytes:    what the voter signs (context + every candidate ciphertext
//                     and bit proof, then the exactly-one-selected proof).
//  - boardBytes:      what the bulletin board commits to (credential + signed
//                     selection + signature), so tampering with ANY of them
//                     changes the Merkle root.

import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import { scalarTo32, type Point } from './group.js';
import type { BitProof, SumProof } from './proofs.js';
import type { Signature } from './credentials.js';
import type { Selection } from './election.js';

/** 4-byte big-endian length prefix. */
function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/** Domain-separated election context bound into every ballot signature. */
export function electionContext(contest: string, publicKey: Point, candidates: string[]): Uint8Array {
  const parts: Uint8Array[] = [utf8ToBytes('vvp-ctx-v1')];
  const c = utf8ToBytes(contest);
  parts.push(u32(c.length), c, publicKey.toRawBytes(), u32(candidates.length));
  for (const name of candidates) {
    const nb = utf8ToBytes(name);
    parts.push(u32(nb.length), nb);
  }
  return concatBytes(...parts);
}

function bitProofBytes(p: BitProof): Uint8Array {
  return concatBytes(
    p.T0g.toRawBytes(), p.T0h.toRawBytes(), p.T1g.toRawBytes(), p.T1h.toRawBytes(),
    scalarTo32(p.c0), scalarTo32(p.c1), scalarTo32(p.s0), scalarTo32(p.s1),
  );
}

function sumProofBytes(p: SumProof): Uint8Array {
  return concatBytes(p.Tg.toRawBytes(), p.Th.toRawBytes(), scalarTo32(p.c), scalarTo32(p.s));
}

export function signingBytes(ctx: Uint8Array, sel: Selection): Uint8Array {
  const parts: Uint8Array[] = [ctx, u32(sel.enc.length)];
  for (let j = 0; j < sel.enc.length; j++) {
    parts.push(sel.enc[j]!.a.toRawBytes(), sel.enc[j]!.b.toRawBytes(), bitProofBytes(sel.bitProofs[j]!));
  }
  parts.push(sumProofBytes(sel.sumProof));
  return concatBytes(...parts);
}

export function boardBytes(ctx: Uint8Array, credentialPub: Point, sel: Selection, sig: Signature): Uint8Array {
  return concatBytes(
    credentialPub.toRawBytes(),
    signingBytes(ctx, sel),
    sig.R.toRawBytes(), scalarTo32(sig.s),
  );
}
