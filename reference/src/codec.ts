// Canonical, deterministic serialization of a published ballot.
// Both the casting service and the independent verifier use this exact byte
// layout to compute the bulletin-board Merkle root, so any later tampering with
// a ballot changes the root and is detected.

import { concatBytes } from '@noble/hashes/utils';
import { scalarTo32 } from './group.js';
import type { Ciphertext } from './elgamal.js';
import type { BitProof } from './proofs.js';

export function serializeBallot(ct: Ciphertext, p: BitProof): Uint8Array {
  return concatBytes(
    ct.a.toRawBytes(), ct.b.toRawBytes(),
    p.T0g.toRawBytes(), p.T0h.toRawBytes(),
    p.T1g.toRawBytes(), p.T1h.toRawBytes(),
    scalarTo32(p.c0), scalarTo32(p.c1),
    scalarTo32(p.s0), scalarTo32(p.s1),
  );
}
