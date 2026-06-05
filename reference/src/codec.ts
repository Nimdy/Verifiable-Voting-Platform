// Canonical, deterministic serialization.
//
//  - signingBytes:  what the voter signs (the ciphertext + its validity proof).
//  - boardBytes:    what the bulletin board commits to (credential + ballot + signature),
//                   so tampering with ANY of them changes the Merkle root.

import { concatBytes } from '@noble/hashes/utils';
import { scalarTo32, type Point } from './group.js';
import type { Ciphertext } from './elgamal.js';
import type { BitProof } from './proofs.js';
import type { Signature } from './credentials.js';

export function signingBytes(ct: Ciphertext, p: BitProof): Uint8Array {
  return concatBytes(
    ct.a.toRawBytes(), ct.b.toRawBytes(),
    p.T0g.toRawBytes(), p.T0h.toRawBytes(),
    p.T1g.toRawBytes(), p.T1h.toRawBytes(),
    scalarTo32(p.c0), scalarTo32(p.c1),
    scalarTo32(p.s0), scalarTo32(p.s1),
  );
}

export function boardBytes(credentialPub: Point, ct: Ciphertext, p: BitProof, sig: Signature): Uint8Array {
  return concatBytes(
    credentialPub.toRawBytes(),
    signingBytes(ct, p),
    sig.R.toRawBytes(), scalarTo32(sig.s),
  );
}
