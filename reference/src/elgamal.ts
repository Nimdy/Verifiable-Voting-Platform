// Exponential ElGamal over ristretto255 with distributed (N-of-N) trustee keys.
//
// A vote m is encrypted as (a, b) = (g^r, g^m · h^r) where h is the joint
// public key. This is *additively homomorphic*: multiplying ciphertexts adds the
// plaintexts, so we can sum encrypted ballots and only ever decrypt the TOTAL.
//
// The secret key is split across trustees and NEVER reconstructed: each trustee
// contributes a decryption share for the aggregate, with a proof it did so
// honestly. No single insider can decrypt an individual ballot — by design.

import { G, ZERO, mul, type Point } from './group.js';

export interface Ciphertext {
  a: Point; // g^r
  b: Point; // g^m · h^r
}

export interface TrusteeKey {
  index: number;
  secret: bigint; // x_i  (kept private; never published)
  pub: Point; // h_i = g^{x_i}  (published)
}

/** Generate one trustee's keypair. */
export function trusteeKeygen(index: number, secret: bigint): TrusteeKey {
  return { index, secret, pub: mul(G, secret) };
}

/** Joint public key h = Π h_i = g^{Σ x_i}. */
export function combinePublicKey(pubs: Point[]): Point {
  return pubs.reduce((acc, p) => acc.add(p), ZERO);
}

/** Encrypt vote value m under joint key h with randomness r. */
export function encrypt(h: Point, m: bigint, r: bigint): Ciphertext {
  return { a: mul(G, r), b: mul(G, m).add(mul(h, r)) };
}

/** Homomorphic sum of ciphertexts → encryption of the sum of plaintexts. */
export function addCiphertexts(cts: Ciphertext[]): Ciphertext {
  return cts.reduce<Ciphertext>(
    (acc, c) => ({ a: acc.a.add(c.a), b: acc.b.add(c.b) }),
    { a: ZERO, b: ZERO },
  );
}

/** Trustee i's decryption share for ciphertext component a: d_i = a^{x_i}. */
export function decryptionShare(a: Point, secret: bigint): Point {
  return mul(a, secret);
}

/**
 * Recover the small plaintext exponent m from M = g^m by brute force over
 * [0, max]. For a tally this range is just the number of voters — cheap.
 */
export function discreteLog(M: Point, max: number): number {
  let acc: Point = ZERO;
  for (let i = 0; i <= max; i++) {
    if (acc.equals(M)) return i;
    acc = acc.add(G);
  }
  throw new Error(`discrete log not found in [0, ${max}]`);
}
