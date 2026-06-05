// k-of-n threshold key generation and decryption (Shamir + Feldman/Pedersen DKG).
//
// The election secret key x is shared as a degree-(k-1) polynomial P with P(0)=x,
// so any k of n trustees can jointly decrypt (the election survives up to n-k
// absent/faulty trustees) while NO single trustee — and no coalition smaller than
// k — can decrypt anything. x is NEVER reconstructed: trustees publish per-aggregate
// decryption shares and the result is combined via Lagrange interpolation at 0.
//
// Public Feldman commitments C_l = g^{A_l} let anyone recompute each trustee's
// verification key g^{P(index)} and confirm the joint public key = C_0, so the
// verifier trusts the math, not the trustees.

import { G, N, ZERO, mod, mul, randScalar, invMod, type Point } from './group.js';

export interface TrusteeShare {
  index: number; // 1-based evaluation point
  share: bigint; // x_index = P(index) — secret, held only by trustee `index`
  verificationKey: Point; // g^{x_index} — public
}

export interface KeySetup {
  publicKey: Point; // g^x = C_0
  commitments: Point[]; // Feldman commitments C_0..C_{k-1}; length === threshold
  threshold: number; // k
  trustees: TrusteeShare[]; // n shares
}

/** Evaluate polynomial (coeffs low→high) at z, mod N (Horner). */
function evalPoly(coeffs: bigint[], z: bigint): bigint {
  let r = 0n;
  for (let l = coeffs.length - 1; l >= 0; l--) r = mod(r * z + coeffs[l]!, N);
  return r;
}

/**
 * Simulated Pedersen DKG producing a degree-(k-1) Shamir sharing of a secret x
 * that nobody reconstructs. A real DKG distributes the coefficient sampling across
 * the trustees (each contributes its own polynomial; the combined polynomial is the
 * sum, and no party learns x); the resulting structure — Shamir shares + public
 * Feldman commitments — is identical to what we generate here in one process.
 */
export function dkg(n: number, k: number): KeySetup {
  if (!Number.isInteger(n) || !Number.isInteger(k) || k < 1 || k > n) {
    throw new Error(`require integers 1 <= k <= n (got k=${k}, n=${n})`);
  }
  const coeffs = Array.from({ length: k }, () => randScalar()); // A_0..A_{k-1}; A_0 = x
  const commitments = coeffs.map((a) => mul(G, a)); // C_l = g^{A_l}
  const trustees: TrusteeShare[] = Array.from({ length: n }, (_, i) => {
    const index = i + 1;
    const share = evalPoly(coeffs, BigInt(index)); // x_index = P(index)
    return { index, share, verificationKey: mul(G, share) };
  });
  return { publicKey: commitments[0]!, commitments, threshold: k, trustees };
}

/** Recompute trustee `index`'s verification key g^{P(index)} = Π_l C_l^{index^l} from public commitments. */
export function verificationKeyAt(commitments: Point[], index: number): Point {
  let acc: Point = ZERO;
  let zPow = 1n;
  const z = BigInt(index);
  for (const C of commitments) {
    acc = acc.add(mul(C, zPow));
    zPow = mod(zPow * z, N);
  }
  return acc;
}

/** Lagrange coefficient λ_j(0) for interpolation over the participating set S (indices). */
export function lagrange0(j: number, S: number[]): bigint {
  let num = 1n;
  let den = 1n;
  for (const m of S) {
    if (m === j) continue;
    num = mod(num * BigInt(-m), N);
    den = mod(den * BigInt(j - m), N);
  }
  return mod(num * invMod(den), N);
}

/**
 * Combine per-trustee decryption shares d_j = a^{x_j} via Lagrange interpolation
 * at 0 → a^x. Correct for ANY participating set of size ≥ k; for fewer than k it
 * yields a wrong value (caught downstream by the tally check).
 */
export function combineShares(shares: { index: number; d: Point }[]): Point {
  const S = shares.map((s) => s.index);
  return shares.reduce<Point>((acc, s) => acc.add(mul(s.d, lagrange0(s.index, S))), ZERO);
}
