// Group arithmetic over the ristretto255 prime-order group.
//
// We build the protocol on top of audited primitives from @noble/curves
// (the same family Helios / ElectionGuard-style systems use). We never invent
// ciphers here — only compose standard, peer-reviewed constructions.

import { RistrettoPoint } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils';

/** An element of the ristretto255 group. */
export type Point = typeof RistrettoPoint.BASE;

/** Order of the prime-order group (ed25519 / ristretto255 scalar field). */
export const N: bigint = 2n ** 252n + 27742317777372353535851937790883648493n;

/** Canonical generator g. */
export const G: Point = RistrettoPoint.BASE;

/** Group identity element (0 in additive notation). */
export const ZERO: Point = RistrettoPoint.BASE.subtract(RistrettoPoint.BASE);

/** Reduce a (possibly negative) integer into [0, m). */
export const mod = (a: bigint, m: bigint = N): bigint => ((a % m) + m) % m;

/** A uniformly random scalar in [0, N). 64 bytes → negligible modulo bias. */
export function randScalar(): bigint {
  const bytes = randomBytes(64);
  let x = 0n;
  for (const byte of bytes) x = (x << 8n) | BigInt(byte);
  return mod(x, N);
}

/**
 * Safe scalar multiplication s·P. @noble rejects the 0 scalar and the identity
 * point, so we handle both explicitly (both yield the identity).
 */
export function mul(P: Point, s: bigint): Point {
  const k = mod(s, N);
  if (k === 0n) return ZERO;
  if (P.equals(ZERO)) return ZERO;
  return P.multiply(k);
}

/** g·s convenience. */
export const gPow = (s: bigint): Point => mul(G, s);

/** Fiat–Shamir domain-separation tag (versioned). */
const FS_DST = 'vvp-fs-v1';

/** 4-byte big-endian length prefix. */
function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/**
 * Fiat–Shamir: hash a domain-separation label plus a list of public points to a
 * scalar challenge. Binding the full statement (not just commitments) into the
 * hash avoids weak-Fiat–Shamir attacks.
 *
 * The preimage is an unambiguous, self-describing frame — version tag,
 * length-prefixed label, explicit point count, then fixed-width point
 * encodings — so two different proof types can never alias the same challenge
 * even if future labels differ in length (audit hardening: domain separation).
 */
export function hashToScalar(label: string, points: Point[]): bigint {
  const labelBytes = utf8ToBytes(label);
  const frame = concatBytes(
    u32(FS_DST.length), utf8ToBytes(FS_DST),
    u32(labelBytes.length), labelBytes,
    u32(points.length),
    ...points.map((p) => p.toRawBytes()),
  );
  const digest = sha512(frame);
  let x = 0n;
  for (const byte of digest) x = (x << 8n) | BigInt(byte);
  return mod(x, N);
}

/** Canonical scalar range check — rejects non-canonical (≥ N) encodings. */
export const inRange = (x: bigint): boolean => x >= 0n && x < N;

/** Encode a scalar as 32 big-endian bytes (for canonical serialization). */
export function scalarTo32(s: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = mod(s, N);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}
