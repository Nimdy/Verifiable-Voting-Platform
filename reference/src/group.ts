// Group arithmetic over the ristretto255 prime-order group.
//
// We build the protocol on top of audited primitives from @noble/curves
// (the same family Helios / ElectionGuard-style systems use). We never invent
// ciphers here — only compose standard, peer-reviewed constructions.

import { RistrettoPoint } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes, concatBytes, utf8ToBytes, bytesToHex } from '@noble/hashes/utils';

/** An element of the ristretto255 group. */
export type Point = typeof RistrettoPoint.BASE;

/** Order of the prime-order group (ed25519 / ristretto255 scalar field). */
export const N: bigint = 2n ** 252n + 27742317777372353535851937790883648493n;

/** Canonical generator g. */
export const G: Point = RistrettoPoint.BASE;

/** Group identity element (0 in additive notation). */
export const ZERO: Point = RistrettoPoint.BASE.subtract(RistrettoPoint.BASE);

// --- Second, independent generator H for Pedersen commitments (everlasting privacy) ---------------
//
// H is a NOTHING-UP-MY-SLEEVE generator: it is the ristretto255 one-way map (RFC 9496 `from_hash`,
// i.e. @noble's `hashToCurve`) applied to SHA-512 of a fixed label, so NOBODY knows its discrete log
// base G. That unknown dlog is exactly what makes a Pedersen commitment C = v·G + d·H *binding*
// (computationally) while d·H makes it *perfectly hiding* (unconditionally). If anyone knew dlog_G(H),
// binding would collapse — hence the NUMS derivation, the pinned self-check below (fail closed), and
// the byte-identical derivation in the independent Python verifier (which uses libsodium's
// `crypto_core_ristretto255_from_hash` over the same SHA-512 digest). NOTE: this is the RFC 9496
// one-way map over a 64-byte digest, NOT RFC 9380 hash-to-curve (which libsodium does not expose).
export const PEDERSEN_H_LABEL = 'vvp-everlasting-pedersen-H-v1';
const PEDERSEN_H_HEX = 'b66dc28b63ecfbb83fa33aad8148a54f17757fce571ad6b8df258d3cfa2a777a';
export const H: Point = RistrettoPoint.hashToCurve(sha512(utf8ToBytes(PEDERSEN_H_LABEL)));
// Fail closed: a wrong/backdoored H (known dlog) would silently break commitment binding.
if (bytesToHex(H.toRawBytes()) !== PEDERSEN_H_HEX) {
  throw new Error('group: Pedersen generator H does not match the pinned NUMS constant');
}
if (H.equals(G) || H.equals(ZERO)) {
  throw new Error('group: Pedersen generator H must differ from G and the identity');
}

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

/**
 * Parse a scalar from its canonical DECIMAL string form. `BigInt(x)` is too permissive — it also accepts
 * `0x..`/`0o..`/`0b..` prefixes, the empty string, signs, and surrounding whitespace — and Python's `int()`
 * is permissive in a DIFFERENT way (underscores, Unicode digits), so relying on each language's native
 * constructor lets one rewrite a scalar into a same-value-different-syntax form that one independent verifier
 * accepts and the other rejects (a dual-verifier equivalence break). Both verifiers gate on this exact
 * canonical decimal grammar before converting, so a non-canonical string is a clean rejection in BOTH.
 */
export function scalarFromDecimal(x: string): bigint {
  if (typeof x !== 'string' || !/^(0|[1-9][0-9]*)$/.test(x)) throw new Error('non-canonical scalar string');
  const v = BigInt(x);
  if (v >= N) throw new Error('non-canonical scalar (>= group order)'); // range-check too, so this MIRRORS the Python parse_scalar exactly (not just the grammar) and downstream verifiers need not re-check
  return v;
}

/** Modular exponentiation base^exp mod m. */
export function modPow(base: bigint, exp: bigint, m: bigint = N): bigint {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

/** Modular inverse mod N (N is prime → Fermat: a^(N-2)). Used for Lagrange coefficients. */
export function invMod(a: bigint, m: bigint = N): bigint {
  if (mod(a, m) === 0n) throw new Error('invMod: no inverse for 0');
  return modPow(mod(a, m), m - 2n, m);
}

/** Encode a group element as hex (canonical 32-byte ristretto encoding). */
export const pointToHex = (p: Point): string => bytesToHex(p.toRawBytes());

/** Parse a group element from hex, validating the encoding (throws on a bad point). */
export const pointFromHex = (hex: string): Point => RistrettoPoint.fromHex(hex);

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
