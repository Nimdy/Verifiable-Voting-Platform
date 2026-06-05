// Voter eligibility credentials — the "one eligible person, one vote" layer.
//
// Belenios-style: a registrar issues each eligible voter a PSEUDONYMOUS credential
// (a Schnorr keypair over ristretto255) that is NOT linked to their real identity
// on the public record. The set of eligible credential public keys is published.
// Each ballot is signed by a credential; the verifier checks the signature is from
// an eligible credential and that no credential is used twice (the public key acts
// as the single-use nullifier). The vote CHOICE stays secret (only the homomorphic
// total is ever decrypted), so publishing "credential X cast ballot Y" reveals
// nothing about how X voted.
//
// NOTE (stage-1 scope): true unlinkability of *which person* holds a credential
// requires the registrar to be separate from the casting server (so no single party
// sees identity AND ballot). This single-process PoC models the credential mechanics
// but not that organizational separation — tracked as M3.

import { sha512 } from '@noble/hashes/sha512';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import { G, N, mod, mul, randScalar, inRange, type Point } from './group.js';

export interface Credential {
  secret: bigint; // kept by the voter; never published
  pub: Point; // published in the eligible roll; also the single-use nullifier
}

export interface Signature {
  R: Point;
  s: bigint;
}

/** Issue one fresh, high-entropy, pseudonymous credential. */
export const issueCredential = (): Credential => {
  const secret = randScalar();
  return { secret, pub: mul(G, secret) };
};

/** Register n eligible voters (the registrar's output). */
export const registerVoters = (n: number): Credential[] =>
  Array.from({ length: n }, () => issueCredential());

/** Fiat–Shamir challenge for the Schnorr signature, binding R, the public key, and the message. */
function challenge(R: Point, pub: Point, msg: Uint8Array): bigint {
  const digest = sha512(concatBytes(utf8ToBytes('vvp-cred-sig-v1|'), R.toRawBytes(), pub.toRawBytes(), msg));
  let x = 0n;
  for (const byte of digest) x = (x << 8n) | BigInt(byte);
  return mod(x, N);
}

/** Schnorr signature over a message with the credential secret. */
export function sign(secret: bigint, msg: Uint8Array): Signature {
  const r = randScalar();
  const R = mul(G, r);
  const e = challenge(R, mul(G, secret), msg);
  return { R, s: mod(r + e * secret, N) };
}

/** Verify a Schnorr signature:  s·G == R + e·pub. */
export function verifySig(pub: Point, msg: Uint8Array, sig: Signature): boolean {
  if (!inRange(sig.s)) return false;
  const e = challenge(sig.R, pub, msg);
  return mul(G, sig.s).equals(sig.R.add(mul(pub, e)));
}
