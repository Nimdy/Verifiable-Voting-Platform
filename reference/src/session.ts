// Cast-or-challenge (Benaloh) voting session — the full spoil-then-revote protocol.
//
// A voter PREPARES a ballot, then either CHALLENGES it (reveal the randomness, audit
// that the device encrypted the intended choice, and PERMANENTLY discard it) or CASTS
// it (randomness stays secret forever). Because a challenged ballot can never be cast
// and the voter casts a FRESH ballot afterward, a cheating device cannot know in
// advance whether a given ballot will be audited — so it cannot safely cheat.

import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, bytesToHex } from '@noble/hashes/utils';
import { auditSelection, encryptSelection, type Selection } from './election.js';
import type { Point } from './group.js';

export interface PreparedBallot {
  selection: Selection;
  randomness: bigint[]; // revealed only if the ballot is challenged; never if cast
  id: string; // commitment to the ciphertexts; identifies this exact ballot
}

export interface VotingSession {
  spoiled: Set<string>; // ids that were challenged and must never be cast
  cast: Set<string>; // ids already cast
}

export const newSession = (): VotingSession => ({ spoiled: new Set(), cast: new Set() });

/** Commitment to a selection's ciphertexts — identifies this exact prepared ballot. */
function ballotId(sel: Selection): string {
  const parts = sel.enc.flatMap((c) => [c.a.toRawBytes(), c.b.toRawBytes()]);
  return bytesToHex(sha256(concatBytes(...parts)));
}

/** The device prepares an encrypted ballot the voter may later challenge or cast. */
export function prepareBallot(pk: Point, choice: number, numCandidates: number): PreparedBallot {
  const { selection, randomness } = encryptSelection(pk, choice, numCandidates);
  return { selection, randomness, id: ballotId(selection) };
}

/**
 * Challenge (spoil): reveal the randomness, audit cast-as-intended against the voter's
 * claimed choice, and PERMANENTLY mark this ballot spoiled so it can never be cast.
 * Returns whether the device honestly encrypted the claimed choice.
 */
export function challengeBallot(
  session: VotingSession,
  pk: Point,
  prepared: PreparedBallot,
  claimedChoice: number,
): boolean {
  if (session.cast.has(prepared.id)) throw new Error('ballot already cast; cannot challenge it');
  session.spoiled.add(prepared.id);
  return auditSelection(pk, prepared.selection, prepared.randomness, claimedChoice);
}

/**
 * Cast: only a ballot that was NEVER challenged may be cast (its randomness stays
 * secret). Returns the selection to submit; the caller must discard the randomness.
 */
export function castBallot(session: VotingSession, prepared: PreparedBallot): Selection {
  if (session.spoiled.has(prepared.id)) {
    throw new Error('cannot cast a spoiled (challenged) ballot — prepare a fresh one');
  }
  if (session.cast.has(prepared.id)) throw new Error('ballot already cast');
  session.cast.add(prepared.id);
  return prepared.selection;
}
