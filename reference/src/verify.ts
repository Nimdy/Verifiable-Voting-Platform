// The INDEPENDENT VERIFIER — the thing that makes the system trustless.
//
// It takes only the public transcript and rechecks EVERYTHING from scratch,
// trusting nothing about who produced it. If any insider altered a ballot,
// stuffed an invalid vote, faked a decryption, or lied about the tally, at least
// one check below fails. In production this is re-implemented in a different
// language by a different team so a single bug cannot hide itself.

import { addCiphertexts, combinePublicKey, discreteLog } from './elgamal.js';
import { verifyBit, verifyDecryption } from './proofs.js';
import { ZERO, type Point } from './group.js';
import { serializeBallot } from './codec.js';
import { BulletinBoard } from './bulletin.js';
import type { Transcript } from './election.js';

export interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface VerifyResult {
  ok: boolean;
  checks: Check[];
  computedTally: number | null;
}

export function verifyTranscript(t: Transcript): VerifyResult {
  const checks: Check[] = [];

  // 1. The joint public key is exactly the product of the published trustee keys.
  const h = combinePublicKey(t.trusteePubs.map((p) => p.pub));
  checks.push({ name: 'Joint public key = combination of trustee keys', ok: h.equals(t.publicKey) });

  // 2. The bulletin-board Merkle root commits to exactly these ballots, in order.
  const board = new BulletinBoard();
  for (const b of t.ballots) board.append(serializeBallot(b.ct, b.proof));
  const rootOk = board.root() === t.boardRoot;
  checks.push({
    name: 'Bulletin-board Merkle root matches the published ballots',
    ok: rootOk,
    detail: rootOk ? undefined : `recomputed ${board.root().slice(0, 16)}… ≠ published ${t.boardRoot.slice(0, 16)}…`,
  });

  // 3. Every ballot is a well-formed 0/1 vote (zero-knowledge) — no stuffing.
  let invalid = 0;
  for (const b of t.ballots) if (!verifyBit(t.publicKey, b.ct, b.proof)) invalid++;
  checks.push({
    name: 'Every ballot proves it encrypts a valid 0/1 vote',
    ok: invalid === 0,
    detail: invalid === 0 ? `${t.ballots.length}/${t.ballots.length} valid` : `${invalid} INVALID ballot(s)`,
  });

  // 4. The aggregate is the honest homomorphic sum of the published ballots.
  const agg = addCiphertexts(t.ballots.map((b) => b.ct));
  const aggOk = agg.a.equals(t.aggregate.a) && agg.b.equals(t.aggregate.b);
  checks.push({ name: 'Aggregate ciphertext = homomorphic sum of all ballots', ok: aggOk });

  // 5. Every trustee's decryption share is provably correct.
  let badShares = 0;
  for (const s of t.decShares) {
    const pub = t.trusteePubs.find((p) => p.index === s.trusteeIndex)?.pub;
    if (!pub || !verifyDecryption(t.aggregate.a, pub, s.share, s.proof)) badShares++;
  }
  checks.push({
    name: 'Every trustee decryption share is provably honest',
    ok: badShares === 0,
    detail: badShares === 0 ? `${t.decShares.length}/${t.decShares.length} proven` : `${badShares} BAD share(s)`,
  });

  // 6. The published tally is the true decryption of the aggregate.
  const combined = t.decShares.reduce<Point>((acc, s) => acc.add(s.share), ZERO);
  const messagePoint = t.aggregate.b.subtract(combined);
  let computedTally: number | null = null;
  let tallyOk = false;
  try {
    computedTally = discreteLog(messagePoint, t.numVoters);
    tallyOk = computedTally === t.claimedTally;
  } catch {
    tallyOk = false;
  }
  checks.push({
    name: 'Published tally equals the decrypted aggregate',
    ok: tallyOk,
    detail: `claimed=${t.claimedTally} computed=${computedTally}`,
  });

  return { ok: checks.every((c) => c.ok), checks, computedTally };
}
