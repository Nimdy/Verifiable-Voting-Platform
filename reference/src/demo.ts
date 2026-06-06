// End-to-end demo: register eligible voters, run a real MULTI-CANDIDATE verifiable
// election, audit a ballot (cast-as-intended), then play the INSIDER and try to
// cheat seven ways — and watch the independent verifier catch every one.
// Run with:  npm run demo

import { encrypt, addCiphertexts } from './elgamal.js';
import { proveBit, proveSumOne } from './proofs.js';
import { randScalar, mod, N, type Point } from './group.js';
import { issueCredential, sign, type Credential } from './credentials.js';
import { Registrar, type Eligible } from './registrar.js';
import { pointToHex } from './group.js';
import { signingBytes, boardBytes, electionContext } from './codec.js';
import { BulletinBoard } from './bulletin.js';
import {
  setupKeys, runElection, encryptSelection, singleTrusteeAttempt,
  type Transcript, type Voter, type BallotEntry, type Selection,
} from './election.js';
import { newSession, prepareBallot, challengeBallot, castBallot } from './session.js';
import { transcriptToJSON, rankedTranscriptToJSON } from './transcript-json.js';
import {
  runStructuredElection, verifyStructured, childrenOf, allTags, isLeaf,
  type ElectionSpec, type StructuredVoter,
} from './structured.js';
import { runRankedElection, verifyRankedTranscript, type RankedVoter } from './ranked.js';
import { runMixnetElection, verifyMixnetTranscript, type MixnetVoter } from './mixnet-irv.js';
import { mkdirSync, writeFileSync } from 'node:fs';
import { verifyTranscript, type VerifyResult } from './verify.js';

const line = (c = '─') => console.log(c.repeat(72));

function report(label: string, r: VerifyResult): void {
  for (const c of r.checks) {
    console.log(`   ${c.ok ? '✅' : '❌'} ${c.name}${c.detail ? `  (${c.detail})` : ''}`);
  }
  console.log(`   ${r.ok ? '🟢 VERIFIED' : '🔴 REJECTED'} — ${label}\n`);
}

function rootOf(ctx: Uint8Array, ballots: BallotEntry[]): string {
  const board = new BulletinBoard();
  for (const b of ballots) board.append(boardBytes(ctx, b.credentialPub, b.selection, b.sig));
  return board.root();
}

function makeBallot(ctx: Uint8Array, cred: Credential, selection: Selection, label: string): BallotEntry {
  const sig = sign(cred.secret, signingBytes(ctx, selection));
  return { voter: label, credentialPub: cred.pub, selection, sig };
}

/** A malicious "overvote": select TWO candidates (each a valid bit, but the sum is 2). */
function overvoteSelection(pk: Point, K: number): Selection {
  const enc = [], bitProofs = [], rs: bigint[] = [];
  for (let j = 0; j < K; j++) {
    const v: 0 | 1 = j === 0 || j === 1 ? 1 : 0;
    const r = randScalar();
    const ct = encrypt(pk, BigInt(v), r);
    enc.push(ct); bitProofs.push(proveBit(pk, ct, v, r)); rs.push(r);
  }
  const R = rs.reduce((a, b) => mod(a + b, N), 0n);
  return { enc, bitProofs, sumProof: proveSumOne(pk, addCiphertexts(enc), R) };
}

line('━');
console.log('  VERIFIABLE VOTING — reference proof of concept');
console.log('  "One eligible voter, one vote. Verify everything. Reveal nothing."');
line('━');

const CANDIDATES = ['Tacos 🌮', 'Pizza 🍕', 'Sushi 🍣', 'Salad 🥗'];
const K = CANDIDATES.length;
const keys = setupKeys(5, 3); // 5 trustees; ANY 3 can decrypt
// A SEPARATE registrar issues credentials; the casting server will see ONLY the published roll.
const registrar = new Registrar();
const eligible: Eligible[] = Array.from({ length: 9 }, (_, i) => ({ id: `citizen-${i + 1}` }));
const packets = registrar.register(eligible); // 7 vote; 2 spare eligible credentials for attackers
const eligibleRoll = registrar.publishedRoll(); // identity-free, decorrelated order
const choices = [0, 1, 0, 2, 0, 3, 1]; // Tacos×3, Pizza×2, Sushi×1, Salad×1
const voters: Voter[] = choices.map((choice, i) => ({ credential: packets[i]!.credential, choice }));

console.log(`\nContest: "Best team lunch?"   Candidates: ${CANDIDATES.join(', ')}`);
console.log(`Trustees: ${keys.trustees.length} (any ${keys.threshold} can decrypt)   Registered: ${registrar.size()}   Voters: ${voters.length}`);

// Decrypt with only trustees #1, #3, #5 — trustees #2 and #4 are "offline".
const t = runElection('Best team lunch?', CANDIDATES, voters, keys, eligibleRoll, [1, 3, 5]);
const ctx = electionContext(t.contest, t.publicKey, t.candidates);
console.log(`Decryption performed by 3 of 5 trustees (#2 and #4 offline).`);
console.log('Announced results: ' + CANDIDATES.map((c, j) => `${c} ${t.results[j]}`).join('   ') + '\n');

line();
console.log('1) HONEST ELECTION — anyone re-verifies it from the transcript alone:');
line();
report('the published result is provably correct', verifyTranscript(t));

console.log('2) BALLOT SECRECY — a lone trustee tries to unmask one ciphertext:');
line();
const sneaky = singleTrusteeAttempt(t.ballots[0]!.selection.enc[0]!, keys.trustees[0]!, t.numVoters);
console.log(`   Trustee #1 alone tries to read a ballot value → ${sneaky === null ? '❌ FAILED' : `got ${sneaky}`}`);
console.log('   ✅ No single trustee can read any ballot. Only per-candidate TOTALS are decrypted.\n');

console.log('   REGISTRAR SEPARATION — no single party links identity to vote:');
line();
const sample = t.ballots[0]!;
console.log(`   Public board entry "${sample.voter}" shows a credential, not a person: ${pointToHex(sample.credentialPub).slice(0, 16)}…`);
console.log('   Can the casting server / public map it to an identity?  ✅ NO (the transcript has no identities)');
console.log(`   Only the registrar can, privately:  credential → ${registrar.identityOf(sample.credentialPub) ?? '(unknown)'}`);
console.log('   …and even the registrar cannot see the VOTE (encrypted; only the total is ever decrypted).\n');

console.log('3) CAST-OR-CHALLENGE (Benaloh) — audit one ballot, then cast a fresh one:');
line();
const session = newSession();
const trial = prepareBallot(t.publicKey, 2, K); // device claims to encrypt "Sushi"
console.log(`   Challenged ballot audits as the chosen candidate?  ${challengeBallot(session, t.publicKey, trial, 2) ? '✅ YES' : '❌ NO'}`);
let castBlocked = false;
try { castBallot(session, trial); } catch { castBlocked = true; }
console.log(`   Casting the challenged (spoiled) ballot is blocked?  ${castBlocked ? '✅ YES' : '🔴 NO'}`);
const lying = prepareBallot(t.publicKey, 0, K); // a device that secretly encrypted "Tacos"
console.log(`   A device that secretly encrypted a DIFFERENT candidate passes the audit?  ${challengeBallot(newSession(), t.publicKey, lying, 2) ? '🔴 YES' : '✅ NO'}`);
castBallot(session, prepareBallot(t.publicKey, 2, K)); // voter casts a FRESH, unrevealed ballot
console.log('   ✅ A challenged ballot is permanently discarded; the voter casts a fresh ballot.\n');

console.log('4) DOUBLE VOTE — voter-1 votes again with the same credential:');
line();
const dbl = [...t.ballots, makeBallot(ctx, packets[0]!.credential, encryptSelection(t.publicKey, 1, K).selection, 'voter-1-again')];
report('the same credential cannot be used twice', verifyTranscript({ ...t, ballots: dbl, boardRoot: rootOf(ctx, dbl), numVoters: dbl.length }));

console.log('5) INELIGIBLE VOTER — someone not on the roll forges a credential and votes:');
line();
const inel = [...t.ballots, makeBallot(ctx, issueCredential(), encryptSelection(t.publicKey, 0, K).selection, 'gate-crasher')];
report('only credentials on the published roll may vote', verifyTranscript({ ...t, ballots: inel, boardRoot: rootOf(ctx, inel), numVoters: inel.length }));

console.log('6) OVERVOTE — an eligible voter tries to vote for TWO candidates at once:');
line();
const over = [...t.ballots, makeBallot(ctx, packets[7]!.credential, overvoteSelection(t.publicKey, K), 'overvoter')];
report('a ballot must select exactly one candidate', verifyTranscript({ ...t, ballots: over, boardRoot: rootOf(ctx, over), numVoters: over.length }));

console.log('7) RIGGED RESULT — a corrupt authority pads a candidate\'s total:');
line();
const rigged = { ...t, results: t.results.map((n, j) => (j === 0 ? n + 2 : n)) };
report('the verifier recomputes the real totals and rejects the lie', verifyTranscript(rigged));

console.log('8) BELOW QUORUM — an insider drops trustees so fewer than k remain:');
line();
const fewer = { ...t, decShares: t.decShares.slice(0, keys.threshold - 1) };
report(`fewer than ${keys.threshold} trustees cannot produce a valid decryption`, verifyTranscript(fewer));

console.log('STRUCTURED BALLOT — parent → drill-down contests with tags:');
line();
const spec: ElectionSpec = {
  title: 'Community decisions',
  contests: [
    { id: 'budget', title: 'Budget', tags: ['budget'] },
    { id: 'park', title: 'Park budget', tags: ['budget', 'parks'], parent: 'budget', candidates: ['Low', 'Mid', 'High'] },
    { id: 'lib', title: 'Library hours', tags: ['budget'], parent: 'budget', candidates: ['Keep', 'Extend'] },
    { id: 'fest', title: 'Festival theme', tags: ['events'], candidates: ['Music', 'Food', 'Art'] },
  ],
};
const sVoters: StructuredVoter[] = packets.slice(0, 5).map((pk, i) => ({
  credential: pk.credential,
  choices: { park: i % 3, lib: i % 2, ...(i % 2 ? { fest: i % 3 } : {}) },
}));
const sResult = runStructuredElection(spec, sVoters, keys, eligibleRoll);
const sVerify = verifyStructured(sResult);
for (const top of childrenOf(spec, undefined)) {
  const fmt = (id: string, cands: string[]) => {
    const res = sResult.results.find((r) => r.id === id)!;
    return cands.map((c, j) => `${c} ${res.transcript.results[j]}`).join('  ');
  };
  if (isLeaf(top)) {
    console.log(`   ▸ ${top.title} [${top.tags.join(',')}]: ${fmt(top.id, top.candidates!)}`);
  } else {
    console.log(`   ▸ ${top.title} [${top.tags.join(',')}]  (drill down)`);
    for (const child of childrenOf(spec, top.id)) console.log(`      • ${child.title}: ${fmt(child.id, child.candidates!)}`);
  }
}
console.log(`   tags: ${allTags(spec).join(', ')}   ·   all ${sResult.results.length} contests verify: ${sVerify.ok ? '✅' : '❌'}\n`);

console.log('MULTI-SEAT — "vote for exactly 2 of 4" (block voting):');
line();
const seatCands = ['Ana', 'Ben', 'Cy', 'Dee'];
const seatVoters: Voter[] = packets.slice(0, 5).map((pk, i) => ({ credential: pk.credential, choice: [i % 4, (i + 1) % 4] }));
const seatT = runElection('Board seats (pick 2)', seatCands, seatVoters, keys, eligibleRoll, undefined, 2);
console.log('   results: ' + seatCands.map((c, j) => `${c} ${seatT.results[j]}`).join('   ') + `   ·   verify: ${verifyTranscript(seatT).ok ? '✅' : '❌'}  (Σ = 2×${seatT.numVoters})\n`);

console.log('RANKED-CHOICE (Borda) — a full ranked election, end to end:');
line();
const rkCands = ['Ada', 'Grace', 'Alan', 'Linus'];
const rkVoters: RankedVoter[] = packets.slice(0, 5).map((pk, i) => ({ credential: pk.credential, ranking: [0, 1, 2, 3].map((x) => (x + i) % 4) }));
const rkT = runRankedElection('Board chair (ranked)', rkCands, rkVoters, keys, eligibleRoll, [1, 3, 5]);
const rkV = verifyRankedTranscript(rkT);
console.log('   Borda totals: ' + rkCands.map((c, i) => `${c} ${rkT.results[i]}`).join('   '));
console.log(`   ${rkV.ok ? '🟢 VERIFIED' : '🔴 REJECTED'} — each ballot a valid permutation matrix; Borda tally threshold-decrypted by 3 of 5 trustees.`);
console.log('   (Borda never reveals a ballot. For true IRV elimination, see the mixnet path below.)\n');

console.log('RANKED-CHOICE (IRV) — verifiable instant-runoff via a re-encryption mixnet:');
line();
const irvCands = ['Ada', 'Grace', 'Alan'];
// 2× Ada>Grace>Alan, 2× Grace>Ada>Alan, 1× Alan>Ada>Grace → round 1 [2,2,1] eliminate Alan → round 2 [3,2,0] Ada wins.
const irvRanks = [[0, 1, 2], [0, 1, 2], [1, 0, 2], [1, 0, 2], [1, 2, 0]];
const irvVoters: MixnetVoter[] = packets.slice(0, 5).map((pk, i) => ({ credential: pk.credential, ranking: irvRanks[i]! }));
const irvT = runMixnetElection('Board chair (IRV)', irvCands, irvVoters, keys, eligibleRoll, [1, 3, 5]);
const irvV = verifyMixnetTranscript(irvT);
for (const [n, rd] of irvT.rounds.entries()) {
  const tally = irvCands.map((c, i) => `${c} ${rd.tallies[i]}`).join('  ');
  console.log(`   round ${n + 1}: ${tally}${rd.eliminatedThisRound !== null ? `  → eliminate ${irvCands[rd.eliminatedThisRound]}` : `  → 🏆 ${irvCands[rd.winner!]} wins`}`);
}
console.log(`   ${irvV.ok ? '🟢 VERIFIED' : '🔴 REJECTED'} — ballots shuffled by a proven re-encryption mixnet, then threshold-decrypted and tabulated; the verifier re-runs the rounds.`);
console.log('   ⚠ IRV REVEALS the anonymized ranking multiset (hides only WHICH voter cast which) — weaker than Borda. Not coercion-resistant.\n');

// Publish the transcripts so anyone can re-verify them from the public record alone.
mkdirSync('out', { recursive: true });
writeFileSync('out/transcript.json', transcriptToJSON(t));
writeFileSync('out/ranked.json', rankedTranscriptToJSON(rkT));
console.log('Public transcripts written to reference/out/ — verify them yourself:');
console.log('  npm run verify -- out/transcript.json   (plurality)');
console.log('  npm run verify -- out/ranked.json        (ranked-choice Borda)\n');

line('━');
console.log('  Summary: the honest election verifies; every insider attack is caught.');
console.log('  Eligibility · one-vote-per-credential · one-of-K · secrecy · k-of-n · cast-or-challenge · verifiable tally.');
line('━');
