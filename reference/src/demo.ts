// End-to-end demo: run a real verifiable election, then play the INSIDER and try
// to cheat four different ways — and watch the independent verifier catch every
// one. Run with:  npm run demo
//
// Thesis on display: count the votes, reveal no one's ballot, and make cheating
// impossible to hide.

import { mkdirSync, writeFileSync } from 'node:fs';
import { encrypt } from './elgamal.js';
import { proveBit, verifyBit } from './proofs.js';
import { randScalar, type Point } from './group.js';
import {
  setupTrustees, runElection, singleTrusteeAttempt, type Transcript,
} from './election.js';
import { verifyTranscript, type VerifyResult } from './verify.js';

const line = (c = '─') => console.log(c.repeat(72));
const h = (P: Point) => Buffer.from(P.toRawBytes()).toString('hex');

function report(label: string, r: VerifyResult): void {
  for (const c of r.checks) {
    console.log(`   ${c.ok ? '✅' : '❌'} ${c.name}${c.detail ? `  (${c.detail})` : ''}`);
  }
  console.log(`   ${r.ok ? '🟢 VERIFIED' : '🔴 REJECTED'} — ${label}\n`);
}

line('━');
console.log('  VERIFIABLE VOTING — reference proof of concept');
console.log('  "Verify everything. Reveal nothing. No insider can cheat unseen."');
line('━');

// ---------------------------------------------------------------------------
// Setup: 3 trustees (e.g. 3 independent observers) jointly hold the key.
// 7 voters cast a yes/no ballot. True result: 4 YES, 3 NO.
// ---------------------------------------------------------------------------
const trustees = setupTrustees(3);
const votes: (0 | 1)[] = [1, 0, 1, 1, 0, 1, 0]; // 4 YES, 3 NO
const truth = votes.filter((v) => v === 1).length;

console.log(`\nContest: "Adopt Proposal 1?"   Options: [No, Yes]`);
console.log(`Trustees (key split across them): ${trustees.length}`);
console.log(`Voters: ${votes.length}   (ground truth: ${truth} YES / ${votes.length - truth} NO)\n`);

const transcript = runElection('Adopt Proposal 1?', ['No', 'Yes'], votes, trustees);

console.log(`Joint public key:  ${h(transcript.publicKey).slice(0, 32)}…`);
console.log(`Bulletin-board root: ${transcript.boardRoot.slice(0, 32)}…`);
console.log(`Authority announces: ${transcript.claimedTally} YES\n`);

// Persist the public transcript so it can be eyeballed — this is ALL that's public.
mkdirSync('out', { recursive: true });
writeFileSync('out/transcript.json', JSON.stringify({
  contest: transcript.contest,
  options: transcript.options,
  numVoters: transcript.numVoters,
  publicKey: h(transcript.publicKey),
  trusteePubs: transcript.trusteePubs.map((p) => ({ index: p.index, pub: h(p.pub) })),
  ballots: transcript.ballots.map((b) => ({
    voter: b.voter,
    a: h(b.ct.a), b: h(b.ct.b),
    validityProof: {
      T0g: h(b.proof.T0g), T0h: h(b.proof.T0h), T1g: h(b.proof.T1g), T1h: h(b.proof.T1h),
      c0: b.proof.c0.toString(), c1: b.proof.c1.toString(),
      s0: b.proof.s0.toString(), s1: b.proof.s1.toString(),
    },
  })),
  boardRoot: transcript.boardRoot,
  claimedTally: transcript.claimedTally,
}, null, 2));
console.log('Public transcript written to reference/out/transcript.json');
console.log('(Notice: it contains encrypted ballots only — no plaintext votes.)\n');

line();
console.log('1) HONEST ELECTION — anyone re-verifies it from the transcript alone:');
line();
report('the published result is provably correct', verifyTranscript(transcript));

// ---------------------------------------------------------------------------
// Privacy: a lone trustee tries to decrypt a single ballot. It can't.
// ---------------------------------------------------------------------------
line();
console.log('2) BALLOT SECRECY — a lone trustee tries to unmask one voter:');
line();
const sneaky = singleTrusteeAttempt(transcript.ballots[1]!.ct, trustees[0]!, transcript.numVoters);
console.log(`   Trustee #1 alone tries to decrypt voter-2's ballot → ${sneaky === null ? '❌ FAILED' : `recovered ${sneaky}`}`);
console.log('   ✅ No single trustee can read any ballot. Only the TOTAL is ever decrypted.\n');

// ---------------------------------------------------------------------------
// 3) INSIDER ATTACK A — alter a ballot already on the board.
// ---------------------------------------------------------------------------
line();
console.log('3) INSIDER ATTACK — an admin secretly flips voter-3\'s stored ballot:');
line();
const tamperedBallots = transcript.ballots.map((b, i) =>
  i === 2 ? { ...b, ct: { a: b.ct.a, b: b.ct.b.add(transcript.publicKey) } } : b);
const attackA: Transcript = { ...transcript, ballots: tamperedBallots };
report('tampering breaks the Merkle root AND the validity proof', verifyTranscript(attackA));

// ---------------------------------------------------------------------------
// 4) INSIDER ATTACK B — stuff an out-of-range vote (a "10" instead of 0/1).
// ---------------------------------------------------------------------------
line();
console.log('4) BALLOT STUFFING — a voter tries to cast "10" instead of 0 or 1:');
line();
const r = randScalar();
const stuffed = encrypt(transcript.publicKey, 10n, r);
const fakeProof = proveBit(transcript.publicKey, stuffed, 1, r); // lie: claim it's a "1"
const accepted = verifyBit(transcript.publicKey, stuffed, fakeProof);
console.log(`   Forged validity proof for an illegal vote accepted? ${accepted ? '🔴 YES' : '✅ NO'}`);
console.log('   ✅ Only genuine 0/1 ballots can ever produce a valid proof.\n');

// ---------------------------------------------------------------------------
// 5) INSIDER ATTACK C — a corrupt authority lies about the result.
// ---------------------------------------------------------------------------
line();
console.log('5) RIGGED RESULT — a corrupt authority announces a fake landslide:');
line();
const attackC: Transcript = { ...transcript, claimedTally: transcript.numVoters }; // claim all YES
report('the verifier recomputes the real tally and rejects the lie', verifyTranscript(attackC));

line('━');
console.log('  Summary: the honest election verifies; every insider attack is caught.');
console.log('  This is the seed the rest of the platform grows from.');
line('━');
