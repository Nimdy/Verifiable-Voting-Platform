// Standalone verifier: re-verify a published election transcript from the public
// record ALONE, trusting nothing about who produced it.
//
//   npx tsx src/verify-cli.ts out/transcript.json   # plurality / multi-seat
//   npx tsx src/verify-cli.ts out/ranked.json       # ranked-choice (Borda)
//
// The transcript's own `kind` field selects the verifier, so one command checks
// either format. Exit code 0 = VERIFIED, 1 = REJECTED, 2 = usage error.

import { readFileSync } from 'node:fs';
import { transcriptFromJSON, rankedTranscriptFromJSON } from './transcript-json.js';
import { verifyTranscript } from './verify.js';
import { verifyRankedTranscript } from './ranked.js';

const path = process.argv[2];
if (!path) {
  console.error('usage: tsx src/verify-cli.ts <transcript.json>');
  process.exit(2);
}

let result;
try {
  const raw = readFileSync(path, 'utf8');
  const kind: unknown = JSON.parse(raw).kind;
  result = kind === 'ranked'
    ? verifyRankedTranscript(rankedTranscriptFromJSON(raw))
    : verifyTranscript(transcriptFromJSON(raw));
} catch (err) {
  console.error(`❌ Could not parse/verify transcript: ${String(err)}`);
  process.exit(1);
}

for (const c of result.checks) {
  console.log(`${c.ok ? '✅' : '❌'} ${c.name}${c.detail ? `  (${c.detail})` : ''}`);
}
console.log(result.ok ? `\n🟢 VERIFIED — results: ${JSON.stringify(result.results)}` : '\n🔴 REJECTED');
process.exit(result.ok ? 0 : 1);
