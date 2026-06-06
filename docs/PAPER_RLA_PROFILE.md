# Paper + RLA hybrid profile

> Honesty first. This profile **raises assurance; it does not certify**. Paper is the legal record;
> the risk-limiting audit on paper is what catches a flipped outcome; this engine is the transparent
> digital companion, not the source of software independence. See [ADR-0004](ADRs/ADR-0004-paper-ballots-of-record-plus-risk-limiting-audits-are-the-on.md)
> and [ADR-0009](ADRs/ADR-0009-the-digital-paper-anchor-binds-the-board-root-to-the-paper-bal.md).

## The model — three layers, three authorities

| Layer | Authority | What it provides |
|-------|-----------|------------------|
| **Paper ballots** (voter-verified, retained under custody) | **The legal record. Paper wins on any discrepancy.** | The recountable physical truth an audit reads. |
| **This E2E-V engine** (the digital companion) | Transparency | An encrypted RFC-6962 board, public ZK proofs, a publicly re-verifiable tally checked by **two** independent verifiers (TS + Python). It is *not* the legal record and casts no ballot of record itself. |
| **A risk-limiting audit on the paper** (VotingWorks Arlo / SHANGRLA) | Statistical confirmation | A hypothesis test on the reported **winner** to a chosen risk limit α — escalating to a full hand count if the reported outcome is wrong. |

The three together are strictly stronger than any one alone: the digital layer independently rejects a
rigged *digital* tally; the RLA independently rejects a wrong *paper-vs-reported* outcome; and the
**anchor** makes a swap between the two records detectable.

## What this profile adds — `reference/src/rla.ts`

It is an **export + anchor** layer over the existing engine. It re-implements **no** authoritative RLA
statistics; it produces the inputs an external RLA tool ingests, plus the binding anchor.

- **Ballot manifest** (`makeManifest`, `ballotManifestRoot`) — the paper batches (`batchId`, `ballotCount`)
  an RLA samples from. The RFC-6962 root over the (sorted) batch rows is the `paperManifestRoot`.
- **Digital↔paper anchor** (`buildAnchor`, `verifyAnchor`) — a single object signed by the named
  election-authority key that binds the published `boardRoot` (the digital universe) to the
  `paperManifestRoot` (the paper universe), with the ballot counts and the election public key. Anyone
  re-verifies it from the public record; `verifyAnchor` never throws. **This is the only thing an
  optional blockchain adapter writes — ~64 bytes of roots, never a ballot** ([ADR-0002](ADRs/ADR-0002-the-blockchain-is-non-load-bearing-anchor-only-signed-merkle.md)).
- **Ballot-polling export** (`pollingExport`, `reportedResults`) — contest, candidates, reported tally,
  total ballots, manifest, anchor. **For secret-ballot paths this carries totals only — never a
  per-ballot CVR** (that is the privacy guarantee, made concrete).
- **External-tool emitters** — `toArloManifestCsv` (Container, Tabulator, Batch Name, Number of Ballots),
  `toShangrlaManifestCsv` (Batch, Total Ballots).
- **Illustrative risk reference** (`bravoSampleSize`) — a top-two BRAVO sample-size estimate, **clearly
  labelled non-authoritative** (ignores undervotes/other candidates; no stratification). Arlo/SHANGRLA on
  the paper are the audit of record.
- **mixnet-IRV anonymized CVRs** (`toRankingsCsv`) — only the IRV path, whose anonymized ranking multiset
  is *already public* (decrypted, unlinked to voters), may be exported as anonymized CVRs.

## The hard rules (do not relax)

1. **Secret-ballot tallies (plurality / multi-seat / Borda) → ballot-POLLING RLAs only; never per-ballot
   CVRs.** They decrypt only per-candidate totals — there is no per-ballot plaintext to leak, and a
   comparison RLA's CVRs would break ballot secrecy.
2. **Paper wins.** A paper/digital count mismatch is a *flagged discrepancy* resolved by the canvass/RLA,
   not a halt — the paper is the legal record.
3. **Software independence comes from paper + a correctly-run RLA, not from this engine.** A sound E2E-V
   transcript over a malicious endpoint still faithfully carries a flipped choice; only the paper-anchored
   RLA catches that. This is the **in-person, supervised polling-place profile only**.

## What the hybrid catches — and does not

**Catches:** an outcome-changing tabulation/scanner error or a rigged reported tally (the RLA against
paper, to risk limit α); a rigged *digital* tally (the engine's verifier); a post-hoc swap of either
record (the anchor).

**Does NOT catch:** coercion / vote-buying; a compromised endpoint's effect on the *digital* artifacts;
ballot-stuffing of the *paper* itself or phantom paper ballots; chain-of-custody breaks; a wrong or
untrusted ballot manifest. Chain-of-custody, the scanner interpretation, and the RLA ceremony are
**off-system / represented**. **Pre-audit; not certified for binding government use.**

## Using it

```ts
import { makeManifest, buildAnchor, verifyAnchor, toArloManifestCsv, bravoSampleSize } from '@vvp/reference';

const manifest = makeManifest(t.contest, [{ batchId: 'precinct-1', ballotCount: 400 }, /* … */]);
const anchor = buildAnchor({ contest: t.contest, boardRoot: t.boardRoot, numVoters: t.numVoters,
                             publicKey: t.publicKey, manifest, signer: electionAuthorityKey, anchoredAt });
// publish `anchor` (+ the digital transcript). anyone re-verifies — PIN the published authority key:
verifyAnchor(anchor, manifest, { boardRoot: t.boardRoot, numVoters: t.numVoters, publicKey, signerPub: trustedAuthorityPub });
// (a valid self-signature alone proves only self-consistency; pinning `signerPub` proves the authority you trust signed it)
// hand toArloManifestCsv(manifest) + the reported tally to Arlo/SHANGRLA; run the RLA on the PAPER.
```

`npm run demo` prints this end-to-end. Deferred (tracked): a Python cross-verifier for the anchor,
the chain-anchor adapter, and production RLA statistics (Arlo/SHANGRLA remain authoritative).
