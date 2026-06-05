# Security Policy

This is a voting system. Integrity and ballot secrecy are the product. We treat
security reports with the seriousness that implies.

## Reporting a vulnerability

**Do not open a public issue for security problems.** This includes cryptographic
weaknesses, ways to forge or alter ballots, ways to de-anonymize a voter, ways to
double-vote, or ways to make the tally disagree with the ballots.

Report privately via a
[GitHub Security Advisory](https://github.com/Nimdy/voting-system-blockchain/security/advisories/new).
Include a description, affected component, and a proof-of-concept if you have one.

## Scope & honest status

> ⚠️ **This project is pre-audit and explicitly NOT for binding government or public
> elections.** See [docs/SCOPE.md](docs/SCOPE.md). It targets low-stakes, low-coercion,
> recoverable voting (clubs, societies, associations, DAO/governance, polls).

- The `reference/` directory is a **stage-1 proof of concept** for learning and
  protocol validation. It has **not** been independently audited and must not be used
  to run a consequential election.
- The cryptographic core, independent verifier, and any deployment profile must pass an
  **external cryptographic review and red-team** (milestone M7) before real-world use.

## What we will never do

- Derive identity from, or store, Social Security Numbers or other durable government IDs.
- Put plaintext ballots on a blockchain, or give a voter a transferable receipt proving
  how they voted.
- Claim software independence for a remote/digital-only deployment (only paper + a
  risk-limiting audit provides it).
