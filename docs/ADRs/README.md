# Architecture Decision Records

| ADR | Title | Status |
|-----|-------|--------|
| [0001](ADR-0001-never-derive-identity-tokens-from-ssn-or-any-durable-governm.md) | Never derive identity tokens from SSN or any durable government identifier; keep identity proofing off-ledger | Accepted |
| [0002](ADR-0002-the-blockchain-is-non-load-bearing-anchor-only-signed-merkle.md) | The blockchain is non-load-bearing: anchor only signed Merkle roots, never ballots | Accepted |
| [0003](ADR-0003-no-proof-of-stake-as-election-authority-permissioned-bft-wit.md) | No Proof-of-Stake as election authority; permissioned BFT with named validators if any chain is used | Accepted |
| [0004](ADR-0004-paper-ballots-of-record-plus-risk-limiting-audits-are-the-on.md) | Paper ballots of record plus risk-limiting audits are the only software-independence anchor; digital-only deployments must state they do not achieve software independence | Accepted |
| [0005](ADR-0005-enforce-single-use-with-published-per-credential-nullifiers-.md) | Enforce single-use with published per-credential nullifiers, not a time-to-live (TTL) | Accepted |
| [0006](ADR-0006-the-independent-verifier-is-implemented-in-a-different-langu.md) | The independent verifier is implemented in a different language and by a different team than the core | Accepted |
| [0007](ADR-0007-use-ristretto255-with-exponential-elgamal-following-election.md) | Use ristretto255 with exponential ElGamal following ElectionGuard 2.x; no hand-rolled ciphers | Accepted |
| [0008](ADR-0008-receipt-freeness-never-give-a-voter-a-transferable-proof-of-.md) | Receipt-freeness: never give a voter a transferable proof of how they voted | Accepted |
| [0009](ADR-0009-the-digital-paper-anchor-binds-the-board-root-to-the-paper-bal.md) | A signed digital↔paper anchor binds the bulletin-board root to the paper ballot manifest; secret-ballot paths use ballot-polling RLAs, never per-ballot CVRs | Accepted |
