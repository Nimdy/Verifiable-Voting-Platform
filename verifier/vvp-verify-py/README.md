# Independent verifier (Python + libsodium)

A **second, independent implementation** of the transcript verifier — a different
language (Python) on a different cryptographic library (**libsodium's ristretto255**
via `pysodium`), written to the published `transcript.json` wire format. It re-derives
everything from the public record alone and trusts nothing about who produced it.

This embodies the project's *"two implementations, two teams, two languages"* principle:
if this verifier and the TypeScript reference verifier agree on every transcript, a
single-implementation bug in either is far less likely to hide. **CI runs both on every
push** (a transcript produced by the TS engine is independently checked here).

## Run

```bash
# from this directory; needs a system libsodium (e.g. libsodium23)
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# generate a transcript with the TypeScript engine first:
#   (cd ../../reference && npm install && npm run demo)
python vvp_verify.py ../../reference/out/transcript.json
```

Exit code: `0` = 🟢 VERIFIED, `1` = 🔴 REJECTED, `2` = usage error.

It validates every group element on parse, recomputes the RFC-6962 Merkle root, and
re-checks all signatures, the disjunctive/exactly-one/decryption zero-knowledge proofs,
the k-of-n threshold quorum and Lagrange combination, and the final tally — exactly the
checks in [`reference/src/verify.ts`](../../reference/src/verify.ts), reimplemented
independently.

> ⚠️ Pre-audit. Not for binding elections. See [../../docs/SCOPE.md](../../docs/SCOPE.md).
