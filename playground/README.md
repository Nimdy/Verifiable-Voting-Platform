# Playground

Run a real **end-to-end-verifiable election in your browser** in ~30 seconds.

```bash
cd playground
npm install
npm run dev        # opens http://localhost:5173
```

Then, in 5 steps:

1. **Ask a question** and cast votes (or hit *Simulate 7 voters*).
2. **Watch the public bulletin board** fill with your votes — encrypted. This is all anyone ever sees.
3. **Tally & Verify** — the result is proven correct from the public record alone, and *no individual ballot is revealed*.
4. **Try to cheat it** — flip a stored ballot, stuff a fake vote, or rig the result — and watch the verifier catch you every time.

It reuses the **exact audited crypto** from [`../reference`](../reference) (built automatically on `dev`/`build`). No crypto is reimplemented here.

> ⚠️ Pre-audit demo. Not for binding elections. See [../docs/SCOPE.md](../docs/SCOPE.md).
