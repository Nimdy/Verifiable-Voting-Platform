#!/usr/bin/env python3
"""Independent verifier for a published Verifiable Voting transcript.

This is a SECOND, independent implementation of the verifier — a different language
(Python) on a different cryptographic library (libsodium's ristretto255 via pysodium),
written to the published wire format (transcript.json). If it agrees with the
TypeScript reference verifier on every transcript, a single-implementation bug in
either is far less likely to hide. It re-derives everything from the public record
alone and trusts nothing about who produced it.

    python3 vvp_verify.py <transcript.json>      # exit 0 = VERIFIED, 1 = REJECTED, 2 = usage

Requires: pysodium + a system libsodium.  (pip install pysodium)
"""
import hashlib
import json
import sys

import pysodium

# ristretto255 scalar-field (prime) order.
L = 2**252 + 27742317777372353535851937790883648493
ZERO = b"\x00" * 32  # canonical encoding of the ristretto identity element


# ---- group / scalar helpers (mirrors reference/src/group.ts) ----------------
def scalar_le(n: int) -> bytes:
    return (n % L).to_bytes(32, "little")


def smul(p: bytes, n: int) -> bytes:
    """n * p, handling the 0-scalar / identity cases libsodium rejects."""
    n %= L
    if n == 0 or p == ZERO:
        return ZERO
    try:
        return pysodium.crypto_scalarmult_ristretto255(scalar_le(n), p)
    except Exception:
        return ZERO  # libsodium raises iff the result is the identity


G = pysodium.crypto_scalarmult_ristretto255_base(scalar_le(1))


def padd(a: bytes, b: bytes) -> bytes:
    if a == ZERO:
        return b
    if b == ZERO:
        return a
    return pysodium.crypto_core_ristretto255_add(a, b)


def pneg(p: bytes) -> bytes:
    return smul(p, L - 1)  # (L-1)*p = -p


def psub(a: bytes, b: bytes) -> bytes:
    return padd(a, pneg(b))


def u32(n: int) -> bytes:
    return n.to_bytes(4, "big")


def scalar_be(x: int) -> bytes:
    return (x % L).to_bytes(32, "big")


def hash_to_scalar(label: str, points) -> int:
    dst = b"vvp-fs-v1"
    lab = label.encode()
    frame = u32(len(dst)) + dst + u32(len(lab)) + lab + u32(len(points)) + b"".join(points)
    return int.from_bytes(hashlib.sha512(frame).digest(), "big") % L


# ---- parsing (validates every point + scalar; mirrors pointFromHex/inRange) --
def parse_point(h: str) -> bytes:
    b = bytes.fromhex(h)
    if len(b) != 32 or not pysodium.crypto_core_ristretto255_is_valid_point(b):
        raise ValueError("invalid ristretto point")
    return b


def parse_scalar(s: str) -> int:
    x = int(s)
    if x < 0 or x >= L:
        raise ValueError("non-canonical scalar")
    return x


def parse_ct(j):
    return {"a": parse_point(j["a"]), "b": parse_point(j["b"])}


def parse_bit(j):
    return {
        "T0g": parse_point(j["T0g"]), "T0h": parse_point(j["T0h"]),
        "T1g": parse_point(j["T1g"]), "T1h": parse_point(j["T1h"]),
        "c0": parse_scalar(j["c0"]), "c1": parse_scalar(j["c1"]),
        "s0": parse_scalar(j["s0"]), "s1": parse_scalar(j["s1"]),
    }


def parse_sum(j):
    return {"Tg": parse_point(j["Tg"]), "Th": parse_point(j["Th"]),
            "c": parse_scalar(j["c"]), "s": parse_scalar(j["s"])}


def parse_sel(j):
    return {"enc": [parse_ct(c) for c in j["enc"]],
            "bitProofs": [parse_bit(b) for b in j["bitProofs"]],
            "sumProof": parse_sum(j["sumProof"])}


def parse_dec(j):
    return {"Tg": parse_point(j["Tg"]), "Ta": parse_point(j["Ta"]),
            "c": parse_scalar(j["c"]), "s": parse_scalar(j["s"])}


# ---- serialization (mirrors reference/src/codec.ts) -------------------------
def bit_bytes(p) -> bytes:
    return (p["T0g"] + p["T0h"] + p["T1g"] + p["T1h"]
            + scalar_be(p["c0"]) + scalar_be(p["c1"]) + scalar_be(p["s0"]) + scalar_be(p["s1"]))


def sum_bytes(p) -> bytes:
    return p["Tg"] + p["Th"] + scalar_be(p["c"]) + scalar_be(p["s"])


def election_context(contest: str, pk: bytes, candidates) -> bytes:
    out = b"vvp-ctx-v1"
    cb = contest.encode()
    out += u32(len(cb)) + cb + pk + u32(len(candidates))
    for name in candidates:
        nb = name.encode()
        out += u32(len(nb)) + nb
    return out


def signing_bytes(ctx: bytes, sel) -> bytes:
    out = ctx + u32(len(sel["enc"]))
    for j in range(len(sel["enc"])):
        out += sel["enc"][j]["a"] + sel["enc"][j]["b"] + bit_bytes(sel["bitProofs"][j])
    return out + sum_bytes(sel["sumProof"])


def board_bytes(ctx: bytes, cred: bytes, sel, sig) -> bytes:
    return cred + signing_bytes(ctx, sel) + sig["R"] + scalar_be(sig["s"])


# ---- RFC-6962 Merkle (mirrors reference/src/bulletin.ts) --------------------
def mth(items) -> bytes:
    n = len(items)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + items[0]).digest()
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + mth(items[:k]) + mth(items[k:])).digest()


# ---- proof verification (mirrors reference/src/proofs.ts + credentials.ts) --
def verify_bit(h, ct, p) -> bool:
    a, b = ct["a"], ct["b"]
    B0, B1 = b, psub(b, G)
    c = hash_to_scalar("ballot-bit", [h, a, b, p["T0g"], p["T0h"], p["T1g"], p["T1h"]])
    if (p["c0"] + p["c1"]) % L != c:
        return False
    if smul(G, p["s0"]) != padd(p["T0g"], smul(a, p["c0"])):
        return False
    if smul(h, p["s0"]) != padd(p["T0h"], smul(B0, p["c0"])):
        return False
    if smul(G, p["s1"]) != padd(p["T1g"], smul(a, p["c1"])):
        return False
    if smul(h, p["s1"]) != padd(p["T1h"], smul(B1, p["c1"])):
        return False
    return True


def verify_sum_equal(h, agg, p, L) -> bool:
    LG = smul(G, L)
    target = psub(agg["b"], LG)  # equals h^R iff Σ votes == L
    c = hash_to_scalar("sum-eq", [h, agg["a"], agg["b"], LG, p["Tg"], p["Th"]])
    if c != p["c"]:
        return False
    if smul(G, p["s"]) != padd(p["Tg"], smul(agg["a"], p["c"])):
        return False
    if smul(h, p["s"]) != padd(p["Th"], smul(target, p["c"])):
        return False
    return True


def verify_decryption(a, pub, share, p) -> bool:
    c = hash_to_scalar("decryption", [G, a, pub, share, p["Tg"], p["Ta"]])
    if c != p["c"]:
        return False
    if smul(G, p["s"]) != padd(p["Tg"], smul(pub, p["c"])):
        return False
    if smul(a, p["s"]) != padd(p["Ta"], smul(share, p["c"])):
        return False
    return True


def verify_sig(pub, msg, sig) -> bool:
    d = hashlib.sha512(b"vvp-cred-sig-v1|" + sig["R"] + pub + msg).digest()
    e = int.from_bytes(d, "big") % L
    return smul(G, sig["s"]) == padd(sig["R"], smul(pub, e))


# ---- threshold (mirrors reference/src/threshold.ts) -------------------------
def verification_key_at(commitments, index: int) -> bytes:
    acc = ZERO
    zpow = 1
    for C in commitments:
        acc = padd(acc, smul(C, zpow))
        zpow = (zpow * index) % L
    return acc


def lagrange0(j: int, S) -> int:
    num, den = 1, 1
    for m in S:
        if m == j:
            continue
        num = (num * (-m)) % L
        den = (den * (j - m)) % L
    return (num * pow(den, L - 2, L)) % L


def combine_shares(shares) -> bytes:
    S = [idx for idx, _ in shares]
    acc = ZERO
    for idx, d in shares:
        acc = padd(acc, smul(d, lagrange0(idx, S)))
    return acc


def discrete_log(M, max_n: int):
    acc = ZERO
    for i in range(max_n + 1):
        if acc == M:
            return i
        acc = padd(acc, G)
    return None


def selection_valid(pk, sel, K, L) -> bool:
    if len(sel["enc"]) != K or len(sel["bitProofs"]) != K:
        return False
    for j in range(K):
        if not verify_bit(pk, sel["enc"][j], sel["bitProofs"][j]):
            return False
    agg = {"a": ZERO, "b": ZERO}
    for c in sel["enc"]:
        agg = {"a": padd(agg["a"], c["a"]), "b": padd(agg["b"], c["b"])}
    return verify_sum_equal(pk, agg, sel["sumProof"], L)


# ---- the verifier ----------------------------------------------------------
def verify(j):
    checks = []

    def add(name, ok, detail=None):
        checks.append((name, ok, detail))

    candidates = j["candidates"]
    K = len(candidates)
    k = j["threshold"]
    n_trustees = j["trustees"]
    num_voters = j["numVoters"]
    selection_limit = j["selectionLimit"]

    shape_ok = (
        K > 0 and isinstance(k, int) and k >= 1
        and isinstance(n_trustees, int) and n_trustees >= k
        # numVoters is attacker-controlled; pin it to the ballot count (discrete-log bound + sum target).
        and isinstance(num_voters, int) and num_voters == len(j["ballots"])
        and isinstance(selection_limit, int) and 1 <= selection_limit <= K
        and len(j["commitments"]) == k
        and len(j["aggregates"]) == K and len(j["results"]) == K
        and all(len(b["selection"]["enc"]) == K and len(b["selection"]["bitProofs"]) == K for b in j["ballots"])
        and all(len(d["shares"]) == K and len(d["proofs"]) == K for d in j["decShares"])
    )
    add("Transcript shape: K-length arrays and k commitments", shape_ok)
    if not shape_ok:
        return False, checks, None

    commitments = [parse_point(c) for c in j["commitments"]]
    public_key = parse_point(j["publicKey"])
    eligible = {parse_point(c) for c in j["eligibleRoll"]}
    add("Eligible roll has no duplicate credentials", len(eligible) == len(j["eligibleRoll"]))
    ctx = election_context(j["contest"], public_key, candidates)

    ballots = [{
        "voter": b["voter"], "credentialPub": parse_point(b["credentialPub"]),
        "selection": parse_sel(b["selection"]),
        "sig": {"R": parse_point(b["sig"]["R"]), "s": parse_scalar(b["sig"]["s"])},
    } for b in j["ballots"]]
    aggregates = [parse_ct(c) for c in j["aggregates"]]
    dec_shares = [{
        "trusteeIndex": d["trusteeIndex"],
        "shares": [parse_point(s) for s in d["shares"]],
        "proofs": [parse_dec(p) for p in d["proofs"]],
    } for d in j["decShares"]]

    add("Joint public key = commitment C0 (threshold key)", commitments[0] == public_key)

    root = mth([board_bytes(ctx, b["credentialPub"], b["selection"], b["sig"]) for b in ballots]).hex()
    add("Bulletin-board Merkle root matches the published ballots", root == j["boardRoot"])

    seen = set()
    inelig = bad_sig = dup = 0
    for b in ballots:
        key = b["credentialPub"]
        if key not in eligible:
            inelig += 1
        if not verify_sig(b["credentialPub"], signing_bytes(ctx, b["selection"]), b["sig"]):
            bad_sig += 1
        if key in seen:
            dup += 1
        seen.add(key)
    add("Every ballot is signed by an eligible voter credential", inelig == 0 and bad_sig == 0,
        f"{inelig} ineligible, {bad_sig} bad sig" if (inelig or bad_sig) else None)
    add("No credential voted more than once (single-use nullifier)", dup == 0)

    invalid = sum(0 if selection_valid(public_key, b["selection"], K, selection_limit) else 1 for b in ballots)
    add(f"Every ballot selects exactly {selection_limit} candidate(s) (zero-knowledge)", invalid == 0)

    agg_bad = 0
    for jx in range(K):
        a = {"a": ZERO, "b": ZERO}
        for b in ballots:
            a = {"a": padd(a["a"], b["selection"]["enc"][jx]["a"]),
                 "b": padd(a["b"], b["selection"]["enc"][jx]["b"])}
        if a["a"] != aggregates[jx]["a"] or a["b"] != aggregates[jx]["b"]:
            agg_bad += 1
    add("Each candidate aggregate = homomorphic sum of its column", agg_bad == 0)

    indices = [d["trusteeIndex"] for d in dec_shares]
    distinct = len(set(indices)) == len(indices)
    registered = all(isinstance(i, int) and 1 <= i <= n_trustees for i in indices)
    add(f"Decryption quorum: >= {k} distinct registered trustees (1..{n_trustees})",
        distinct and registered and len(dec_shares) >= k)

    bad_shares = 0
    for d in dec_shares:
        if not (isinstance(d["trusteeIndex"], int) and 1 <= d["trusteeIndex"] <= n_trustees):
            bad_shares += K
            continue
        pub = verification_key_at(commitments, d["trusteeIndex"])
        for jx in range(K):
            if not verify_decryption(aggregates[jx]["a"], pub, d["shares"][jx], d["proofs"][jx]):
                bad_shares += 1
    add("Every trustee decryption share is provably honest", bad_shares == 0)

    valid = [d for d in dec_shares if isinstance(d["trusteeIndex"], int) and 1 <= d["trusteeIndex"] <= n_trustees]
    results = []
    tally_bad = 0
    for jx in range(K):
        combined = combine_shares([(d["trusteeIndex"], d["shares"][jx]) for d in valid])
        m = discrete_log(psub(aggregates[jx]["b"], combined), len(ballots))
        results.append(m if m is not None else -1)
        if m != j["results"][jx]:
            tally_bad += 1
    sum_ok = sum(results) == selection_limit * num_voters
    add("Published per-candidate totals equal the decrypted aggregates", tally_bad == 0 and sum_ok,
        f"sum={sum(results)}")

    ok = all(c[1] for c in checks)
    return ok, checks, (results if tally_bad == 0 else None)


def main():
    if len(sys.argv) < 2:
        print("usage: python3 vvp_verify.py <transcript.json>", file=sys.stderr)
        sys.exit(2)
    try:
        with open(sys.argv[1]) as f:
            data = json.load(f)
        ok, checks, results = verify(data)
    except Exception as e:  # the trust root always emits a verdict
        print(f"❌ could not parse/verify: {e}")
        sys.exit(1)
    for name, cok, detail in checks:
        print(f"{'✅' if cok else '❌'} {name}" + (f"  ({detail})" if detail else ""))
    print(("\n\U0001f7e2 VERIFIED — results: " + str(results)) if ok else "\n\U0001f534 REJECTED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
