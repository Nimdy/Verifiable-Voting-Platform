#!/usr/bin/env python3
"""Independent verifier for a published Verifiable Voting transcript.

This is a SECOND, independent implementation of the verifier — a different language
(Python) on a different cryptographic library (libsodium's ristretto255 via pysodium),
written to the published wire format (transcript.json). If it agrees with the
TypeScript reference verifier on every transcript, a single-implementation bug in
either is far less likely to hide. It re-derives everything from the public record
alone and trusts nothing about who produced it.

Handles all transcript kinds — plurality/multi-seat, ranked-choice (Borda),
ranked-choice IRV (mixnet), the paper+RLA hybrid export (rla-export), and the
everlasting-privacy commitment trail (everlasting-trail) — dispatching on the
transcript's own `kind` field.

    python3 vvp_verify.py <transcript.json>      # exit 0 = VERIFIED, 1 = REJECTED, 2 = usage

Requires: pysodium + a system libsodium.  (pip install pysodium)
"""
import hashlib
import json
import re
import sys

import pysodium

# ristretto255 scalar-field (prime) order.
L = 2**252 + 27742317777372353535851937790883648493
ZERO = b"\x00" * 32  # canonical encoding of the ristretto identity element
SECURITY_T = 128  # mixnet shuffle Fiat-Shamir floor (mirrors reference/src/mixnet.ts)


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

# Second, independent generator H for Pedersen commitments (everlasting privacy; mirrors group.ts).
# NUMS: the ristretto255 one-way map (RFC 9496 from_hash) over SHA-512 of a fixed label, so dlog_G(H)
# is unknown. libsodium's crypto_core_ristretto255_from_hash and @noble's hashToCurve agree byte-for-byte.
PEDERSEN_H_LABEL = b"vvp-everlasting-pedersen-H-v1"
PEDERSEN_H_HEX = "b66dc28b63ecfbb83fa33aad8148a54f17757fce571ad6b8df258d3cfa2a777a"
H = pysodium.crypto_core_ristretto255_from_hash(hashlib.sha512(PEDERSEN_H_LABEL).digest())


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
    # Gate the STRING form to a strict canonical decimal grammar before converting. int() is permissive
    # (underscores, Unicode digits, signs, whitespace) and JS BigInt() is permissive in OTHER ways
    # (0x/0o/0b prefixes, empty string), so without this gate one verifier could accept a same-value-
    # different-syntax scalar the other rejects (a dual-verifier equivalence break). Mirrors group.ts
    # scalarFromDecimal exactly.
    if not isinstance(s, str) or not re.fullmatch(r"0|[1-9][0-9]*", s):
        raise ValueError("non-canonical scalar string")
    x = int(s, 10)
    if x >= L:
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


# ---- ranked-choice (Borda): mirrors reference/src/ranked.ts -----------------
def parse_ranked_ballot(j):
    return {
        "matrix": [[parse_ct(c) for c in row] for row in j["matrix"]],
        "bitProofs": [[parse_bit(b) for b in row] for row in j["bitProofs"]],
        "rowSums": [parse_sum(s) for s in j["rowSums"]],
        "colSums": [parse_sum(s) for s in j["colSums"]],
    }


def ranked_signing_bytes(ctx: bytes, b) -> bytes:
    K = len(b["matrix"])
    out = ctx + u32(K)
    for i in range(K):
        for r in range(K):
            ct = b["matrix"][i][r]
            out += ct["a"] + ct["b"] + bit_bytes(b["bitProofs"][i][r])
    for i in range(K):
        out += sum_bytes(b["rowSums"][i])
    for r in range(K):
        out += sum_bytes(b["colSums"][r])
    return out


def ranked_board_bytes(ctx: bytes, cred: bytes, b, sig) -> bytes:
    return cred + ranked_signing_bytes(ctx, b) + sig["R"] + scalar_be(sig["s"])


def verify_ranking_valid(pk, b) -> bool:
    K = len(b["matrix"])
    if K == 0 or len(b["bitProofs"]) != K or len(b["rowSums"]) != K or len(b["colSums"]) != K:
        return False
    for i in range(K):
        if len(b["matrix"][i]) != K or len(b["bitProofs"][i]) != K:
            return False
        for r in range(K):
            if not verify_bit(pk, b["matrix"][i][r], b["bitProofs"][i][r]):
                return False
    for i in range(K):  # every row (candidate) gets exactly one rank
        agg = {"a": ZERO, "b": ZERO}
        for c in b["matrix"][i]:
            agg = {"a": padd(agg["a"], c["a"]), "b": padd(agg["b"], c["b"])}
        if not verify_sum_equal(pk, agg, b["rowSums"][i], 1):
            return False
    for r in range(K):  # every column (rank) goes to exactly one candidate
        agg = {"a": ZERO, "b": ZERO}
        for row in b["matrix"]:
            agg = {"a": padd(agg["a"], row[r]["a"]), "b": padd(agg["b"], row[r]["b"])}
        if not verify_sum_equal(pk, agg, b["colSums"][r], 1):
            return False
    return True


def borda_ballot_totals(b):
    """Candidate i -> Sum_r (K-1-r)*M[i][r], a public-weight linear combo of verified ciphertexts."""
    K = len(b["matrix"])
    out = []
    for row in b["matrix"]:
        acc = {"a": ZERO, "b": ZERO}
        for r in range(K):
            w = K - 1 - r
            acc = {"a": padd(acc["a"], smul(row[r]["a"], w)), "b": padd(acc["b"], smul(row[r]["b"], w))}
        out.append(acc)
    return out


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


# ---- the ranked-choice (Borda) verifier; mirrors verifyRankedInner ----------
def verify_ranked(j):
    checks = []

    def add(name, ok, detail=None):
        checks.append((name, ok, detail))

    candidates = j["candidates"]
    K = len(candidates)
    k = j["threshold"]
    n_trustees = j["trustees"]
    num_voters = j["numVoters"]

    def square(b):  # every ranked ballot must be exactly K x K
        m = b["ballot"]
        return (
            len(m["matrix"]) == K and all(len(row) == K for row in m["matrix"])
            and len(m["bitProofs"]) == K and all(len(row) == K for row in m["bitProofs"])
            and len(m["rowSums"]) == K and len(m["colSums"]) == K
        )

    shape_ok = (
        K > 0 and isinstance(k, int) and k >= 1
        and isinstance(n_trustees, int) and n_trustees >= k
        # numVoters is attacker-controlled; pin it to the ballot count (discrete-log bound + sum target).
        and isinstance(num_voters, int) and num_voters == len(j["ballots"])
        and len(j["commitments"]) == k
        and len(j["bordaAggregates"]) == K and len(j["results"]) == K
        and all(len(d["shares"]) == K and len(d["proofs"]) == K for d in j["decShares"])
        and all(square(b) for b in j["ballots"])
    )
    add("Transcript shape: K aggregates, k commitments, numVoters = ballots", shape_ok)
    if not shape_ok:
        return False, checks, None

    commitments = [parse_point(c) for c in j["commitments"]]
    public_key = parse_point(j["publicKey"])
    eligible = {parse_point(c) for c in j["eligibleRoll"]}
    ctx = election_context(j["contest"], public_key, candidates)

    ballots = [{
        "voter": b["voter"], "credentialPub": parse_point(b["credentialPub"]),
        "ballot": parse_ranked_ballot(b["ballot"]),
        "sig": {"R": parse_point(b["sig"]["R"]), "s": parse_scalar(b["sig"]["s"])},
    } for b in j["ballots"]]
    borda_aggregates = [parse_ct(c) for c in j["bordaAggregates"]]
    dec_shares = [{
        "trusteeIndex": d["trusteeIndex"],
        "shares": [parse_point(s) for s in d["shares"]],
        "proofs": [parse_dec(p) for p in d["proofs"]],
    } for d in j["decShares"]]

    add("Joint public key = commitment C0 (threshold key)", commitments[0] == public_key)

    root = mth([ranked_board_bytes(ctx, b["credentialPub"], b["ballot"], b["sig"]) for b in ballots]).hex()
    add("Bulletin-board Merkle root matches the published ballots", root == j["boardRoot"])

    add("Eligible roll has no duplicate credentials", len(eligible) == len(j["eligibleRoll"]))

    seen = set()
    inelig = bad_sig = dup = 0
    for b in ballots:
        key = b["credentialPub"]
        if key not in eligible:
            inelig += 1
        if not verify_sig(b["credentialPub"], ranked_signing_bytes(ctx, b["ballot"]), b["sig"]):
            bad_sig += 1
        if key in seen:
            dup += 1
        seen.add(key)
    add("Every ballot is signed by an eligible voter credential", inelig == 0 and bad_sig == 0,
        f"{inelig} ineligible, {bad_sig} bad sig" if (inelig or bad_sig) else None)
    add("No credential voted more than once (single-use nullifier)", dup == 0)

    invalid = sum(0 if verify_ranking_valid(public_key, b["ballot"]) else 1 for b in ballots)
    add("Every ballot is a valid strict ranking (permutation matrix)", invalid == 0)

    per_ballot = [borda_ballot_totals(b["ballot"]) for b in ballots]
    agg_bad = 0
    for i in range(K):
        acc = {"a": ZERO, "b": ZERO}
        for pb in per_ballot:
            acc = {"a": padd(acc["a"], pb[i]["a"]), "b": padd(acc["b"], pb[i]["b"])}
        if acc["a"] != borda_aggregates[i]["a"] or acc["b"] != borda_aggregates[i]["b"]:
            agg_bad += 1
    add("Borda aggregates = homomorphic Borda sum of the ballots", agg_bad == 0)

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
        for i in range(K):
            if not verify_decryption(borda_aggregates[i]["a"], pub, d["shares"][i], d["proofs"][i]):
                bad_shares += 1
    add("Every trustee decryption share is provably honest", bad_shares == 0)

    valid = [d for d in dec_shares if isinstance(d["trusteeIndex"], int) and 1 <= d["trusteeIndex"] <= n_trustees]
    max_borda = (K - 1) * num_voters
    results = []
    tally_bad = 0
    for i in range(K):
        combined = combine_shares([(d["trusteeIndex"], d["shares"][i]) for d in valid])
        m = discrete_log(psub(borda_aggregates[i]["b"], combined), max_borda)
        results.append(m if m is not None else -1)
        if m != j["results"][i]:
            tally_bad += 1
    expected_sum = num_voters * (K * (K - 1) // 2)  # each ballot distributes 0+1+...+(K-1) Borda points
    sum_ok = sum(results) == expected_sum
    add("Borda totals equal the decrypted aggregates", tally_bad == 0 and sum_ok, f"sum={sum(results)}")

    ok = all(c[1] for c in checks)
    return ok, checks, (results if tally_bad == 0 else None)


# ---- mixnet instant-runoff (IRV); mirrors reference/src/mixnet-irv.ts + mixnet.ts -----------
def reenc_item(pk, item, factors):
    return [{"a": padd(item[w]["a"], smul(G, factors[w])), "b": padd(item[w]["b"], smul(pk, factors[w]))}
            for w in range(len(item))]


def apply_perm(src, perm):
    return [src[pi] for pi in perm]  # output[i] = src[perm[i]]


def is_permutation(perm, n) -> bool:
    if not isinstance(perm, list) or len(perm) != n:
        return False
    seen = [False] * n
    for v in perm:
        if not isinstance(v, int) or isinstance(v, bool) or v < 0 or v >= n or seen[v]:
            return False
        seen[v] = True
    return True


def flat_items(items):  # [a, b, a, b, ...] in item-then-component-then-(a,b) order
    out = []
    for it in items:
        for ct in it:
            out.append(ct["a"]); out.append(ct["b"])
    return out


def shuffle_challenge_bits(pk, L0, L, intermediates, t):
    pts = [pk] + flat_items(L0) + flat_items(L)
    for M in intermediates:
        pts += flat_items(M)
    c = scalar_be(hash_to_scalar("mixnet-shuffle", pts))  # 32-byte big-endian, mirrors scalarTo32(hashToScalar(...))
    bits = []
    block = -1
    digest = b""
    for j in range(t):
        b = j // 512
        if b != block:
            block = b
            digest = hashlib.sha512(b"vvp-fs-v1" + b"mixnet-shuffle-bits" + c + u32(b)).digest()
        idx = j % 512
        bits.append((digest[idx >> 3] >> (idx & 7)) & 1)
    return bits


def verify_shuffle(pk, L0, L, proof) -> bool:
    t = proof["t"]
    if not (isinstance(t, int) and not isinstance(t, bool) and t >= SECURITY_T):
        return False
    n = len(L0)
    if not (len(proof["intermediates"]) == t and len(proof["openings"]) == t and n >= 1 and len(L) == n):
        return False
    W = len(L0[0])
    if W < 1 or any(len(it) != W for it in L0) or any(len(it) != W for it in L):
        return False
    for M in proof["intermediates"]:
        if len(M) != n or any(len(it) != W for it in M):
            return False
    for op in proof["openings"]:
        if len(op["perm"]) != n or len(op["factors"]) != n or any(len(f) != W for f in op["factors"]):
            return False
    for op in proof["openings"]:  # canonical scalars already enforced by parse_scalar; check bijection
        if not is_permutation(op["perm"], n):
            return False
    bits = shuffle_challenge_bits(pk, L0, L, proof["intermediates"], t)
    for j in range(t):
        M = proof["intermediates"][j]
        op = proof["openings"][j]
        src = L0 if bits[j] == 0 else M  # bit 0 opens L0->M_j; bit 1 opens M_j->L
        dst = M if bits[j] == 0 else L
        permuted = apply_perm(src, op["perm"])
        for i in range(n):
            cand = reenc_item(pk, permuted[i], op["factors"][i])
            d = dst[i]
            for wi in range(W):
                if cand[wi]["a"] != d[wi]["a"] or cand[wi]["b"] != d[wi]["b"]:
                    return False
    return True


def ballot_to_ranks(matrix, K):
    if len(matrix) != K:
        return None
    rank_of = [0] * K
    col_used = [False] * K
    for i in range(K):
        row = matrix[i]
        if len(row) != K:
            return None
        ones = 0
        col = -1
        for r in range(K):
            v = row[r]
            if v != 0 and v != 1:
                return None
            if v == 1:
                ones += 1
                col = r
        if ones != 1 or col_used[col]:
            return None
        col_used[col] = True
        rank_of[i] = col
    return rank_of


def entry_idx(item, i, r, K):
    return ((item * K) + i) * K + r


def flatten_ballot(b):  # b = parsed ranked ballot {'matrix': [[ct...]...]}
    K = len(b["matrix"])
    return [b["matrix"][i][r] for i in range(K) for r in range(K)]


def tabulate_irv(decrypted, K):
    rank_matrix = []
    for b in range(len(decrypted)):
        ranks = ballot_to_ranks(decrypted[b], K)
        if ranks is None:
            return {"error": f"ballot {b} is not a permutation matrix"}
        rank_matrix.append(ranks)
    n = len(rank_matrix)
    eliminated = [False] * K
    rounds = []
    alive = K
    for rnd in range(K):
        elim_snap = sorted([c for c in range(K) if eliminated[c]])
        tally = [0] * K
        for rank_of in rank_matrix:
            best = -1
            best_rank = K
            for c in range(K):
                if not eliminated[c] and rank_of[c] < best_rank:
                    best_rank = rank_of[c]
                    best = c
            tally[best] += 1
        if sum(tally) != n:
            return {"error": f"round {rnd}: active total != n"}
        winner = -1
        for c in range(K):
            if not eliminated[c] and 2 * tally[c] > n:
                winner = c
                break
        if winner != -1 or alive == 1:
            if winner == -1:
                for c in range(K):
                    if not eliminated[c]:
                        winner = c
                        break
            rounds.append({"eliminated": elim_snap, "tallies": tally, "eliminatedThisRound": None, "winner": winner})
            return {"rounds": rounds, "winner": winner}
        mn = min(tally[c] for c in range(K) if not eliminated[c])
        victim = -1
        for c in range(K):  # ascending scan + overwrite => HIGHEST index among the minimizers
            if not eliminated[c] and tally[c] == mn:
                victim = c
        rounds.append({"eliminated": elim_snap, "tallies": tally, "eliminatedThisRound": victim, "winner": None})
        eliminated[victim] = True
        alive -= 1
    return {"error": "IRV did not terminate within K rounds"}


def verify_mixnet_irv(j):
    checks = []

    def add(name, ok, detail=None):
        checks.append((name, ok, detail))

    candidates = j["candidates"]
    K = len(candidates)
    k = j["threshold"]
    n = len(j["ballots"])
    W = K * K
    nkk = n * K * K

    def idx_ok(i):
        return isinstance(i, int) and not isinstance(i, bool) and 1 <= i <= j["trustees"]

    shape_ok = (
        K > 0 and isinstance(k, int) and k >= 1 and isinstance(j["trustees"], int) and j["trustees"] >= k
        and len(j["commitments"]) == k and isinstance(j["numVoters"], int) and j["numVoters"] == n and n >= 1
        and all(len(b["ballot"]["matrix"]) == K and all(len(row) == K for row in b["ballot"]["matrix"])
                and len(b["ballot"]["bitProofs"]) == K and all(len(row) == K for row in b["ballot"]["bitProofs"])
                and len(b["ballot"]["rowSums"]) == K and len(b["ballot"]["colSums"]) == K for b in j["ballots"])
        and isinstance(j["shuffled"], list) and len(j["shuffled"]) == n and all(len(it) == W for it in j["shuffled"])
        and isinstance(j["decShares"], list)
        and all(len(ds["shares"]) == nkk and len(ds["proofs"]) == nkk for ds in j["decShares"])
        and isinstance(j["decryptedMatrices"], list) and len(j["decryptedMatrices"]) == n
        and all(len(M) == K and all(len(row) == K and all(v in (0, 1) for v in row) for row in M) for M in j["decryptedMatrices"])
        and isinstance(j["rounds"], list) and len(j["rounds"]) >= 1
        and isinstance(j["winner"], int) and 0 <= j["winner"] < K
    )
    add("Transcript shape: KxK ballots, n items width K^2, n*K^2 shares, well-formed rounds", shape_ok)
    if not shape_ok:
        return False, checks, None

    commitments = [parse_point(c) for c in j["commitments"]]
    public_key = parse_point(j["publicKey"])
    eligible = {parse_point(c) for c in j["eligibleRoll"]}
    ctx = election_context(j["contest"], public_key, candidates)
    ballots = [{
        "voter": b["voter"], "credentialPub": parse_point(b["credentialPub"]),
        "ballot": parse_ranked_ballot(b["ballot"]),
        "sig": {"R": parse_point(b["sig"]["R"]), "s": parse_scalar(b["sig"]["s"])},
    } for b in j["ballots"]]
    shuffled = [[parse_ct(c) for c in it] for it in j["shuffled"]]
    proof = {
        "t": j["shuffleProof"]["t"],
        "intermediates": [[[parse_ct(c) for c in it] for it in M] for M in j["shuffleProof"]["intermediates"]],
        "openings": [{"perm": op["perm"], "factors": [[parse_scalar(x) for x in f] for f in op["factors"]]}
                     for op in j["shuffleProof"]["openings"]],
    }
    dec_shares = [{
        "trusteeIndex": ds["trusteeIndex"],
        "shares": [parse_point(s) for s in ds["shares"]],
        "proofs": [parse_dec(p) for p in ds["proofs"]],
    } for ds in j["decShares"]]

    add("Joint public key = commitment C0 (threshold key)", commitments[0] == public_key)

    root = mth([ranked_board_bytes(ctx, b["credentialPub"], b["ballot"], b["sig"]) for b in ballots]).hex()
    add("Bulletin-board Merkle root matches the published ballots", root == j["boardRoot"])

    add("Eligible roll has no duplicate credentials", len(eligible) == len(j["eligibleRoll"]))
    seen = set()
    inelig = bad_sig = dup = 0
    for b in ballots:
        key = b["credentialPub"]
        if key not in eligible:
            inelig += 1
        if not verify_sig(b["credentialPub"], ranked_signing_bytes(ctx, b["ballot"]), b["sig"]):
            bad_sig += 1
        if key in seen:
            dup += 1
        seen.add(key)
    add("Every ballot is signed by an eligible voter credential", inelig == 0 and bad_sig == 0,
        f"{inelig} ineligible, {bad_sig} bad sig" if (inelig or bad_sig) else None)
    add("No credential voted more than once (single-use nullifier)", dup == 0)

    invalid = sum(0 if verify_ranking_valid(public_key, b["ballot"]) else 1 for b in ballots)
    add("Every ballot is a valid strict ranking (permutation matrix)", invalid == 0)

    # RE-DERIVE L0 from the validated ballots (never trust a published L0) + verify the shuffle
    l0 = [flatten_ballot(b["ballot"]) for b in ballots]
    add("Shuffle proof meets the SECURITY_T floor", isinstance(proof["t"], int) and proof["t"] >= SECURITY_T)
    add("Shuffle is a proven re-encryption permutation of the board ballots (L0 re-derived)",
        verify_shuffle(public_key, l0, shuffled, proof))

    indices = [d["trusteeIndex"] for d in dec_shares]
    add(f"Decryption quorum: >= {k} distinct registered trustees (1..{j['trustees']})",
        len(set(indices)) == len(indices) and all(idx_ok(i) for i in indices) and len(dec_shares) >= k)
    bad_shares = 0
    for ds in dec_shares:
        if not idx_ok(ds["trusteeIndex"]):
            bad_shares += nkk
            continue
        pub = verification_key_at(commitments, ds["trusteeIndex"])
        for item in range(n):
            for i in range(K):
                for r in range(K):
                    a = shuffled[item][i * K + r]["a"]
                    ix = entry_idx(item, i, r, K)
                    if not verify_decryption(a, pub, ds["shares"][ix], ds["proofs"][ix]):
                        bad_shares += 1
    add("Every trustee decryption share is provably honest", bad_shares == 0)

    valid = [ds for ds in dec_shares if idx_ok(ds["trusteeIndex"])]
    recovered = []
    recover_bad = field_mismatch = 0
    for item in range(n):
        M = []
        for i in range(K):
            row = []
            for r in range(K):
                ix = entry_idx(item, i, r, K)
                combined = combine_shares([(ds["trusteeIndex"], ds["shares"][ix]) for ds in valid])
                m = discrete_log(psub(shuffled[item][i * K + r]["b"], combined), 1)
                if m is None:
                    recover_bad += 1
                    m = -1
                row.append(m)
                if m != j["decryptedMatrices"][item][i][r]:
                    field_mismatch += 1
            M.append(row)
        recovered.append(M)
    add("Recovered entries match the published decrypted matrices", recover_bad == 0 and field_mismatch == 0)
    non_perm = 0
    for M in recovered:
        for i in range(K):
            if sum(M[i][r] for r in range(K)) != 1:
                non_perm += 1
        for r in range(K):
            if sum(M[i][r] for i in range(K)) != 1:
                non_perm += 1
    add("Every recovered matrix is a permutation (every row & column sums to 1)", non_perm == 0)

    out = tabulate_irv(recovered, K)
    irv_ok = False
    round0 = None
    if "error" not in out:
        same = (
            len(out["rounds"]) == len(j["rounds"])
            and all(R["eliminated"] == T["eliminated"] and R["tallies"] == T["tallies"]
                    and R["eliminatedThisRound"] == T["eliminatedThisRound"] and R["winner"] == T["winner"]
                    for R, T in zip(out["rounds"], j["rounds"]))
            and out["winner"] == j["winner"]
        )
        irv_ok = recover_bad == 0 and non_perm == 0 and same
        if irv_ok:
            round0 = list(out["rounds"][0]["tallies"])
    add("IRV tabulation is correct and deterministic (recomputed over recovered matrices)", irv_ok)

    ok = all(c[1] for c in checks)
    return ok, checks, (round0 if ok else None)


# ---- paper + RLA hybrid anchor; mirrors reference/src/rla.ts -----------------
def is32hex(h) -> bool:
    return isinstance(h, str) and len(h) == 64 and all(c in "0123456789abcdefABCDEF" for c in h)


def valid_u32(n) -> bool:
    return isinstance(n, int) and not isinstance(n, bool) and 0 <= n <= 0xFFFFFFFF


def batch_row_bytes(row) -> bytes:
    idb = row["batchId"].encode()
    return b"vvp-batch-v1" + u32(len(idb)) + idb + u32(row["ballotCount"])


def ballot_manifest_root(m) -> str:
    rows = sorted(m["batches"], key=lambda r: r["batchId"].encode())  # UTF-8 byte order (matches cmpBytes)
    return mth([batch_row_bytes(r) for r in rows]).hex()


def anchor_bytes(a) -> bytes:
    cb = a["contest"].encode()
    at = a["anchoredAt"].encode()
    br = bytes.fromhex(a["boardRoot"])
    pr = bytes.fromhex(a["paperManifestRoot"])
    pk = bytes.fromhex(a["publicKey"])
    sp = bytes.fromhex(a["signerPub"])
    return (b"vvp-anchor-v1" + u32(len(cb)) + cb + u32(len(br)) + br + u32(len(pr)) + pr
            + u32(a["numVoters"]) + u32(a["paperBallotsTotal"]) + u32(len(pk)) + pk + u32(len(sp)) + sp
            + u32(len(at)) + at)


def verify_anchor(a, manifest=None, expect=None):
    checks = []

    def add(name, ok, detail=None):
        checks.append((name, ok, detail))

    add("Anchor version is recognized", a.get("version") == "vvp-paper-anchor-1")
    canon = (is32hex(a.get("boardRoot")) and is32hex(a.get("paperManifestRoot")) and is32hex(a.get("publicKey"))
             and is32hex(a.get("signerPub")) and is32hex((a.get("sig") or {}).get("R"))
             and valid_u32(a.get("numVoters")) and valid_u32(a.get("paperBallotsTotal")))
    add("Anchor fields are canonically encoded (32-byte roots/keys, uint32 counts)", canon)
    if not canon:
        return False, checks, None
    sig_ok = verify_sig(parse_point(a["signerPub"]), anchor_bytes(a), {"R": parse_point(a["sig"]["R"]), "s": parse_scalar(a["sig"]["s"])})
    add("Anchor self-signature is valid (over all bound fields, incl. the signer key)", sig_ok)
    if expect and expect.get("signerPub") is not None:
        add("Anchor is signed by the PINNED election-authority key", a["signerPub"] == expect["signerPub"])
    if manifest is not None:
        add("Paper-manifest root matches the published batches", ballot_manifest_root(manifest) == a["paperManifestRoot"])
        s = sum(b["ballotCount"] for b in manifest["batches"])
        add("Manifest total = sum batch counts = anchor paper total", s == manifest["paperBallotsTotal"] and s == a["paperBallotsTotal"])
    if expect:
        add("Anchor binds the published digital transcript (board root, count, key)",
            a["boardRoot"] == expect["boardRoot"] and a["numVoters"] == expect["numVoters"] and a["publicKey"] == expect["publicKey"])
    reconciled = a["paperBallotsTotal"] == a["numVoters"]
    add(f"Reconciliation: paper ballots ({a['paperBallotsTotal']}) = digital ballots ({a['numVoters']})", reconciled,
        None if reconciled else "discrepancy — paper is the legal record; resolve by canvass/RLA (ADR-0004)")
    return all(c[1] for c in checks), checks, None


def verify_rla_export(j):
    _, checks, _ = verify_anchor(j["anchor"], j.get("manifest"))
    checks = list(checks)
    rep = j["reported"]
    checks.append(("Reported results bind the same contest as the anchor", rep["contest"] == j["anchor"]["contest"], None))
    checks.append(("Reported tally is an aggregate ballot-polling result (no per-ballot CVR)",
                   rep["auditMethod"] == "ballot-polling" and isinstance(rep["reportedTally"], list) and len(rep["reportedTally"]) == len(rep["candidates"]), None))
    return all(c[1] for c in checks), checks, None


# ---- everlasting-privacy commitment trail (mirrors reference/src/everlasting.ts + proveConsistency) --
def parse_consistency(j):
    # parse_scalar enforces 0 <= x < L (mirrors the TS inRange hardening on zv, zr, zd).
    return {"Aa": parse_point(j["Aa"]), "Ab": parse_point(j["Ab"]), "Ac": parse_point(j["Ac"]),
            "zv": parse_scalar(j["zv"]), "zr": parse_scalar(j["zr"]), "zd": parse_scalar(j["zd"])}


def parse_cell(j):
    return {"ct": parse_ct(j), "bit": parse_bit(j["bit"]), "C": parse_point(j["C"]), "cons": parse_consistency(j["cons"])}


def verify_consistency(pk, ct, C, p) -> bool:
    """Proves C = v*G + d*H commits to the same v that (a,b) encrypts under pk (shared zv = cross-binding)."""
    a, b = ct["a"], ct["b"]
    e = hash_to_scalar("everlasting-consistency-v1", [G, H, pk, a, b, C, p["Aa"], p["Ab"], p["Ac"]])
    if smul(G, p["zr"]) != padd(p["Aa"], smul(a, e)):  # a = r*G
        return False
    if padd(smul(G, p["zv"]), smul(pk, p["zr"])) != padd(p["Ab"], smul(b, e)):  # b = v*G + r*PK
        return False
    if padd(smul(G, p["zv"]), smul(H, p["zd"])) != padd(p["Ac"], smul(C, e)):  # C = v*G + d*H (same zv)
        return False
    return True


def verify_everlasting_trail(j):
    checks = []

    def add(name, ok, detail=None):
        checks.append((name, ok, detail))

    add("Trail version/kind recognized", j.get("version") == "vvp-everlasting-trail-1" and j.get("kind") == "everlasting-trail")
    # Fail closed: our independently-derived H must match the pinned NUMS constant AND the document's H.
    h_ok = (H.hex() == PEDERSEN_H_HEX) and (j.get("pedersenH") == H.hex())
    add("Pedersen generator H matches the pinned NUMS constant (fail closed)", h_ok)
    if not h_ok:
        return False, checks, None
    # Structural gate mirrors the TS Array.isArray guards: candidates and ballots MUST be JSON arrays, so a
    # string `candidates` (len matches K) or a dict `ballots` cannot be silently accepted here while TS rejects.
    well_formed = isinstance(j.get("candidates"), list) and isinstance(j.get("ballots"), list)
    add("Trail is well-formed (candidates and ballots are arrays)", well_formed)
    if not well_formed:
        return False, checks, None
    pk = parse_point(j["publicKey"])
    K = len(j["candidates"])
    add("Candidate set is non-empty", K > 0)
    if K == 0:
        return False, checks, None
    ballots = j["ballots"]
    # Require cells to be a list (mirrors TS Array.isArray(b.cells)) so a non-array cells fails at this
    # named shape check, exactly as TS does, rather than mid-parse downstream.
    shape_ok = all(isinstance(b.get("cells"), list) and len(b["cells"]) == K for b in ballots)
    add(f"Every ballot has exactly one commitment per candidate (K={K})", shape_ok)
    if not shape_ok:
        return False, checks, None
    bit_bad = 0
    cons_bad = 0
    for b in ballots:
        for cj in b["cells"]:
            cell = parse_cell(cj)
            if not verify_bit(pk, cell["ct"], cell["bit"]):
                bit_bad += 1
            if not verify_consistency(pk, cell["ct"], cell["C"], cell["cons"]):
                cons_bad += 1
    add("Every ciphertext is proven to encrypt a bit in {0,1} (disjunctive Chaum-Pedersen)", bit_bad == 0)
    add("Every commitment is bound to the SAME vote as its ciphertext (consistency NIZK); combined with the bit-proof above, C therefore commits to a bit", cons_bad == 0)
    add(f"Commitment trail is perfectly hiding by construction ({len(ballots) * K} commitments)", True)
    return all(c[1] for c in checks), checks, None


def main():
    if len(sys.argv) < 2:
        print("usage: python3 vvp_verify.py <transcript.json>", file=sys.stderr)
        sys.exit(2)
    try:
        with open(sys.argv[1]) as f:
            data = json.load(f)
        # the transcript's own `kind` field selects the verifier (default: plurality).
        kind = data.get("kind")
        verifier = (verify_rla_export if kind == "rla-export"
                    else verify_everlasting_trail if kind == "everlasting-trail"
                    else verify_mixnet_irv if kind == "mixnet-irv"
                    else verify_ranked if kind == "ranked"
                    else verify)
        ok, checks, results = verifier(data)
    except Exception as e:  # the trust root always emits a verdict
        print(f"❌ could not parse/verify: {e}")
        sys.exit(1)
    for name, cok, detail in checks:
        print(f"{'✅' if cok else '❌'} {name}" + (f"  ({detail})" if detail else ""))
    print(("\n\U0001f7e2 VERIFIED — results: " + str(results)) if ok else "\n\U0001f534 REJECTED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
