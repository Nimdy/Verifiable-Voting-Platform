# CRYPTO_SPEC.md — canonical cryptographic & transcript specification

_Version: **`vvp-cryptospec-1`** · Status: **normative for the Stage‑1 reference protocol** · Last updated: 2026‑06‑07_

This is the **contract that every independent implementation MUST agree on, byte for byte**. It is the
document ADR‑0006 ("the independent verifier is implemented in a different language than the core") and
ADR‑0007 ("ristretto255 + exponential ElGamal, no hand‑rolled ciphers") refer to as the shared
specification, and it closes the long‑standing gap tracked in
[#11](https://github.com/Nimdy/Verifiable-Voting-Platform/issues/11).

Two implementations already implement everything below and are cross‑checked on **every push/PR** across
**seven transcript kinds** with **zero divergence**:

- the TypeScript reference (`reference/src/`, `@noble/curves` + `@noble/hashes`), and
- the independent Python verifier (`verifier/vvp-verify-py/vvp_verify.py`, `libsodium`/`pysodium` + `hashlib`).

> **Scope & honesty.** This specifies the **ristretto255 Stage‑1 reference protocol** as it exists today.
> It is a *reference PoC specification*, not a finished production standard, and the protocol has **not**
> had external cryptographic review ([#54](https://github.com/Nimdy/Verifiable-Voting-Platform/issues/54)).
> Sections marked **EXPERIMENTAL** (the Terelius–Wikström shuffle) are opt‑in, **not the default**, and
> **not audited** (ADR‑0012). Anything an independent verifier must check to accept a default transcript is
> pinned precisely in §1–§11; optional seams (chain anchors, paper+RLA) are referenced, not re‑specified.

---

## 0. Conventions

- **`‖`** denotes byte concatenation. **UTF‑8** is the encoding for every text label.
- **`u32(n)`** is the 4‑byte **big‑endian** encoding of a non‑negative integer `n`.
- **`scalar32(s)`** is the 32‑byte **big‑endian** encoding of a scalar `s` (see §1.3).
- Additive group notation: `s·P` is scalar multiplication; `P + Q` is the group operation; `0` is the identity.
- "Hex" always means **lowercase**, no `0x` prefix.
- A **scalar** is an integer mod `N` (§1.2). A **point** is a ristretto255 group element (§1.1).

---

## 1. Group and encodings

### 1.1 Group
The group is **ristretto255** (RFC 9496) — a prime‑order group built over Curve25519. Implementations MUST
use an audited library (`@noble/curves` in the reference; `libsodium`'s `crypto_core_ristretto255_*` in the
verifier). No curve, cipher, or proof system is hand‑rolled (ADR‑0007).

- **Order** `N = 2^252 + 27742317777372353535851937790883648493`
  = `7237005577332262213973186563042994240857116359379907606001950938285454250989`.
- **Generator** `G` = the ristretto255 base point. Canonical encoding (hex):
  `e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76`.
- **Identity** `0` encodes as 32 zero bytes:
  `0000000000000000000000000000000000000000000000000000000000000000`.

### 1.2 Point encoding
A point is its **canonical 32‑byte ristretto255 encoding**, as lowercase hex on the wire.

> **MUST validate on parse.** Every point read from a transcript MUST be parsed through a validating
> decoder (`RistrettoPoint.fromHex` / `crypto_core_ristretto255_is_valid_point`) that **rejects
> non‑canonical or off‑curve encodings**. This is the deserialization‑boundary input validation a
> networked verifier needs.

### 1.3 Scalar encodings (two forms)
- **On the wire (JSON):** a scalar is a **canonical decimal string** matching the grammar
  **`^(0|[1-9][0-9]*)$`** whose value is **`< N`**. Both verifiers gate on this *exact* grammar **and** the
  range check before converting. This is deliberate: a language's native integer parser is too permissive
  (TS `BigInt` also accepts `0x…`/`0o…`/`0b…`/sign/empty; Python `int()` accepts underscores and Unicode
  digits), which would let a scalar be rewritten into a same‑value/different‑syntax form that one verifier
  accepts and the other rejects — a dual‑verifier equivalence break. The shared grammar makes a
  non‑canonical string a clean rejection in **both**.
- **Inside hash preimages:** a scalar is `scalar32(s)` — **32 bytes big‑endian**.

> **MUST range‑check.** Any scalar received in a proof MUST be checked `0 ≤ s < N` *before use*. Verifiers
> reject (do not reduce) out‑of‑range scalars, so the proof object is not malleable in its integer
> representation.

### 1.4 Randomness
A uniform scalar is drawn as **64 random bytes**, interpreted big‑endian, reduced mod `N` (modulo bias
≈ 2⁻²⁵⁹, negligible). Provers MUST use a CSPRNG; the value form is not otherwise constrained.

---

## 2. Hash functions

| Use | Function |
|-----|----------|
| Fiat–Shamir challenges, NUMS generators, credential signatures | **SHA‑512** |
| Bulletin‑board Merkle tree (§7) | **SHA‑256** |

A challenge scalar derived from a SHA‑512 digest is the **full 64‑byte digest** interpreted **big‑endian**,
reduced mod `N`.

---

## 3. NUMS generators (nothing‑up‑my‑sleeve)

### 3.1 Pedersen generator `H`
`H` is the second generator for perfectly‑hiding Pedersen commitments `C = v·G + d·H`. Its discrete log
base `G` MUST be unknown to everyone (that unknown dlog is exactly what makes the commitment
*computationally binding*; the `d·H` term makes it *unconditionally hiding*).

```
H_LABEL = "vvp-everlasting-pedersen-H-v1"
H        = ristretto255_from_hash( SHA-512(H_LABEL) )
```

`ristretto255_from_hash` is the **RFC 9496 one‑way map over a 64‑byte digest**
(`@noble`'s `hashToCurve`, `libsodium`'s `crypto_core_ristretto255_from_hash`) — **NOT** RFC 9380
hash‑to‑curve (libsodium does not expose that). Both libraries agree byte‑for‑byte. Implementations MUST
**pin and fail‑closed** on this constant:

```
H_hex = b66dc28b63ecfbb83fa33aad8148a54f17757fce571ad6b8df258d3cfa2a777a
```

A wrong/backdoored `H` (known dlog) silently breaks binding, so a mismatch MUST abort.

### 3.2 Terelius–Wikström generator vector (EXPERIMENTAL — ADR‑0012)
For the experimental O(N) shuffle only: `h_i = ristretto255_from_hash( SHA-512("vvp-tw-gen-v1|" ‖ decimal(i)) )`
for `i = 0,1,2,…`. Not used by any default transcript.

---

## 4. Fiat–Shamir framing

All default sigma‑protocol challenges are derived through one self‑describing, length‑prefixed frame. This
binds the **full statement** (not just commitments) into the hash, defeating weak‑Fiat–Shamir attacks, and
makes it impossible for two proof types to alias the same challenge even if future labels differ in length.

```
FS_DST = "vvp-fs-v1"

hashToScalar(label, [P_0, …, P_{k-1}]) :
    frame  = u32(len(FS_DST)) ‖ FS_DST
           ‖ u32(len(label))  ‖ label
           ‖ u32(k)
           ‖ P_0.encode() ‖ … ‖ P_{k-1}.encode()
    return  int_be( SHA-512(frame) )  mod  N
```

`len(·)` is the UTF‑8 byte length; `P.encode()` is the 32‑byte canonical point encoding (§1.2).

> **Verifier rule (normative).** A verifier MUST **recompute** every challenge from the statement and the
> prover's commitments and MUST **never trust a transmitted challenge**. Where a proof object carries
> sub‑challenges (e.g. `c0`,`c1`), the verifier recomputes the bound challenge `e` and checks the algebraic
> relation among the sub‑challenges (e.g. `c0 + c1 ≡ e mod N`).

### 4.1 Documented non‑frame hashes
Three hashes deliberately use a direct SHA‑512 preimage rather than the §4 frame:

- **Credential signature** (§8): `SHA-512("vvp-cred-sig-v1|" ‖ R ‖ pub ‖ msg)`.
- **Sako–Kilian challenge‑bit expansion** (§10.8): `SHA-512("vvp-fs-v1" ‖ "mixnet-shuffle-bits" ‖ scalar32(c) ‖ u32(b))`.
- **Terelius–Wikström challenge expansion** (EXPERIMENTAL): `SHA-512("vvp-fs-v1" ‖ label ‖ seed ‖ u32(i))`.

---

## 5. Domain‑separation label registry

Every label the protocol uses, where it appears, and how it is framed. ("frame" = the §4 `hashToScalar`
frame; "direct" = direct SHA‑512 preimage; "from_hash" = §3 NUMS map; "tag" = a UTF‑8 prefix inside a
serialized byte‑string; "version" = a JSON envelope discriminator.)

| Label | Hash | Framing | Used by |
|-------|------|---------|---------|
| `vvp-fs-v1` | SHA‑512 | frame DST | every default sigma proof (§10) |
| `ballot-bit` | SHA‑512 | frame | ballot‑validity bit proof (§10.1) |
| `decryption` | SHA‑512 | frame | decryption‑correctness proof (§10.2) |
| `sum-eq` | SHA‑512 | frame | exactly‑L sum proof (§10.3) |
| `everlasting-consistency-v1` | SHA‑512 | frame | ElGamal↔Pedersen consistency (§10.4) |
| `everlasting-commit-bit-v1` | SHA‑512 | frame | everlasting commit‑bit (§10.5) |
| `everlasting-commit-sum-v1` | SHA‑512 | frame | everlasting commit‑sum (§10.6) |
| `selene-tracker-consistency-v1` | SHA‑512 | frame | Selene tracker↔commitment (§10.7) |
| `mixnet-shuffle` | SHA‑512 | frame | Sako–Kilian shuffle challenge (§10.8) |
| `mixnet-shuffle-bits` | SHA‑512 | direct | Sako–Kilian challenge‑bit expansion (§10.8) |
| `vvp-cred-sig-v1\|` | SHA‑512 | direct | credential Schnorr signature (§8) |
| `vvp-everlasting-pedersen-H-v1` | SHA‑512 | from_hash | Pedersen generator `H` (§3.1) |
| `vvp-ctx-v1` | — | tag | election‑context binding (§6.1) |
| `vvp-selene-v1` | — | tag | Selene per‑record binding bytes |
| `vvp-tw-gen-v1\|` | SHA‑512 | from_hash | **EXPERIMENTAL** TW generator vector (§3.2) |
| `mixnet-tw-mul-v1` | SHA‑512 | frame | **EXPERIMENTAL** TW committed‑multiplication proof |
| `vvp-transcript-1` | — | version | plurality / multi‑seat transcript (§11) |
| `vvp-ranked-transcript-1` | — | version | ranked (Borda) transcript (§11) |
| `vvp-mixnet-irv-transcript-1` | — | version | mixnet‑IRV transcript (§11) |
| `vvp-selene-transcript-1` | — | version | Selene transcript (§11) |
| `vvp-everlasting-trail-1` | — | version | everlasting commitment trail (§11) |
| `vvp-tw-shuffle-1` | — | version | **EXPERIMENTAL** TW shuffle transcript (§11) |
| `vvp-bp-export-1` | — | version | paper + RLA ballot‑polling export (§11) |

**Reserved (optional seams — layouts live in `anchorlog.ts` / `rla.ts`, not re‑specified here):**
`vvp-anchor-v1`, `vvp-anchor-log-v1`, `vvp-batch-v1`, `vvp-root-commitment-1`, `vvp-root-commitment-2`
(chain‑anchor seam, ADR‑0002/0003); `vvp-paper-anchor-1`, `vvp-ballot-manifest-1`, `vvp-reported-results-1`
(paper + RLA, ADR‑0004/0009).

---

## 6. Canonical serialization

### 6.1 Election context
Bound into every ballot signature so a ballot/signature cannot be replayed into a different contest or
election.

```
electionContext(contest, publicKey, candidates[]) =
    "vvp-ctx-v1"
  ‖ u32(len(contest)) ‖ contest
  ‖ publicKey.encode()
  ‖ u32(#candidates)
  ‖ for each name:  u32(len(name)) ‖ name
```

### 6.2 Signed selection bytes
What the voter signs (§8 `msg`):

```
bitProofBytes(p)  = T0g ‖ T0h ‖ T1g ‖ T1h ‖ scalar32(c0) ‖ scalar32(c1) ‖ scalar32(s0) ‖ scalar32(s1)
sumProofBytes(p)  = Tg ‖ Th ‖ scalar32(c) ‖ scalar32(s)

signingBytes(ctx, selection) =
    ctx
  ‖ u32(#enc)
  ‖ for each candidate j:  enc[j].a ‖ enc[j].b ‖ bitProofBytes(bitProofs[j])
  ‖ sumProofBytes(sumProof)
```

### 6.3 Bulletin‑board leaf
The exact bytes committed by the Merkle tree (§7); tampering with any field changes the root:

```
boardBytes(ctx, credentialPub, selection, sig) =
    credentialPub.encode()
  ‖ signingBytes(ctx, selection)
  ‖ sig.R.encode() ‖ scalar32(sig.s)
```

---

## 7. Bulletin board (RFC‑6962 Merkle)

The board is an append‑only log of `boardBytes` leaves in cast order. Its root is the RFC‑6962 Merkle Tree
Hash over SHA‑256, with leaf prefix `0x00` and node prefix `0x01`:

```
MTH([])            = SHA-256( "" )
MTH([d0])          = SHA-256( 0x00 ‖ d0 )
MTH(items), n>1    = let k = largest power of two with k < n
                     SHA-256( 0x01 ‖ MTH(items[0:k]) ‖ MTH(items[k:n]) )
boardRoot          = hex( MTH(leaves) )
```

The split point `k` is the largest power of two **strictly less than** `n`, and a lone node is **never
duplicated** — this avoids the CVE‑2012‑2459 odd‑node ambiguity (two different ballot sets sharing a root).

---

## 8. Credentials, signatures, and the nullifier

A voter credential is a Schnorr keypair over ristretto255: secret `x` (kept by the voter), public
`pub = x·G`. The registrar publishes the set of eligible `pub` values (the **eligible roll**). **The
credential public key doubles as the single‑use nullifier**: a verifier rejects a transcript in which any
`pub` casts more than one ballot. Because only the homomorphic total is ever decrypted, publishing
"credential X cast ballot Y" reveals nothing about how X voted.

```
sign(x, msg):
    r ← random scalar
    R = r·G
    e = int_be( SHA-512("vvp-cred-sig-v1|" ‖ R ‖ pub ‖ msg) ) mod N      # pub = x·G
    return (R, s = r + e·x  mod N)

verify(pub, msg, (R, s)):
    require 0 ≤ s < N
    e = int_be( SHA-512("vvp-cred-sig-v1|" ‖ R ‖ pub ‖ msg) ) mod N
    accept iff  s·G == R + e·pub
```

For a ballot, `msg = signingBytes(ctx, selection)` (§6.2).

---

## 9. Exponential ElGamal

Trustee `i` holds secret `x_i`, public `h_i = x_i·G`. The **joint public key** is `h = Σ h_i` (for the
N‑of‑N reference; a k‑of‑n threshold uses a Pedersen DKG and Lagrange interpolation at decryption).

```
encrypt(h, m, r)        = ( r·G ,  m·G + r·h )          # additively homomorphic
addCiphertexts([c_j])   = ( Σ c_j.a ,  Σ c_j.b )        # = encryption of Σ m_j
decryptionShare_i(a)    = x_i · a
```

The tally never decrypts an individual ballot. The combined decryption recovers `M = m·G` for the **total**
`m`; the small exponent `m` (bounded by the number of voters) is found by brute‑force discrete log.

---

## 10. Sigma proofs

For each proof: the statement, the commitment(s), the **exact** Fiat–Shamir input (label + ordered point
list), the responses, and the verifier's equations. All challenges use §4 unless noted. All responses are
mod `N`; verifiers range‑check every scalar (§1.3) before use.

### 10.1 Ballot validity — `(a,b)` encrypts `m ∈ {0,1}` (label `ballot-bit`)
Disjunctive Chaum–Pedersen (CDS OR‑composition). `B_0 = b`, `B_1 = b − G`; exactly one of
`log_g(a) = log_h(B_i)` holds. Object: `{T0g,T0h,T1g,T1h, c0,c1,s0,s1}`.

```
e  = hashToScalar("ballot-bit", [h, a, b, T0g, T0h, T1g, T1h])
require c0 + c1 ≡ e (mod N)
require s0·G == T0g + c0·a    and    s0·h == T0h + c0·B_0
require s1·G == T1g + c1·a    and    s1·h == T1h + c1·B_1
```

### 10.2 Decryption correctness — `log_g(pub) = log_a(share)` (label `decryption`)
Chaum–Pedersen DH‑equality. Object: `{Tg, Ta, c, s}`.

```
e = hashToScalar("decryption", [G, a, pub, share, Tg, Ta])
require c == e
require s·G == Tg + c·pub     and    s·a == Ta + c·share
```

### 10.3 Exactly‑L selection — homomorphic sum encrypts `L` (label `sum-eq`)
`L` (the selection limit) is bound into both the challenge and the target, so a proof for `L` cannot be
reused for `L'`. `target = agg.b − L·G` (equals `h^R` iff the votes sum to `L`). Object: `{Tg, Th, c, s}`.

```
e = hashToScalar("sum-eq", [h, agg.a, agg.b, L·G, Tg, Th])
require c == e
require s·G == Tg + c·agg.a   and    s·h == Th + c·(agg.b − L·G)
```
Plurality / single‑choice is the `L = 1` case.

### 10.4 ElGamal↔Pedersen consistency (label `everlasting-consistency-v1`)
Proves `C = v·G + d·H` commits to the same `v` that `(a,b)` encrypts under `pk` — the everlasting‑privacy
binding. Generalized‑Schnorr for `φ(v,r,d) = (r·G, v·G + r·PK, v·G + d·H)`; the **shared response `zv`** is
the cross‑binding. Object: `{Aa, Ab, Ac, zv, zr, zd}`.

```
e = hashToScalar("everlasting-consistency-v1", [G, H, pk, a, b, C, Aa, Ab, Ac])
require zr·G            == Aa + e·a
require zv·G + zr·pk    == Ab + e·b
require zv·G + zd·H     == Ac + e·C        # same zv ⇒ same v as in b
```

### 10.5 Everlasting commit‑bit — `C` commits to a bit, from `(G,H,C)` alone (label `everlasting-commit-bit-v1`)
Disjunctive Schnorr (base `H`) proving knowledge of `d` with `C = d·H` (v=0) **or** `C − G = d·H` (v=1).
Lets the commitments‑only record be self‑sufficient for ballot validity. Object: `{A0,A1, c0,c1,s0,s1}`,
with `T0 = C`, `T1 = C − G`.

```
e = hashToScalar("everlasting-commit-bit-v1", [G, H, C, A0, A1])
require c0 + c1 ≡ e (mod N)
require s0·H == A0 + c0·T0     and    s1·H == A1 + c1·T1
```

### 10.6 Everlasting commit‑sum — `ΣC` commits to exactly `L` (label `everlasting-commit-sum-v1`)
Plain Schnorr (base `H`) for `D = Σd` with `ΣC − L·G = D·H`. Object: `{A, z}`.

```
e = hashToScalar("everlasting-commit-sum-v1", [G, H, sumC, L·G, A])
require z·H == A + e·(sumC − L·G)
```

### 10.7 Selene tracker↔commitment consistency (label `selene-tracker-consistency-v1`)
Proves `Com = T + d·H` and `ET = (ρ·G, T + ρ·PK)` encode the same tracker point `T`. The tracker `T`
cancels in `ET.b − Com = ρ·PK − d·H`, leaving a two‑scalar relation in `(ρ,d)`. Object: `{A1, A2, zr, zd}`.

```
e = hashToScalar("selene-tracker-consistency-v1", [G, H, pk, ET.a, ET.b, Com, A1, A2])
require zr·G            == A1 + e·ET.a
require zr·pk − zd·H    == A2 + e·(ET.b − Com)
```

### 10.8 Verifiable re‑encryption mixnet — Sako–Kilian (label `mixnet-shuffle`)
The **default** anonymizing shuffle. A cut‑and‑choose proof of `t` parallel re‑encryption shuffles: the
prover commits to `t` intermediate shuffles; the challenge selects, per instance, whether to reveal the
shuffle relative to the input or the output. The base challenge is
`c = hashToScalar("mixnet-shuffle", <all public ciphertext columns + intermediates>)`, expanded to `t`
challenge bits by `bit_b = SHA-512("vvp-fs-v1" ‖ "mixnet-shuffle-bits" ‖ scalar32(c) ‖ u32(b))` (LSB).
Soundness ≈ `2^-t` (the reference uses `t = 128`). Transcript object: `{t, intermediates[][], openings[{perm, factors[][]}]}`
(§11). This is the by‑hand‑checkable default; it is `O(t·N)`.

### 10.9 Terelius–Wikström O(N) shuffle — **EXPERIMENTAL, NOT THE DEFAULT, NOT AUDITED (ADR‑0012)**
An opt‑in O(N) proof of shuffle (labels `mixnet-tw-mul-v1`, generators §3.2, challenge expansion §4.1). It
is shipped behind an explicit experimental flag, is **not** wired into any election, and **must not** be
used for anything consequential until externally audited (the 2019 SwissPost break was a missing check in a
shuffle proof that had passed expert audit). The by‑hand‑checkable Sako–Kilian proof (§10.8) remains the
default. Full construction: `reference/src/mixnet-tw.ts` + ADR‑0012. It is intentionally **not** pinned as
normative here.

---

## 11. Transcript wire formats (JSON)

### 11.1 Envelope and rules
- UTF‑8 JSON. Points are lowercase hex (§1.2); scalars are canonical decimal strings (§1.3).
- Every point is validated on parse; every scalar is gated by the decimal grammar **and** range‑checked.
- Two discriminators: **`version`** (format/version) and **`kind`** (selects the verifier).

**Dispatch (`kind` → verifier):**

| `kind` | verifier | `version` |
|--------|----------|-----------|
| `plurality` *(or absent — default)* | plurality / multi‑seat | `vvp-transcript-1` |
| `ranked` | ranked Borda | `vvp-ranked-transcript-1` |
| `mixnet-irv` | mixnet instant‑runoff | `vvp-mixnet-irv-transcript-1` |
| `selene` | Selene coercion‑mitigation | `vvp-selene-transcript-1` |
| `everlasting-trail` | everlasting commitment trail | `vvp-everlasting-trail-1` |
| `tw-shuffle` **(EXPERIMENTAL)** | TW shuffle | `vvp-tw-shuffle-1` |
| `rla-export` | paper + RLA ballot‑polling export | `vvp-bp-export-1` |

A multi‑seat ("vote for exactly N") transcript uses the plurality format with `selectionLimit = N`; the
default verifier (no `kind`, or `kind = plurality`) handles it.

### 11.2 Top‑level fields by kind
The reference's serializers (`reference/src/transcript-json.ts` and the per‑feature modules) are the source
of truth; the following enumerates the top‑level keys of each kind as actually emitted.

- **plurality** (`vvp-transcript-1`): `version, kind, contest, candidates[], numVoters, selectionLimit,
  eligibleRoll[], publicKey, commitments[], trustees, threshold, ballots[], boardRoot, aggregates[],
  decShares[], results[]`. Each `ballots[i]` = `{voter, credentialPub, selection:{enc[], bitProofs[],
  sumProof}, sig:{R, s}}`. Each `decShares[i]` = `{trusteeIndex, shares[], proofs[]}`.
- **ranked** (`vvp-ranked-transcript-1`): like plurality but each ballot carries a permutation‑matrix
  `ballot:{matrix[][], bitProofs[][], rowSums[], colSums[]}`, and `bordaAggregates[]` replaces `aggregates[]`.
- **mixnet-irv** (`vvp-mixnet-irv-transcript-1`): ranked ballots, plus `shuffled[]`,
  `shuffleProof:{t, intermediates[][], openings[{perm, factors[][]}]}`, `decShares[]`,
  `decryptedMatrices`, `rounds`, `winner`.
- **selene** (`vvp-selene-transcript-1`): plurality‑style core plus `shuffled[]`, `shuffleProof`,
  `trackerPoints[]`, `votes`. Per‑record binding bytes use the `vvp-selene-v1` tag.
- **everlasting-trail** (`vvp-everlasting-trail-1`): `version, kind, contest, candidates[], selectionLimit,
  publicKey, pedersenH, boardRoot, ballots[]`. Each ballot has `cells[]` (`{ct:{a,b}, commitment, bitProof,
  consistency, commitBit}`) and a `sumProof`/`commitSum`. `pedersenH` MUST equal the pinned `H` (§3.1).
- **tw-shuffle** (`vvp-tw-shuffle-1`) **EXPERIMENTAL**: `version, kind, publicKey, L0, L, proof`.
- **rla-export** (`vvp-bp-export-1`): `version, kind, anchor, manifest, reported` — the signed digital↔paper
  anchor binding a board root to a paper ballot manifest, plus reported results (ADR‑0004/0009).

---

## 12. Worked example (canonical test vectors)

Deterministic vectors emitted by the reference primitives. An independent implementation that reproduces
these has correctly implemented §1–§8.

```
# Group (§1)
N              = 7237005577332262213973186563042994240857116359379907606001950938285454250989
G_hex          = e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76
scalar32(1)    = 0000000000000000000000000000000000000000000000000000000000000001

# Pedersen H (§3.1)
H_label        = "vvp-everlasting-pedersen-H-v1"
H_hex          = b66dc28b63ecfbb83fa33aad8148a54f17757fce571ad6b8df258d3cfa2a777a

# Fiat–Shamir frame (§4), label "vvp-spec-example", points [G, H]
FS_frame_hex   = 000000097676702d66732d7631000000107676702d737065632d6578616d706c65
                 00000002
                 e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76
                 b66dc28b63ecfbb83fa33aad8148a54f17757fce571ad6b8df258d3cfa2a777a
                 (concatenated, no whitespace)
FS_digest_hex  = 1a20dcf6f551463cf29acd181e395063d63060fba25dc2a4fbfff8c49f8d60e4
                 cf39746ca3157ced6ad2b5c96c7a5cedeaf5abfdb506ad2759a826b55710b104
hashToScalar   = 4295489874469658940361992038498814341386559662619122550997844146990027781568

# Merkle bulletin board (§7), SHA-256
MTH([])        = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
MTH(["a"])     = 022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c
MTH(["a","b"]) = b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb
                 # = SHA-256(0x01 ‖ MTH(["a"]) ‖ MTH(["b"]))

# Credential signature challenge (§8) for R=G, pub=G, msg="vote"
e              = 2350596918581551747409214031942212569759782512299066514365017620140469621405
                 # = int_be( SHA-512("vvp-cred-sig-v1|" ‖ G ‖ G ‖ "vote") ) mod N
```

(`MTH(["a"])` uses leaf `"a"` = byte `0x61`; the node hashes the two leaf hashes under prefix `0x01`.)

---

## 13. Conformance — what an independent verifier MUST do

A transcript counts as **verified** only when an implementation that shares **no code** with the prover and
reads **only the published transcript** accepts it. Such a verifier MUST:

1. **Validate every point on parse** (reject non‑canonical/off‑curve), and **gate every scalar** on the
   decimal grammar **and** range check (§1.2–§1.3) — at the deserialization boundary, before any use.
2. **Recompute every Fiat–Shamir challenge** from the statement and commitments (§4); never trust a
   transmitted challenge; check sub‑challenge sums where applicable.
3. **Recompute the Merkle root** from the `boardBytes` leaves (§6.3, §7) and check it equals `boardRoot`.
4. **Check every signature** and enforce the **single‑use nullifier** (no `pub` casts twice; every signer is
   on the eligible roll) (§8).
5. **Re‑verify every sigma proof** (§10) and **re‑derive the results** from the decryption shares — never
   trusting the `results` field.
6. **Pin `H`** (§3.1) and, for everlasting transcripts, check `pedersenH` equals it.
7. **Never throw on hostile input.** A malformed or adversarial transcript MUST produce a clean
   *rejection*, never a crash — the verifier is a security boundary.

The reference ships two such verifiers (TypeScript `reference/src/verify*.ts`; Python
`verifier/vvp-verify-py/`) and CI fails on any divergence across all seven kinds.

---

## 14. Versioning & status

- This document is `vvp-cryptospec-1`. Any change to an encoding, a label, a frame, or a proof transcript
  is a **breaking change** and MUST bump the relevant `version` tag (§5) and this spec's version.
- The protocol is the **Stage‑1 reference**. It is **pre‑audit** ([#54](https://github.com/Nimdy/Verifiable-Voting-Platform/issues/54))
  and is appropriate for clubs/DAOs/HOAs/community voting and as the digital companion to paper + RLA — **not**
  for binding government remote/online elections (SCOPE.md, ADR‑0004). The Terelius–Wikström shuffle is
  EXPERIMENTAL and opt‑in (ADR‑0012); Sako–Kilian is the default.

See also: [THREAT_MODEL.md](THREAT_MODEL.md), [SCOPE.md](SCOPE.md), [CRYPTO_REVIEW.md](CRYPTO_REVIEW.md),
[ADRs/](ADRs/), and the live status in [STATUS.md](STATUS.md).
