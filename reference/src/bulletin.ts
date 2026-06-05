// Append-only public bulletin board with an RFC-6962-style Merkle root.
//
// This is the "no insider can quietly alter or delete a ballot" layer. The board
// stores opaque, deterministic ballot bytes; its Merkle root is a single hash
// that commits to the entire ordered set. Change, drop, or reorder any ballot
// and the root changes — and everyone watching sees it.
//
// In production this interface is the chain-pluggable seam: the default backend
// is a Postgres transparency log, and an optional adapter anchors ONLY the root
// (never ballots) on a blockchain. Here we keep it in-memory.

import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, bytesToHex } from '@noble/hashes/utils';

const LEAF = new Uint8Array([0x00]);
const NODE = new Uint8Array([0x01]);

export class BulletinBoard {
  private entries: Uint8Array[] = [];

  /** Append a ballot's canonical bytes; returns its position. */
  append(payload: Uint8Array): number {
    this.entries.push(payload);
    return this.entries.length - 1;
  }

  size(): number {
    return this.entries.length;
  }

  /**
   * RFC 6962 Merkle Tree Hash. Splits at the largest power of two strictly less
   * than n and never duplicates a lone node, so it is not vulnerable to the
   * CVE-2012-2459 odd-node ambiguity (where two different ballot sets could
   * otherwise share a root). (audit hardening)
   */
  private mth(items: Uint8Array[]): Uint8Array {
    const n = items.length;
    if (n === 0) return sha256(new Uint8Array());
    if (n === 1) return sha256(concatBytes(LEAF, items[0]!));
    let k = 1;
    while (k * 2 < n) k *= 2;
    return sha256(concatBytes(NODE, this.mth(items.slice(0, k)), this.mth(items.slice(k))));
  }

  /** Merkle root over all appended ballots (hex). */
  root(): string {
    return bytesToHex(this.mth(this.entries));
  }
}
