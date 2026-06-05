// Registrar (Registration Authority) — Belenios-style identity↔credential separation.
//
// The registrar is a SEPARATE party from the casting server. It alone holds the
// identity↔credential mapping; it publishes ONLY the set of eligible credential
// public keys (the "roll"), in an order decorrelated from identity. The casting
// server and the public transcript therefore never see identities. And because
// ballots are encrypted and only the AGGREGATE is ever decrypted, no single party —
// registrar, casting server, or any sub-quorum of trustees — can link a person to
// their vote:
//   • registrar knows identity↔credential, but the vote is encrypted (can't see it);
//   • server/public knows credential↔encrypted-ballot, but not identity (and not the vote);
//   • trustees only ever decrypt the per-candidate TOTALS, never an individual ballot.
//
// Stage-1 scope (be honest about it):
//   • PRIVACY of the *vote content* holds (above). But the registrar ALONE learns per-identity
//     PARTICIPATION/turnout — credentialPub is published in the roll and on every ballot, so the
//     registrar can see who cast a ballot (just not how they voted). Intrinsic to credential-roll
//     voting; hiding turnout needs anonymous/blind-signature issuance (M3+).
//   • INTEGRITY: this stage-1 registrar generates and STORES each voter's full signing keypair
//     (issueCredential → {secret, pub}), so a dishonest registrar could vote as any registered
//     voter who hasn't yet cast. Full Belenios integrity ("safe if registrar OR server is honest")
//     needs a voter-contributed credential part — tracked as M3+.
// Identities here are abstract roll entries (org membership, OIDC subject, jurisdiction roll …) —
// NEVER an SSN or durable government ID (ADR-0001).

import { issueCredential, type Credential } from './credentials.js';
import { pointToHex, type Point } from './group.js';

/** An entry on the off-ledger eligibility roll. */
export interface Eligible {
  id: string;
}

/** What a voter privately receives from the registrar (their secret credential). */
export interface VoterCredential {
  id: string;
  credential: Credential;
}

export class Registrar {
  private readonly book = new Map<string, Credential>(); // id → credential (PRIVATE; never published)

  /** Issue a fresh credential for each eligible voter; returns each voter's private packet. */
  register(eligible: Eligible[]): VoterCredential[] {
    return eligible.map((e) => {
      if (this.book.has(e.id)) throw new Error(`already registered: ${e.id}`);
      const credential = issueCredential();
      this.book.set(e.id, credential);
      return { id: e.id, credential };
    });
  }

  /**
   * The ONLY thing the casting server / public ever sees: the set of eligible credential
   * public keys, sorted by encoding so the publication order is independent of identity /
   * registration order (a ballot's later board position then leaks nothing about who cast it).
   */
  publishedRoll(): Point[] {
    return [...this.book.values()]
      .map((c) => c.pub)
      .sort((a, b) => pointToHex(a).localeCompare(pointToHex(b)));
  }

  /** Registrar-only, PRIVATE: which identity owns a credential public key (eligibility disputes). */
  identityOf(pub: Point): string | undefined {
    const target = pointToHex(pub);
    for (const [id, c] of this.book) {
      if (pointToHex(c.pub) === target) return id;
    }
    return undefined;
  }

  /** Number of registered voters. */
  size(): number {
    return this.book.size;
  }
}
