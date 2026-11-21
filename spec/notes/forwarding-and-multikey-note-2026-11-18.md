# Three-key wallets from two-party sessions: forwarding and multi-key contributions, considered and deferred

*2026-11-18. Design note for the Multisig Session Protocol (MSP). Records two routes to a wallet with more keys than a v0.1 session has participants, why neither is in v0.1, and what each would need if adopted later. Written so that the group-session and asynchronous designs start from this analysis rather than repeat it. Terms are defined where first used.*

## 1. The situation

A v0.1 session has two participants, each contributing one key, so setup creates two-key wallets (spec §1.3). The most common personal multisig is a 2-of-3. There are three ways to reach it:

1. **A group session** — three clients connected at once, each contributing one key. This is the planned route (Appendix B item 4). It needs the relay cap lifted and a membership mechanism that tells each participant the expected count before it reveals its SAS nonce (§5.3, §6.8).
2. **A chain of pairwise sessions with forwarding** — participants pair two at a time, and a participant that already holds another's key passes it along. Proposed by the external reviewer on 2026-11-18, then withdrawn by agreement the same day.
3. **Several keys in one contribution** — one client that holds two keys (say, two hardware wallets owned by one person) contributes both in one KEY_CONTRIBUTION. This is option D-15 in the 2026-11-07 defect-decision memo.

v0.1 ships none of them and says so. This note records 2 and 3.

## 2. Forwarding

### 2.1 What it is

A participant that has received another participant's key over an authenticated session includes that key, alongside its own, in its contribution to a third participant. The third participant then holds a key it did not receive from its owner.

### 2.2 The reviewer's three worked cases

| Case | Direct exchange (every pair meets) | With forwarding | What forwarding saves |
|---|---|---|---|
| Alice holds keys A and B on two devices; Bob holds C remotely. | Two remote pairings (A↔C, B↔C). | Alice moves B's xpub to A's client locally; A↔C exchange all three keys in one remote session; Alice moves C's xpub to B locally. | One remote pairing. The two local transfers are not MSP sessions. This case is really option 3 (one client, two keys) and does not need forwarding between participants. |
| Three remote clients, one key each. | Three pairings (A↔B, A↔C, B↔C). | A↔B; then B↔C with B passing on A's key; then B→A passing on C's key. | Nothing in count (still three exchanges), but A and C never have to be online together. |
| Four remote clients, one key each. | Six pairings. | A↔B and C↔D exchange keys; then A↔C and B↔D exchange the pairs they hold. | Two exchanges (four instead of six). Distribution only; final verification is extra. |

The counts are correct. In the four-client case each client ends with all four keys after two sessions of its own.

### 2.3 What forwarding costs

- **A forwarded key is unauthenticated until the end.** When C receives A's key from B, C has B's word for it. If B is dishonest or compromised, B can hand C a key B controls in A's place; C's software has no way to tell. The only check is the final one: every intended contributor confirms the same assembled wallet with every other intended contributor, each having verified its own key on its own device, and the full first address is compared. A common address by itself does not establish that every intended key was included; it is the combination of each owner's own-key check and a common address across all owners that does.
- **Final verification may undo the savings.** If the direct final confirmation requires reopening a session with every other contributor, the pairings forwarding saved come back at the end. Confirmation over the authenticated out-of-band channel avoids that, at the cost of moving the descriptor agreement out of the protocol and into a human text exchange, which is the design the author declined for v0.1.
- **Forwarding discloses.** An xpub forwarded to a recipient is known to that recipient at once. Who receives what must be decided before the transfer, and the leaked-code threat model (§4.2) applies to every hop.
- **State across sessions.** A wallet under construction must persist between sessions, with per-contributor stored keys and a setup identifier, and the spec has no such object today.

### 2.4 Why the scheduling benefit is smaller for the asynchronous design than it looks

The real attraction of forwarding is that A and C never have to be online together. But the asynchronous profile (Appendix A.1) solves that problem a different way: each participant encrypts its own contribution into every other participant's mailbox (a prekey bundle), and nobody has to be present at the same time as anyone else. Under mailboxes, forwarding buys no scheduling. What it still buys is **route availability**: when an intermediary is the only path to a recipient (an air-gapped participant, a participant without relay access). That is a narrower case, and it carries the unauthenticated-hop cost above.

**Position.** Forwarding is an open design choice for the asynchronous version, not a planned feature. If it is adopted, each contributor must verify its own key on its own device, check the intended policy and chain, and confirm the same assembled wallet with every other intended contributor before funding, and the spec must define the wallet-under-construction object.

## 3. Several keys in one contribution (D-15)

### 3.1 What it is

KEY_CONTRIBUTION carries a list of key expressions instead of one. `n` in SESSION_INIT counts keys, not clients. A client holding two keys contributes both; the other client contributes one; both assemble a three-key descriptor.

### 3.2 What it would give

The first case in §2.2 — one person holding two keys, one cosigner holding the third — with no third connection and no forwarding between participants. It is the cheapest route to a live 2-of-3 and covers a large share of real personal setups (collaborative custody with one remote cosigner; a person and a spouse with a third key at a lawyer's).

### 3.3 What it would cost

- The contribution body changes shape (a list), which is a wire change and a vector change.
- The consent display must show how many keys each participant holds: "Alice: 2 keys, Bob: 1 key" is a materially different wallet from three independent holders, and §4.3 already says distinct keys do not prove distinct custody. A display that said only "2-of-3" would mislead.
- Duplicate-key rejection (§6.6) already applies across the whole set.
- The pre-funding checkpoint must run on every device that holds a key, which for a two-device holder is two registrations and two own-key checks.
- The participant-count rule (§5.3) stays at two clients; what changes is the key count, and SESSION_INIT must say both.

### 3.4 Why not in v0.1

The revision of 2026-11-18 already changes the wire format in several places under a publication deadline. D-15 would be a further format change with a consent-display question attached, and the n-party work needs to decide how multi-key holders are shown anyway. Deferred, with this note as the starting point.

**Position.** D-15 is the first candidate extension after publication, because it reaches a live 2-of-3 without a third connection. It should be designed together with the consent display for mixed holdings, not bolted on.

## 4. Summary table

| Route | Connections for a 2-of-3 | Wire change | New trust assumption | Status |
|---|---|---|---|---|
| Group session | 3 at once | none to the envelope; relay cap, membership mechanism | none | planned (Appendix B item 4) |
| Forwarding chain | 2 at a time, several sessions | wallet-under-construction object; multi-key contribution | intermediary honest until final all-party verification | open choice for the asynchronous design |
| Multi-key contribution (D-15) | 2 at once | contribution becomes a list; consent display for mixed holdings | none beyond §4.3 custody caveat | first post-publication candidate |

## Sources

- External design review and follow-up of 2026-11-18 (author's working files): proposed resolutions, follow-up withdrawing forwarding for synchronous v0.1, and the three worked cases above.
- `msp-next/defect-decision-memo-2026-11-07.md`, item D-15.
- MSP specification v0.1-draft.2, §1.3, §4.3, §5.3, §6.6, §6.8, Appendix A.1, Appendix B item 4.
