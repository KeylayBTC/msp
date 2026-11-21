# Proposal: symmetric descriptor assembly (every participant is its own coordinator)

*2026-10-06. Design note against spec v0.1-draft (§2, §6.2, §6.6, §6.8, A.6, Appendix B item 4). Origin: the author's question, "can't all participants serve as a coordinator — the information is available to them, and they could assemble a descriptor locally?" Answer: yes, once one message's addressing changes; and doing so removes the attack A.6 exists to detect rather than detecting it after the fact.*

---

## 1. What the spec does today, and why A.6 exists

§6.6 has a distinguished **coordinator**. Signers send `KEY_CONTRIBUTION` to the coordinator only (§6.2 registry: signer → coordinator). The coordinator assembles the descriptor, sends `DESCRIPTOR_PROPOSAL` to everyone, collects `DESCRIPTOR_ACK`s, and sends `SESSION_FINALIZE`. Each participant checks only that *its own* key appears correctly.

Because envelopes are pairwise-encrypted, a compromised coordinator can send Alice a descriptor containing (Alice, attacker, attacker) and Bob one containing (attacker, Bob, attacker). Each passes its own-slot check. That is the Benma substitution attack surviving inside a correctly established session, and it is why §6.6 carries a "known limitation (n ≥ 3)" and why Appendix A.6 — broadcast ACKs, mandatory `wallet_sig` from the contributed key, an n-signatures finalization rule — is a precondition for any session with more than two parties.

A.6 is a correct patch. It is also the most complicated construction in the spec, and it exists only because the coordinator assembles the descriptor.

## 2. The change

**Send `KEY_CONTRIBUTION` to every participant, not only to the coordinator.** Each participant then holds the same inputs — the frozen `SESSION_INIT` terms and every signed BSMS Round-1 record, each received directly from its contributor over that pair's authenticated channel — and assembles the descriptor locally with a normative, deterministic function. There is no `DESCRIPTOR_PROPOSAL` because nobody proposes a descriptor; everybody computes the same one.

Consequences, in order of importance:

1. **The coordinator-equivocation attack is gone, not detected.** No party ever sends a descriptor, so no party can send two. Alice's descriptor contains Bob's real key because Alice got it *from Bob*, signed by Bob's key, over the Alice–Bob channel. The only thing that can poison it is a break of the session layer itself (code interception), which is what the SAS is for and which no ceremony design can fix.
2. **The "coordinator" shrinks to an "initiator."** One participant proposes terms (`SESSION_INIT`: m, n, script type, derivation template, network). Those terms are already bound into the SAS, so every participant confirms them in the SAS comparison. After that the initiator has no privileged role in setup. §4.3's residual-trust item "the coordinator's honesty about slot assignments and SESSION_INIT parameters" reduces to liveness.
3. **Slot assignment disappears.** §6.6's first-come-first-served rule exists because one party had to pick an order. With local assembly the order must be a function of content: `sortedmulti` / `sortedmulti_a` (BIP-67 key ordering) for standard multisig, which is what BSMS Round 2 produces anyway. Ordered policies (miniscript with distinct roles) are out of scope for v0.1 and say so.
4. **A.6 collapses to its asynchronous half.** Synchronous n-party sessions no longer need `wallet_sig` at all: each participant verified every key directly. `wallet_sig` stays REQUIRED only in the async profile (A.1), where there is no live SAS and a returning participant needs retained evidence of what it agreed to. The "not every device can sign" objection stops mattering for the common case.
5. **n > 2 becomes reachable.** Appendix B item 4 made A.6 the precondition for multi-party relaying. The precondition becomes: the assembly function specified, the confirmation round specified, and the relay lifted to n connections. All three are smaller than A.6.
6. **Every signer already needs the full descriptor** for the §6.7 refusal check (do not sign a PSBT that does not spend from the finalized descriptor). Symmetric assembly is the design that takes that requirement seriously instead of having the signer receive the descriptor from the party it is supposed to be defending against.

## 3. What is still required

**A confirmation round.** Replace `DESCRIPTOR_PROPOSAL` / `DESCRIPTOR_ACK` with one broadcast message:

```
DESCRIPTOR_CONFIRM  (every participant → all)
  { 1: descriptor_hash: bytes(32), 2: first_address: text, 3: wallet_sig?: bytes }
```

A participant MUST NOT import or fund the wallet until it holds a `DESCRIPTOR_CONFIRM` from every other participant whose `descriptor_hash` and `first_address` equal its own. Any mismatch is ABORT, and the mismatching pair is identifiable. This catches two things the broadcast alone does not:

- **Signer equivocation.** Bob sends record R to Alice and R′ to Carol. Bob cannot profit (he still holds one key of the threshold), but Alice and Carol would hold different wallets. The hash round exposes it immediately. (Bob also had to sign both records with his contributed key, so there is evidence.)
- **Implementation divergence.** Two implementations whose assembly functions differ in one byte — key origin formatting, checksum, a derivation-template expansion — produce different hashes. This is the same class of bug test vectors exist for, caught at ceremony time with a clear "abort, do not fund" rather than a wallet that silently disagrees about addresses later.

**A normative assembly function.** This is the real specification work and it is unavoidable: "assemble the descriptor locally" means every implementation must produce the *identical* descriptor string from the same inputs. The spec must state, to the byte: key ordering (BIP-67 sorted, over the full key expression), key-origin formatting (`[fingerprint/path]xpub`), how `derivation_template` expands to the per-key path and the `/<0;1>/*` suffix, the script wrapper per `script_type`, the descriptor checksum, and the exact BSMS Round-2 file bytes. Then one transcript vector (three contributions in, one descriptor out) pins it. Most of this is already implied by BSMS; the spec has to say it rather than point at it.

**SAS binds the result.** §6.8 currently binds `channel_id`, all session public keys, and the `SESSION_INIT` body. Replace the last term with `descriptor_hash` (which commits to the terms *and* every key) in setup sessions, and keep `descriptor_hash` of the existing wallet in signing-only sessions. One human check then covers membership, terms, and the wallet that resulted. This is a change to a construction already slated for external review (commitment phase); make it part of the same revision so the reviewer sees the final form once.

## 4. What it does not change

- The session layer (§5), the join, the pairwise keys, the counters, the air-gap bridge mechanics. A bridged record is still injected by the bridging human and still carries the BSMS signature of the contributed key; it is now fanned out to everyone instead of delivered to one party.
- The irreducible human step. Signed records prove key *possession*, not identity. Alice still has to know that the person reading the SAS to her over the phone is Bob. Nothing in-band can supply that.
- The signing phase. Whoever constructs a PSBT sends `PSBT_REQUEST`; the signer's refusal check is the protection, as before. "Coordinator" was never a trust role in signing.
- Message count rises from n−1 to n(n−1) contributions. At n = 7 and ~300 bytes per record that is 42 messages, a few kilobytes. Irrelevant on WebSocket or Nostr; on the air-gap side the bridging app fans out one scan.

## 5. Spec deltas, by section

| Section | Change |
|---|---|
| §2 Roles | Rename *coordinator* → *initiator*: "the participant that sends SESSION_INIT. After SESSION_INIT the initiator has no role the other participants do not have." |
| §4.1 / §4.3 | Threat model: "a compromised initiator can propose wrong terms (caught by the SAS) or refuse to proceed (liveness). It cannot substitute keys or equivocate descriptors, because it does not distribute either." Residual-trust item on the coordinator reduces accordingly. |
| §6.2 registry | `KEY_CONTRIBUTION`: signer → **all**. Delete `DESCRIPTOR_PROPOSAL`, `DESCRIPTOR_ACK`. Add `DESCRIPTOR_CONFIRM`: each → all. `SESSION_FINALIZE` becomes an initiator announcement with no authority (A.6's own wording). |
| §6.6 | Delete the slot-assignment paragraph (replace with the ordering rule in the assembly function). Add **§6.6a Descriptor assembly (normative)** with the byte-exact function. Add the `DESCRIPTOR_CONFIRM` rule. Delete the "Known limitation (n ≥ 3)" paragraph — it no longer applies. |
| §6.8 | Bind `descriptor_hash` in place of `init_bind` for setup sessions; wallet's `descriptor_hash` for signing-only. Fold into the commitment-phase revision. |
| §7.1 | Relay limit becomes `n` as declared in SESSION_INIT (reject the n+1th connection), not two. |
| §10 | New transcript vector: three Round-1 records + SESSION_INIT → descriptor string, `descriptor_hash`, BSMS Round-2 bytes, SAS. |
| A.6 | Retitle "Asynchronous descriptor evidence." Keep: `wallet_sig` REQUIRED in async, signature scope, retention rule, the non-simultaneous fingerprint comparison. Delete: broadcast-ACK and n-signatures finalization as the *synchronous* mechanism — superseded by §6.6a + `DESCRIPTOR_CONFIRM`. |
| Appendix B item 4 | Precondition for n > 2 becomes: §6.6a specified with a vector; `DESCRIPTOR_CONFIRM` specified; relay lifted to n. |
| Explainer | Mirror all of the above; the "coordinator trust" discussion in the generalization note (May 2026, "Critical design decisions") is superseded and should say so. |
| Limitations (front matter) | "Two parties" stays until §7.1 is lifted — but the reason changes from "A.6 unbuilt" to "assembly function and confirm round unspecified," which is honest and smaller. |

## 6. Effect on the OpenSats narrative

The one-sentence claim gets stronger and simpler: *there is no coordinator in the trust model.* Every participant computes the wallet from keys it received directly from each cosigner, and the ceremony cannot complete unless every participant computed the same wallet. That is a cleaner answer to the Benma problem than "the coordinator proposes and everyone checks their own slot," and it is a claim no wallet-integrated product makes, because each of them *is* the coordinator.

It also answers the seven-questions table's row 7 ("n-of-m setup through the initiator makes the initiator the middleman the design is meant to remove"): the initiator is no longer a middleman for anything but the terms, and the terms are what the SAS comparison confirms.

## 7. Recommendation

Adopt it in the next spec revision, before publication if the edit fits the weekend, otherwise as revision `v0.1-draft.2` immediately after, so the Delving post describes the symmetric design. Do the §6.6a assembly function carefully — it is the one place this proposal creates new byte-level surface — and write its transcript vector in the same sitting, because that is how the under-specification will be found.
