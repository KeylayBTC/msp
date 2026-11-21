# MSP Question One: Closing the SAS Collision Hole Without an Extra Round

*Study dated 2026-11-07. Scope: review question Q1 (`spec/review-questions.md`), the §6.8 short authentication string. Inputs: the v0.1-draft.1 spec text (§5.3, §5.4, §6.6, §6.7, §6.8), the published literature on SAS-based authentication, and an independent adversarial check of the proposed construction (§10). Every term is defined where it first appears. This is a design study, not a review; the construction still goes to the cryptographer, with a narrower question than before.*

---

## 1. Bottom line

**The hole can be closed with no extra round in setup sessions and one one-way message in signing-only sessions, using a known structure rather than a new one.** Each participant's hello carries a 32-byte commitment to a fresh random nonce. The nonce is revealed inside the participant's first encrypted message, which in a setup session is the KEY_CONTRIBUTION it already sends. The SAS is computed over the session keys and the nonces. The descriptor hash comes out of the SAS, because once the keys are authenticated the descriptor is protected by the channel.

Against an attacker on the relay path who holds the code, success drops from a 2^30 offline search (minutes on a GPU) to a 2^-59 chance per session with no search possible, which is the bound the 60-bit rendering was always supposed to provide. The structure is the commit-then-reveal pattern of Vaudenay's SAS protocols, Laur and Pasini's group version, and Bluetooth's numeric comparison, placed on messages MSP already sends. Nothing here is new cryptography, and that is the point: a fix a reviewer has seen before gets confirmed in an evening.

The one deliberate departure from the current spec is removing `descriptor_hash` from the SAS input. §6 argues why that is safe and why keeping it would reopen the hole. The one new rule an implementation must get right is stated in §7.

---

## 2. The problem, stated precisely

A short authentication string (SAS) is a short code two or more people read to each other over a channel the attacker cannot forge, such as a phone call between people who know each other's voices. If everyone sees the same code, nobody is sitting in the middle swapping keys. MSP's SAS (§6.8) is 60 bits, rendered as 12 characters, computed as a hash over the channel identifier, every participant's ephemeral public key, and the assembled wallet's descriptor hash.

The attacker that matters is a relay operator who also holds the session code. Holding the code makes it a valid Layer-1 participant: it can produce hellos that pass the HMAC check and establish pairwise keys with every honest party. It interposes itself, so that honest A talks to the attacker's persona "B'" and honest B talks to persona "A'". A and B then compare SAS values, and the attacker needs those two values to be equal.

Sixty bits should make that a 2^-60 event. It does not, because of ordering. The attacker receives A's hello and B's hello before it has to send either persona's hello, so it can choose both persona keys after seeing both honest keys. It can then search: generate candidate persona keys, compute the two SAS values, and stop when they collide. Finding a collision between two freely chosen 60-bit values is a birthday search, named for the fact that any 23 people probably contain two with the same birthday: about 2^30 trials per side rather than 2^60. That is minutes on a graphics card, inside the 15-minute idle timer.

What the attacker varies depends on the session, as the spec already records. In a signing-only session the descriptor hash is known in advance, so it varies the persona session keys at hello time. In a setup session the session keys are fixed at hello time before the descriptor hash exists, so it varies the xpubs it substitutes in KEY_CONTRIBUTION, which it sends after seeing the honest ones. In a setup session where it only reads and relays unchanged, it is not in the middle at all and there is nothing to detect.

The spec's draft remedy was a dedicated commitment round before the keys are revealed. The question put to the reviewer was what the commitment must cover and in what order for n parties. The author's constraint for this study: no extra round.

---

## 3. Principles from the literature

Five principles decide this design. Each has a source.

**P1. Commit before knowledge.** An attacker that must fix its values before learning the honest values cannot search; it gets one try per session. This is the organizing idea of every SAS protocol since Vaudenay (CRYPTO 2005), and Nguyen and Roscoe named their family after it: "hash commitment before knowledge." ZRTP's RFC states the consequence plainly: the commitment "forces the MiTM to choose his own two DH public values before learning the public values of either of the two parties," which limits the attacker to a single guess and lets the SAS stay short.

**P2. Only values the attacker can choose after seeing honest input need committing.** A value the attacker must send *before* the honest party's last input is already non-adaptive. Bluetooth's numeric comparison uses this: only the responder commits (to its nonce), because the initiator sends its nonce first and the responder's nonce comes last. The protocol's rules are exactly "the responder MUST share Cb before it receives Na" and "the initiator MUST share Na before it receives Nb." Lindell proved the mode secure in the standard model. One commitment plus an ordering rule gives both sides non-adaptivity.

**P3. Commit to a nonce, not to the value you need early.** ZRTP commits to the DH public value itself and reveals it later, which delays key agreement by a round. Bluetooth and Laur–Pasini commit to a random sub-key and reveal it after keys are exchanged. The nonce enters the SAS, so revealing it late is what makes the SAS unpredictable, while the keys can be exchanged immediately and encryption can start. The nonce must be long enough to make the commitment hiding (256 bits is conventional).

**P4. Group version: everyone commits, then everyone reveals; no other ordering needed.** Laur and Pasini's SAS-based group message authentication (PKC 2008) has every party commit to a sub-key in round one and open it in round two; the SAS is a hash of the group description and all messages keyed by the combined sub-keys. Their bound is about n·ε + 2^-ℓ for an ℓ-bit SAS, and they note the sub-keys "are released only after the adversary has delivered all messages." The rule that makes it work is local: do not open your commitment until you hold everyone's commitment. That answers Q1.2 directly.

**P5. Two moves cannot do it; three can.** Every optimal SAS protocol in the literature is three moves per pair: commit, respond, open. Pasini and Vaudenay's SAS-based key agreement is three moves and they show the bound is tight for that structure. A protocol in which each party sends exactly one message carrying everything that enters the SAS gives the last sender full adaptivity, which is MSP's current state. The way to avoid *adding* a round is to notice that MSP's setup already has more than three moves per pair (hello, hello, SESSION_INIT, contribution, contribution, confirm), so the commit and the open can ride on messages that already exist.

---

## 4. Comparable systems, and what each lends MSP

| System | Commitment | Where revealed | SAS | What MSP takes |
|---|---|---|---|---|
| **ZRTP** (RFC 6189) | Initiator commits `hvi` = hash of its DHPart2 (its DH value) in the Commit message | DHPart2, after responder's DHPart1 | 32 bits, rendered 20 bits as 4 base-32 characters | The argument for why commitment makes a short SAS safe; the warning that committing to the key itself costs a round |
| **Bluetooth Secure Simple Pairing, numeric comparison** | Responder commits `Cb = f1(PKb, PKa, Nb, 0)` | `Nb`, after initiator's `Na` | 6 decimal digits (≈20 bits) | Commit to a nonce after keys are exchanged; one side committing is enough when the other side speaks first; proven secure (Lindell 2009) |
| **Vaudenay 2005 / Pasini–Vaudenay 2006** | Alice commits to a key K with her message | Alice opens after Bob's random R | ρ bits; SAS = R ⊕ h_K(m_B) | The three-move minimum and the tight 2^-ρ-per-attempt bound |
| **Laur–Pasini SAS-GMA** (PKC 2008) | Every party commits to a sub-key with its message | Everyone opens in round two | ℓ bits over all messages and sub-keys | The n-party answer: all commit, all reveal, no ordering between parties beyond "hold all commitments first" |
| **Nguyen–Roscoe HCBK/SHCBK** | Every party commits to a hash of its contribution | Opened in the next round | b bits; bound 2^-b per attempt, q·2^-b for q runs | The name of the principle, and the conservative multi-run bound |
| **Signal safety numbers** | None | — | 60 decimal digits (≈200 bits) | The alternative when the compared value is long enough that search is infeasible (MSP's Q2 and A.6) |

Two observations from the table. First, MSP's 60-bit SAS is three times longer than anything in the table; with a sound commitment, the rendering could shrink, which is a usability question for later (§8). Second, none of these systems puts the wallet or payload into the SAS. They authenticate the keys, and everything after that rides on the authenticated channel. That is the argument of §6.

---

## 5. The search: alternatives and what each buys

The table scores each option on the only thing that matters, whether the attacker is *adaptive* toward each honest party (can it choose its SAS-relevant inputs after seeing that party's last input), and what that costs it.

| | Option | Extra messages | Attacker toward joiner | Attacker toward initiator | Success | Verdict |
|---|---|---|---|---|---|---|
| A | Status quo, SAS lengthened to 80 bits | none | adaptive | adaptive | birthday, 2^40 per side (GPU-days) | Not a fix; delays, does not remove |
| B | Dedicated COMMIT message before hello reveal (ZRTP style; the Q1 draft) | +1 round trip, every session | fixed | fixed | 2^-59 | Correct, but encryption waits for the reveal and every session pays a round |
| C | Ordering only: "the initiator speaks last" at hello and at contribution | none | adaptive | fixed | target search 2^59 per joiner, online, inside the session | Explains why Bluetooth needs only one commitment; alone it is thin (§5.1) |
| D | **Commit-in-hello nonce, revealed in first encrypted message; descriptor hash out of the SAS** | none in setup; one one-way flight in signing-only | fixed | fixed | 2^-59, no search | **Recommended** |
| E | Commit-in-hello covering the xpub, descriptor hash kept in SAS | none | fixed | fixed | 2^-59 | Requires the key before the terms are known; breaks the consent-then-contribute flow (§6) |
| F | Use `K_code` as a shortcut (Q1.3) | none | adaptive | adaptive | unchanged | No: the attacker holds `K_code`; anything keyed by it is computable by the attacker |
| G | Interlock-style split messages | none | — | — | — | Known broken for authentication (Bellovin–Merritt 1994); rejected |
| H | Compare a long value instead (first address, Q2) | none | fixed | fixed | 2^-256 | Correct for text channels; not readable aloud; does not detect a silent interposer (Q2.3); complement, not replacement |
| I | C + D together | as D | fixed | fixed | 2^-59 | C adds nothing once D is in place |

### 5.1 Why ordering alone (C) is worth understanding but not adopting

Option C needs no new bytes. The initiator creates the session and knows n, so it can wait for n−1 hellos before sending its own, and wait for n−1 contributions before sending its own. Toward the initiator, every persona value is then fixed before the initiator's last input, so the initiator's SAS is a random 60-bit value the attacker cannot steer. Toward each joiner the attacker is still adaptive, but it is now searching for a fixed target rather than a collision between two free values: 2^59 trials per joiner, not 2^30 for a pair.

That sounds like enough until you cost a trial. In a setup session the attacker varies substituted xpubs, and an xpub's chain code is 32 free bytes, so each trial is a few hashes. At 10^10 hashes per second per GPU, 2^59 is about five GPU-years; a well-funded attacker with ten thousand GPUs does it in under five hours, which is longer than the 60-minute session cap but not by a margin a specification should rest on. In a signing-only session each trial is an X25519 key generation, roughly a thousand times slower, and the margin is comfortable. Ordering also depends on a rule every joiner must obey without being able to verify who is "last," and it does nothing for the asynchronous profile. It is the right explanation for why Bluetooth commits one side only, and the wrong thing to ship alone.

### 5.2 Why the commitment cannot cover the xpub (E)

If the descriptor hash stays in the SAS, the attacker regains adaptivity through the xpubs it substitutes in KEY_CONTRIBUTION, which it sends after seeing the honest nonces. The only way to keep the descriptor hash and close the hole is to commit to the xpub in the hello. But the participant does not know which xpub to contribute until it has seen and consented to the terms in SESSION_INIT, which arrives after the hellos. Committing to the xpub at hello time would require every participant to export the right key before joining, which is the flow MSP's consent step was designed to avoid. Rejected on UX grounds, not security grounds.

---

## 6. The recommended construction (D), spec-ready

Section references are to v0.1-draft.1.

### 6.1 Hello (§5.3)

```
hello (109 bytes) =
    ASCII("MSP-HELLO")         // offset  0,  9 bytes
 || uint8(v)                   // offset  9,  1 byte
 || uint16_be(caps)            // offset 10,  2 bytes
 || uint8(kdf)                 // offset 12,  1 byte
 || pk                         // offset 13, 32 bytes  ephemeral X25519 public key
 || cm                         // offset 45, 32 bytes  SAS commitment (new)
 || mac                        // offset 77, 32 bytes

r   = 32 bytes from a cryptographically secure random source, generated together
      with (sk, pk) and never derived from sk; retained until revealed, then zeroed;
      never reused across sessions or keys. A re-sent hello (rejoin, §8.3) carries
      the same pk and the same cm, or it is ignored. A session that aborts after any
      nonce has been revealed is over; the next attempt uses new keys and new nonces.
cm  = SHA-256(ASCII("MSP-V1-SAS-COMMIT") || pk || r)
mac = HMAC-SHA256(K_code, hello[0..77))
```

The MAC covers `cm`, so the commitment is bound to the code holder who sent it. `pk` is inside the commitment so that a nonce cannot be paired with a different key. Processing order (§5.3) is unchanged: magic and length, version and KDF, MAC, then `pk` and `cm`. A v1 hello of any length other than 109 is ignored. Two additional ignore rules, both cheap: a hello whose `pk` equals the receiver's own `pk`, and a hello whose `pk` equals an already-accepted `pk`, are ignored (the second is the existing key-change rule read from the other side).

### 6.2 Reveal

**Setup sessions.** KEY_CONTRIBUTION (§6.6) gains field `4: sas_nonce: bytes(32)` (field 3 stays reserved). **Rule:** a participant MUST NOT send any KEY_CONTRIBUTION until it holds valid hellos from all n−1 other participants, n from SESSION_INIT, and has consented to the terms. Both halves of that rule already exist in spirit (you cannot encrypt to a peer whose hello you lack; consent precedes contribution); the new part is "all n−1," which is what forces every persona to commit before the honest nonce is revealed to anyone.

**Signing-only sessions.** New message type `9 SAS_REVEAL` (each → all, AEAD per recipient), body `{ 1: sas_nonce: bytes(32) }`, sent once the participant holds all expected hellos. In the two-party profile that is one hello. For n-party signing sessions, where the participant set is not fixed by the wallet (m of n sign, not all n), the requester's SAS_REVEAL additionally carries `2: participants: [pk, …]`, the full sorted set including the requester's own `pk`; other participants send their SAS_REVEAL only after holding a hello for every listed `pk`, and compute the SAS over exactly that set.

**Freeze rule (both session kinds).** At the moment a participant sends its first reveal, its view of the session is frozen: the set of accepted `pk`s, `n`, and (in signing) the participant list. A valid hello from a new `pk`, a SESSION_INIT, or a participant list arriving after that point is an ABORT, not an update. For a given `pk`, the first hello accepted is the only one; a later hello with the same `pk` and a different `cm` is ignored. The wallet is not shown as created, and no PSBT is sent or signed, before the human comparison. This is the Laur–Pasini rule, "open only after holding every commitment," with the requester supplying the list because it is the one who knows who was invited.

**Verification.** On receiving a nonce from a sender, compute `SHA-256("MSP-V1-SAS-COMMIT" || pk_sender || r)` and compare with the `cm` from that sender's hello. Mismatch → ABORT, new reason `10 commit_mismatch` (§6.9). A nonce that arrives before the sender's hello cannot happen, since the envelope cannot be decrypted without the pairwise key.

### 6.3 SAS (§6.8)

```
sas_input = SHA-256(
      ASCII("MSP-V1-SAS")
   || channel_id                          // 32 bytes
   || uint8(participant_count)
   || concat over participants, sorted by pk byte-wise, of (pk_i || r_i)
                                          // participant_count × 64 bytes
   || uint16_be(0))                       // ceremony_bind removed; prefix kept for layout stability

SAS = (sas_input as a 256-bit big-endian integer) mod 31^12 → 12 base-31 characters.
```

One rendering change from the current text: reduce the whole digest, not its first 60 bits. Reducing a 60-bit value modulo 31^12 (about 2^59.4) makes the smaller outputs about twice as likely as the larger ones; reducing 256 bits makes the bias negligible. The alphabet, grouping, and uppercase rendering are unchanged.

Timing: the SAS can be displayed as soon as every nonce is held. In a setup session keep the checkpoint where it is, after DESCRIPTOR_CONFIRM, so there is one checkpoint at the end. In a signing-only session the checkpoint moves *before* PSBT_REQUEST: the requester SHOULD NOT send the PSBT until the SAS is confirmed, which also stops a man in the middle from reading the PSBT before being detected. A signer MUST NOT send PSBT_RESPONSE before confirming the SAS, as now.

### 6.4 Why `descriptor_hash` leaves the SAS

The descriptor hash was put in the SAS on 2026-10-06 so that the human comparison would catch participants who assembled different wallets. With the nonce commitment it must come out, for a security reason and a sufficiency reason.

Security: anything in the SAS that the attacker can influence after the honest nonces are revealed reopens adaptivity. The descriptor hash depends on the xpubs delivered to each party, and the attacker delivers its personas' xpubs after it has seen the honest nonces. Keeping it would hand the attacker a free variable with a cheap search (chain codes), which is Option E without E's commitment.

Sufficiency: the SAS's job is to authenticate the pairwise keys. Once that is done, every KEY_CONTRIBUTION travels inside AEAD under keys only the honest parties hold, so an attacker who is not in the middle cannot substitute an xpub, and one who is in the middle has already been caught. Two honest parties assembling different wallets can then only result from a bug or from a legitimate participant sending different xpubs to different peers; DESCRIPTOR_CONFIRM, exchanged under the same authenticated keys, catches both and aborts. That last step depends on a property the spec already has and the rationale should name: the envelope's `from` and `to` fields are authenticated (§6.4 AAD) and the nonce carries a direction byte, so a relay cannot reflect a party's own CONFIRM back to it as if from a peer. (The shipped app, which uses one key in both directions, is open to exactly that reflection, external finding E9; the spec's envelope is not.) The scope note at the top of §6.8 ("who is in the session, on what terms, which wallet resulted") becomes "who is in the session"; terms and wallet are protected by the channel the SAS authenticates. This is also how every system in §4 works: none of them puts the payload into the SAS.

The §6.7 signer check (a PSBT must spend only from a wallet the signer holds) is unchanged and is what protects signing, independent of the SAS.

### 6.5 Error registry, vectors, size

- §6.9: add `10 commit_mismatch`.
- §10.2 hello vector: regenerate for the 109-byte layout (add `r`, `cm`; MAC input is now 77 bytes).
- §10.3 SAS vector: regenerate with three nonces, no `ceremony_bind`.
- §10.4 assembly vector: unchanged (assembly has no SAS dependence), except its embedded SAS values, which are recomputed.
- Hello grows by 32 bytes; a QR-carried hello is still one small frame. KEY_CONTRIBUTION grows by 34 bytes.
- Wire-breaking relative to draft.1, which has no implementation; the app has not adopted the v1 hello, so there is no flag day beyond the one already planned.

---

## 7. What an implementation must get right, and what it does not fix

**The one rule, in five forms.** Reveal your nonce only after you hold hellos from every expected participant, only inside encrypted messages, and treat your view of the session as frozen from that moment. The ways an implementation gets this wrong silently, each of which hands the attacker an honest nonce before one of its own inputs is fixed and turns the 2^-59 chance back into a 2^60 offline search: contributing to peers one at a time as their hellos arrive; letting a later hello replace an earlier one for the same key; accepting SESSION_INIT or a changed `n` after revealing; accepting a changed participant list after revealing; reusing a nonce after an abort. The conformance suite needs a refusal vector for each: an implementation offered SESSION_INIT and one of two expected hellos must not contribute; offered a second hello for a known key with a different commitment, must ignore it; offered a hello from a new key after it has revealed, must abort.

**What stays true.**
- A relay still sees IP addresses, timing, and sizes. The SAS has never addressed that.
- If the session code is intercepted and the attacker uses it, the SAS is still what detects the interposition; the PAKE question (Q3) is separate and unchanged.
- A malicious legitimate cosigner can still refuse to proceed, or contribute a key it cannot sign with; the test spend covers the latter.
- A participant's own compromised software can still misreport the SAS to its user; the device-screen rule (§6.6a) is the defense there, as before.
- The attacker can always abort the session. Nothing changes that.

---

## 8. Corollaries

**Q1.2 (n-party ordering) is answered.** No ordering between parties is needed. Every party commits in its hello and reveals only after holding every commitment. The attacker's success for any number of honest parties is still about 2^-59 per session, because every honest party's SAS is a hash whose last input it never saw.

**Q1.3 (`K_code` shortcut) is answered: no.** The attacker in scope holds `K_code`. Any construction keyed by it is one the attacker can compute, so it cannot substitute for a commitment. What `K_code` does do is make the hello's commitment attributable to a code holder, which is what keeps a code-less eavesdropper out of the key-set entirely.

**Q2 narrows.** The long-value comparison was proposed for the asynchronous profile because a live SAS is impossible there. With the commitment, the SAS no longer needs to be live: there is no offline search, so the 12-character string can be pasted into a verified text channel hours later with the same 2^-59 guarantee, and because it covers the session keys it detects the silent interposer that a first-address comparison cannot (Q2.3). The first-address comparison remains the right check against a compromised bridge (§6.6a), which the SAS never addressed. Q2 becomes "confirm that the commit-in-hello SAS, compared asynchronously over a verified text channel, is sufficient for A.6," which is a smaller question.

**The SAS could be shorter.** Sixty bits was chosen against an offline search that no longer exists. ZRTP and Bluetooth use about 20 bits with the same structure. Eight characters (about 40 bits, 1 in 10^12 per attempt) would be easier to read aloud. Keep 12 for v0.1 so the rendering and vectors stay stable, and put the length on the reviewer's list as a usability question, not a security one.

---

## 9. What goes to the reviewer now

Replace Q1 with:

> **Q1 (revised).** Each participant's hello commits to a 256-bit nonce (`cm = SHA-256(domain || pk || r)`, MAC'd under `K_code`); the nonce is revealed inside the participant's first AEAD message, sent only after hellos from all expected participants are held; the SAS is a 60-bit truncation of `SHA-256(domain || channel_id || n || sorted (pk_i || r_i))`. We believe an attacker on the path holding the code succeeds with probability about 2^-59 per session, with no offline work, for any n, by the Laur–Pasini argument. (1) Is the "reveal only after all commitments" rule sufficient for n parties over pairwise channels with an interposed party, and is there a delivery schedule we have missed? (2) Is removing `descriptor_hash` from the SAS sound given DESCRIPTOR_CONFIRM under authenticated keys? (3) Given the online-only bound, what SAS length would you accept?

That is three narrow questions a protocol cryptographer can answer against a structure they already know, instead of a request to design an ordering.

---

## 10. Independent adversarial check

*(Findings from a fresh reviewing agent given only the construction, without this report's reasoning, are recorded here with the changes they produced.)*

The agent was given §6's construction as a bare protocol description, without this report, and asked to break it. Its verdict: "sound with the following rule changes." It found no attack on the setup flow, none on the signing-only flow, none on the commitment, and none from removing the descriptor hash, in each case giving the reason (every input to an honest party's SAS other than its own nonce is fixed before that party's first encrypted message, and a replayed hello cannot be opened without its private key). Its findings and what they changed:

1. **Reflection of DESCRIPTOR_CONFIRM.** If a pairwise key were used in both directions with nothing in the authenticated data distinguishing sender from recipient, a cosigner who also controls the relay could send different xpubs to A and B, then reflect each party's own CONFIRM back to it relabeled, so each sees a "matching" hash. **Already closed by the spec, which the brief omitted:** the envelope header's `from` and `to` fields are authenticated as AAD (§6.4), and the GCM nonce carries a direction byte, so a reflected envelope fails to decrypt. Worth a sentence in §6.8's rationale, since the argument for removing the descriptor hash leans on it. (The same reflection against the shipped app is external finding E9, which the app's one-key-both-ways design permits and the spec's does not.)

2. **Nonce reuse across a rejoin turns the online bound back into an offline search.** If an implementation reveals `r`, the session aborts, and it then re-sends a hello with the same `r` (or derives `r` from `sk`), the attacker knows `r` before the next attempt begins and can grind its own nonce offline to a fixed target. **Adopted as rules:** `r` is generated fresh with every new `(sk, pk)`; it is zeroed after reveal; a re-sent hello (§8.3 rejoin) carries the same `pk` and the same `cm` or is ignored; a session that aborts after any reveal is a new session with new keys and new nonces.

3. **Ordering rules that fail silently.** Five implementation mistakes each give the attacker an honest nonce before one of its own inputs is fixed: contributing per peer as hellos arrive instead of after all n−1 are held; last-hello-wins instead of first-hello-wins for a given `pk`; accepting SESSION_INIT, or a changed `n`, after revealing; in n-party signing, accepting a second or different participant list after revealing; showing the wallet as created before the human comparison. **Adopted:** the participant set, `n`, and (for signing) the list are frozen at a participant's first reveal; any later hello, SESSION_INIT, or list is an abort; the conformance suite gets refusal vectors for each of the five.

4. **Signing-only list convention.** The non-requester cannot know the participant count at hello time and learns it from the requester's list; that is safe because it reveals only after holding every listed hello. The list must state whether it includes the sender's own `pk` so both sides hash the same set. **Adopted:** the list is the full sorted set including the requester.

5. **Rendering bias.** Twelve base-31 characters give 31^12 ≈ 2^59.4 values; reducing a 60-bit integer modulo 31^12 makes the low values about twice as likely as the high ones, which costs a fraction of a bit. **Adopted:** reduce the full 256-bit `sas_input` modulo 31^12 instead of its first 60 bits; the bias becomes negligible and the vectors are being regenerated anyway. The per-session bound is then 2^-59.4, which this report rounds to 2^-59.

---

## Sources

- Vaudenay, *Secure Communications over Insecure Channels Based on Short Authenticated Strings*, CRYPTO 2005 — [IACR program page](https://iacr.org/archive/crypto2005/crypto2005.html)
- Pasini and Vaudenay, *SAS-Based Authenticated Key Agreement*, PKC 2006 — [paper](https://www.iacr.org/archive/pkc2006/39580401/39580401.pdf)
- Laur and Pasini, *SAS-Based Group Authentication and Key Agreement Protocols*, PKC 2008 — [paper](https://www.iacr.org/archive/pkc2008/49390198/49390198.pdf)
- Laur and Nyberg, *Efficient Mutual Data Authentication Using Manually Authenticated Strings* (MANA IV), CANS 2006 — [paper](https://typeset.io/pdf/efficient-mutual-data-authentication-using-manually-3magn28hrf.pdf)
- Nguyen and Roscoe, *Authentication protocols based on low-bandwidth unspoofable channels: a comparative survey* — [paper](https://typeset.io/pdf/authentication-protocols-based-on-low-bandwidth-unspoofable-29kn4oyw36.pdf)
- RFC 6189, *ZRTP: Media Path Key Agreement for Unicast Secure RTP*, §4.4.1.1 (commitment) and §4.5.2 (SAS) — [RFC](https://www.rfc-editor.org/rfc/rfc6189.html)
- Bluetooth SIG, *Bluetooth Pairing Part 4: LE Secure Connections — Numeric Comparison* — [blog](https://www.bluetooth.com/blog/bluetooth-pairing-part-4/)
- Lindell, *Comparison-Based Key Exchange and the Security of the Numeric Comparison Mode in Bluetooth v2.1*, CT-RSA 2009 — [abstract](https://u.cs.biu.ac.il/~lindell/abstracts/BT-numeric_abs.html), [ePrint 2009/013](https://eprint.iacr.org/2009/013)
- Bellovin and Merritt, *An Attack on the Interlock Protocol When Used for Authentication*, IEEE Trans. Inf. Theory 1994 (for Option G)
