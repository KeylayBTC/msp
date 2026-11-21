# MSP — questions for cryptographic review

*Recorded 2026-10-08; Q1 revised and Q2 narrowed 2026-11-09 after the SAS commitment was adopted; Q1 revised again and Q3/Q4 extended 2026-11-18 after an external design review moved the nonce reveal ahead of every other message (spec v0.1-draft.2). These are the questions the external review (OpenSats milestone, months 3–5) is scoped to answer, and the questions the Delving Bitcoin thread asks in public first. Section references are to the MSP draft specification v0.1. Each question states what we believe, so a reviewer can answer "yes, because…" or "no, because…" rather than start from nothing.*

*When the public repository exists, each question becomes one GitHub issue, opened in the author's words before anyone else raises it.*

---

## Background a reviewer needs in one paragraph

Participants share a short session code out of band. Each stretches it (PBKDF2-HMAC-SHA512, 300k iterations) to `K_code`, derives a public rendezvous identifier `channel_id = SHA-256("MSP-V1-CHANNEL" || K_code)`, and announces a fresh X25519 key in a hello authenticated by `HMAC(K_code, …)` (§5.2–5.3). Pairwise keys come from HKDF over the X25519 shared secret with `K_code` as salt and the channel and both public keys in `info` (§5.4). Each hello also carries a commitment to a fresh random nonce. As soon as both hellos are held, each participant reveals its nonce in a SAS_REVEAL message, and the humans compare a ~59-bit short authentication string (SAS) over `channel_id`, both session public keys, and both nonces over an authenticated side channel (§6.8) — before anything else is sent. Only then does the initiator open the ceremony. In a setup session every participant sends its account key as a plain output-descriptor key expression to the other, assembles the descriptor locally by a byte-exact function, and broadcasts its hash (§6.6–6.6a); before funding, each verifies its own key and the first address on its signing device and the humans compare the address (§6.6, pre-funding checkpoint). The relay is the adversary; the threat that matters most is a party that is on the relay path *and* holds the session code.

---

## Q1. The commitment-in-hello SAS (adopted 2026-11-09; reveal moved 2026-11-18): is it sound as specified?

**What changed.** The October draft's SAS hashed the session keys and the descriptor hash with nothing committed, so an attacker on the relay path holding the code saw every honest value before sending its own and could birthday-search for a collision at about 2^30 per side. The draft adopts a commitment in the hello: each hello carries `cm = SHA-256("MSP-V1-SAS-COMMIT" || pk || r)` for a fresh 256-bit nonce `r`, MAC'd under `K_code`; `r` is revealed in a dedicated SAS_REVEAL message — the first AEAD message any participant sends, in setup and signing alike (draft.2; draft.1 revealed it inside KEY_CONTRIBUTION in setup, which disclosed the account key before the comparison and was withdrawn) — sent only after the sender holds the other hello; the SAS is `SHA-256("MSP-V1-SAS" || channel_id || n || sorted (pk_i || r_i) || 0x0000)` reduced modulo 31^12. `descriptor_hash` is no longer in the SAS. Membership is frozen at a participant's reveal; nothing but hellos and reveals is sent before the humans have confirmed the SAS. Nonces are never reused, and a participant keeps its own nonce until it has computed and confirmed the SAS. The design study with the alternatives considered and an independent adversarial check is `notes/sas-commitment-study-2026-11-07.md`.

**What we believe.** Every value the attacker can choose toward an honest participant X is fixed in hellos X holds before X reveals `r_X`, so `SAS_X` is a hash whose last input the attacker never saw; the attacker succeeds with probability about 2^-59 per session, with no offline work, for any n, by the Laur–Pasini argument (every party commits, every party opens after holding all commitments). Removing `descriptor_hash` is necessary (the attacker delivers its substitute contributions after seeing the honest nonces, and an xpub's chain code is 32 free bytes) and sufficient (once the keys are authenticated, contributions travel under AEAD with authenticated `from`/`to`, and DESCRIPTOR_CONFIRM catches divergence).

**What we want from the reviewer.**
1. Is the "reveal only after holding the other commitment, then freeze membership" rule sufficient for two parties over a pairwise channel with an interposed party, in the draft.2 schedule where both parties reveal symmetrically in a dedicated message and the ceremony opens only after both users confirm? Then: what must a group profile add so that the same argument holds for n parties, given that each participant must know the expected set before it reveals and the message that carried `n` in draft.1 (SESSION_INIT) now comes after the reveal? Is there a delivery schedule we have missed?
2. Is removing `descriptor_hash` from the SAS sound, given DESCRIPTOR_CONFIRM under authenticated pairwise keys?
3. Given the online-only bound, what SAS length would you accept? Twelve base-31 characters (≈59.4 bits) were sized against an offline search that no longer exists; ZRTP and Bluetooth use about 20 bits with the same structure.

## Q2. Does comparing a long value remove the need for commitment? *(narrowed 2026-11-09)*

*With the Q1 construction the SAS permits no offline search, so it can be compared later over a verified text channel, and because it covers the session keys it detects the silent interposer that a first-address comparison cannot (item 3 below). The question becomes: is the commit-in-hello SAS, compared asynchronously over a verified text channel, sufficient for A.6? The original text follows.*

**What we believe.** The birthday search works because the compared value is short. If participants compare a value too long to collide by search — the wallet's first receive address (256 bits for P2WSH) or full key fingerprints — over an authenticated text channel, the search is infeasible and no commitment is needed. We propose this as the only mechanism in the asynchronous profile (A.6), where no live SAS is possible, and as an optional alternative in live sessions where participants have a verified messaging channel.

**What we want from the reviewer.**
1. Is that sufficient, given that each participant also checks its own key is present (§6.6a)?
2. In the asynchronous profile the attacker has unlimited time. Is a full first address still the right value, or should the comparison cover the full `descriptor_hash` (or both)?
3. A comparison over the *result* (the wallet) cannot detect an attacker that interposes, reads, and relays everything honestly, because the results then agree; the xpubs and descriptor leak undetected. We therefore want the asynchronous comparison to also cover a value bound to the session's key material, so that such an attacker is at least detected after the fact. What should that value be in the prekey profile (A.1), where participants never hold one simultaneous set of session keys — and can it be made long enough to resist search while remaining comparable by humans over text?

## Q3. Is the join safe against offline guessing, and does the split-code proposal fix it?

**What we believe.** The join is not a standard PAKE (password-authenticated key exchange). Everything the relay sees — `channel_id` and every hello MAC — is an offline oracle on the code. Security therefore rests on code entropy (10 characters of a 31-character set ≈ 49.5 bits) times PBKDF2 cost, and a fixed public salt means one search covers every session the relay logs (finding S11). Forward secrecy holds, so recovering a code after a session yields nothing; recovering it during a session enables active interposition.

Proposed fix: split the code into a short public **rendezvous segment**, the only part hashed into `channel_id`, and a **secret segment** used only as the password in CPace. The relay would then learn nothing offline about the secret; each join attempt would test one guess, online and visibly.

**What we want from the reviewer.**
1. Does the split-code + CPace design eliminate offline guessing on the secret segment?
2. Does the rendezvous segment leak anything we have not considered — for example, correlation across sessions if users reuse rendezvous segments?
3. Is CPace the right PAKE for an n-party setting built from pairwise channels, or does running it pairwise introduce a weakness a group PAKE would avoid?
4. A practical consequence we want confirmed: under the PAKE, user-chosen memorable codes would face only online guessing, so a code of ~25–30 bits could be acceptable where today's join needs ~50. Is that reasoning sound, and what guess-rate assumption should the spec state?
5. With a PAKE in place, is the SAS still necessary? (We believe yes — no PAKE helps if the code itself was intercepted — but want that confirmed.)
6. *(Added 2026-11-18.)* We now state that the online-only claim requires replacing **all three** code-derived verifiers the relay can see — `channel_id`, the hello MAC, and the A.1 bundle MAC — not only the hello. Is that list complete?

## Q4. Is the asynchronous prekey-bundle MAC sound? *(lower priority)*

**What we believe.** Appendix A.1 authenticates prekey bundles with a MAC under `K_code` rather than with identity keys, because participants already share `K_code`. This defeats an attacker who does not hold the code from posting a bundle first. It does nothing against an attacker who does — which is the A.6 problem, handled by the signed confirmations and the first-address comparison.

**What we want from the reviewer.** Confirm or refute; and note that the bundle's byte layout is not yet specified (it carries the same class of defect as the draft.1 hello MAC), so the review may need to wait for that text. *(Added 2026-11-18.)* A MAC under `K_code` on a bundle that sits on a relay is itself an offline verifier for the code; under the Q3 PAKE profile the bundle would have to be authenticated under the PAKE output instead, and the profile must say which key exists when the bundle is posted. Is there a sound way to authenticate a first bundle before any PAKE exchange has completed?

---

## Not in scope for this review

The descriptor-assembly function (§6.6a) is a byte-exactness problem settled by test vectors, not cryptography. Transport bindings (WebSocket, Nostr, QR) do not affect the security of the session layer. Post-quantum protection is out of scope for v0.1 and is stated as a limitation.
