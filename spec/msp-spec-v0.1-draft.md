# Multisig Session Protocol (MSP) — Draft Specification v0.1

```
  Title:    Multisig Session Protocol (MSP) — Encrypted Session Layer for Remote Multisig Setup and Signing
  Author:   Stan Reeves <contact@keylay.org>
  Status:   Draft
  Type:     Standards Track (informational until a second implementation exists)
  Created:  2026-08-29 (first complete draft); published 2026-11-21 as v0.1-draft.2
  License:  CC0-1.0 (text) · MIT (test vectors, conformance tooling)
  Version:  0.1-draft.2 (2026-11-18) — see CHANGELOG.md. draft.2 changes
            wire behavior (SAS_REVEAL in every session; KEY_CONTRIBUTION
            field 4 withdrawn; ERROR body field 3 withdrawn; PSBT_REQUEST
            field 3 added) and is incompatible with draft.1.
  Reference implementation: none yet. Keylay (app.keylay.org, MIT) is the
            basis for one and implements a two-party subset; see §14.
```

**Abstract.** The Multisig Session Protocol (MSP) is a session-layer protocol for coordinating a bitcoin multisig wallet between participants who are not in the same place. It collects cosigner keys, lets the participants confirm that they assembled the same wallet descriptor, and routes partially signed transactions. Participants share a short code out of band. From it they derive a rendezvous identifier, perform an ephemeral key exchange, authenticate each other by comparing a short string before anything else is sent, and then exchange typed, authenticated, replay-protected messages. The artifacts are existing standards: keys travel as output-descriptor key expressions (BIP-380), each participant generates the wallet locally as a BSMS (BIP-129) Round-2 descriptor file, and transactions are BIP-174 PSBTs. The relay that carries the session is treated as hostile. It sees ciphertext, the rendezvous identifier, the unencrypted hello fields (ephemeral public keys, version, capabilities, commitments), the authenticated-but-clear envelope headers (message type, key identifiers, counters, request pairing), and network metadata; from these it can tell a setup session from a signing session and count the messages, and it learns no key, no wallet, and no transaction (§7.4).

Every participant receives every cosigner's key contribution directly from its contributor, assembles the wallet descriptor itself by a deterministic function, and confirms that every other participant assembled the same one. Every signer refuses to sign a transaction that does not spend from a wallet it holds, and approves the transaction's destinations, amounts, and fee itself. No party distributes keys or descriptors, so no central coordinator exists to be compromised. Two human checks are specified: a short authentication string compared at the start of every session, before any key or transaction is disclosed, and the wallet's first address compared from signing-device screens before funding. The protocol defines session establishment, the message vocabulary, and bindings to a WebSocket relay, to Nostr, and to QR codes across an air gap; it defines no payload formats of its own.

**Status:** DRAFT for review and study. Not frozen. Not a compliance target. Nothing may be called a "reference implementation" of this document until it is frozen (see §13). Read §1.3 (Limitations) before the normative text.

**Date:** first complete draft 2026-08-29; this revision 2026-11-18. Every normative change is dated in `CHANGELOG.md`.
**Companion document:** `msp-explainer.md` — plain-language rationale for every decision in this specification. Section numbers match.

---

## 0. Motivation

BIP-129 (BSMS) standardized the *file* a multisig setup produces. Nothing standardizes how remote cosigners exchange that file, or the PSBTs that follow. In practice they use email, messaging apps, or a vendor's coordination server. Each of those gives a third party the cosigner set, the wallet structure, and the ability to delay or alter a spend.

The more serious problem is not confidentiality. In a hardware-wallet multisig, each signer knows its own key but learns the *other* cosigners' keys from the coordinator. A compromised coordinator can substitute keys it controls at setup time; the signer then faithfully verifies every address against a poisoned descriptor. This was described in 2020 ("How nearly all personal hardware wallet multisig setups are insecure," BitBox) and remains the default situation for remote setups: there is no authenticated path between cosigners that does not run through the coordinator.

MSP supplies that path. It gives cosigners a private, ephemeral session authenticated by a code they share out of band and by a short string they compare before anything else is sent, not by the coordinator. Keys move over this session without the participation of a trusted coordinator. Every participant receives every cosigner key directly from its contributor, assembles the descriptor itself, and cannot complete the ceremony unless every other participant computed the identical wallet. Every signer then refuses to sign a PSBT that does not spend from a wallet it holds. The relay carrying the session learns nothing about the wallet.

The protocol is deliberately narrow. It defines no payload formats (those are BSMS, PSBT, and output descriptors), no wallet logic, and no identity system. A wallet that already implements BSMS has most of what it needs; the incremental work is the session and message layers defined here.

---

## 1. Purpose and scope

The Multisig Session Protocol (MSP) is a coordination protocol for remote multisig wallet setup and signing. It provides a private, ephemeral, encrypted session between participants who are not in the same room, over which they exchange the artifacts a multisig ceremony requires: extended public keys, confirmations of the wallet descriptor each of them assembles, and partially signed bitcoin transactions (PSBTs).

The protocol deliberately does **not** define multisig payload formats. Payloads are existing standards — output-descriptor key expressions (BIP-380) for the keys, the BSMS (BIP-129) Round-2 descriptor file for the wallet each participant generates, BIP-174 PSBTs for transactions. MSP defines the three things those standards leave undefined for remote participants:

1. **Session establishment** — how strangers-to-the-network form a private encrypted channel from a shared code (Layer 1, §5).
2. **Message vocabulary** — typed, authenticated, replay-protected envelopes that carry ceremony payloads and pair requests with responses (Layer 2, §6).
3. **Transport bindings** — how envelopes move over a WebSocket relay, over Nostr, or across an air gap via QR codes (Layer 3, §7).

The envelope is identical across all transports. A conforming implementation can participate in a session without depending on infrastructure operated by any particular party.

### 1.1 Non-goals for v0.1

- Asynchronous sessions (participants online at different times). **These are the target of version 2 of this protocol.** v0.1 is synchronous, and its decisions are taken so as not to foreclose the asynchronous profile — deterministic message identity (§6.1), symmetric assembly (§6.6a), and the long-value comparison (A.6) exist for that reason. A profile is specified in Appendix A.1 and is not required for v0.1 conformance. Decided 2026-11-05.
- Multiple initiators (co-proposed terms). Explicitly out of scope; extension point reserved (§6.2, §13). Note that descriptor assembly is already symmetric (§6.6a) — this item concerns only who proposes the ceremony terms.
- Group encryption / MLS. Evaluated and deferred (Appendix A.5).
- Payload validation logic (descriptor construction, PSBT parsing). That is wallet logic, not protocol logic. §6.6a (descriptor assembly) and §6.7 (what a signer must verify and what its user must approve before a signature leaves) are the deliberate exceptions: both exist because the protocol's safety claims are false without them, and both are written as checks on standard payloads, not as new formats.

### 1.2 Requirement language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

In practice: MUST is an absolute requirement for conformance, and every MUST is a conformance test; SHOULD is a strong recommendation an implementation may depart from only for an understood reason; MAY is optional, and implementations that include and omit it must interoperate. Lowercase "must," "should," and "may" in this document are ordinary English.

### 1.3 Limitations of this draft

Implementers and reviewers should read this section before the specification proper.

- **Two clients at a time, and what that means for wallets.** A v0.1 session has exactly two participants: the reference relay binding (§7.1) admits two connections (`n_max = 2`), and every client enforces the count itself (§5.3). The consequences for wallets are stated here so that no reader infers more. *Setup* creates **two-key wallets** only, one key contributed by each client; the threshold may be 1 or 2, and the consent screen says which (§6.6). *Signing* works for any wallet that **both parties to the session hold** — however it was created, in MSP or elsewhere — whose keys use the BIP-48 paths this document permits (§6.6, §6.7). A 2-of-3 wallet made elsewhere is signed by two of its cosigners in one session; a wallet needing three signatures is signed in sequential sessions, since a PSBT accumulates signatures. The 2-of-3 in §10.4 is a descriptor-assembly computation vector, not a session this version can run. A three-key setup is deferred to the group-session work: the envelope and ceremony layers are n-party by construction (symmetric assembly, §6.6a), and lifting the limit waits on the assembly function implemented against its vector, DESCRIPTOR_CONFIRM implemented, the relay limit made configurable, and a membership mechanism that tells each participant the expected count before it reveals its SAS nonce (Appendix B item 4). It also waits, as a matter of sequencing rather than safety, on external review of the SAS construction (§5.3, §6.8; review question Q1): if the review changes that construction, the change is wire-breaking, and it should land before multi-party sessions have users rather than after. Multi-party sessions MUST NOT be offered until then. Two other routes to a three-key wallet were considered on 2026-11-18 and are recorded in `notes/forwarding-and-multikey-note-2026-11-18.md`: a chain of pairwise sessions with keys forwarded between them, and a single contribution carrying several keys for one client that holds them; neither is in v0.1.
- **Both parties online.** Sessions are synchronous. Asynchronous sessions are the version-2 target (§1.1); the profile in Appendix A.1 is specified, not built, and not part of v0.1 conformance.
- **No external cryptographic review.** The constructions in §5.3 (hello authentication and SAS commitment), §6.8 (short authentication string), and Appendix A.1 have not been reviewed by a cryptographer. Two concerns are known. The SAS was found in October to lack a commitment phase, which let an attacker on the relay path holding the code search offline for a colliding string at about 2^30 work per side; the 2026-11-09 revision adopted a commitment-in-hello construction — each hello commits to a nonce, the nonces are revealed after every hello is held, and the SAS covers keys and nonces — which the author believes restores the 2^-59-per-session bound with no offline search, following the structure of Vaudenay's and Laur–Pasini's SAS protocols and Bluetooth numeric comparison. This revision (2026-11-18) moves the reveal to a dedicated message sent before any terms, keys, or transactions, so that a participant admitted under a leaked code learns nothing but a random number before the humans can catch it (§6.8). The security argument is restated for that schedule in §6.8 and awaits review (Q1, `review-questions.md`). §5.3 authenticates the join with an HMAC under a stretched copy of the code rather than with a standardized password-authenticated key exchange, so the rendezvous identifier and the hello MAC are offline oracles on the code, bounded only by code entropy and PBKDF2 cost (the S11 bound in the Keylay security review); a split-code CPace join is proposed and not adopted (Q3). The questions are filed as issues #1–#4 (https://github.com/KeylayBTC/msp/issues).
- **No post-quantum protection.** X25519 and AES-GCM. Recorded sessions are exposed to a future quantum adversary; the ceremony artifacts (xpubs, descriptors, PSBTs) are long-lived.
- **Test vectors incomplete.** §10 covers code normalization, the hello MAC, the SAS, and descriptor assembly. Pairwise key derivation, envelope encryption (nonce and AAD construction), and a full setup-then-sign transcript are not yet published; a transcript drafted against draft.1 exists and must be regenerated against this revision's message order before it is evidence of anything. Two implementations of this draft may agree in prose and disagree in bytes.
- **No conforming implementation exists.** Keylay implements a two-party subset with different domain-separation strings and framing; see §14. Nothing may be called a reference implementation of this document until the freeze conditions in §13 are met.
- **Taproot multisig is not supported.** `script_type = 1` (P2TR) is reserved and MUST be rejected in v0.1 (§6.6, §6.6a). BSMS has no settled convention for `sortedmulti_a` templates, and an unspecified option is worse than an absent one.
- **Derivation templates are restricted** to the BIP-48 forms (§6.6). A general grammar is deferred until a second implementer needs a path outside them.
- **Relay metadata is not hidden.** Any transport operator sees IP addresses, timing, sizes, and the rendezvous identifier (§4.2, §7.4). Nostr transport changes *who* operates the relay, not what a relay sees. Hiding IPs requires Tor or an onion service. The per-transport metadata tables §7.4 requires, and the per-message payload-size budget against QR capacity §7.3 needs, are not yet written (Appendix B items 7–8).

---

## 2. Roles and terminology

- **Session** — one ephemeral encrypted namespace, created from a session code, in which one ceremony (setup or signing) takes place.
- **Session code** — the human-shareable secret that both names and authenticates a session (§5.1).
- **Initiator** — the participant whose user chose to start the ceremony rather than join it. The protocol identifies the initiator by one act: after the SAS checkpoint (§6.8) it sends the session's first ceremony message — SESSION_INIT in a setup session, PSBT_REQUEST in a signing session — and that message names the kind of ceremony. Exactly one participant does this per session (§6.8, "Opening the ceremony"). The initiator has no capability the other participant lacks: every participant receives every key contribution directly and assembles the descriptor itself (§6.6a). Cryptographically an ordinary peer. (Earlier drafts called this role the *coordinator* and gave it descriptor assembly; that design is withdrawn — see §6.6 and A.6.)
- **Requester** — in a signing session, the participant that sends the PSBT_REQUEST. In v0.1 there is one requester per session, it is the initiator, and it sends one request (§6.7); a different payment is a new session.
- **Signer** — a participant contributing a key or a signature.
- **Bridged participant** — an air-gapped device that cannot join the session directly; a live participant carries its payloads in and out via QR/file (§7.3).
- **Envelope** — the typed, encrypted, authenticated message unit of Layer 2 (§6.1).
- **Relay** — any server or network that moves opaque envelopes between participants. The relay is untrusted for confidentiality and integrity; it is trusted only for best-effort delivery (§4).
- **Short authentication string (SAS)** — a 12-character string, rendered `XXXX-XXXX-XXXX`, that every participant's implementation computes from the channel identifier, every participant's session public key, and a nonce each participant committed to in its hello, and that participants compare over a channel outside the session that authenticates them to each other (a phone or video call, in person, a verified messenger). It is compared at the start of every session, before any terms, keys, or transactions are sent. Matching strings show that no one is interposed between the participants; a mismatch means abort. It says nothing about the wallet: agreement on the wallet is established afterward by DESCRIPTOR_CONFIRM and the pre-funding address check (§6.6). Mandatory (§6.8).
- **Ceremony** — the sequence of typed messages that accomplishes one task in a session: *setup* (contributing keys, assembling and confirming a descriptor) or *signing* (requesting and returning partial signatures).

**Abbreviations.** Standard terms are used with their usual meanings: AAD — additional authenticated data (input an AEAD authenticates but does not encrypt); AEAD — authenticated encryption with associated data; BSMS — Bitcoin Secure Multisig Setup (BIP-129); CBOR — Concise Binary Object Representation (RFC 8949); HKDF — HMAC-based key derivation function (RFC 5869); HMAC — hash-based message authentication code (RFC 2104); KDF — key derivation function; MAC — message authentication code; PAKE — password-authenticated key exchange; PBKDF2 — Password-Based Key Derivation Function 2 (RFC 8018); PSBT — partially signed bitcoin transaction (BIP-174); UR / BBQr — multi-part QR encodings (Blockchain Commons BCR-2020-005; Coinkite BBQr).

---

## 3. Cryptographic primitives (normative for v0.1)

| Function | Primitive | Notes |
|---|---|---|
| Hash | SHA-256 | |
| Code stretching | PBKDF2-HMAC-SHA512, 300,000 iterations, 32-byte output | §5.2; `kdf = 1`; field allows future Argon2id |
| Key agreement | X25519, ephemeral per participant per session | private keys zeroed immediately after derivation |
| Key derivation | HKDF-SHA256 | domain-separation strings in §5.4 |
| AEAD (authenticated encryption) | AES-256-GCM, 96-bit deterministic nonce | §6.4; suite field allows future ChaCha20-Poly1305 |
| Message authentication (pre-session) | HMAC-SHA256 | hello binding, §5.3 |
| Encoding | Deterministic CBOR (RFC 8949 §4.2 Core Deterministic Encoding) | §6.3 |

**Domain-separation strings (also called context strings).** Every hash, MAC, and key derivation in this specification begins with, or takes as its HKDF `info`, a fixed public ASCII label naming its purpose — `MSP-V1-KDF-SALT`, `MSP-V1-CHANNEL`, `MSP-V1-PAIR`, `MSP-V1-SAS`, and so on. Distinct labels guarantee that two computations over the same secret produce unrelated outputs, so a value published in one role (the `channel_id`, which the relay sees) reveals nothing about a value used in another (the hello MAC key, the pairwise key). The labels are not secret and not salts (except `MSP-V1-KDF-SALT`, which is used as the PBKDF2 salt). All are ASCII, prefixed `MSP-V1-` so they cannot collide with another protocol's or another version's, and included as raw bytes with no terminator or length prefix (see the concatenation convention below). Changing any primitive or any label requires a new wire version (§5.5), with one exception: the hello magic `MSP-HELLO` carries no version number and is the same in every wire version, so that any version can recognize another's hello (§5.3). The hello's version is its `v` byte, which the MAC covers, so hellos of different versions still never share a MAC input. This document uses the term *domain-separation string* throughout.

**Concatenation convention (normative).** Wherever this specification writes `||`, it denotes concatenation of **fixed-width byte strings**. Every operand's width — and, for integers, its endianness — is stated at the point of use. ASCII domain-separation strings are included as their raw bytes, with no terminator and no length prefix. Where an operand is variable-length (a run of items, or a blob whose length is not fixed by context), the construction MUST prepend an explicit count or length so that the concatenation is injective — two different inputs can never produce the same byte string. This convention exists because every place a value is hashed or MAC'd is a place two independent implementations must produce identical bytes; prose like "hash the fields together" does not.

---

## 4. Trust and threat model

### 4.1 What the protocol defends against

- A relay that reads, records, modifies, injects, reorders, or replays traffic.
- A network attacker with the same capabilities on any hop.
- A passive attacker who later obtains the session code (forward secrecy across sessions: ephemeral keys are deleted; past traffic is not decryptable).
- A malicious or compromised participant, the initiator included. The initiator proposes only the ceremony terms, which every participant must accept before contributing (§6.6); no participant distributes keys or descriptors; each assembles the wallet itself (§6.6a) and confirms the others assembled the same one (DESCRIPTOR_CONFIRM); the SAS (§6.8) authenticates who is in the session before any of this begins. Key substitution and equivocation are not constructible inside a correctly established session; what remains to a hostile participant is refusal to proceed.
- Replay of recorded ciphertext into a live session (§6.5).
- Disclosure of account keys to a party who holds the session code but is not an intended participant: nothing but hellos and SAS nonces moves before the humans have compared the SAS (§6.8), so an interposer or extra party admitted under a leaked code is caught having learned only random values.

### 4.2 What the protocol does not defend against

- Compromise of a participant's endpoint (malware on the device that holds plaintext).
- An attacker who obtains the session code **before or during** the session. Code knowledge equals session membership. Mitigations: high-entropy codes (§5.1), out-of-band distribution guidance (§5.6), and the mandatory SAS check (§6.8), which detects an interposed attacker even when the code leaked, and detects it before any key or transaction has been sent. What such an attacker can still do is prevent the session from completing.
- Relay-visible metadata: timing, participant count, message sizes, message types, IP addresses (mitigations and per-transport disclosure in §7.4).
- A participant — initiator or otherwise — who refuses to proceed, withholds a message, or aborts. Any participant can stall a ceremony.

**What the protocol guarantees to each participant separately (normative).** The guarantees are per participant, because the two participants can be in different states when a session stalls or aborts, and a message already sent cannot be recalled.

- No participant is left holding a *wrong* wallet: a participant imports or funds a wallet only after its own checks pass (§6.6, "Pre-funding checkpoint"). A participant whose setup stalled or aborted before those checks has no wallet. The guarantee is local: a setup can end with one participant completed and the other not (below), and no participant can conclude anything about the other's state from its own. *(Corrected 2026-11-18; the first text said a stalled setup "produces no wallet for anyone," which the next guarantee contradicts.)*
- No signer releases a signature its user did not approve (§6.7). A released signature cannot be recalled: once a PSBT_RESPONSE has been handed to the transport, a later abort or disconnect leaves the requester possibly holding it. A signer's implementation MUST record "signature may have been sent" before handing the response to the transport, MUST show that state to its user as distinct from "no signature released," and MUST NOT describe an aborted or timed-out signing session as having produced no signature unless no response was ever handed to the transport. Receiving PSBT_COMBINE and checking it resolves the uncertainty one way; a broadcast transaction resolves it the other.
- One participant's local completion establishes only what that participant verified. A setup participant that holds every matching DESCRIPTOR_CONFIRM and has passed its own checks may complete locally even if its last message never reached the other side; it has then verified its own wallet, not the other participant's state.

### 4.3 Residual trust statement

After a session completes with all mandatory checks passed, each participant is still trusting:

1. The relay operator's handling of metadata (who, when, how much — never content).
2. Their own software: that their MSP implementation displays faithfully what they are asked to accept — the participant count and SAS (§6.8), the ceremony terms (§6.6), the first address (§6.6a), the transaction's destinations, amounts, and fee (§6.7) — and that their wallet validates payloads correctly (descriptor parsing, PSBT input and output checking). Each participant's software is also trusted **by every other participant for confidentiality**: one participant's compromised implementation can disclose every xpub and the descriptor, which together let anyone derive every address the wallet will ever use. Against another participant's compromised software, **integrity** is protected only if the first address is verified and compared on signing-device screens (§6.6, "Pre-funding checkpoint"); a comparison of values displayed by online software does not protect against it.
3. Their signing device, where one is used: its screen is the trusted display for the own-key check, the first address, and the transaction (§6.6, §6.7, A.7).
4. The out-of-band channels used to share the session code, to compare the SAS, and to compare the first address.
5. For a browser-delivered implementation, the web origin that serves the client code. A page served from the relay operator's own domain makes that operator a trusted party for the integrity of the software, whatever the protocol says about the relay — the largest residual trust assumption in such a deployment. The mitigation is a published release hash that users can verify against the tagged source, and self-hosting.

No other participant is trusted for the integrity of the wallet — the initiator included. The ceremony terms are not a trust assumption: every participant sees them and must accept them before contributing a key (§6.6). The SAS proves that the two parties who compared it are the two parties in the session; DESCRIPTOR_CONFIRM, exchanged under the keys the SAS authenticated, proves that both assembled the same wallet; the pre-funding address check proves it on the signing devices. What another participant can still do is refuse to proceed (§4.2), which costs time but never a wrong wallet. Distinct public keys do not prove distinct custody: nothing in the protocol establishes that the two keys of a wallet are held by two people.

An implementation's user-facing security documentation MUST state these residual assumptions.

### 4.4 Prior and related work

**Blind Relay / Signing Room** (S. Carlin, Delving Bitcoin, April 2026; CC0 draft "Stateless PSBT Coordination"). A browser-based, account-free relay with client-side AES-256-GCM, test vectors, a TypeScript SDK, and a live product. It predates this specification's first complete draft and makes the same claim about relay confidentiality. It differs in scope: it covers signing only, with no setup phase, so cosigner keys and the descriptor are assembled elsewhere before a room is used; and it does not define ephemeral per-session key agreement (so has no forward-secrecy claim), a mutual-authentication checkpoint, or descriptor binding before signing. The two are complementary at the relay layer and distinct at the ceremony layer. As of 2026-11-05 the draft remains "Early Draft" (`BIP: ?`); its September 2026 revision added capability-token access control (bearer tokens carried in the URL fragment, hashed at the relay, with per-guest policy enforced mostly by the client) and in-progress Taproot (BIP-371) support, and the Delving thread has no posts other than the author's. The access-control feature exists because that design has a trusted coordinator who delegates authority; MSP has no such role to delegate from (§4.3).

**PSBT/MuSig2 coordination over Nostr relays** (R. Turon, Delving Bitcoin, September 2026). States three transport invariants for coordination over at-least-once relays — idempotent message identity bound to (session, round, signer), per-session monotonic sequencing, and consume-once nonce state — motivated by nonce-reuse hazards in BIP-327 under duplicated or reordered delivery. This specification adopts the first two (§6.1, §6.5) and does not carry MuSig2 or FROST rounds in v0.1; the invariants are the reason the message identity in §6.1 is deterministic rather than random.

**BSMS (BIP-129)** defines the artifacts of a multisig setup. This specification uses them as follows: the Round-1 key record is not carried (the key travels as a plain output-descriptor key expression, §6.6, because common wallets do not export signed Round-1 records); the Round-2 descriptor file is not carried either, but every participant generates it locally by the deterministic procedure in §6.6a and imports it into its wallet; and BSMS's first-address confirmation is the model for the pre-funding checkpoint (§6.6). **BIP-174 PSBT** is the signing payload (§6.7). **Output descriptors** (BIP-380 family) are the wallet-policy representation and the key-expression format on the wire. **BIP-48** defines the derivation paths this specification permits (§6.6).

**Blockchain Commons.** BC-UR (BCR-2020-005) is the normative QR encoding for the air-gap bridge (§7.3). The deterministic CBOR this specification requires (§6.3) is compatible with dCBOR (BCR-2024-002). BCR-2024-004 / GSTP defines request/response pairing (ARID) and function-number registries for envelope-based protocols; §6.10 maps this specification's message types onto it as a compatibility profile and poses an explicit question to that community about registry allocation. Gordian Envelope and GSTP sealing were evaluated as the message layer and not adopted for v0.1: GSTP seals to long-term recipient keys and identifies parties by stable identifiers, which conflicts with this specification's forward secrecy and absence of persistent identity (§4). Hubert (BCR-2025-006), a write-once dead-drop layer for asynchronous coordination, is the natural reference for the version-2 asynchronous work (§1.1) and does not fit a browser-delivered v0.1.

**NIP-46 (Nostr Connect)** performs remote signing over Nostr relays using long-term Nostr identity keys. It is the clearest example of the road not taken here: long-term keys give every relay a durable identifier and no forward secrecy. **NIP-44** likewise derives from persistent keys; this specification carries its own ephemeral handshake inside Nostr events rather than adopting it.

**X3DH / PQXDH** (Signal) are the shape of the asynchronous profile in Appendix A.1, simplified because participants already share `K_code` and so need no identity keys to authenticate prekey bundles. **CPace** (CFRG) is the password-authenticated key exchange named in Appendix A.2. **ZRTP** (RFC 6189) is the origin of the hash-commitment technique the §5.3/§6.8 SAS adopts. **MLS** (RFC 9420) was evaluated for group keying and deferred (Appendix A.5).

**Nunchuk free group wallets** derive a symmetric group key from the finalized descriptor via PBKDF2 and use an asymmetric bootstrap during setup; **Bitcoin Safe** syncs PSBTs and chat over Nostr with both synchronous and asynchronous signing. Both are wallet-integrated coordination features rather than wallet-independent protocols, which is the gap this specification addresses.

---

## 5. Layer 1 — Session establishment

### 5.1 Session code

- **Unambiguous character set:** the 31 characters formed from the digits `2`–`9` and the lowercase letters `a`–`z` with the visually ambiguous `0 1 i l o` removed — i.e. `23456789abcdefghjkmnpqrstuvwxyz` minus `i l o`. Codes are lowercase. The short-authentication string (§6.8) renders this same 31-character set in **uppercase** for human comparison, spoken or written. Removing the look-alikes is what lets a value in this set be read off one screen and reproduced on another without `0`/`o` or `1`/`l`/`i` confusion.
- **Generated codes:** implementations MUST generate codes of at least 10 characters (~49.5 bits of entropy) from the unambiguous set (lowercase) using a cryptographically secure random source with rejection sampling (reject byte values ≥ 248 before reduction modulo 31, so no character is more likely than another). Ten characters suffices because every code-derived value, including the channel identifier, is computed through the stretched key `K_code` (§5.2). This means recovering the code from anything the relay or an eavesdropper observes costs a full key-stretching evaluation per guess, and forward secrecy (§5.4) ensures a code recovered after the fact reveals no past traffic. Display is grouped for readability; separators are formatting and are removed on input (see Normalization).
- **User-chosen codes:** MAY be accepted. Acceptance is deliberately **broader** than generation. Any lowercase letters and digits `[a-z0-9]` (36 characters) are valid *content*, including the `i l o 0 1` the generator omits. Most memorable codes contain them, so rejecting them would defeat the feature. Implementations MUST warn that a guessable code is a guessable session. They SHOULD estimate the strength of a user-chosen code with a pattern-based estimator, one that models how guessers actually attack human-chosen strings (dictionary words, common passwords, names, dates, keyboard walks, repeats, sequences, character substitutions), in the manner of zxcvbn. They MUST NOT present `length × log2(alphabet size)` as the strength of a user-chosen code: that formula is valid only for uniformly random codes and overstates human choices by orders of magnitude. For generated codes it is exact and SHOULD be shown (10 characters ≈ 49.5 bits). The estimate SHOULD be shown as an approximate time to guess for an offline attacker at the §5.2 stretching cost, using a stated and conservative guess rate, with a note that one attacker logging many sessions tests each guess against all of them at once (the fixed-salt property, §5.2). Implementations SHOULD warn strongly when the estimate falls below the generated-code floor of about 49.5 bits. These thresholds assume the §5.3 join, under which the relay can test guesses offline. A join based on a password-authenticated key exchange (Appendix A.2, review question Q3) would make guessing online-only and would permit much shorter memorable codes. Implementations SHOULD also note that a hand-shared code containing a look-alike character (`l`/`1`, `o`/`0`, `i`/`1`) can be mistranscribed into a different, non-connecting channel — a risk generated codes do not carry.
- The code is a **secret**, not an address. It MUST NOT appear in logs, URLs, or any transport-visible field.

**Normalization (normative).** Before any derivation in §5.2, an implementation MUST normalize candidate code input by the following steps, in order:

1. Map ASCII uppercase letters (`A`–`Z`) to lowercase.
2. Remove every character that is not a lowercase ASCII letter or digit (`[^a-z0-9]`). This removes display separators — spaces, hyphens, and any middle-dot (`·`) or other grouping character an implementation renders — along with any other punctuation or non-ASCII codepoint, **uniformly**. Stripping the whole complement of `[a-z0-9]`, rather than a fixed separator list, is what lets one participant enter a code grouped for readability and another enter it plain and still derive the same channel, and it means an implementation's own grouped display always round-trips regardless of which separator it chose. Non-ASCII look-alikes (e.g. Cyrillic `а`, U+0430) are not in `[a-z0-9]` and are removed, so the resulting code differs from the one intended. It is either too short and rejected (§10.1), or a valid code that matches no other participant's, leaving the participant waiting for a peer who never arrives. Implementations SHOULD warn when normalization removed any character other than whitespace and common separators.
3. Require the remaining length to be at least the generated-code minimum (10 characters), unless the implementation has been explicitly configured to accept shorter user-chosen codes (see "User-chosen codes" above).

Characters outside the generator's unambiguous set (`i l o 0 1`) are deliberately **not** rejected: they are valid content in user-chosen codes, and rejecting them would break memorable codes. (There is likewise no Crockford-style mapping of `o`→`0` or `l`→`1`: the two forms are distinct, accepted codes, so mapping would silently merge codes a user meant to keep apart. The SAS in §6.8 raises no such acceptance question because it is machine-rendered into the unambiguous set and never re-parsed from user input.)

The result is the `code` string used in §5.2. Normalization is part of the protocol, not a user-interface convenience: two participants who normalize differently derive different `K_code`, a different `channel_id`, and therefore sit in two different rendezvous points, each waiting for someone who never arrives — with no error visible to either side (neither sees a bad MAC, because neither sees the other at all). Test vectors are in §10.

### 5.2 Derived values

All participants derive, from the code alone:

```
salt_v1    = SHA-256("MSP-V1-KDF-SALT")                     // fixed, public
K_code     = PBKDF2-HMAC-SHA512(password = code,
                                 salt     = salt_v1,
                                 iters    = 300000,
                                 length   = 32 bytes)
channel_id = SHA-256("MSP-V1-CHANNEL" || K_code)             // 32 bytes
```

`channel_id` is the only code-derived value a transport ever sees. It names the rendezvous point. Because it is derived through the stretched `K_code` rather than the raw code, an eavesdropper on the transport cannot cheaply brute-force short codes from the channel identifier.

The `hello` message (§5.3) carries a `kdf` field naming the stretching function (`1` = PBKDF2-HMAC-SHA512, 300,000 iterations). SHA-512 rather than SHA-256 inside PBKDF2 raises the per-guess cost to a GPU attacker (64-bit lanes, larger state) at no meaningful cost to a legitimate client; it is also what the shipped implementation uses.

**KDF agility is not yet real, and this document does not claim it (corrected 2026-11-18).** The `kdf` byte records which stretching function a hello's sender used, but it cannot by itself let two implementations with different KDFs find each other: `channel_id` is derived through the KDF, so two participants stretching the same code with different functions arrive at two different rendezvous points and never see each other's hello to negotiate. Adding a memory-hard KDF (Argon2id) later therefore needs a bootstrap rule — for example, a rendezvous identifier derived by a fixed cheap function with the stretched key used only for the MAC and pairwise keys, or a code prefix that names the KDF — and that rule is not specified here. v0.1 pins one KDF (`kdf = 1`), and an implementation MUST treat any other value as unsupported (§5.5). The byte is reserved so the future rule has somewhere to live, not a promise that a switch will be free of a flag day (a coordinated cutover on which every implementation must change at once).

### 5.3 Join handshake

On joining, each participant generates a fresh X25519 keypair `(sk, pk)` — used for this session only, never persisted — together with a fresh 32-byte random **SAS nonce** `r` (§6.8), and announces a `hello`.

**Wire encoding.** The hello is a **fixed-width 109-byte string**, not CBOR. It is the one message a participant receives from a stranger before any authentication, so it is defined so that it can be authenticated without being parsed:

```
hello (109 bytes) =
    ASCII("MSP-HELLO")         // offset  0,  9 bytes, no terminator (the hello magic)
 || uint8(v)                   // offset  9,  1 byte   wire version (this document: 1)
 || uint16_be(caps)            // offset 10,  2 bytes  capability bitfield, big-endian (§5.5)
 || uint8(kdf)                 // offset 12,  1 byte   KDF identifier, 1 = PBKDF2-HMAC-SHA512-300k
 || pk                         // offset 13, 32 bytes  ephemeral X25519 public key, raw
 || cm                         // offset 45, 32 bytes  SAS commitment (below)
 || mac                        // offset 77, 32 bytes

cm        = SHA-256(ASCII("MSP-V1-SAS-COMMIT") || pk || r)
mac_input = hello[0..77)       // the first 77 bytes, exactly as sent
mac       = HMAC-SHA256(K_code, mac_input)
```

**SAS commitment (normative; adopted 2026-11-09, reveal moved 2026-11-18).** `r` is 32 bytes from a cryptographically secure random source, generated together with `(sk, pk)` and never derived from `sk`. `cm` commits to it: a receiver learns nothing about `r` from `cm`, and the sender cannot later open `cm` to a different `r`. The sender reveals `r` in a SAS_REVEAL message (§6.8) — the first encrypted message any participant sends, in setup and signing sessions alike — and only after it holds hellos from every expected participant; a receiver recomputes `cm` from the revealed `r` and the sender's `pk` and MUST ABORT (`commit_mismatch`, 10) on mismatch. The sender MUST retain its own `r` until it has computed the SAS and its user has confirmed it, because its own nonce is an input to its own SAS; it MUST zero `r` once the session reaches VERIFIED or ends. The nonces enter the SAS (§6.8). The purpose is to fix every participant's SAS input before any participant's nonce is known, so that a party on the relay path who holds the code cannot choose its own values after seeing the honest ones; §6.8 states the argument. Including `pk` in the commitment binds the nonce to the key; the MAC covering `cm` binds the commitment to a code holder. (draft.1 revealed the nonce inside KEY_CONTRIBUTION, together with the account key; that let a party admitted under a leaked code learn the key before the humans could catch it, and was withdrawn.)

The field widths are the value ranges: `v` and `kdf` are 0–255 and `caps` is 0–65535 by construction, so no out-of-range value can be expressed.

**Recognizing a hello.** On the WebSocket binding each hello occupies one complete binary WebSocket message (§7.1). A message is a hello if and only if it begins with the 9 ASCII bytes `MSP-HELLO`; every other message is an envelope (§6.1), whose deterministic-CBOR encoding always begins with a map header byte (0xA0–0xBF) and so can never collide with the magic. The magic deliberately carries **no version number** and is the same in every wire version — it is the one domain-separation string without a `V1` — so that a v1 participant can always recognize a later version's hello and respond per §5.5; the version is carried in `v`, which the MAC covers. A v1 hello is exactly 109 bytes; a message with the magic, `v = 1`, and any other length MUST be ignored silently.

**Processing order (normative).** A receiver MUST: (1) check the magic and length; (2) check `v` and `kdf` against what it supports (§5.5); (3) verify `mac` over `hello[0..77)` with a constant-time comparison; and only then (4) read `pk` and `cm`. No field is interpreted before step 3 except the magic, length, `v`, and `kdf`, which are fixed-offset single bytes.

The message type registry (§6.2) keeps type `0` for HELLO, but the hello carries no type field: the magic identifies it. Defining the hello this way means the MAC covers exactly the bytes on the wire, with one valid form and nothing to parse before authentication. Earlier drafts encoded the hello as a CBOR map and computed the MAC over a separate fixed-width layout, which required decoding attacker-supplied CBOR to find the MAC and left the value ranges unstated. A test vector (the full 109-byte hello, its 77-byte `mac_input`, the commitment, and the MAC) is in §10.

Receivers MUST verify `mac` before accepting `pk`. A hello with a bad MAC MUST be ignored silently (no error response — responding confirms the channel is live to a code-guesser). A hello whose `pk` equals the receiver's own `pk` MUST be ignored. For a given `pk`, the first hello accepted is the only one: a later hello carrying the same `pk` with a different `cm` MUST be ignored, and a later hello identical to the accepted one is a harmless repeat (a rejoin, §8.3, re-sends the identical hello; a relay may also replay it, §7.1).

**Participant-count rule (client-side; the only membership rule).** The relay's connection limit (§7.1) is a courtesy, not a control: the relay is the adversary (§4). Each participant MUST therefore enforce the expected participant count itself. In v0.1 the expected count is 2: the participant itself and one peer. The first valid hello (correct MAC) whose `pk` is not the participant's own is accepted into the empty peer slot; thereafter a valid hello from a public key that is neither the participant's own nor the accepted peer's MUST cause ABORT with reason `unexpected_participant` (8), whether it arrives before or after the SAS checkpoint and until the session is CLOSED. A correct MAC from an unexpected key means a further party holds the session code; silently ignoring it would hide exactly the event the user most needs to see. The rule is stated in terms a client can observe — public keys in authenticated hellos — and in no other: a client sees only its own connection to the relay and has no authenticated way to tell which connection a hello came from. (draft.1 also had a "key-change rule" that ignored a different `pk` arriving "from the same transport peer"; it is withdrawn, because no client can make that distinction. Anyone holding the code can end a session by sending a hello; the design accepts that the disruption is visible rather than silent.) A future group profile that admits more than two participants MUST define how each participant learns the expected count before it sends its SAS_REVEAL; until then no larger count exists (Appendix B item 4).

### 5.4 Pairwise session keys

For each pair of participants (A, B), both derive:

```
shared  = X25519(sk_A, pk_B)                 // = X25519(sk_B, pk_A)
K_AB    = HKDF-SHA256(
            ikm  = shared,
            salt = K_code,
            info = "MSP-V1-PAIR" || channel_id || sort(pk_A, pk_B),
            length = 32 bytes)
```

**All-zero check (normative).** If `shared` is 32 zero bytes, the participant MUST ABORT the session (reason `validation_failure`, 4) and MUST NOT derive `K_AB`. X25519 returns all zeros when the peer's public key is one of the small set of low-order points, whatever the private key; the "shared secret" is then known to everyone (RFC 7748 §6.1). Accepting such a key requires a valid hello, and `K_code` in the HKDF salt would still protect `K_AB`, so this check is defense in depth — but it is cheap, standard, and expected. The comparison SHOULD be constant-time.

`sort()` is byte-wise lexicographic ordering of the two public keys, so both sides compute identical `info`. Binding `K_code` into the salt means a man-in-the-middle who intercepted the transport but does not know the code derives nothing useful even if it substituted hellos. Binding both public keys and the `channel_id` into `info` means a key transplanted into a different session or pair is useless.

Immediately after every needed `K_AB` is derived, the participant MUST zero its X25519 private key `sk`. This deletion is the forward-secrecy event: after it, nothing on the device can reconstruct session keys from recorded traffic.

### 5.5 Version and capability negotiation

`v` is the wire version (this document: `1`). `caps` is a bitfield of optional features:

| Bit | Capability |
|---|---|
| 0 | ChaCha20-Poly1305 suite supported |
| 1 | Async prekey profile (Appendix A) |
| 2 | In-session ratchet (Appendix A.4) |
| 3–15 | Reserved; MUST be zero, MUST be ignored on receipt |

Participants operate at the **lowest common version** among session members and use only capabilities present in **all** relevant peers' `caps`. **v0.1 pins one suite:** `v = 1`, `kdf = 1`, AES-256-GCM; a hello with any other `v` or `kdf` is incompatible. A participant that receives an incompatible hello MUST NOT derive keys from it and SHOULD tell its user that the peer runs an incompatible version; it cannot send a wire `ERROR`, because ERROR travels inside an envelope under a pairwise key that does not exist (`version_mismatch` in §6.9 is kept for a peer that passes the hello and is found incompatible later, for example by a capability it uses without advertising). The hello is the only place where selection can happen, and `channel_id` already depends on the KDF (§5.2), so a future suite needs an explicit discovery rule that works before the parties depend on different rendezvous identifiers. Defining the version byte in v0.1 — before any public release — is deliberate: version negotiation retrofitted after fragmentation never un-fragments.

### 5.6 Session code distribution (out of band)

The protocol does not carry the code; humans do. Normative guidance:

- The code SHOULD be shared over an end-to-end encrypted channel or in person, and SHOULD NOT be shared over the same transport the session will use.
- The code is single-use. Implementations MUST NOT allow a code to be reused for a second session.
- Because code interception before join enables a full man-in-the-middle, the SAS check in §6.8 is mandatory, not advisory — it is the detector for exactly this attack.

---

## 6. Layer 2 — Envelopes and message vocabulary

### 6.1 Envelope structure

Every Layer-2 message is one deterministic-CBOR map:

```
envelope = {
  1: v,        // uint   wire version
  2: t,        // uint   message type (registry §6.2)
  3: sid,      // bytes(8)   first 8 bytes of channel_id
  4: from,     // bytes(8)   sender key id = first 8 bytes of SHA-256(pk_sender)
  5: to,       // bytes(8)   recipient key id, same construction
  6: ctr,      // uint   per-(sender→recipient) monotonic counter, starts at 1
  7: mid,      // bytes(16)  deterministic message identity (see below)
  8: re,       // bytes(16)  OPTIONAL: mid this message responds to
  9: body      // bytes  AEAD ciphertext of the type-specific payload
}
```

Integer keys keep envelopes small for QR transport. Fields 1–8 are the **header**; the header is authenticated but not encrypted (§6.4). `mid`/`re` provide request/response pairing: a responder copies the request's `mid` into `re`. **`re` is present on exactly three message types** — PSBT_RESPONSE and PSBT_COMBINE (naming the PSBT_REQUEST they answer) and an ERROR that concerns a specific received message (naming it) — and MUST be absent from every other envelope; an envelope that carries `re` where this rule forbids it, or omits it where the rule requires it, MUST be dropped as malformed (§6.4). This is the same pairing discipline as Blockchain Commons' ARID mechanism in BCR-2024-004 (§6.10) and is what makes duplicate and replayed responses detectable at the application layer.

**Message identity (normative; adopted 2026-11-05, replacing a random `mid`).** `mid` is not random. It is derived from what the message *is* in the ceremony, so that a message sent twice — after a reconnect, or by a store-and-forward transport that delivers at least once — has the same identity both times:

```
mid = SHA-256("MSP-V1-MID" || channel_id || pk_sender || uint8(t) || uint32be(round))[0:16]
```

`round` is a per-(sender, type) sequence number starting at 0. For message types of which a sender legitimately sends at most one per session — SAS_REVEAL, SESSION_INIT, KEY_CONTRIBUTION, DESCRIPTOR_CONFIRM, SESSION_FINALIZE — `round` is always 0. For PSBT_REQUEST and PSBT_COMBINE, `round` is the index of the request among that sender's requests in the session; because v0.1 permits one request per session (§6.7), `round` is 0 for these too in v0.1, and the rule is kept so that a later version can allow several requests without changing the identity construction. A PSBT_RESPONSE uses the `round` of the request it answers (its `re` already names that request). For the control messages ERROR and ABORT, `round` is the envelope's `ctr`, so control messages are never deduplicated. `round` is not carried on the wire; both sides compute it from the ceremony state, and §6.5 already guarantees that `ctr` orders a sender's messages.

A receiver that holds a message with a given `mid` and receives another with the same `mid`: if the decrypted body is byte-identical, the second is a **resend** and MUST be ignored without changing state; if the body differs, the sender has issued two conflicting messages under one identity, and the receiver MUST ABORT (`identity_conflict`, §6.9). This is the first of the three transport invariants in Turon's analysis (§4.4): it is harmless on a live two-party relay and is a precondition for the asynchronous profile (A.1, A.4) and for any future threshold-signature rounds, where processing a duplicated round-one message twice under a fresh identity is a nonce-reuse hazard. Replay protection (§6.5) still operates on `ctr` and is unchanged: an exact duplicate envelope is discarded by `ctr` before decryption; message identity catches the case §6.5 cannot, a *re-encrypted* resend under a new `ctr`.

The plaintext of `body` is itself a deterministic-CBOR map whose schema depends on `t`. Where a body schema lists key `0: note` — SESSION_INIT, KEY_CONTRIBUTION, and PSBT_REQUEST do — it MAY carry a short human-readable string explaining the request to the person at the other end, displayed before any action is taken. A body MUST contain exactly the keys its schema lists (optional keys may be absent); a receiver MUST reject a body carrying any other key (§6.3). In particular SAS_REVEAL carries no `note` and nothing but the nonce (§6.8): before the SAS is confirmed, no human-readable text crosses in either direction. *(Narrowed 2026-11-18; draft.1 allowed `note` on every body.)* This field is adopted directly from the Request/Response pattern: machine-readable messages with a built-in human explanation measurably reduce ceremony abandonment.

### 6.2 Message type registry

| `t` | Name | Direction | Phase |
|---|---|---|---|
| 0 | HELLO | any | Layer 1 (unencrypted, MAC'd) |
| 1 | SESSION_INIT | initiator → all | setup (opens the ceremony, §6.8) |
| 2 | KEY_CONTRIBUTION | each → all | setup |
| 3 | DESCRIPTOR_CONFIRM | each → all | setup |
| 4 | *(reserved — was DESCRIPTOR_ACK in draft.1; withdrawn)* | | |
| 5 | SESSION_FINALIZE | initiator → all (announcement only, §6.6) | setup |
| 6 | PSBT_REQUEST | requester → signer(s) | signing (opens the ceremony, §6.8) |
| 7 | PSBT_RESPONSE | signer → requester | signing |
| 8 | PSBT_COMBINE | requester → all | signing |
| 9 | SAS_REVEAL | each → all | both kinds; the first encrypted message every participant sends (§6.8) |
| 17 | ERROR | any | control |
| 18 | ABORT | any | control |
| 19–63 | Reserved (core) | | |
| 64–127 | Reserved: multiple-initiator extension (A.3) | | |
| 128–255 | Private/experimental use | | |

Unknown types in the reserved core range MUST cause `ERROR` (`unsupported_type`); types in the private range MUST be ignored if unrecognized.

HELLO (type 0) is the one exception to the envelope format: it is a Layer-1, unencrypted, MAC'd, fixed-width 109-byte message defined in §5.3, identified by its 9-byte magic `MSP-HELLO` rather than by a type field. The envelope structure (§6.1) and encryption (§6.4) do **not** apply to it.

### 6.3 Encoding

All envelopes and bodies use RFC 8949 §4.2 Core Deterministic Encoding: shortest-form integers, definite lengths, sorted map keys. **Decoding is strict (normative):** a receiver MUST reject an envelope or body that contains a duplicate map key, a non-shortest integer or length encoding, an indefinite-length item, unsorted keys, or any bytes after the end of the top-level item, and MUST reject a body whose fields do not match the schema for its type (missing required field, wrong CBOR type, unknown required-range key). A malformed envelope is dropped silently before decryption (§6.4); a malformed body, which can only be seen after authenticated decryption, is answered with ERROR (`decode_failure`) and does not advance the ceremony. Rationale is threefold: (a) compactness — QR and Nostr transports are size-constrained and JSON is 2–4× larger; (b) signability — deterministic encoding means the same logical message always produces the same bytes, so MACs and signatures over encoded bytes are well-defined; (c) it is the encoding of the wider bitcoin interop ecosystem (UR, Gordian Envelope, BSMS tooling), which lowers the cost of the compatibility profile in §6.10.

### 6.4 Encryption

`body` plaintext is encrypted with AES-256-GCM under `K_AB` (sender→recipient pair):

```
dir   = 0x00 if sender's pk is byte-wise lexicographically smaller than
        recipient's pk, else 0x01
nonce (12 bytes) = dir || 0x00 0x00 0x00 || 8-byte big-endian ctr
AAD   = deterministic-CBOR encoding of the header map containing exactly
        those of fields 1..8 that are present
```

The AAD is the CBOR map of the **present** header fields only. Field 8 (`re`) is present only where §6.1 requires it: when it is absent it is **omitted from the encoded map entirely** — it is not encoded as `null` and not present with a zero value. Per §6.3 the map keys are sorted and lengths definite, so both sender and recipient encode byte-identical AAD from the same set of present fields; any disagreement (one side including a `null` field 8, the other omitting it) makes every decryption fail.

**Field 9 layout (normative).** `body` is the AES-GCM ciphertext followed immediately by the full 16-byte (128-bit) authentication tag, as WebCrypto and most libraries emit it; the tag is never truncated and never carried in a separate field. A `body` shorter than 16 bytes is malformed.

**Receiver steps (normative), in order.** For each incoming binary message that is not a hello: (1) decode the envelope under §6.3; drop silently if malformed, if `v`, `sid`, or `to` do not match this session and participant, if `from` is not an accepted peer, or if `re` is present or absent against the §6.1 rule; (2) apply the §6.5 counter check; drop silently on failure; (3) reconstruct the nonce and AAD and decrypt; drop silently on authentication failure; (4) check that `ctr` is exactly the stored value plus one, else end the session as *incomplete* (§6.5, counter gap); only now advance the stored counter for that sender; (5) compute `mid` from `(t, round)` per §6.1 and compare it with the header's `mid`; mismatch is ERROR (`validation_failure`) and the message is not acted on; (6) apply the message-identity rule (§6.1) — resend ignored, conflict aborts; (7) decode the body under §6.3 and validate it against its type's schema and the current state (§8.1); then act. Nothing an unauthenticated sender can do advances a counter, changes state, or produces a wire response; nothing a malformed-but-authenticated body can do changes ceremony state beyond an ERROR.

Deterministic nonces are safe here because `(K_AB, dir, ctr)` never repeats: `K_AB` is unique per pair per session, the direction byte unambiguously separates the two directions that share `K_AB`, and `ctr` strictly increases per direction. (A truncated sender-id in the nonce was considered and rejected: a truncation collision between the two key ids of a pair would permit nonce reuse under one key, which is catastrophic for GCM. The direction byte cannot collide by construction.) Binding the full header as AAD (associated authenticated data — bytes the cipher authenticates without encrypting) means any tampering with type, addressing, counter, or pairing IDs makes decryption fail.

AES-256-GCM is the **sole** v0.1 suite (§5.5): it is the one AEAD available natively in every browser WebCrypto implementation, and the reference implementation is browser-first. Capability bit 0 (§5.5) is reserved to advertise ChaCha20-Poly1305 in a future version; in v0.1 a participant MUST ignore it and MUST NOT use any suite but AES-256-GCM, because no selection rule exists (an earlier sentence here said the suite "MAY be negotiated"; it was removed 2026-11-18, since §5.5 pins one suite and nothing defined the negotiation).

### 6.5 Replay protection

Each receiver tracks, per sender, the highest `ctr` successfully decrypted. An envelope with `ctr` ≤ that value MUST be discarded **before** decryption is attempted; the stored counter MUST be advanced only **after** authenticated decryption succeeds. (Advancing on receipt rather than on success lets an attacker burn counter slots with garbage and desynchronize honest peers — this exact bug existed and was fixed in the Keylay app.)

**Counters are consecutive (normative; added 2026-11-18).** A sender's `ctr` toward a given recipient starts at 1 and increases by exactly 1 per envelope sent, resends included (a resend is a new envelope with the same `mid`, §6.1). After an envelope authenticates, the receiver MUST check that its `ctr` equals the stored value plus one. If it is greater, a message from that sender was lost on this ordered live binding, and the receiver MUST end the session with the local outcome *incomplete* (§8.4) and MAY send ABORT (`counter_gap`, 12); it MUST NOT act on the message that revealed the gap. A stale (`≤`) or unauthenticated counter keeps the silent-drop behavior above and is not a gap. The consecutive rule is what gives §6.7 and §8.4 their "a gap means a lost message" semantics; without it the receiver would accept any higher counter and never notice the loss.

### 6.6 Setup phase

Setup is **symmetric**: every participant sends its key contribution to every other participant, every participant assembles the descriptor itself by the deterministic function in §6.6a, and every participant confirms to all others the hash of what it assembled. No participant ever sends a descriptor to another. The initiator's only distinguished act is proposing the terms.

**Order of a setup session (normative; revised 2026-11-18).** Nothing about the wallet moves until the humans have authenticated the session.

1. Hellos (§5.3). Each participant sends its hello and holds the other's.
2. SAS_REVEAL (§6.8) from each participant, as soon as it holds the other's hello. Membership is frozen at this point.
3. Each participant verifies the peer's nonce against its commitment, computes the SAS, displays it with the participant count, and its user compares it with the other user over the authenticated channel and confirms or aborts. The session is VERIFIED for a participant when its own user has confirmed.
4. SESSION_INIT from the initiator, sent only after the initiator's user has confirmed the SAS; processed by the peer only after the peer's user has confirmed, and held until then (§6.8, hold rule). This message opens the ceremony and names it a setup (§6.8, "Opening the ceremony"). The terms are frozen on acceptance.
5. Consent to the terms by each user; then KEY_CONTRIBUTION from each participant. The initiator's contribution may arrive while the peer is still on the SAS screen; the peer holds it (§6.8).
6. Assembly (§6.6a) and DESCRIPTOR_CONFIRM from each participant.
7. The pre-funding checkpoint (below): own key and first address verified on each signing device and the address compared between the humans.
8. SESSION_FINALIZE from the initiator, an announcement.

**SESSION_INIT** body (initiator → all):

```
{ 0: note?, 1: m, 2: n, 3: script_type, 4: derivation_template, 5: network }
```

`n` is the number of keys in the wallet, `m` the number of signatures required. In v0.1 `n` MUST be 2 — one key per participant, two participants (§1.3) — and `m` MUST be 1 or 2; any other value MUST ABORT (`validation_failure`). A future group profile will admit larger `n` together with the membership mechanism §5.3 requires; the general rule it will enforce is `1 ≤ m ≤ n` with `n` within the script type's limit (20 keys under `wsh`, BIP-383). `script_type` from a registry: `0` = P2WSH, `2` = P2SH-P2WSH. Value `1` is **reserved** for P2TR and MUST be rejected in v0.1 (ABORT `validation_failure`): BSMS has no settled convention for `sortedmulti_a` templates, and an unspecified option would let two implementations build two wallets from one ceremony. Taproot multisig is deferred to a later version (decided 2026-11-05; Appendix B item 5a). `derivation_template` is restricted in v0.1 to the BIP-48 forms and MUST match exactly `m/48'/C'/A'/S'` where `C` is `0` for mainnet and `1` for testnet or signet and MUST agree with `network`; `A` is the account index, a decimal integer from `0` to `2147483647` without leading zeros; and `S` is `2` for P2WSH and `1` for P2SH-P2WSH and MUST agree with `script_type`. Hardened markers are the apostrophe only (`h` is not accepted here, unlike in key expressions, because this string is never re-parsed from a device export). Any other value MUST ABORT (`validation_failure`). This is an enumeration of the paths today's multisig wallets import, not a grammar; a grammar replaces it when a second implementer needs a path outside these forms (decided 2026-11-05; Appendix B item 5). `network`: `0` mainnet, `1` testnet, `2` signet (added 2026-11-18). Testnet and signet share derivation (`C = 1`) and key encoding (`tpub`), and so produce identical canonical templates and identical `descriptor_hash` values for the same keys; the distinct value exists so that the consent display and the signing-request binding (§6.7) can tell them apart.

**Terms freeze (normative).** A participant accepts exactly one SESSION_INIT per session, and only after its own user has confirmed the SAS (§6.8). The accepted terms are frozen: a second SESSION_INIT with a different body is an `identity_conflict` ABORT (§6.1), an identical one is a resend and is ignored, and a SESSION_INIT from a participant other than the one that opened the ceremony is a `role_conflict` ABORT (§6.8). Changing the terms requires ABORT and a new session. Every participant MUST hold the accepted SESSION_INIT before accepting any KEY_CONTRIBUTION, and MUST NOT send its own KEY_CONTRIBUTION until it has accepted SESSION_INIT and its user has consented to the terms.

**Consent to terms (normative).** Before sending its own KEY_CONTRIBUTION, an implementation MUST display the terms to its user in human-readable form — for example `2-of-2 · P2WSH · mainnet · m/48'/0'/0'/2'` — and MUST NOT send the contribution until the user explicitly accepts them; declining MUST ABORT. For a threshold of 1 the display MUST say, in words, that either key alone can spend. Sending a KEY_CONTRIBUTION is the participant's consent to the terms. This step is what makes the terms a matter of each participant's consent rather than of trust in the initiator. The SAS does not do it: it proves who is in the session, not what the terms are — an initiator who proposes 1-of-2 in place of 2-of-2 produces matching strings for everyone.

**KEY_CONTRIBUTION** body (each → all; one envelope per recipient, identical body):

```
{ 0: note?, 1: key: text, 2: bridged: bool }   // fields 3 and 4 reserved
```

`key` is the contributed key expression `[fingerprint/path]xpub` — the master-key fingerprint (8 hex characters), the derivation path from the master key, and the extended public key — normalized per §6.6a step 1. This is what signing devices and wallets actually export (as text, as JSON with fingerprint/xpub/path fields, or as UR `crypto-account`/`crypto-hdkey`); converting those export formats into a key expression is the contributing implementation's job, not the protocol's. Testing in October 2026 found that common coordinator wallets do not export BIP-129 Round-1 records at all, so the protocol does not require one.

Field 3 is reserved. Draft revisions of 2026-10-08 briefly made a signed BSMS Round-1 record an optional field 3; it was removed because "optional to send" is "mandatory to verify": every implementation would have needed a BSMS parser and a Bitcoin signed-message verifier, in two incompatible signature formats, for a benefit — proof that the contributor holds the private key — that a test spend provides better (§6.6a). A future version MAY assign field 3 to a proof-of-possession signature, most plausibly alongside the asynchronous `wallet_sig` (A.6). Field 4 is reserved: draft.1 carried the SAS nonce here, and it moved to SAS_REVEAL on 2026-11-18 (§5.3). `bridged: true` marks a key injected on behalf of an air-gapped device (§7.3); the field is defined on this message only.

A participant MUST send its KEY_CONTRIBUTION to every other participant, and MUST NOT proceed to assembly until it holds a valid contribution from every other participant (`n − 1` of them) plus its own. **Validity** of a received contribution: `key` parses as a key expression; after §6.6a step 1 normalization its extended key carries the standard version bytes for `network` (`xpub` mainnet, `tpub` testnet or signet); its origin path matches `derivation_template`; its fingerprint is 8 lowercase hex characters; and its xpub's encoded depth equals the number of path levels. An invalid record → ERROR (`validation_failure`) to the sender and, if not corrected before timeout, ABORT. **Duplicate key material (normative; added 2026-11-18).** Before assembly, a participant MUST compare the 33-byte compressed public key decoded from each contribution's extended key — the key itself, not the Base58 string, not the fingerprint, and not the parent fingerprint or other serialization metadata, any of which can differ while the key is the same — against every other contribution's, including its own; two equal keys MUST ABORT (`validation_failure`). Without this check two contributions can describe one signing key under two origin labels, and both participants would then confirm a "2-of-2" wallet that one key spends from. Distinct keys still do not prove distinct custody (§4.3).

There is no slot assignment and no slot field. Key order is the byte-wise lexicographic order of the key expressions (§6.6a). The draft.1 first-come-first-served rule, and the `slot_conflict` error, are withdrawn.

### 6.6a Descriptor assembly (normative)

Every participant computes the following from the SESSION_INIT body and the `n` valid key contributions (including its own). Two conforming implementations MUST produce byte-identical output from identical inputs; §10.4 is the vector.

1. **Key expression.** For each contribution, take `key` — `[` fingerprint `/` path `]` xpub — and normalize: fingerprint lowercase; hardened markers as apostrophe `'` (an `h` on input is converted); no whitespace; and the extended key re-encoded with the **standard version bytes** — `xpub` (`0488b21e`) for mainnet, `tpub` (`043587cf`) for testnet or signet. Keys exported with SLIP-132 prefixes (`ypub`, `zpub`, `Ypub`, `Zpub`, `upub`, `vpub`, `Upub`, `Vpub`) MUST be converted by Base58Check-decoding, verifying the checksum, replacing the 4 version bytes, and re-encoding with a new checksum; the key material is unchanged. This is not a text substitution: changing the version bytes changes nearly every character of the encoded string. Without this rule two implementations would write the same key two ways and compute different `descriptor_hash` values. Append `/**` (the BSMS template wildcard). Example: `[397a4a50/48'/0'/0'/2']xpub6Es…S7/**`.
2. **Order.** Sort the `n` key expressions in ascending byte-wise (ASCII) order of the full expression string. Because every expression begins with `[` and a fingerprint, this orders by fingerprint. The order affects only the descriptor *string* — `sortedmulti` makes addresses independent of it — but the string must be identical everywhere for `descriptor_hash` to agree.
3. **Template.** By `script_type`:
   - `0` P2WSH: `wsh(sortedmulti(m,K1,K2,…,Kn))`
   - `2` P2SH-P2WSH: `sh(wsh(sortedmulti(m,K1,…,Kn)))`
   - `1` P2TR: **reserved; not part of v0.1.** BSMS predates taproot and there is no settled convention for `sortedmulti_a` templates with `/**`; an implementation receiving `script_type = 1` MUST ABORT (`validation_failure`). The value is reserved so that a later version can add it without renumbering (§6.6; Appendix B item 5a, closed 2026-11-05).
   No spaces anywhere. `m` in decimal, no leading zeros.
4. **Checksum.** Append `#` and the 8-character descriptor checksum (BIP-380) computed over the template string of step 3. The result is the **canonical descriptor template**.
5. **Hash.** `descriptor_hash = SHA-256(canonical descriptor template as ASCII bytes)`, 32 bytes. This is the value DESCRIPTOR_CONFIRM, PSBT_REQUEST (§6.7), and SESSION_FINALIZE carry. The template, and so the hash, does not encode the network beyond the key version bytes; testnet and signet wallets with the same keys hash identically, which is why PSBT_REQUEST carries `network` alongside the hash (§6.7).
6. **First address.** Expand `/**` to `/0/0` in every key expression, derive, and encode the address for `network`. (BIP-129: "the first address from the first path restriction.")
7. **BSMS Round-2 file** (for import into wallet software): four lines separated by LF (0x0A), with a trailing LF: `BSMS 1.0`; the canonical descriptor template; `/0/*,/1/*`; the first address. *(VERIFY the trailing-LF convention against a Sparrow-exported Round-2 file before freeze; the file is for import and is not hashed, so this does not affect `descriptor_hash`.)*

Any participant whose own key expression does not appear in the sorted list it assembled has a bug, not an attack, and MUST ABORT.

**Canonical import of an existing wallet (normative; added 2026-11-18).** A signing session (§6.7) may concern a wallet created outside MSP. To compute its `descriptor_hash`, the implementation MUST reconstruct the canonical template above from the wallet as it holds it: a wallet stored as one descriptor with the `/**` or `<0;1>/*` multipath convention, or as separate receive and change descriptors, MUST reconstruct to exactly one supported template with exactly the two branches `/0/*` and `/1/*`, with the same `m`, `script_type`, and sorted normalized key set in both branches. A wallet that does not reconstruct to one such template — a third branch, differing key sets, an unsupported script type, a key outside the BIP-48 forms — has no `descriptor_hash` under this document, and the implementation MUST refuse to use it in a signing session rather than guess.

**Verify on the signing device (normative).** The online implementation that assembles the descriptor is software the participant may not be able to trust — a browser page served by a third party, or a compromised computer. If it is malicious it can substitute the participant's own xpub when bridging it, and every software-level check, including DESCRIPTOR_CONFIRM, will then pass, because every participant assembles the same substituted wallet. The final defense is the signing device's own screen. Where the participant's signing device can register a multisig wallet and display it — showing whether its own key is present and the wallet's first receive address, as most multisig-capable hardware signers do on registration — the participant MUST register the wallet on the device before funding and MUST confirm on the device that its own key is present, and, where the device displays one, MUST use the first address **as shown by the signing device** in the comparison with other participants (the pre-funding checkpoint in §6.6; A.6), rather than the address shown by the online implementation (raised from SHOULD to MUST 2026-11-05: an address read from the online software is exactly the value a compromised bridge controls). The own-key check catches a participant's own software substituting that participant's key; the device-shown address comparison additionally lets the others catch it if that participant skipped the check. Where the signing device cannot register a multisig wallet, neither check is available, and that participant's protection against their own software rests on the software alone; implementations MUST tell the user so and MUST label the outcome as a software-only check (§6.6, "Pre-funding checkpoint").

**Test spend (recommended).** The protocol does not prove that each contributed key can sign; a participant could contribute a key it does not control, by mistake or otherwise, which leaves the wallet with fewer usable keys than its policy implies. Before funding the wallet with a meaningful amount, participants SHOULD fund it with a small amount and spend it with every cosigner signing (all `n`, not only `m`). The success criterion is that a valid partial signature from every distinct key in the descriptor has been verified — on the combined PSBT before finalization, since a finalized `m`-of-`n` witness carries only `m` signatures and proves nothing about the rest — or that the remaining keys have each been exercised in a further spend. This proves every key can sign, exercises every participant's signing setup end to end, and is the check BSMS-era practice already recommends.

**DESCRIPTOR_CONFIRM** body (each → all):

```
{ 1: descriptor_hash: bytes(32), 2: first_address: text, 3: wallet_sig?: bytes }
```

Sent immediately after assembly. A participant MUST NOT import or fund the wallet until it holds a DESCRIPTOR_CONFIRM from every other participant whose `descriptor_hash` and `first_address` both equal its own. Any mismatch is a mandatory ABORT (`descriptor_mismatch`); the sender of the mismatching CONFIRM is identifiable and SHOULD be named in the ABORT `detail`. This round is what catches a participant that sent different records to different peers, and two implementations whose §6.6a differs by a byte. It is a check between the two pieces of software; the check between the two humans and their devices is the checkpoint below. `wallet_sig` is an OPTIONAL signature over `descriptor_hash` by the key at the first derived path — a portable, offline-verifiable record that this participant verified this wallet. It is optional in synchronous sessions because the pre-funding checkpoint supplies the human binding; it is REQUIRED in the asynchronous profile (A.6).

**Pre-funding checkpoint (normative; added 2026-11-18).** After its DESCRIPTOR_CONFIRMs match, and before it reports the wallet as ready to fund, each participant's implementation MUST walk its user through the following, and MUST record the outcome:

1. Register the assembled wallet on the participant's signing device, provisionally if the device requires registration before it will display anything (§6.6a, "Verify on the signing device"), and confirm on the device's screen that the device's own key is present.
2. Read the wallet's **full first receive address** from the device's screen — not from the online implementation — and compare it with the other participant's device-shown address over the authenticated channel of §6.8 (the same call or verified thread the SAS was compared on, or a later one; the address is a stable value and the comparison need not be simultaneous). Participants SHOULD paste or read the full address, not a prefix or suffix: a short fragment can be searched for by an attacker who controls one key, a full address cannot.
3. Record the result as one of **device-verified** (both steps done on a device that displays the address), **software-only** (this participant's device cannot register the wallet or display the address, so the address compared came from the online implementation and protects against the other participant's software but not against this participant's own), or **not done**. A mismatch at step 2 is a mandatory ABORT (`descriptor_mismatch`) and the recovery guidance of A.6 applies.

"Ready to fund" MUST depend on this checkpoint: an implementation MUST NOT present the wallet as ready, and MUST NOT describe it as verified, until the user has recorded step 2 as done with a matching address, and MUST show the software-only label where that is the outcome. This is the second and last human step of a setup; the SAS (§6.8) establishes who is in the session, this establishes which wallet they built. It is the step BSMS itself asks for, placed where a live session needs it: §6.6a's device rule said what to verify, and until this revision no part of the live procedure said when.

**SESSION_FINALIZE** body (initiator → all):

```
{ 1: descriptor_hash: bytes(32), 2: sas_confirmed: bool }
```

FINALIZE is an announcement, not an authority. A participant's warrant to import the wallet is its own complete set of matching DESCRIPTOR_CONFIRMs plus its own completed pre-funding checkpoint; FINALIZE with a `descriptor_hash` different from the participant's own is an ABORT condition, and FINALIZE is never sufficient on its own. The initiator MUST NOT send FINALIZE until it has itself completed those checks. `sas_confirmed` is retained from draft.1; under this revision's order it is necessarily `true` by the time any ceremony message exists, and a FINALIZE carrying `false` is malformed.

### 6.7 Signing phase

**Order of a signing session (normative; revised 2026-11-18).** Hellos (§5.3); SAS_REVEAL from each participant (§6.8); SAS compared and confirmed by both users; then PSBT_REQUEST from the requester, which opens the ceremony and names it a signing session (§6.8, "Opening the ceremony"); PSBT_RESPONSE from the signer; PSBT_COMBINE from the requester. Nothing about the transaction or the wallet moves before the SAS is confirmed.

**One request, one requester (normative; v0.1).** A session carries one PSBT_REQUEST, sent by the initiator, which is thereby the requester; a second PSBT_REQUEST with a different body is an `identity_conflict` ABORT (§6.1), an identical one is a resend, and a PSBT_REQUEST from the other participant is a `role_conflict` ABORT (§6.8). A different payment is a new session with a new code. This keeps `round` at 0 (§6.1) and removes the need for a retransmission protocol in v0.1: on this ordered live binding a gap in a sender's authenticated counter (§6.5) is a lost message, and the participant that observes it MUST end the session with a local outcome of *incomplete* rather than ask for a resend. A requester whose session times out without a PSBT_RESPONSE has an *incomplete* exchange and an *unknown* remote outcome — it does not know whether the signer signed — and a signer whose session times out after handing over its response has an *incomplete* exchange and MUST keep displaying "signature may have been sent" (§4.2, §8.4). Neither is a *failed* outcome: no counter gap is produced by a final message that never arrived, so nothing tells either side what the other holds.

**PSBT_REQUEST** body (requester → signer): `{ 0: note?, 1: psbt: bytes, 2: descriptor_hash: bytes(32), 3: network: uint }`. `descriptor_hash` is the canonical hash (§6.6a) of the wallet the requester's user selected for this spend, and `network` its chain (`0`, `1`, `2` as in §6.6); both are required (field 3 added 2026-11-18, because the hash alone does not distinguish testnet from signet). The PSBT MUST be a BIP-174 PSBT whose inputs carry the witness UTXO (`PSBT_IN_WITNESS_UTXO`) and BIP-32 derivation fields for the wallet's keys, and whose wallet-owned outputs carry `PSBT_OUT_BIP32_DERIVATION`, so that the signer can perform the checks below without any other source of information.

**Mandatory signer validation (normative).** Before releasing a signature, a signer MUST verify:

- (a) `descriptor_hash` equals the canonical hash (§6.6a) of a wallet the signer holds — one finalized in an MSP setup, or one imported by other means under the canonical-import rule of §6.6a — and `network` equals that wallet's chain. Because every signer makes this check against the hash the requester sent, a session can sign only for a wallet that the requester and the signer hold in common; a wallet that one of them does not hold cannot be signed for in that session. *(Reworded 2026-11-18.)*
- (b) every input the PSBT asks it to sign spends from an address derivable from that descriptor at the stated path on branch `/0/*` or `/1/*`, and the input's witness UTXO script matches that address;
- (c) every output the PSBT marks as belonging to the wallet (an output carrying `PSBT_OUT_BIP32_DERIVATION` for the wallet's keys) derives from that descriptor at the stated path on an allowed branch, and every output that does not is presented to the user as an external payment at full prominence;
- (d) the signature-hash type requested for every input it will sign is `SIGHASH_ALL` (0x01) with no modifier; an absent `PSBT_IN_SIGHASH_TYPE` means `SIGHASH_ALL`, and a PSBT that requests any other type MUST be refused. `SIGHASH_ALL` is the one type under which a signature commits to every input and every output, so that what the user approved is what the signature authorizes; the others let a counterparty change outputs after signing. Other signing policies are out of scope for v0.1 and MUST NOT be accepted by a conforming signer. *(Added 2026-11-18.)*
- (e) the amount of **every input of the transaction** — not only the inputs this signer signs — is **verified**, not merely read: from a full previous transaction (`PSBT_IN_NON_WITNESS_UTXO`) whose transaction id equals the input's previous-output id, or, for a software signer with its own chain access, from a trusted UTXO lookup. A `PSBT_IN_WITNESS_UTXO` field alone is a *claimed* amount: nothing in the PSBT authenticates it, and a signer's own `SIGHASH_ALL` signature commits only to the amount of the input it signs (BIP-143), so a false amount on another party's input leaves the signature valid and the displayed fee wrong. The signer's own inputs are not exempt, because a false amount on an own input yields a signature that is invalid *for that input*, and an attacker who obtains two such sessions with different false amounts can combine the inputs that were each signed correctly into a valid transaction whose real fee is far larger than either session displayed (the 2020 attack on single-signature hardware wallets). The fee is then the sum of verified inputs minus the sum of outputs. A PSBT in which any input's amount cannot be verified has no verifiable fee and MUST be refused; an implementation MUST NOT display an unverifiable fee as the fee. The cost is PSBT size on the QR binding, since previous transactions can be large; Appendix B item 8 must budget for it. *(Added 2026-11-18; corrected twice the same day.)*

A signer MUST refuse to sign otherwise. Check (b) closes the substitute-wallet attack: a valid session channel is not evidence that a PSBT belongs to your wallet; only the descriptor binding is. Check (c) closes the change-address attack, in which a PSBT that does spend from the wallet sends the change to an attacker's address while the user approves what looks like a small payment; it is the attack that drains multisig wallets in practice, and it is why hardware signers require the multisig wallet to be registered before they will sign for it. Where the signer is a hardware device, checks (b)–(e) are the device's, and the bridging implementation (§7.3) MUST pass the PSBT through with its input and output derivation fields, witness UTXOs, and sighash fields intact: an implementation that strips them blinds the device. Because every signer assembled or canonically imported the descriptor itself (§6.6a), it holds what it needs for these checks without having received the descriptor from anyone. *(Check (c) added 2026-11-08.)*

**Mandatory approval (normative; added 2026-11-18).** Passing the checks establishes that the PSBT is a well-formed spend from the right wallet; it does not establish that the user wants it. Before a signature is released, the signer MUST display to its user, and the user MUST explicitly approve: every external output's destination address (in full) and amount; the total amount leaving the wallet; the fee; and the `note`, if any. Change outputs that passed check (c) MAY be summarized as change. Where a signing device with a trusted screen is in use, this display and approval MUST happen on the device's screen, and the online implementation's display is informational; where the signer is software only, the implementation MUST say so in the approval screen, since a compromised computer can show one transaction and sign another. Approval MUST be an explicit action with a refuse option of equal prominence; refusing sends ERROR (`validation_failure`) with `re` set to the request and does not release a signature.

**PSBT_RESPONSE** body: `{ 1: psbt: bytes }` — the partially signed PSBT, `re` set to the request's `mid`. Before handing the response to the transport the signer MUST record that a signature may have been sent (§4.2).

**PSBT_COMBINE** body (requester → all): `{ 1: psbt: bytes, 2: txid?: bytes(32) }` — the combined PSBT (and transaction id if finalized), distributed so every signer can see what they co-signed. `txid` is the 32-byte transaction id in the byte order in which it is hashed (internal byte order), not the reversed order in which block explorers display it.

**Requester checks and the two kinds of success (normative; added 2026-11-18, corrected the same day).** A signing session has two distinct successful outcomes, and an implementation MUST report which one occurred. *Signatures collected:* the response added the expected signatures but the wallet's threshold is not yet met — the ordinary case for a wallet that needs more signatures than one session can gather (§1.3), where the combined PSBT is carried to the next session. *Finalized:* the threshold is met and the transaction is complete.

On receiving a PSBT_RESPONSE the requester MUST verify: that the unsigned transaction in the response is byte-identical to the one it sent; that every partial signature already present in the request is still present and unchanged; that for every input the signer was asked to sign the response carries **at least one new** partial signature, under a key of the wallet's descriptor that had no signature on that input in the request, and that each new signature verifies against that input's `SIGHASH_ALL` digest; and that nothing else in the PSBT was added or changed. A response that fails any of these MUST be refused and MUST NOT be combined. A signer MUST NOT finalize inputs in its response — finalization removes the partial-signature entries the requester checks (BIP-174 input finalizer) — so a response carrying finalized inputs is refused. **What a collected signature proves.** A new valid signature under a descriptor key proves progress toward the threshold; it does not by itself say *which cosigner* signed, since the requester holds no authenticated link between the session peer and a key. An implementation MAY report the signing key by the fingerprint and origin the descriptor gives it, and MAY attach a cosigner's name only where its own wallet has labeled that key; it MUST NOT report that a named cosigner signed on the strength of the session alone. "One new wallet signature collected" is always a true statement; "Bob signed" is true only if the key that signed is the key the wallet knows as Bob's. The requester combines (BIP-174 combiner), and then: if the threshold is not met on every input, the outcome is *signatures collected*, PSBT_COMBINE carries the combined partial PSBT with `txid` absent, and the requester MUST NOT report a transaction id; if the threshold is met, the requester finalizes locally, computes the transaction id from the finalized transaction rather than trusting any reported value, checks the finalized transaction against the request its user approved, and the outcome is *finalized*, with PSBT_COMBINE carrying the finalized PSBT and `txid`. A signer receiving PSBT_COMBINE MUST verify the same things about the transaction it co-signed, and MUST treat a reported `txid` as a claim to check, not a fact.

### 6.8 Short authentication string (SAS) — mandatory checkpoint

**Scope note.** The SAS authenticates *who is in the session*: the set of session public keys, each bound to a nonce its holder committed to before anyone revealed one. Everything else — the ceremony terms, every key contribution, every descriptor hash, every PSBT — travels afterward inside AEAD under the pairwise keys the SAS authenticates, so it needs no separate human check for authenticity; agreement on the wallet is established by DESCRIPTOR_CONFIRM and the pre-funding checkpoint (§6.6). *(Revised 2026-11-09: until that revision the SAS also covered `descriptor_hash`; see "Why the descriptor hash is not in the SAS" below. Revised 2026-11-18: the comparison now precedes every ceremony message in both session kinds.)* Because the construction permits no offline search, the comparison need not be simultaneous: the string can be compared over a verified text channel with a delay (A.6, review question Q2).

**When.** At the start of every session, in both kinds, **before any ceremony message**. Each participant sends its SAS_REVEAL (below) as soon as it holds the other's hello; when it holds the other's reveal it verifies the nonce, computes the SAS, and displays it; its user compares and confirms. Until its own user has confirmed, a participant MUST NOT send SESSION_INIT, KEY_CONTRIBUTION, DESCRIPTOR_CONFIRM, SESSION_FINALIZE, PSBT_REQUEST, PSBT_RESPONSE, or PSBT_COMBINE, and MUST NOT act on any of them it receives. **Hold rule (normative; corrected the same day).** The two users confirm at different moments, and the one who confirms first may lawfully send more than one message before the other has looked up: an initiator whose user has confirmed and consented sends SESSION_INIT and then its KEY_CONTRIBUTION; a requester sends PSBT_REQUEST. A participant still awaiting its own user's confirmation MUST therefore accept, authenticate, and **hold** — unacted on, in arrival order — every ceremony message that would be lawful at the start of a ceremony: one SESSION_INIT and one KEY_CONTRIBUTION (setup), or one PSBT_REQUEST (signing), bounded by the message-identity rule (§6.1), which admits one of each. On "matches" it processes the held messages in order under the ordinary rules, including the opening-message checks below; on "does not match" it discards them and aborts. Any held message outside that set, or a second of any kind, is a `role_conflict` ABORT when processed. Holding is required, not optional: an implementation that aborted because the peer's user was faster would fail two honest users. This is the one rule that replaces draft.1's separate "SHOULD NOT send PSBT_REQUEST" and "MUST NOT sign" sentences: nothing but hellos and reveals moves before the SAS is confirmed, and the only thing a party admitted under a leaked code can learn before the humans catch it is a random number. Every participant's implementation MUST display the string derived as follows:

```
sas_input = SHA-256(
      ASCII("MSP-V1-SAS")
   || channel_id                          // 32 bytes (§5.2)
   || uint8(participant_count)            // number of session participants
   || concat over participants, in byte-wise lexicographic order of pk,
        of (pk || r)                      // participant_count × 64 bytes
   || uint16_be(0))                       // reserved; a future version may bind a value here

SAS = (sas_input, read as a 256-bit big-endian integer) mod 31^12,
      rendered as 12 characters of the §5.1 unambiguous set in its uppercase form
      (`23456789ABCDEFGHJKMNPQRSTUVWXYZ`, most-significant first, zero-padded to 12),
      grouped XXXX-XXXX-XXXX.
```

`r` is each participant's SAS nonce, committed in its hello (§5.3) and revealed in its SAS_REVEAL. Reducing the whole digest rather than its first 60 bits avoids the bias of reducing a 60-bit value modulo 31^12 (≈ 2^59.4): the rendered string has about 59.4 bits of entropy. The inputs are the same as in draft.1, so the §10.3 vector is unchanged by this revision; what changed is when the nonce is revealed.

**SAS_REVEAL** (type 9; every session) body: `{ 1: sas_nonce: bytes(32) }`, and **exactly that**: a receiver MUST reject (ABORT, `validation_failure`) a reveal whose plaintext map has any key other than `1`, including `0: note`, or whose value is not 32 bytes. Field 2 is reserved (draft.1 defined an optional participant list here for n-party signing; it is withdrawn with the two-participant scope, and the group profile will define its own membership mechanism, §5.3). It is the first encrypted message any participant sends and is identical in form for both participants and both session kinds: it says nothing about who is initiating or what the session is for.

**Control messages before confirmation (normative).** Before its own user has confirmed the SAS, a participant MUST NOT send ERROR, and MUST NOT include `detail` text in an ABORT. Every failure in this phase — a bad nonce opening, a malformed or over-full reveal, a third hello, an unexpected message type, the user choosing "does not match" — ends the session **locally** first (keys wiped, code burned, §6.9), and the participant MAY then send one ABORT carrying the reason code alone. The ABORT discloses one byte to a party who may be an attacker; `detail` or an ERROR could disclose more, and nothing before confirmation justifies that. The receiver-step ERRORs of §6.4 therefore apply only from VERIFIED onward. A participant sends it once it holds the other participant's hello, and to no one else. On receipt, the recipient MUST recompute `cm` from the revealed nonce and the sender's `pk` and ABORT (`commit_mismatch`) on mismatch, before computing the SAS.

**Two freezes (normative; revised 2026-11-18).** *Membership* freezes when a participant sends its SAS_REVEAL: the set of accepted public keys and their commitments is fixed, and a valid hello from any other key afterward MUST cause ABORT (`unexpected_participant`, §5.3), not an update. *Terms* freeze later and separately: after its own user has confirmed the SAS, a participant accepts exactly one SESSION_INIT (setup) or one PSBT_REQUEST (signing), and from then on a second with a different body is an `identity_conflict` ABORT (§6.1, §6.6, §6.7). The two freezes are at different moments because the two users confirm at different moments; the sending rules ("not until my user has confirmed") and the receiving rules ("hold the opening message until my user has confirmed") in "When" above are what let the two sides be out of step without either acting early. No wallet is shown as created, and no PSBT is sent or signed, before the user has confirmed the SAS.

**Opening the ceremony (normative; added 2026-11-18).** After the SAS checkpoint, exactly one participant opens the ceremony by sending the first ceremony message: SESSION_INIT for a setup, PSBT_REQUEST for a signing session. That message names the kind of session and identifies its sender as the initiator (§2); in a signing session the initiator is also the requester. Which participant opens is decided by the users out of band — the one whose user chose *start* rather than *join* in the implementation — and the protocol enforces it: a participant whose user chose *join* MUST NOT send an opening message; a participant MUST ABORT (`role_conflict`, 11) if it receives an opening message after sending one itself, if it receives an opening message of a kind other than the one its user selected (a SESSION_INIT when the user chose to co-sign, a PSBT_REQUEST when the user chose to set up), or if it receives any ceremony message before an opening message; and if no opening message arrives within the §8.2 idle timer the session ends with `timeout`. The opening message is the only place the kind of session is stated; the hellos and reveals carry no such field, deliberately, so that an admitted party learns nothing about the session's purpose before the comparison. (draft.1 had no rule here: a signer waiting for SESSION_INIT and one expecting a reveal both had reasonable readings of the same hello.)

**Why this defeats the collision search.** The attacker in scope (§4) is on the relay path and holds the code, so it can send valid hellos and sit between the two honest participants, presenting its own key to each. Draft.1's SAS was a hash over the session keys and the descriptor hash, nothing committed; the attacker received every honest value before it had to send its own, chose its two substitute values after seeing them, and could search offline for a pair whose strings collided — a birthday search of about 2^30 per side, minutes on commodity hardware, inside the §8.2 idle timer. With the commitment, every value the attacker can choose toward an honest participant X — the public key it presents to X and the nonce behind the commitment in that hello — is fixed in a hello that X must hold before X reveals `r_X`, and X reveals only inside an encrypted message to the key it already holds. `SAS_X` is therefore a hash whose last input is a uniformly random 256-bit value the attacker did not know when it fixed its inputs. The attacker's success is the probability that both honest participants' independent strings coincide: about 2^-59 per session, with no offline work that helps. The 2026-11-18 change moves the reveal to an earlier, dedicated message and makes both participants reveal in the same way, which leaves the argument's structure intact: X's rule is still "hold the peer's hello, then reveal," and X's nonce is still the last input. What the earlier reveal changes is what the attacker has learned by the time it is caught — now a random number, before it was an account key. This is the commit-then-reveal structure of Vaudenay's SAS protocols, the Laur–Pasini group version (every party commits, then every party opens, no ordering between parties beyond "hold every commitment first"), and Bluetooth numeric comparison. The construction, in this revision's schedule, is adopted pending external review (Appendix B item 6; `review-questions.md` Q1); until that review, implementations SHOULD describe the SAS as "about 59 bits, pending review" rather than as 60 bits.

**Why the descriptor hash is not in the SAS.** Anything in the SAS that the attacker can influence *after* the honest nonces are revealed reopens the search. The descriptor hash a participant computes depends on the key contributions delivered to it, and an interposed attacker delivers its substitute contributions after it has seen the honest nonces; the chain code of an xpub is 32 free bytes, so the search would cost a few hashes per trial. Keeping the descriptor hash would require committing to one's own key in the hello, before the terms that determine which key to contribute have been seen, which breaks the consent-then-contribute flow of §6.6. It is also unnecessary: once the SAS has authenticated the pairwise keys, an attacker who is not in the middle cannot alter a contribution, and one who is in the middle has already been caught — and, under this revision's order, caught before any contribution was sent. Honest participants assembling different wallets can then result only from a bug or from a legitimate participant sending different keys to different peers, and DESCRIPTOR_CONFIRM, exchanged under the authenticated keys, catches both. That argument relies on the envelope: `from` and `to` are authenticated header fields (§6.4) and the nonce carries a direction byte, so a relay cannot reflect a participant's own CONFIRM back to it as a peer's. None of the comparable systems (ZRTP, Bluetooth, Signal) puts the payload into the string the humans compare; they authenticate the keys and let the channel carry the rest. The lesson from draft.1 still stands: never bind envelope *headers*, which differ per recipient.

Two details that must not be left to inference:

- **Sort order** is byte-wise lexicographic on the raw 32-byte public keys — the same rule as §5.4 — and each participant's `r` follows its `pk` in that order. It is restated here rather than imported, because an implementer who did not cross-reference §5.4 might otherwise sort by hex string, by key id, or by join order.
- **The count prefix makes the concatenation injective.** The run of `(pk || r)` pairs is variable-length; the `uint8` count fixes its extent. The trailing `uint16_be(0)` is a reserved length prefix retained so the layout need not change if a future version binds a value here.

A worked 3-participant example, with all intermediate values, is in §10; it exercises the function for the future group profile, and the two-participant case is the same function with `participant_count = 2`.

**Nonce hygiene (normative; corrected 2026-11-18).** `r` is fresh for every `(sk, pk)` and is never reused: a session that aborts after any nonce has been revealed is over, and the next attempt uses new keys and new nonces. An implementation that reused a revealed nonce would hand the attacker that nonce before the next attempt began and turn the online bound back into an offline search. A participant retains its own `r` until it has computed the SAS and its user has confirmed it (its own nonce is one of the SAS inputs; draft.1's instruction to zero it "after revealing" was wrong), and zeroes it when the session reaches VERIFIED or ends. While a resend of its SAS_REVEAL could still be needed (§8.3), it retains the exact encrypted envelope it sent, not the plaintext.

**Comparison channel (normative).** The comparison MUST take place over a channel that authenticates each participant to the others: in person; a voice or video call between people who recognize each other; or a messaging channel with verified sender identity (for example, an end-to-end encrypted messenger contact whose safety number has been verified, or a signed message under a key already trusted). Unauthenticated channels — SMS, ordinary email, unverified messenger contacts, any channel where the sender cannot be established — MUST NOT be used. The comparison channel SHOULD be independent of the channel over which the session code was distributed: the SAS exists to detect a compromised code, and a compromise of the code's channel may extend to anything else sent over it. Confidentiality of the comparison channel is not required; the SAS is useless to an attacker who learns it.

**What the implementation displays (normative).** Alongside the SAS the implementation MUST display the number of session participants (for example, `2 participants — FFHJ-2HU2-H7EV`), because the SAS detects participants holding *different* views of the session but not an additional participant whom every view contains (§5.3). Every implementation MUST render the SAS identically — same alphabet, same grouping — so that users of two different implementations read the same representation. Confirmation MUST be an explicit choice between two equally prominent options ("matches" / "does not match"), with neither preselected and no path that skips the choice; "does not match" MUST ABORT the session. The display MUST NOT show the kind of session, the terms, a wallet name or identifier, or anything else about the ceremony at this point, because the implementation does not yet know them and must not pretend to.

**Procedure.** Both participants MUST confirm from their own screen; one participant's confirmation is not sufficient, because a participant displaced by an impostor may simply be absent. Participants SHOULD read the string in turns — one reads the first group, the other the second, and so on, each checking the groups they did not read — so that each must look at their own screen and no single reader controls what the other hears. Over a text channel, participants SHOULD paste the full string rather than retype it.

**What the SAS detects.** A party interposed between the participants — whether it intercepted the code or substituted it — sits between half-sessions whose participant key sets differ, so the participants' strings differ, with probability about 1 − 2^-59 per session, and it is detected before it has received anything but a random nonce. It does not by itself detect participants who assembled different descriptors; DESCRIPTOR_CONFIRM and the pre-funding checkpoint (§6.6) do, over the channels the SAS authenticates. It does not detect an additional participant visible to everyone; the participant count, the client-side cap (§5.3), and the requirement that both participants confirm are what catch that. It does not detect a participant who is the intended person but whose own software is compromised; the device-screen checks in §6.6 and §6.7 are for that.

### 6.9 Control messages

**ERROR** body: `{ 1: code: uint, 2: detail?: text }`. An ERROR about a specific received message names it in the envelope header's `re` (§6.1); draft.1 also carried a copy as body field 3, which is withdrawn (2026-11-18) so that there is one place to look and nothing to disagree. Registry: `1 version_mismatch`, `2 unsupported_type`, `3 decode_failure`, `4 validation_failure`, `5 counter_regression`, `6 descriptor_mismatch` (was `slot_conflict` in draft.1), `7 timeout`, `8 unexpected_participant` (§5.3), `9 identity_conflict` (§6.1), `10 commit_mismatch` (§5.3), `11 role_conflict` (§6.8, "Opening the ceremony"; added 2026-11-18), `12 counter_gap` (§6.5; added 2026-11-18). ABORT `reason` values are drawn from the same registry. ERROR is informational; it never changes session state by itself.

**ABORT** body: `{ 1: reason: uint, 2: detail?: text }`. ABORT ends the session for the sender and instructs peers to end it. Any participant may abort. After ABORT, the session code is burned (§5.6 single-use rule) and all keys MUST be wiped.

### 6.10 Compatibility profile: BCR-2024-004 / GSTP (non-normative in v0.1)

MSP's vocabulary deliberately mirrors Blockchain Commons Request/Response semantics so a future bridge is a mapping, not a rewrite:

| MSP | BCR-2024-004 |
|---|---|
| `mid` / `re` pairing | ARID request/response pairing |
| `note` body field | request `note` assertion |
| PSBT_REQUEST / PSBT_RESPONSE | `signPSBT` (function 102) |
| KEY_CONTRIBUTION (as answer to SESSION_INIT) | `getKey` (101) response semantics |
| DESCRIPTOR_CONFIRM (the locally assembled descriptor, confirmed rather than proposed) | `getOutputDescriptor` (103) response semantics |

A future capability MAY define `body` payloads that are GSTP-sealed Gordian Envelopes carried opaquely inside MSP envelopes — end-to-end message sealing that survives hops the session does not control. It is not required in v0.1 because no browser-native Envelope/GSTP implementation exists; requiring it would make the spec unimplementable by its own reference implementation. This is a stated question to the Gordian community, not a rejection.

---

## 7. Layer 3 — Transport bindings

An envelope is transport-independent bytes. A binding defines only: rendezvous (how `channel_id` maps to a place), framing, and the metadata that transport inevitably exposes.

### 7.1 WebSocket relay binding (normative)

- **Join (normative; made exact 2026-11-18).** The first message a client sends on a new connection is a **text** WebSocket message whose content is exactly the 64 lowercase hexadecimal characters of `channel_id` and nothing else. The relay replies with one text message: `joined` (the connection is now a member of that channel), `full` (the channel already has `n_max` members; the relay then closes the connection), or `invalid` (the join was not 64 lowercase hex characters, or a second join was sent on the same connection; the relay closes the connection). A client that receives anything but `joined` MUST treat the attempt as failed and MUST NOT retry on the same connection. The raw code and `K_code` never leave the client. (Keylay's current relay uses a JSON join; §14.)
- **Framing.** After `joined`, every message in either direction is **binary**, and one MSP item — one hello or one envelope — is one complete binary WebSocket **message**, after reassembly of any fragments (RFC 6455 §5.4). A WebSocket *frame* is not the unit: an endpoint may fragment a message across frames, and an implementation that treated frames as items would break on any fragmenting peer or proxy (draft.1 said "frame" and meant "message"). Maximum item size is 262,144 bytes (256 KiB) after reassembly; the relay MUST close a connection that sends a larger message, and a client MUST ignore one.
- **Relay obligations.** Forward each binary message verbatim to every other member of the channel. **Replay hellos to a later joiner:** retain, per member, the first binary message it sent (its hello), for as long as that member's connection is open, and on admitting a new member deliver every retained hello to it in one batch before forwarding anything else; because a hello is MAC'd and a repeated identical hello is harmless (§5.3), this is safe, and without it a client that joined an empty room would never see a peer who joined later (draft.1 left this to inference). Enforce a configured maximum number of connections per channel (`n_max`), replying `full` to the `n_max+1`th; the v0.1 reference binding sets `n_max = 2` until Appendix B item 4 is discharged (the relay cannot see SESSION_INIT, so the limit is relay configuration, not per-session). The relay limit is not a security control — a dishonest relay may ignore it — and clients MUST enforce the participant count themselves (§5.3). Expire channels at 15 min idle / 60 min absolute (§8.2) and drop retained hellos with the connection that sent them; rate-limit; log at most truncated IPs and message types.
- **Relay non-obligations:** ordering across senders, delivery guarantees, persistence beyond the retained hellos. Anything stronger belongs to the envelope layer, which is why counters and `re` pairing exist.
- Self-hosting MUST be possible with configuration only (a relay URL field).

### 7.2 Nostr binding (planned; normative once shipped)

- **MSP's cryptography rides inside the event; Nostr's does not replace it.** NIP-44's conversation key is a static ECDH between identity keys — no forward secrecy, by its own specification. An MSP session over NIP-44 would be a silent security downgrade, so it is prohibited: envelopes are produced exactly as in §6, then wrapped for metadata protection per NIP-59 (gift wrap) using throwaway Nostr keys.
- Rendezvous: both sides derive a session Nostr keypair from `HKDF(K_code, info="MSP-V1-NOSTR-RENDEZVOUS")`; gift-wrapped events are addressed (p-tag) to its public key. Any public relay works; no project-operated infrastructure required.
- Events carry an expiration tag (NIP-40) of session max lifetime. Store-and-forward retention is what makes the ratchet (Appendix A.4) a **precondition**: this binding MUST NOT ship persistent/async sessions before the ratchet is specified and implemented.
- Metadata disclosure: relays still observe timing, event counts, sizes, and client IPs; gift wrap hides sender identity keys but not traffic patterns. §7.4 applies.

### 7.3 QR / file air-gap bridge (normative)

- Encoding: envelope bytes as UR (`ur:bytes`) or BBQr multi-part QR, or a `.msp` binary file. The envelope — not decrypted content — crosses the gap whenever the air-gapped device can produce/consume envelopes; otherwise the *payload* (BSMS record, PSBT) crosses in its native format and the bridging participant wraps it.
- A bridging participant injecting a wrapped key on a device's behalf MUST set `bridged: true` in the KEY_CONTRIBUTION body; the field exists on that message only (§6.6). For signing, the bridge is a courier: it carries the PSBT from PSBT_REQUEST to the device and the device's signed PSBT back into PSBT_RESPONSE, with every derivation, witness-UTXO, and sighash field intact (§6.7), and nothing marks a signing message as bridged because nothing in it is the bridge's. The bridge is attesting only to faithful transcription of the device's exported key. Because most devices export an unsigned key expression, nothing in the payload can prove the bridge transcribed it faithfully; a malicious bridge could substitute the key and every software-level check would pass. Authenticity of a bridged key therefore rests on the signing device itself: registering the assembled wallet on the device and confirming there that the device's own key is present and that the first address matches the one compared with other participants (§6.6a, "Verify on the signing device"). A signing-device profile in which the device itself handles envelopes, so the bridge sees only ciphertext, is specified for the future in Appendix A.7.

### 7.4 Metadata disclosure (all transports)

The specification's security documentation MUST include, per transport, a table of what the transport operator observes and what it never observes. Leaving metadata exposure implicit misrepresents the threat model; stating it is a conformance requirement, not a courtesy. The full per-transport tables are Appendix B item 7; the inventory they must cover is fixed here (2026-11-18) so that no summary elsewhere in this document understates it.

**What every transport operator observes.** Network metadata: IP addresses unless Tor is used, connection timing, message timing, message sizes, and message count. The rendezvous identifier (`channel_id`, or the Nostr rendezvous key). **Every field of every hello** (§5.3), since hellos are unencrypted: wire version, capabilities, KDF identifier, each participant's ephemeral public key, and each SAS commitment. **Every header field of every envelope** (§6.1), since headers are authenticated but not encrypted: message type, the two 8-byte key identifiers, the per-direction counter, the message identity, and request/response linkage. From the message types alone the operator can tell a setup session from a signing session and follow the ceremony step by step; from the counters it can count messages per direction; from the sizes it can estimate PSBT size.

**What no transport operator observes.** The session code and `K_code`; any plaintext body; the SAS nonces and the SAS; the ceremony terms; any key expression or xpub; the descriptor, its hash, or any address; any PSBT or transaction id. The abstract's sentence about the relay is a summary of these two lists and does not override them.


### 7.5 Transports considered and not specified (non-normative)

Recorded so that a reviewer can see what was evaluated and why, and so that a future binding starts from the analysis rather than repeating it. The envelope (§6.1) is transport-independent; adding any of these later is a new §7 binding, not a protocol change.

**Lightning onion messages.** Lightning's onion messages (the payment-less, onion-routed messages introduced with BOLT 12 offers) are the right primitive if MSP is ever carried over Lightning: they cost nothing, need no payment to succeed, and route through several hops so that no single hop learns both sender and recipient, with the recipient able to hide its node behind a blinded path. That is a network-level privacy property no other binding in this section provides — the WebSocket relay and every Nostr relay see participant IP addresses (§7.4). Payments carrying custom data (keysend-style records) and direct peer messages were rejected: the first costs sats and fails like a payment, the second works only between directly connected nodes.

Onion messages are not specified for v0.1 because (a) every participant must run, or delegate to, a Lightning node, which a browser cannot do and which delegation would reintroduce as a trusted party; (b) a node's public key is a long-lived identifier, so sessions run from the same node are linkable across sessions, contrary to §4's no-persistent-identity property, and blinded paths only partly mitigate this; (c) a node with channels has an on-chain footprint, so coordinating a multisig ceremony from a funded node can correlate the ceremony with on-chain funds (§7.4); (d) delivery is best-effort with no store-and-forward, so it serves neither offline participants nor the asynchronous profile (A.1); (e) forwarding support differs across node implementations; and (f) message size is bounded at tens of kilobytes, so large PSBTs would require chunking. The natural future audience is wallets that already embed a Lightning node: for two such wallets, an onion-message binding would give MSP onion-routed transport without a relay. A binding MUST NOT reuse a node's long-lived identity key for session authentication; the §5 handshake runs unchanged inside the messages, exactly as it does inside Nostr events (§7.2).

**Oblivious HTTP (RFC 9458).** Rejected. OHTTP encapsulates single, stateless request/response exchanges and requires a relay and a gateway run by non-colluding operators; an interactive session is outside its model, and the `channel_id` would let the gateway link a session's requests regardless. IP privacy for the live relay is better obtained from Tor or an onion-service relay, which carry the existing binding unchanged.
---

## 8. Session lifecycle

### 8.1 States

`IDLE → JOINING (hello sent) → PAIRED (peer hello held, keys derived, SAS_REVEAL sent) → REVEALED (peer's reveal verified, SAS displayed) → VERIFIED (SAS confirmed by this user) → CEREMONY (opening message sent or accepted; typed messages) → FINALIZED | ABORTED → CLOSED`

*(Reordered 2026-11-18: VERIFIED now precedes CEREMONY.)* The only envelope acted on in PAIRED or REVEALED is SAS_REVEAL; in REVEALED the messages named by the hold rule (§6.8, "When") MUST be authenticated and held, unacted on, until the user confirms; in VERIFIED the held messages, or the opening message as it arrives, are acted on; any other ceremony message before CEREMONY is a `role_conflict` ABORT. A participant leaves VERIFIED for CEREMONY when it sends the opening message (initiator) or accepts one (the other participant). FINALIZED requires, in a setup session, the descriptor assembled (§6.6a), matching DESCRIPTOR_CONFIRM held from the other participant, and the pre-funding checkpoint **completed with a matching address** (outcome *device-verified* or *software-only*, never *not done*; §6.6); in a signing session, PSBT_COMBINE sent or received and checked (§6.7). Each participant tracks its own state; the two participants are routinely one state apart.

### 8.2 Timers

Idle timeout 15 minutes (any valid envelope resets it); absolute lifetime 60 minutes. Both enforced independently by every participant and by relays. On expiry: wipe keys, burn code, CLOSED.

### 8.3 Disconnects and rejoin

A participant that drops before FINALIZE MAY rejoin on a new transport connection by re-announcing the **identical hello** (same `pk`, same `cm`), provided it has retained **all** of its session state: the pairwise key `K_AB` and both counters (these survive §5.4, which zeroes only the X25519 *private key*; the derived session key legitimately lives until session end), the exact encrypted envelope of the last message it sent (so that a resend is byte-identical, §6.1), its own SAS nonce if the SAS has not yet been confirmed (§6.8), and the ceremony state (§8.1). Peers recognize the same `pk`, keep existing pairwise keys and counters, and resume. A replayed same-`pk` hello injected by the relay is harmless: it changes no keys and no counters, and the impersonator cannot produce or read a single valid envelope without `K_AB`. A hello with a **new** `pk` mid-session aborts the session (§5.3, participant-count rule); recovering from a genuinely lost device state — any part of the list above — means ABORT and a fresh session with a fresh code; an implementation MUST NOT resume with reconstructed or guessed counters. This is deliberately conservative: session continuity is cheap to get wrong and expensive to get wrong silently.

### 8.4 Partial-failure rules

- No SAS_REVEAL or no opening message at the idle timer → the session ends with `timeout`; nothing has been disclosed.
- Missing KEY_CONTRIBUTION at timeout → either participant MAY send ABORT (`timeout`); the initiator SHOULD.
- Any DESCRIPTOR_CONFIRM or pre-funding address mismatch → mandatory ABORT (`descriptor_mismatch`), code burned, A.6 recovery guidance shown.
- A signer that will not sign (validation failure or user refusal, §6.7) sends ERROR (`validation_failure`) with `re`; in v0.1 the requester's only options are to abort or to try again in a new session with a corrected request. (In a future group session the requester may continue with other signers; `m`-of-`n` may not need every signer.)
- **Outcome vocabulary (normative).** Every session ends for each participant in exactly one local outcome: *finalized* or *signatures collected* (§6.7) or *wallet ready* (§6.6) for success; *aborted* when this participant or its peer sent ABORT or a check failed; *incomplete* when the exchange ended without the messages this participant needed (timeout, disconnect, counter gap). *Incomplete* describes this participant's exchange only; what the peer did with messages already sent is separately either *known* (a later message proved it) or *unknown*. A signer that handed a PSBT_RESPONSE to the transport and ended *incomplete* has an unknown remote outcome and MUST display "signature may have been sent" (§4.2); a requester that never received the response has an unknown remote outcome too. Neither may be displayed as "no signature was made."
- An authenticated counter gap (§6.5) → the observing participant ends the session *incomplete*, MAY send ABORT (`counter_gap`), and does not request retransmission; there is none in v0.1.

---

## 9. Conformance

Two conformance roles at v0.1 (a third, for signing devices, is specified for the future in A.7):

- **Signer role (minimum):** Layer 1; SAS_REVEAL, SAS display, and the confirmation choice (§6.8); envelope encode/decode with the strict receiver steps (§6.3, §6.4); terms display and consent (§6.6); KEY_CONTRIBUTION send-to-all and receive-from-all with the duplicate-key check; descriptor assembly (§6.6a); DESCRIPTOR_CONFIRM and the pre-funding checkpoint (§6.6); PSBT_REQUEST validation, the approval display, and PSBT_RESPONSE with the release-status record (§6.7, §4.2); ERROR/ABORT; WebSocket binding.
- **Initiator role:** signer role plus SESSION_INIT, FINALIZE, PSBT_REQUEST with the requester checks, PSBT_COMBINE (§6.7), and bridge support (§7.3).
- **Device role (future, Appendix A.7):** the signer role carried over the QR binding by an air-gapped signing device, with the terms, participant count, SAS, own-key presence, and first address displayed on the device. Not part of v0.1 conformance.

The signer role is intentionally small — it is the adoption wedge. Descriptor assembly is in it because every signer must hold the descriptor for the §6.7 check anyway, and a wallet that implements BSMS already generates Round-2 files; §6.6a only pins the bytes. A wallet can be a conforming signer without ever initiating a session.

## 10. Test vectors

Still REQUIRED-before-freeze in full: pairwise key derivation with fixed X25519 keys, envelope AEAD (nonce/AAD construction), and one full setup transcript are not yet published here. A spec without test vectors produces implementations that agree in prose and disagree in bytes.

The three constructions clarified in this revision (§5.1 normalization, §5.3 hello MAC, §6.8 SAS) each ship with a vector below; all bytes are hex, big-endian.

**10.1 Code normalization and derivation (§5.1, §5.2).**

```
salt_v1 = SHA-256("MSP-V1-KDF-SALT")
        = d1db8c9013968b828b2172582e5cf96c76b8ba82ea1e646406c3316f99b717fc

Normalization = lowercase, then remove every character not in [a-z0-9].
These inputs all normalize to the code "7k4m2xqtb9":
    "7k4m2xqtb9"   "7K4M2XQTB9"   "7k4m-2xqt-b9"   "7k4m · 2xqt · b9"   "  7K4M 2XQT B9  "
and therefore all derive the same value:
    K_code     = PBKDF2-HMAC-SHA512("7k4m2xqtb9", salt_v1, 300000, 32)
               = 53ceab3fedbbfdcad80e4560dd51358b30a798ef6f556937b17625741a5bf608
    channel_id = SHA-256("MSP-V1-CHANNEL" || K_code)
               = 9863a5bb51a2457e808fba35e35ef557caadaf0fda30a7de870ef0afab74520c

Look-alike characters are content, not errors — they normalize to distinct codes:
    "7k4m2xqtbo" (letter o) and "7k4m2xqtb0" (digit 0) are two different codes,
    neither equal to "7k4m2xqtb9". The generator never emits o/0/1/i/l precisely so
    a generated code cannot land in this trap; a user-chosen code may.

Removing non-ASCII can shorten a code below the minimum and fail the length check:
    "7k4m2xqtbа" (final char Cyrillic а, U+0430) → "7k4m2xqtb" (9 chars) → rejected (< 10)
```

**10.2 Hello (§5.3).**

```
K_code    = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
pk        = 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
r         = 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
v = 1,  caps = 0,  kdf = 1

cm = SHA-256("MSP-V1-SAS-COMMIT" || pk || r)
   = 1b3f6c9788fc5393e2f8e27e5f77504bf40a2e6824526d0a6420d477db075117

mac_input (77 bytes) =
   4d53502d48454c4c4f 01 0000 01 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f 1b3f6c9788fc5393e2f8e27e5f77504bf40a2e6824526d0a6420d477db075117
   └ "MSP-HELLO" ────┘ v  caps kdf └ pk ──────────────────────────────────────────────────────────┘ └ cm ──────────────────────────────────────────────────────────┘

mac = HMAC-SHA256(K_code, mac_input)
    = cca68784379bfffa701c2de466f44de6b0b9cee0ded2d02e461a806e236fb3ca

hello (109 bytes, as sent) = mac_input || mac
   = 4d53502d48454c4c4f 01 0000 01
     202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
     1b3f6c9788fc5393e2f8e27e5f77504bf40a2e6824526d0a6420d477db075117
     cca68784379bfffa701c2de466f44de6b0b9cee0ded2d02e461a806e236fb3ca
```

**10.3 SAS, 3-participant session (§6.8).** Three session keys with their revealed nonces; each nonce opens the commitment in that participant's hello. The function is the same for the two-participant sessions v0.1 runs (`participant_count = 2`); three participants are used so that the sort rule is exercised. The 2026-11-18 change to *when* the nonce is revealed does not change the inputs, so this vector is unchanged from draft.1.

```
channel_id = 9863a5bb51a2457e808fba35e35ef557caadaf0fda30a7de870ef0afab74520c   (code "7k4m2xqtb9", §10.1)

participants (already in byte-wise lexicographic order of pk):
   pk = a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1
   r  = 1111111111111111111111111111111111111111111111111111111111111111
   cm = f6266ec7fcfafd404584394caec073da4d02593143d8f66f736deed85a55f907
   pk = b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
   r  = 2222222222222222222222222222222222222222222222222222222222222222
   cm = 5cd93083bf6bb4bfd9956f9c8cd5341db3b99c02d5a10eff95578969ae16d252
   pk = c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3
   r  = 3333333333333333333333333333333333333333333333333333333333333333
   cm = 9e0196dba0ee34c2b67bc31d9f5082c151151a582d0c6fcf6231e9a5dc17645a

sas_input = SHA-256( "MSP-V1-SAS" || channel_id || 03
                     || pk_a1 || r_11 || pk_b2 || r_22 || pk_c3 || r_33 || 0000 )
          = 2b389f3f144e2d4ffa4831a4e6e7afe5491af56a331cb165a1ec52506a904a79

SAS = sas_input mod 31^12, base-31 in the §5.1 unambiguous set (uppercase)
    = 4WUZ-4HN9-4GF8
```

Full vectors: `vectors/v1/hello.json`, `vectors/v1/sas.json`.

**10.4 Descriptor assembly, 2-of-3 P2WSH, mainnet (§6.6a).** Full vector with the three key contributions, intermediate values, canonical template, hash, first address, and Round-2 file: `vectors/v1/assembly.json`, generated by `vectors/gen-assembly-vector.py`. Test keys only — never fund. **Scope note (2026-11-18):** this is a vector for the assembly *function*, which is defined for any `n`; it is not a session this version can run. v0.1 setup sessions create two-key wallets (§1.3), and a two-key assembly is the same function with two expressions and `m` of 1 or 2. A 2-of-3 wallet with these keys can be *signed for* in a v0.1 session by two of its holders, which is why the vector's hash is still the value a PSBT_REQUEST for that wallet would carry.

```
SESSION_INIT body: {1:2, 2:3, 3:0, 4:"m/48'/0'/0'/2'", 5:0}

key expressions, sorted (§6.6a step 2):
   [397a4a50/48'/0'/0'/2']xpub6EsnL4EEJsStRbt9DL8ykLJYXWC1VCH7xh2Qn3amtcxRYYk1Xc4eTNpM2iwquBKjzbH6Y5M1SD3CB2W2eh14Nqrz24PuFVKQ7p1hmc8txS7
   [70ecd03a/48'/0'/0'/2']xpub6F8NXrA3Pr3u6DLbmuQYshUQCk51MucTNrmzUqqBGbCXkcNSDbdfXmbkX2fLmoa97pdpzvTPBcSuwBd31EDesj7JkPvX3fTK9XFxXzMWGN2
   [c8e3b3d3/48'/0'/0'/2']xpub6Di4UNDukEWM6HJBwyTtRx3gzHoxjNCqJTuKk8LEk4dwMxsDobtch6x7sy1V9K4UcJiF8EAMWLSkvQSVUtd8k8k12vWeNQy16Lm18mAYBXy

canonical descriptor template:
   wsh(sortedmulti(2,[397a4a50/48'/0'/0'/2']xpub6Esn…txS7/**,[70ecd03a/48'/0'/0'/2']xpub6F8N…WGN2/**,[c8e3b3d3/48'/0'/0'/2']xpub6Di4…YBXy/**))#jy43mxww
   (full string in assembly.json; the elided xpubs are the ones above)

descriptor_hash = SHA-256(canonical template)
   = 0874ee66df4de02ce1c5a0e7a7aef735528e8acae05b5d2780aba596f8998d5d
first_address   = bc1qcre8wm7a5mwls0dn5e8mxk4fnphmy2r2zasnpmd9ajppj64xm6cqn4as5j   (receive /0/0)
first_change    = bc1qpsejuz7cusul5l2uqy3y4p9apyrgwqky4503s9ac594s0ll50egq267vnw   (change /1/0)
```

## 11. Registries

Message types (§6.2), error codes (§6.9), script types (§6.6), KDF ids (§5.2), cipher suites (§5.5 caps), wire versions. Registry policy pre-freeze: this document is the registry; post-freeze: additions via the standardization venue chosen in §13.

## 12. Security considerations (summary)

Consolidates: code entropy and single-use (§5.1, §5.6); silent-drop of bad MACs (§5.3); participant-count rule as the only membership rule (§5.3); zeroization as the FS event (§5.4); one pinned suite, no agility claimed (§5.2, §5.5); strict decoding and ordered receiver steps (§6.3, §6.4); deterministic nonce safety argument (§6.4); counter-advance ordering (§6.5); SAS before any ceremony content, two freezes, one opener (§6.8); duplicate-key rejection (§6.6); descriptor-and-chain binding, `SIGHASH_ALL`, and explicit approval as the signing preconditions (§6.7); per-participant guarantees and signature-release status (§4.2); pre-funding device-address checkpoint (§6.6); NIP-44 prohibition (§7.2); bridged-payload authentication (§7.3); metadata inventory (§7.4); ratchet-before-persistence rule (§7.2, A.4).

## 13. Standardization venue and process (decision deferred, deliberately)

Candidates: bitcoin BIP process, self-published spec (BSMS-style repository + versioned drafts), or IETF. Deferred until one external implementer exists, because a venue chosen before any second implementation is theater. Interim rule: this document is versioned in the open (public repository), changes are logged, and **freeze** is defined as: test vectors published, two independent interoperating implementations of the signer role, and no normative changes for 90 days. Only after freeze may "reference implementation" be claimed. The protocol is published under its own name so that implementations other than Keylay can carry it without carrying a product name.

## 14. Relationship to the shipping app

Keylay (app.keylay.org, MIT, single-file browser application) is the basis for a future reference implementation of this specification. It is not one today. As of app v0.9.1 (2026-10-28; "protocol v2" in the app's own numbering, unchanged since v0.9.0) it implements the *Layer 1 session* for two parties and the *Layer 3 QR/file bridge*, using constructions that are the same in shape as §5 but differ in bytes. It implements none of the Layer 2 ceremony messages (§6.6–6.8): it relays files and QR payloads without session semantics, and the descriptor-binding and SAS checks exist only in this document. The v0.9.1 release changed the relay only (crash and session-reset hardening from an external report); nothing in the table below moved.

The table lists every known divergence, read against the v0.9.1 source on 2026-11-05. The right-hand column states which way the gap will close. Every wire-breaking row closes together, in one flag day, in the app's conformance release.

| Area | This specification (v0.1) | Keylay app v0.9.1 ("v2") | Resolution |
|---|---|---|---|
| Domain-separation prefix | `MSP-V1-…` (uppercase, no separator) | `keylay-v2-…\|` (lowercase, pipe separator) | App adopts `MSP-V1-…` with the other wire-breaking rows. |
| Code stretching | PBKDF2-HMAC-SHA512, 300k, `salt = SHA-256("MSP-V1-KDF-SALT")` | PBKDF2-HMAC-SHA512, 300k, `salt = ASCII "keylay-v2-kdf-salt"` (raw string) | Hash agrees. Salt derivation differs (hashed label vs raw label); app adopts the spec's. |
| Channel identifier | `SHA-256("MSP-V1-CHANNEL" ‖ K_code)`, full 32 bytes | `hex(SHA-256("keylay-v2-channel\|" ‖ K_code))[0:32]` — first 128 bits, as hex text | App moves to full 32 bytes. 128 bits is not a weakness; the truncation exists because the relay's channel field is a string. |
| Hello message | Fixed-width 109-byte string (`MSP-HELLO` ‖ v ‖ caps ‖ kdf ‖ pk ‖ cm ‖ mac); HMAC-SHA256 over its first 77 bytes; `cm` commits to the SAS nonce (§5.3) | JSON `{type:"hello", code: channel id, pubkey: base64 X25519, sig}` where `sig` = HMAC-SHA256 over the base64 `pubkey` text, key = `SHA-256("keylay-v2-hmac\|" ‖ K_code)` | App adopts the spec hello (adds version, capabilities, kdf; MAC covers the fixed-width bytes, not a text encoding). No version negotiation exists in the app today. |
| Pairwise key | HKDF-SHA256, `salt = K_code`, `info = "MSP-V1-PAIR" ‖ channel_id ‖ sort(pk_A, pk_B)` | HKDF-SHA256, `salt = K_code`, `info = "keylay-v2-pair\|" ‖ channelHash ‖ sorted(pk_A, pk_B)` | Prefix only. |
| Private-key zeroing | MUST zero `sk` after derivation | Done (security review R3) | None. |
| Envelope | Deterministic-CBOR, integer keys, fields `v, t, sid, from, to, ctr, mid, re, body` (§6.1) | JSON `{code, payload, counter, format, encrypted}` — no `from/to`, no `mid/re`, no message type beyond `hello`/`data`, `format` string in place of a typed body | App adopts CBOR envelopes with the ceremony messages. Largest single gap. |
| Nonce | Deterministic: `dir ‖ 0x000000 ‖ uint64(ctr)` (§6.4) | Random 96-bit IV per message | App adopts deterministic nonces with the envelope change. |
| AAD | CBOR encoding of the present header fields | ASCII `"keylay-v2\|" ‖ type ‖ channelHash ‖ format ‖ counter`; no direction field, one key both ways (external finding E9: relay can reflect a client's own ciphertext) | Same intent; bytes differ. The spec's `from`/`to` and directional nonce close E9. Follows the envelope change. |
| Replay | Per-sender highest `ctr`; discard before decrypt, advance after success (§6.5) | Gate on `counter` before decrypt, plain assignment after; not monotonic under concurrent handlers (external finding E5, open) | App fixes E5 (advance with max, or serialize) in its next client release; ordering otherwise matches. |
| Message identity | `mid` deterministic from (channel, sender, type, round) (§6.1) | None | App adopts with the envelope. |
| Code alphabet and normalization | §5.1 | Identical (aligned 2026-08; minimum 10 characters after normalization) | None. |
| Participants | Envelope n-party; WebSocket binding `n_max = 2` (§7.1) | Relay enforces exactly two (one sender, one receiver) since v0.9.1; one session per connection; 30-second join deadline | Relay makes the limit configurable when n>2 opens (§1.3, Appendix B item 4). |
| Relay join (§7.1) | Text message of 64 hex characters; `joined` / `full` / `invalid` replies; hello replay to a later joiner | JSON join message; the app's own peer-arrival events, not a relay replay, trigger the hello exchange | App adopts the spec join with the other wire-breaking rows. |
| Ceremony messages (§6.6–6.7) | SAS_REVEAL, then SESSION_INIT, KEY_CONTRIBUTION (each → all), local descriptor assembly (§6.6a), DESCRIPTOR_CONFIRM, pre-funding checkpoint, SESSION_FINALIZE; PSBT_REQUEST/RESPONSE/COMBINE with signer checks and approval | None — files and QR payloads relayed opaquely | Build (grant milestone). |
| SAS (§6.8) | Mandatory checkpoint over keys and committed nonces, before any ceremony message | None | Build; construction pending external review (§1.3). |
| Air-gap bridge (§7.3) | Envelope or native payload across the gap; `bridged: true`; device-shown first address MUST be used in comparison (§6.6a) | Native payload across the gap (BC-UR and BBQr encode/decode shipped in v0.9.0); no `bridged` flag because there is no envelope | Follows the envelope change. |
| Nostr (§7.2) | Planned | None | Specify, then build. |
| Timers (§8.2) | 15 min idle / 60 min absolute | Same (`server.js`) | None. |
| Rejoin (§8.3) | Same `pk` resumes; new `pk` ignored | On `peer_left` the app wipes the session key and performs a fresh handshake with whoever joins next; it does not resume | The spec's rule is stricter and wins. |

The app's "protocol v1 → v2" change (2026-09) is the one case where the app led the specification: deriving the channel identifier from the stretched key rather than the raw code (finding S12) was a security fix shipped in the app, and §5.2 reflects it.

---

# Appendix A — Extensions (specified, not required for v0.1)

## A.1 Asynchronous sessions: prekey profile

Goal: participants need not be online simultaneously; forward secrecy must survive. Design is X3DH-shaped but simpler, because MSP peers already share a secret (`K_code`), which does the authentication work X3DH needs identity keys for.

**Publish:** the responder generates a signed prekey `SPK` and a batch of one-time prekeys `OPK_i` (all X25519), and posts a bundle to the transport's store-and-forward location:

```
bundle = { spk, spk_expiry, [opk_1..opk_k], ctr_bundle,
           mac = HMAC-SHA256(K_code, "MSP-V1-PREKEY" || all fields) }
```

The MAC under `K_code` is the minimum authentication: a bundle not posted by a codeholder is rejected, closing the attacker-posts-first bundle substitution attack. **(Under-specified, deferred with the profile.** `"MSP-V1-PREKEY" || all fields` does not yet give a byte-level layout — the same class of defect fixed in §5.3 and §6.8. Before the async profile is normative it MUST specify the exact serialization of the bundle fields per the §3 concatenation convention: fixed widths for `spk`, `spk_expiry`, the `opk` count and run, and `ctr_bundle`, with lengths stated. Recorded here so the pattern is not rediscovered later.) Where the code may be low-entropy, implementations SHOULD upgrade the code to a strong shared key via a PAKE (password-authenticated key exchange — CPace) in one asynchronous round trip before trusting bundles. **Note (2026-11-18):** a bundle MAC under a key derived from the human secret is itself a password verifier — a relay holding the bundle can test code guesses offline against it, exactly as it can against the §5.3 hello MAC. If the PAKE profile (A.2) is to claim that guessing is online-only, the bundle MUST be authenticated under the PAKE-derived key, not under `K_code`, and the profile MUST say which key exists at the moment the bundle is posted.

**Send (initiator, responder offline):** fresh ephemeral `EK`; `ikm = X25519(EK, SPK) || X25519(EK, OPK_i)`; session key via HKDF with `K_code` as salt; encrypt; publish ciphertext + `pk(EK)` + `opk_id`; **delete `EK` private key immediately.**

**Receive (responder, later):** recompute, decrypt, then **delete `OPK_i` private key immediately.** Forward secrecy comes from these two deletions, not from the handshake.

**Key custody:** prekey private keys must survive between visits. The normative mechanism for a browser implementation is an **exported pending-session key file** the user keeps and can destroy — deleting the file is the visible forward-secrecy event. Rationale over IndexedDB (browsers do not promise erasure) and over passphrase-derived keys (regenerable = never deleted = no FS at all) is in the explainer. **Consequence that MUST be documented publicly:** "no persistent state" becomes "no persistent state except a pending-session file, whose deletion is in your hands."

**Depletion, staleness, replay:** refuse (do not silently downgrade) when one-time prekeys are exhausted; `spk_expiry` MUST be enforced; `ctr_bundle` strictly increases so an old bundle cannot be re-pinned.

## A.2 Async authentication upgrade (PAKE)

CPace over two asynchronous messages upgrades a human-memorable code into a full-strength key that an offline attacker cannot brute-force from transcripts. Two async messages are acceptable: async never required simultaneity, only a round trip allowed to take a day. **The claim holds only if nothing derived from the code is published (2026-11-18).** Under the §5 join the relay sees two offline verifiers for the code — `channel_id` (§5.2) and the hello MAC (§5.3) — and under A.1 a third, the bundle MAC. A PAKE profile that left any of them in place would still permit offline guessing. The split-code design proposed in review question Q3 therefore separates a public rendezvous locator (random, or derived from a non-secret half of the code) from the human secret, replaces the HMAC hello with the CPace exchange, and authenticates the bundle under the PAKE output. All three substitutions are required for the online-only claim; the profile is not specified until they are.

## A.3 Multiple initiators (reserved)

Message types 64–127 reserved. Would allow co-proposed SESSION_INIT terms. Descriptor assembly is already symmetric (§6.6a), so this concerns only who may propose terms. Out of scope for v1 by explicit decision, so implementers do not fork the spec to add it incompatibly.

## A.4 In-session symmetric ratchet (precondition for persistent transports)

Per-pair, per-direction chains with **independent directional roots** (corrected 2026-11-18): `CK_0^{dir} = HKDF(K_AB, "MSP-V1-CK-ROOT" || dir)` for `dir` ∈ {0x00, 0x01} as in §6.4, after which `K_AB` itself MUST be deleted; then `MK_i^{dir} = HKDF(CK_i^{dir}, "MSP-V1-MK")`; `CK_{i+1}^{dir} = HKDF(CK_i^{dir}, "MSP-V1-CK")`; encrypt message `i` in direction `dir` with `MK_i^{dir}`; delete `MK_i^{dir}` and `CK_i^{dir}` immediately after use. (draft.1 seeded both directions with `CK_0 = K_AB` under identical labels, so at equal chain index the two directions derived the same message key, and retaining the slower direction's chain undid the erasure in the faster one; the directional root and the deletion of `K_AB` are the fix.) Envelope `ctr` doubles as the chain index; out-of-order receipt within a bounded window keeps skipped `MK`s briefly, then destroys them; the window size, the retention time, and the behavior on restart from the pending-session file MUST be specified before this appendix is normative. Gives within-session forward secrecy against device compromise while ciphertext persists on relays. Limits stated plainly: no post-compromise security (only a fresh DH re-handshake restores that; REQUIRED after 1,000 messages or 24 h, whichever first), and resumable chain state stored between visits becomes the new thing to protect (it lives in the pending-session file, A.1).

## A.5 MLS considered, deferred

A multisig quorum is a group, and MLS (RFC 9420) is the standard for async group secrecy with post-compromise security; NIP-EE/Marmot binds it to Nostr. Deferred because: a browser MLS implementation is directly hostile to the single-file, one-person-auditable property; pairwise n²  cost is trivial at multisig scale (n ≤ ~7); and v0.1 sessions are short-lived, which is the case MLS is least needed for. Revisit trigger: if MSP grows long-lived groups (recurring signing quorums with membership change), MLS via Marmot is the design to adopt rather than extending A.4 — this is recorded now so the future decision is a comparison, not a rediscovery.

## A.6 Asynchronous descriptor evidence (precondition for A.1)

**History.** Draft.1 of this appendix addressed a coordinator that proposed different descriptors to different participants, with broadcast signed ACKs and an n-signatures finalization rule. The 2026-10-06 revision removed the coordinator from descriptor assembly altogether (§6.6a): every participant assembles from records it received directly from each cosigner, and DESCRIPTOR_CONFIRM plus the pre-funding checkpoint close the synchronous case (the SAS bound `descriptor_hash` from 2026-10-06 to 2026-11-09 and no longer does, §6.8). What remains of this appendix is the part the live checks cannot supply: evidence that survives when participants are never online together.

**Note (2026-11-09).** Since the SAS commitment was adopted (§5.3, §6.8) the SAS no longer requires simultaneity: with no offline search available, the string can be compared later over a verified text channel, and because it covers the session keys it detects an interposer that a comparison of the resulting wallet cannot. Whether that comparison suffices for this profile is review question Q2; the text below predates it and is retained until the review answers.

**Problem.** Asynchrony (A.1) removes the SAS: it cannot be computed before the last participant joins, and it requires all participants reachable at one instant to compare a string. DESCRIPTOR_CONFIRM still runs, but its authenticity rests on the session layer, and in an async session code knowledge is the only membership credential (§4.2). A participant returning days later needs evidence it can re-verify offline that the *holders of the cosigner keys* — not merely holders of the code — agreed to this wallet.

**Required in any asynchronous profile.**

1. **`wallet_sig` becomes REQUIRED** in DESCRIPTOR_CONFIRM. It must be made by the contributed key (or a key derived from it at the first receive path). **This is a real adoption limit:** it requires the signing device to sign an arbitrary message with its multisig key, and testing in October 2026 found that common wallets do not even export signed BSMS Round-1 records. Devices that cannot produce `wallet_sig` are excluded from asynchronous sessions rather than silently degrading them, and the set of devices that can is expected to be small until vendors add support.

2. **Signature scope.** `wallet_sig` covers, per the §3 concatenation convention with widths stated: an ASCII domain-separation string (`MSP-V1-WALLET-SIG`), `channel_id` (§5.2), `descriptor_hash` (§6.6a), and a session expiry. Binding `channel_id` prevents cross-session replay of a CONFIRM, which persistent transports (§7.2, A.1) make a live concern.

3. **Import rule.** A participant MUST NOT import or fund the wallet until it holds `n` DESCRIPTOR_CONFIRMs over an identical `descriptor_hash`, each carrying a `wallet_sig` verifiable against a distinct key in the descriptor, and together covering every key exactly once.

**Why the contributed key and not the session key.** A signature under a participant's session key proves only that some holder of the session code agreed, and code knowledge is precisely what the adversary may hold (§4.2). A signature under the contributed cosigner key proves that the holder of that key saw this exact descriptor — and can never be produced over a descriptor that omits the signer's own key.

**Bridged contributions.** An air-gapped device signs its own CONFIRM, so the bridge attests only to faithful transcription, which is all §7.3 ever claimed.

**Evidence is retained while key material is destroyed.** A.4 deletes chain keys and message keys as they are used. Signed CONFIRMs are not key material and MUST persist for the life of the wallet, in the pending-session file (A.1) or equivalent; a returning participant needs them to re-verify what it agreed to.

**Irreducible out-of-band step.** Signed CONFIRMs prove key possession, not identity: they establish that the holder of a key agreed to this wallet, not that this person is the intended cosigner. One human confirmation therefore survives — before funding, each participant compares the wallet's **full first receive address** (§6.6a step 6) with the people it intends to share a wallet with, over an authenticated channel as defined in §6.8. Unlike the SAS this comparison is over a stable value and need not be simultaneous; a participant may send it by verified message and another may check it days later. The full address is required, not a short fingerprint: with no live commitment phase and unlimited time, an attacker substituting keys can search for colliding short fingerprints (the §6.8 birthday search, with no timer), whereas a full P2WSH address (256 bits) is beyond such a search. The address is also what BSMS asks participants to confirm and what every wallet and signing device displays.

**What asynchrony costs.** In a live session the SAS detects an interposed party *before* any ceremony content is exchanged — true as of the 2026-11-18 revision, which put the reveal and the comparison ahead of every other message (§6.8); under draft.1 the account keys had already been sent by the time the SAS was compared, and this sentence was false. In an asynchronous session there is no such moment, and what is detected afterward depends on what the interposed party did:

- **If it substituted keys** (an attempt at theft), the participants' first addresses differ, the comparison fails, and the wallet is never funded. Theft is prevented.
- **If it only read and relayed everything unchanged**, every participant assembles the same honest wallet, the first addresses match, and *nothing in this comparison reveals the interception*. The contributed xpubs and the descriptor have been disclosed — a permanent loss of privacy for that wallet (anyone holding them can watch every address it will ever use) — and no one knows.

The second case is why the asynchronous comparison SHOULD also cover a value bound to the session's key material, not only to the resulting wallet, so that a reading interposer is detected after the fact even though it could not be prevented. Defining that value for the prekey profile is open (review question Q2) and MUST be resolved before A.1 ships. User-facing documentation for any asynchronous profile MUST state both cases.

**Recovery after a detected interception (any profile).** A setup that fails its comparison, or in which an interposed party is otherwise detected, MUST be discarded: nothing from it may be imported or funded. A redo is safe only if it does not reuse what was exposed. The redo MUST use a new session code distributed over a different channel from the one that carried the compromised code, since that channel is the likeliest point of compromise. Participants SHOULD contribute **new** account-level keys (a different BIP-32 account index or, where the signing device supports it, a different derivation) rather than re-contributing the same xpubs: the exposed xpubs cannot be used to steal — they carry no private keys — but a wallet rebuilt from them is a wallet the attacker can watch from its first transaction. Implementations SHOULD present this guidance when a comparison fails. Implementations MUST NOT present a wallet as verified until the user asserts the comparison was made, and user-facing documentation MUST NOT let "participants need not be online together" be read as "no verification is needed."

**Status:** not required for v0.1 (synchronous). Required before the asynchronous prekey profile (A.1) ships. Recorded here so the constraint is a design input rather than a later rediscovery.

---

## A.7 Signing-device profile (specified, not required for v0.1)

**Goal.** Let an air-gapped signing device take part in a session as a full participant, so that the online device bridging it — a browser page, a coordinator wallet, a phone — is reduced to a courier that carries sealed envelopes between the device's QR display and the transport. The bridge then learns nothing it does not already learn as a relay would (§4.2, §7.4): not the session code, not any participant's xpub, not the descriptor, not the PSBT contents beyond what the device chooses to send in clear. It can delay or drop messages; it cannot read or alter them. Without this profile, §6.6a's "verify on the signing device" rule protects wallet integrity against a compromised bridge but not confidentiality, and the terms and SAS are shown only by software the participant may not be able to trust.

**Status.** Not part of v0.1 conformance. Specified now so that the envelope format and the QR binding (§7.3) are designed with it in mind, and so a device vendor can evaluate it against a stable description. Implementation by a device vendor is expected only after freeze (§13).

**Roles.**
- The **device participant** runs §5 and §6 itself: it holds the session code, `K_code`, its ephemeral X25519 key, and every pairwise key; it assembles the descriptor (§6.6a); it computes and displays the SAS.
- The **bridge** moves bytes. It joins the transport using the public `channel_id`, which the device supplies, and relays messages between the transport and the device's QR interface. It MUST NOT be given the session code.

**Code entry.** The session code MUST be entered on the device itself (by keyboard or the device's own entry interface), or generated on the device and displayed for the participant to share. It MUST NOT be scanned from the bridge's screen: a code the bridge displayed is a code the bridge knows, which returns the bridge to full trust.

**What the device MUST display** before the corresponding step proceeds: the ceremony terms, for consent (§6.6); the participant count and SAS (§6.8); whether its own key is present and the first receive address (§6.6a); and, for signing, the transaction it is asked to sign, as signing devices already do.

**Message flow (setup, n participants; order revised 2026-11-18).** Each arrow is one QR pass, animated where needed.
1. Device → bridge: its hello (§5.3, 109 bytes — fits one QR) and `channel_id`.
2. Bridge → device: the other participants' hellos. The device verifies every hello MAC and derives pairwise keys.
   Device → bridge: its SAS_REVEAL, one envelope per peer (n−1 envelopes, because encryption is pairwise).
3. Bridge → device: the peers' SAS_REVEALs. The device verifies the openings and displays the participant count and SAS for comparison (§6.8); the user confirms on the device.
   Device → bridge (initiator only): SESSION_INIT, n−1 envelopes.
4. Bridge → device (non-initiators): the SESSION_INIT envelope. The device displays the terms; on consent:
   Device → bridge: its KEY_CONTRIBUTION, n−1 envelopes.
5. Bridge → device: the peers' KEY_CONTRIBUTIONs. The device assembles the descriptor and displays whether its own key is present and the first address.
   Device → bridge: its DESCRIPTOR_CONFIRM, n−1 envelopes.
6. Bridge → device: the peers' DESCRIPTOR_CONFIRMs. The device checks them and shows the first address for the pre-funding checkpoint (§6.6), which in this profile is read from the device by construction.

Signing is SAS_REVEAL out and in, then PSBT_REQUEST in and PSBT_RESPONSE out, with the approval display (§6.7) on the device. The profile adds one QR round trip to each kind of session compared with draft.1; it buys a SAS and an address shown by a screen the bridge cannot alter.

**Open items (MUST be resolved before this profile is normative).**
- *Bundle format.* Passes 2–4 carry several envelopes at once. A QR container for multiple envelopes (for example, a CBOR array of envelope byte strings carried as one `ur:bytes` or BBQr sequence) must be specified.
- *Payload size per pass.* Because encryption is pairwise, a broadcast costs n−1 envelopes, so QR volume grows with n. The §7.3 size table must include device-profile passes; a broadcast-encryption optimization may be warranted for n ≥ 4.
- *KDF cost on device hardware.* PBKDF2-HMAC-SHA512 at 300,000 iterations may take tens of seconds or more on a microcontroller. It must be measured on representative devices. `kdf` is session-wide — every participant must derive the same `K_code` — so a cheaper device-friendly KDF would lower the cost for every participant's attacker, not only the device's; if one is defined, it must be paired with a longer minimum code length that restores the same offline-guessing margin, or wait for the PAKE join (A.2), under which the KDF cost matters far less.
- *State lifetime.* The device holds pairwise keys across several QR passes, possibly minutes apart. It MUST keep them only in volatile memory and erase them at session end or on power loss; the §8.2 timers apply.
- *Code entry without a keyboard.* Devices without a keyboard need an on-device entry method practical for 10+ characters, or must generate the code on the device.

**Conformance.** A future *device role* (§9) would be the signer role (§9) with the QR binding (§7.3) in place of the WebSocket binding, the bundle format above, and the display requirements above as MUSTs.

# Appendix B — Items that MUST be resolved before freeze

1. Test vectors (§10).
2. Nostr binding details: exact event kinds, gift-wrap parameters, expiration handling (§7.2).
3. PAKE selection and parameters if adopted for A.2 (CPace proposed).
4. n>2 relay behavior (v0.1 reference relay binding sets `n_max = 2`; the envelope and ceremony layers are already n-party). Preconditions, all smaller than the draft.1 requirement (A.6, now withdrawn for the synchronous case): (a) §6.6a implemented against the §10.4 vector by at least the reference implementation; (b) DESCRIPTOR_CONFIRM implemented; (c) the relay's `n_max` lifted; (d) **a membership mechanism** (added 2026-11-18): under the §6.8 order each participant must know the full expected set of participants before it sends its SAS_REVEAL, and SESSION_INIT, which carried `n` in draft.1, now comes after the reveal; the group profile must say where that count comes from (a signed participant list from the initiator sent before the reveals, a count in the code, or another construction) and the Q1 argument must be restated for it; (e) the group profile must also say how a requester and a subset of signers select each other for signing, and how concurrent requests are identified (the D-17 analysis in `msp-next`). A.6 remains a precondition only for the asynchronous profile.
5. ~~Formal grammar for `derivation_template` (§6.6).~~ **Closed 2026-11-05:** v0.1 restricts the template to the BIP-48 forms (§6.6); a grammar replaces the restriction when a second implementer needs a path outside them.
5a. ~~P2TR assembly (§6.6a step 3, `script_type = 1`).~~ **Closed 2026-11-05:** `script_type = 1` is reserved and rejected in v0.1; Taproot multisig is deferred to a later version (§6.6).
6. External review of session establishment by a cryptographer, against the questions in `review-questions.md`: (Q1, revised 2026-11-09 and 2026-11-18) the commitment-in-hello SAS adopted in §5.3/§6.8, in this revision's schedule (both parties reveal in a dedicated message after holding each other's hello, before any other message) — is the "reveal only after holding every commitment" rule sufficient over pairwise channels with an interposed party, first for two parties and then for n; is removing `descriptor_hash` from the SAS sound given DESCRIPTOR_CONFIRM under authenticated keys; what SAS length is acceptable given the online-only bound; (Q2) whether the SAS compared later over a verified text channel suffices for the asynchronous profile (A.6); (Q3) whether the split-code + CPace join eliminates the offline guessing the §5.3 join permits; (Q4) the A.1 bundle MAC. This document was not written by a cryptographer, and §5.3, §6.8, and A.1 are where an expert is most likely to find a flaw. The design study behind the adopted SAS construction, including an independent adversarial check, is `notes/sas-commitment-study-2026-11-07.md`.
7. Per-transport metadata tables (§7.4) for the WebSocket relay and for Nostr: what the operator observes, what it never observes. Required by §7.4; not yet written.
8. Per-message-type payload-size budget and QR frame-count table (§7.3), measured on named signing devices (SeedSigner, Krux, Coldcard) rather than taken from format specifications. The budget MUST include a PSBT_REQUEST whose inputs each carry a full previous transaction (§6.7(e)), since that is the form a verified fee requires and it is the largest message the protocol carries.
9. ~~Message identity random~~ **Closed 2026-11-05:** deterministic identity adopted (§6.1, ERROR code 9).

