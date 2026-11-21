# Multisig Session Protocol (MSP)

**An encrypted session layer for remote bitcoin multisig setup and signing.**
Draft specification · `v0.1-draft.2` (2026-11-18) · not frozen · no conforming implementation yet · no external review yet

[![vectors](https://github.com/KeylayBTC/msp/actions/workflows/vectors.yml/badge.svg)](https://github.com/KeylayBTC/msp/actions/workflows/vectors.yml) · [Specification](spec/msp-spec-v0.1-draft.md) · [Explainer](spec/msp-explainer.md) · [Test vectors](vectors/) · [Review questions](spec/review-questions.md) · [Discussion on Delving Bitcoin](DELVING-URL) · [Changelog](CHANGELOG.md)

---

## What this is

BIP-129 (BSMS) standardized the file a multisig setup produces. Nothing standardizes how cosigners who are not in the same room exchange it — or the PSBTs that follow — so today that traffic goes over email, chat apps, or a vendor's server, and a compromised coordinator can substitute cosigner keys without any signer noticing.

MSP defines the three things BSMS and PSBT leave undefined for remote participants:

1. **Session establishment** — how participants who share a short code out of band form a private, ephemeral, encrypted channel over an untrusted relay.
2. **Message vocabulary** — typed, authenticated, replay-protected envelopes that carry key contributions, descriptors, and PSBTs. Setup is symmetric: every participant sends its key to every other participant, assembles the wallet descriptor itself by a deterministic function, and confirms that everyone assembled the same one. Nobody distributes a descriptor, so there is no coordinator to compromise. Every signer refuses to sign a PSBT that does not spend from that descriptor.
3. **Transport bindings** — a WebSocket relay, Nostr (planned), and QR codes across an air gap (BC-UR / BBQr).

It defines no payload formats, no wallet logic, and no identity system. A wallet that already implements BSMS has most of what it needs.

## What runs today

[Keylay](https://app.keylay.org) ([source](https://github.com/KeylayBTC/keylay), MIT) is a single-file browser application that implements the session layer for two parties and the QR/file air-gap bridge, live since 2026. It is the basis for a future reference implementation. **It does not conform to this specification:** it uses different domain-separation strings and framing, and it does not yet implement the ceremony messages. Every known difference is in the spec's §14, *Relationship to the shipping app*.

## Threat model in one paragraph

The relay is the adversary: it sees ciphertext, the rendezvous identifier, and network metadata (IP addresses, timing, sizes), and it may drop, delay, duplicate, reorder, or inject. There is no coordinator: the initiator proposes terms, which every participant must accept and which the short authentication string (SAS) proves everyone holds identically, and has no other privileged role. Keys and descriptors are never distributed by any party. The session code is a secret shared out of band; if it is intercepted before the session, the SAS is the last line of defense. What the protocol does **not** defend against: a compromised signing device, a compromised web origin serving the client, and relay-visible metadata. Full statement: spec §4.

## Limitations of this draft

Read these before the spec. They are stated at greater length in spec §1.3.

- **Two clients at a time.** A v0.1 session has two participants. Setup therefore creates **two-key wallets** (threshold 1 or 2); signing works for any wallet both parties hold on BIP-48 paths, however it was created, so a 2-of-3 made elsewhere is signed by two of its cosigners in one session. The ceremony layer is n-party by construction; a three-key setup waits for the group-session work (Appendix B item 4).
- **Both parties online.** Asynchronous sessions are the version-2 target. A profile is specified (Appendix A.1); it is not part of v0.1.
- **No external cryptographic review.** The SAS (§6.8) was found in October to lack a commitment phase; this draft adopts a commitment-in-hello construction (each hello commits to a nonce; both nonces are revealed in a dedicated message and the SAS is compared before any terms, keys, or transactions are sent) that the author believes restores the intended bound, pending review ([#1](ISSUE-1)). An external *design* review of draft.1 was received and closed on 2026-11-18; draft.2 is the result. That review did not cover the cryptography. The join (§5.3) uses an HMAC under a stretched code rather than a standardized PAKE; a split-code CPace join is proposed and not adopted ([#3](ISSUE-3)). Both are stated in the spec's own words in [`spec/review-questions.md`](spec/review-questions.md).
- **Test vectors incomplete.** Normalization, the hello with its commitment and MAC, the SAS over keys and nonces, and descriptor assembly have vectors; pairwise key derivation, envelope encryption, and the end-to-end setup and signing transcripts do not yet. `spec/conformance-suite-spec-v0.1-draft.md` describes draft.1 and is marked superseded; its rewrite is scheduled.
- **No Taproot multisig.** `script_type = 1` is reserved and rejected in v0.1.
- **No post-quantum protection.**
- **Relay metadata is not hidden.** Nostr changes who runs the relay, not what a relay sees. IP privacy requires Tor.

## Test vectors

`vectors/v1/*.json` are machine-readable known-answer tests for §5.1–5.3, §6.6a, and §6.8. `tools/verify-vectors.py` recomputes every value from the inputs with the Python standard library (addresses additionally need `pip install embit`) and exits non-zero on any mismatch:

```
python3 tools/verify-vectors.py
```

The same command runs in CI on every push; the badge above is its result. See [`vectors/README.md`](vectors/README.md) for what each file contains and how to add one.

## Status and process

- The spec is versioned here, in the open. Every normative change is dated in [`CHANGELOG.md`](CHANGELOG.md) and in the spec's own revision note.
- **Freeze** (spec §13) means: test vectors published; two independent interoperating implementations of the signer role; no normative change for 90 days. Only after freeze may anything be called a reference implementation.
- The standardization venue (BIP, self-published, IETF) is deliberately undecided until a second implementation exists.
- Known defects are filed against the spec in [`spec/defects/`](spec/defects/) and in Issues — including the ones found by the author.
- Items that must be resolved before freeze are listed in the spec's Appendix B.

## Related work

Blind Relay / Signing Room (Carlin, 2026) — relay confidentiality, SDK, capability-token access control; no key agreement, SAS, or descriptor binding. Turon (2026) — transport invariants for PSBT/MuSig2 over at-least-once relays; this spec adopts its message-identity and sequencing rules. BSMS, PSBT, BIP-48, BC-UR, dCBOR, BCR-2024-004/GSTP, Hubert, NIP-46, X3DH, CPace, ZRTP, MLS — see spec §4.4, *Prior and related work*.

## How to get involved

- **Review** the open constructions ([#1](ISSUE-1)–[#4](ISSUE-4)). This is the most valuable thing a reader with a cryptography background can do. Each issue states what the author believes, so a reviewer can answer "yes, because…" or "no, because…" rather than start from nothing.
- **Implement the signer role** in any language against `vectors/`. The signer role is deliberately small (spec §9). A partial implementation that fails a vector is more useful than a review that agrees in prose.
- **Hardware-wallet and coordinator maintainers:** tell us what payload-size and frame-count limits your device reads reliably ([#5](ISSUE-5)); spec §7.3 needs the numbers.
- **Ask.** Issues and Discussions are open. Delving Bitcoin thread: [link](DELVING-URL).

Presented at Blockchain Commons' Gordian Developers meeting (August 2026) and TABConf 8 (October 2026).
Contact: Stan Reeves · contact@keylay.org · [@onedigitmoney](https://github.com/onedigitmoney)

## License

Specification text and explainer: [CC0-1.0](LICENSE-CC0). Test vectors and tooling: [MIT](LICENSE-MIT).
