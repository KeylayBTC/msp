# MSP Conformance Suite — Specification v0.1 draft

*Renamed 2026-10-07: the protocol is now the Multisig Session Protocol (MSP); domain-separation strings are `MSP-V1-*` and the hello is a fixed 77-byte string beginning with the version-free magic `MSP-HELLO`, whose first 45 bytes are the MAC input. Vectors referenced here must be regenerated against the renamed spec.*

> **Supersession note (2026-11-18). This document describes protocol draft.1 and is stale.** It specifies the 77-byte hello, a SAS without a commitment, the nonce in KEY_CONTRIBUTION, and a single freeze rule. Protocol **v0.1-draft.2** (2026-11-18) changes all of these: the hello is 109 bytes with a nonce commitment; `SAS_REVEAL` is the first encrypted message in every session and the SAS is compared before any ceremony message; there are two freezes and an opening-message rule; `KEY_CONTRIBUTION` field 4 and `ERROR` body field 3 are withdrawn; `PSBT_REQUEST` gains `network`; counters are consecutive; new error codes 11 and 12. No test in this document should be implemented as written. The rewrite against draft.2 is scheduled project work; until it lands, the protocol spec and its `vectors/` are the only conformance evidence, and where this document and the spec disagree, the spec wins (CS-§9.4).

**Status:** DRAFT, SUPERSEDED (see note above). Companion to `msp-spec-v0.1-draft.md` (hereafter **the protocol spec**). Section references in the form §5.2 refer to that document; references in the form CS-§4 refer to this one.
**Date:** August 2026
**Normative dependency:** this document is subordinate to the protocol spec. Where they disagree, see CS-§9.4.

> **Supersession note (2026-10-06).** The protocol spec adopted symmetric descriptor assembly: KEY_CONTRIBUTION is now each → all; DESCRIPTOR_PROPOSAL and DESCRIPTOR_ACK are withdrawn and replaced by DESCRIPTOR_CONFIRM (each → all); slot assignment and the `slot_conflict` error are withdrawn; a normative assembly function §6.6a and its vector §10.4 were added; the SAS binds `descriptor_hash`; the *coordinator* role is now *initiator*; A.6 applies only to the asynchronous profile. Every test in this document that references PROPOSAL, ACK, slots, or coordinator-side verification (including S-30) must be re-derived against the revised spec before Tier 1 is published. Until then, where this document and the spec disagree, the spec wins (CS-§9.4).

---

## CS-§1 Purpose and scope

### 1.1 Why this exists

The protocol spec states the problem in one line (§10): *"A spec without test vectors produces implementations that agree in prose and disagree in bytes."* This document specifies the artifact that closes that gap.

It is also directly load-bearing for the freeze criteria. §13 defines freeze as three conditions: **test vectors published**, **two independent interoperating implementations of the signer role**, and **no normative changes for 90 days**. The first two are not achievable by good intentions — they require a runnable artifact and an agreed definition of "interoperating." This document supplies both, and CS-§9.5 makes the freeze gate mechanically checkable rather than a judgment call.

Appendix B item 1 of the protocol spec ("Test vectors") is discharged by Tier 1 of this suite. Nothing else in this document is required for freeze; the rest exists because a suite scoped to the freeze gate alone would leave roughly a third of the protocol's normative requirements untested (see CS-Appendix C).

### 1.2 What a conformance suite is for

Three distinct jobs, often conflated:

1. **Detecting divergence.** Two implementations that both "follow the spec" produce different bytes. Static vectors catch this in seconds, offline, with no counterparty.
2. **Detecting missing refusals.** The protocol's security properties live almost entirely in what an implementation *declines* to do — refuse a bad MAC silently, refuse a regressed counter, refuse to sign a PSBT not bound to a finalized descriptor. Nothing about a happy-path test exercises any of these. An implementation can pass every positive test and be catastrophically unsafe.
3. **Lowering the cost of the adoption wedge.** §9 makes the signer role deliberately small so a wallet team can implement it cheaply. A wallet team's actual first question is *"how do I know I got it right?"* A red/green answer to that question is worth more to adoption than another page of specification.

Job 2 is the one most suites neglect and the one this design weights most heavily. Roughly 60% of the specified tests are negative.

### 1.3 Non-goals

- **Not a security audit.** Passing the suite establishes protocol conformance, not the absence of vulnerabilities. Appendix B item 6 of the protocol spec — cryptographer review of the SAS construction and the prekey bundle MAC — is a separate, non-substitutable activity. The suite must never be cited as though it were one.
- **Not a benchmark.** No performance requirements.
- **Not a certification authority.** Conformance is self-declared with a published, reproducible report (CS-§9.3). There is no issuing body, no fee, and no revocation mechanism, because inventing one before a second implementation exists would be governance theater.
- **Does not test payload semantics.** BSMS record validity, descriptor construction, and PSBT parsing are wallet logic, not protocol logic (§1.1). The suite tests that an implementation *carries and binds* those payloads correctly, not that it understands them. One exception, stated because it is a security boundary rather than a formatting question: the coordinator's obligation to verify the BSMS signature on a bridged key contribution (§7.3) is tested, at CS-§5.3 S-30.

---

## CS-§2 Architecture: three tiers

| Tier | Name | Counterparty | Automated | Answers |
|---|---|---|---|---|
| **1** | Vector suite | None — offline | Fully | "Does your crypto and encoding produce the required bytes?" |
| **2** | Interop runner | A driver process | Fully | "Can you complete a ceremony, and do you refuse the things you must refuse?" |
| **3** | Ceremony harness | A human operator | Partially | "Do the mandatory human checkpoints actually happen, and does your documentation say what it must?" |

The tiers are strictly ordered by cost and strictly ordered by what they can prove. Tier 1 proves byte agreement and proves nothing about behavior. Tier 2 proves behavior at the wire and proves nothing about what a user sees. Tier 3 covers the requirements that are only meaningful in front of a person — and there are more of these in the protocol spec than is comfortable, because the SAS check (§6.8), the note field (§6.1), and the descriptor verification (§6.6) are all human-facing MUSTs.

**Design constraint on all three tiers:** the suite must not require the implementation under test to be written in JavaScript, to run in a browser, or to expose an in-process API. The wallets worth recruiting are Java (Sparrow), Rust, C++, Swift, and Kotlin codebases. A harness that taxes them is a harness they will not run. This is why CS-§4.3 defines a process-boundary adapter rather than a library interface.

### 2.1 Naming and identifiers

```
KL-<tier><group>-<nnn>
```

- Tier: `1` vectors, `2` interop, `3` ceremony.
- Group: two-letter code (`KD` key derivation, `HS` handshake, `PK` pairwise keys, `CB` CBOR encoding, `AE` AEAD, `CT` counters, `SA` SAS, `BD` bodies, `CE` ceremony flow, `TR` transport, `LC` lifecycle, `DC` documentation, `AG` air gap).
- Number: zero-padded, assigned once, **never reused**. A withdrawn test keeps its number and is marked `WITHDRAWN` with a reason.

Example: `KL-1AE-004`, `KL-2CE-017`, `KL-3SA-002`.

---

## CS-§3 Conformance claims

### 3.1 Claim structure

A conformance claim is a tuple:

```
(implementation name, version, role, transport bindings, suite version, tier levels reached)
```

**Roles** are exactly those in §9: `signer` and `coordinator`. Coordinator implies signer; a claim of `coordinator` without a passing `signer` result is invalid.

**Transport bindings** claimed independently: `websocket` (normative, §7.1), `airgap` (normative, §7.3), `nostr` (§7.2 — not yet specified in sufficient detail to test; no tests defined in this suite version).

**Tier levels:**

- **T1** — all Tier 1 vectors pass for the claimed role.
- **T2** — T1, plus all Tier 2 scenarios for the claimed role and bindings.
- **T3** — T2, plus a signed ceremony attestation (CS-§6.5) covering all checkpoints for the claimed role.

### 3.2 What a claim may say

Permitted: *"Implements the MSP signer role, conformance suite v0.1, T2."*

Not permitted, and this matters because §13 reserves the term explicitly: **"reference implementation."** That phrase is reserved until the protocol spec is frozen, and it names one specific implementation. A conformance pass does not confer it. Similarly, "MSP-certified" is not permitted — there is no certifier.

A claim SHOULD state the suite version and the git commit of the vector set it ran against. A claim without a published report (CS-§9.3) is an assertion, not a claim.

### 3.3 Claim expiry

A claim is bound to a suite version and an implementation version. It does not expire on a clock, but it is void for any implementation version that changes protocol-relevant code. Implementations SHOULD run the suite in continuous integration and publish the report per release, which makes this moot.

---

## CS-§4 Tier 1 — the vector suite

### 4.1 Form

A directory of JSON files, versioned in the protocol repository, with a stable schema. Language-neutral by construction: an implementer in any language reads JSON, calls their own functions, compares hex.

```
vectors/
  v0.1/
    manifest.json
    kd-key-derivation.json
    hs-handshake.json
    pk-pairwise-keys.json
    cb-cbor-encoding.json
    ae-aead.json
    ct-counters.json
    sa-sas.json
    bd-message-bodies.json
    transcripts/
      setup-2of3-p2wsh.json
      signing-2of3-p2wsh.json
```

`manifest.json` lists every file with a SHA-256 digest, the suite version, and the protocol wire version the vectors target. A runner MUST verify digests before running; a vector set that fails its own manifest is not a vector set.

### 4.2 Vector schema

Every vector is an object with a fixed shape:

```json
{
  "id": "KL-1KD-001",
  "spec": "§5.2",
  "desc": "Session code to K_code, canonical 10-character code",
  "kind": "positive",
  "op": "derive_kdf",
  "in":  { "code": "7k4m2xqtb9" },
  "out": {
    "k_code":     "<64 hex chars>",
    "channel_id": "<64 hex chars>"
  }
}
```

Conventions, stated once and applied everywhere:

- All byte strings are **lowercase hex**, no prefix, no separators.
- All integers are JSON numbers and MUST be exactly representable as a 64-bit unsigned integer.
- Text strings are UTF-8, given as JSON strings.
- `kind` is `positive` (implementation must produce `out`) or `negative` (implementation must reject; `out` carries the expected rejection).
- Negative vectors specify the expected rejection as `{ "reject": "<reason-code>" }` where reason codes are drawn from the §6.9 error registry plus three suite-local codes for rejections the protocol does not surface as ERROR: `silent_drop`, `ignore`, `refuse_action`. The distinction between *silently dropping* and *sending an ERROR* is itself normative (§5.3 requires silence for a bad MAC) and the suite must be able to express it.

### 4.3 The adapter contract

This is the load-bearing design decision. The implementation under test exposes a **conformance adapter** — a thin, test-only shim that answers structured commands. The adapter is not part of the shipped product and is not required to be efficient, pretty, or safe.

**Two bindings, one command schema.**

- **stdio binding (default for native implementations).** The adapter is an executable. The runner writes one JSON object per line to stdin and reads one JSON object per line from stdout. Newline-delimited JSON, UTF-8, no framing beyond the newline. This works for every language on the list without FFI, bindings, or a build system integration.
- **WebSocket binding (for browser implementations).** The adapter is a page that connects out to the runner's WebSocket endpoint and exchanges the same JSON objects as text frames. This exists because a browser-first reference implementation cannot expose a subprocess, and forcing it to would make the reference implementation unable to run its own suite.

**Command envelope:**

```json
{ "id": "<opaque request id>", "op": "<operation>", "args": { ... } }
```

**Response envelope:**

```json
{ "id": "<echoed>", "ok": true,  "result": { ... } }
{ "id": "<echoed>", "ok": false, "reject": "<reason-code>", "detail": "..." }
```

An adapter MUST answer every request. An adapter MUST NOT crash on malformed input; a rejection is a valid answer, a stack trace is not. An adapter that cannot perform an operation returns `{"ok": false, "reject": "unsupported"}` and the runner records the test as `unsupported` rather than `fail` — but any `unsupported` in a required group voids the claim for that role.

**Required operations (Tier 1):**

| `op` | Args | Result | Spec |
|---|---|---|---|
| `capabilities` | — | roles, bindings, suite version supported, optional features | CS-§3.1 |
| `set_entropy` | `stream` (hex) | — | CS-§4.6 |
| `set_clock` | `unix_ms` | — | CS-§5.5 |
| `generate_code` | `length` | `code` | §5.1 |
| `normalize_code` | `display_code` | `code` | §5.1 normalization (lowercase, strip non-`[a-z0-9]`) |
| `derive_kdf` | `code` | `k_code`, `channel_id` | §5.2 |
| `make_hello` | `k_code`, `pk`, `caps`, `kdf`, `v` | `hello_bytes` | §5.3 |
| `verify_hello` | `k_code`, `hello_bytes` | `pk`, `caps`, `kdf`, `v` — or reject | §5.3 |
| `derive_pair` | `sk_self`, `pk_peer`, `k_code`, `channel_id` | `k_ab` | §5.4 |
| `encode_envelope` | header fields, `k_ab`, `body_plaintext` | `envelope_bytes` | §6.1, §6.4 |
| `decode_envelope` | `envelope_bytes`, `k_ab` | header fields, `body_plaintext` — or reject | §6.1, §6.4 |
| `encode_body` | `type`, body fields | `body_bytes` | §6.6, §6.7 |
| `decode_body` | `type`, `body_bytes` | body fields — or reject | §6.6, §6.7 |
| `compute_sas` | `channel_id`, `pk_list`, `session_init_aad` | `sas` (formatted string) | §6.8 |
| `dump_key_state` | — | which key material is currently held | §5.4, CS-§7.2 |
| `reset` | — | — | — |

Note what is deliberately absent: there is no operation for "run a ceremony." Tier 1 tests primitives in isolation, which is what makes failures diagnosable. A failing transcript tells you the ceremony is broken; a failing `KL-1AE-004` tells you your nonce direction byte is inverted.

### 4.4 Vector groups

Each group below lists what MUST be covered. Exact counts are indicative; the requirement is the coverage, not the number.

**KD — key derivation (§5.1, §5.2).** Canonical 10-character code → `K_code` → `channel_id`. A longer code (16, 31 characters). Codes in several display groupings — `7k4m-2xqt-b9`, `7k4m · 2xqt · b9`, `  7K4M 2XQT B9  ` — must all normalize (lowercase, strip non-`[a-z0-9]`) to the same `K_code` as `7k4m2xqtb9`, including the middle-dot grouping an implementation may render. Mixed-case input (`7K4M2XQTB9`) must normalize to the lowercase canonical form, not be rejected. A user-chosen code containing the generator's excluded characters (`i`, `l`, `o`, `0`, `1`) must be **accepted as content**, and two codes differing only in a look-alike (`…bo` with letter `o` vs `…b0` with digit `0`) must derive **different** `K_code`s (no Crockford-style mapping). Negative: a code whose only-non-alphanumeric-stripped remainder is shorter than 10 characters — e.g. a Cyrillic-homoglyph code that strips to 9 characters — reject on the length floor. Negative: a code shorter than 10 characters presented to `generate_code`.

**HS — handshake (§5.3).** Hello MAC over fixed `(v, caps, kdf, pk)` with a fixed `K_code`, in both directions (construct and verify). Byte-exact serialization of the MAC input — the concatenation order `"MSP-HELLO" || v || caps || kdf || pk` needs a vector because the integer encoding of `v`, `caps`, and `kdf` inside that concatenation is a thing two implementers will guess differently. **This is a specification gap the vector will expose** and it must be resolved before freeze (CS-§11.2). Negative: single-bit flip in the MAC → reject with `silent_drop`. Negative: single-bit flip in `pk` → reject. Negative: hello with `caps` bit 5 set → **accept**, ignoring the reserved bit (§5.5); this is a positive test that looks negative and is exactly the kind of thing implementations get wrong by being over-strict.

**PK — pairwise keys (§5.4).** Fixed X25519 keypairs A and B, fixed `K_code` and `channel_id` → identical `K_AB` computed from both sides. Both orderings tested, because the whole point of `sort()` is that they agree. Negative: swapped `sort()` order produces a different key — included as a *diagnostic* vector, labelled as the expected value if you got the ordering wrong, so an implementer sees "you produced the wrong-order key" rather than "mismatch."

**CB — deterministic CBOR (§6.3).** This group will find more bugs than any other. Encode each message type's header with known values and compare bytes. Map keys sorted. Shortest-form integers at every boundary: 23/24, 255/256, 65535/65536, 2³²−1/2³². Definite-length byte and text strings. Negative: map keys out of canonical order → `decode_failure`. Negative: indefinite-length string → `decode_failure`. Negative: non-shortest integer encoding (`0x18 0x0A` for 10) → `decode_failure`. Negative: duplicate map key → `decode_failure`. Negative: trailing bytes after a complete item → `decode_failure`. An implementation that *accepts* non-canonical CBOR is a conformance failure even though it interoperates fine in the happy path, because acceptance is what lets two peers disagree about the AAD bytes.

**AE — AEAD (§6.4).** Nonce construction with `dir = 0x00` and `dir = 0x01`, at `ctr` = 1, 255, 256, 2³²−1, 2⁵³. AAD = deterministic-CBOR encoding of header fields 1–8, given explicitly as bytes in the vector so there is no ambiguity about what got authenticated. Full encrypt and decrypt round trip. Negative: AAD single-bit flip → decrypt fails. Negative: ciphertext single-bit flip → fails. Negative: GCM tag single-bit flip → fails. Negative: correct ciphertext with the wrong `dir` byte → fails.

**CT — counters (§6.5).** Not purely a vector group — the ordering requirement is stateful — but the state machine is small enough to express as a scripted sequence against the adapter. Accept `ctr` 1, 2, 3. Reject `ctr` 3 again. Reject `ctr` 2. **The ordering test:** present `ctr` 4 carrying ciphertext that fails authentication, then present a valid `ctr` 4 — the second MUST be accepted. An implementation that advanced its counter on receipt rather than on successful decryption fails here. This is the exact bug the protocol spec records as having existed in the app, which makes it the single highest-value test in the suite.

**SA — SAS (§6.8).** `sas_input` from fixed `channel_id`, a fixed sorted `pk` list of 2 and of 3 participants, with and without SESSION_INIT AAD present. Truncation to 60 bits. Rendering: 12 characters of the §5.1 alphabet, grouped `XXXX-XXXX-XXXX`. Vectors must pin the **exact string**, including the hyphens, because §6.8 makes identical rendering across implementations a MUST — users of two different implementations reading different groupings cannot complete the comparison. Negative: participant list in unsorted order produces a different SAS — diagnostic vector.

**BD — message bodies (§6.6, §6.7, §6.9).** Encode/decode for each of SESSION_INIT, KEY_CONTRIBUTION, DESCRIPTOR_PROPOSAL, DESCRIPTOR_ACK, SESSION_FINALIZE, PSBT_REQUEST, PSBT_RESPONSE, PSBT_COMBINE, ERROR, ABORT. Optional fields present and absent (the `note` field in every type; `wallet_sig` absent in DESCRIPTOR_ACK; `txid` absent in PSBT_COMBINE). Negative: required field missing → `decode_failure`. Negative: `script_type` outside the registry → `validation_failure`.

**Transcripts.** Two complete recorded sessions — a 2-of-3 P2WSH setup and a signing round — given as an ordered list of envelope bytes with all keys disclosed. An implementer decrypts the whole thing offline and checks every field. This is the highest-value onboarding artifact in the suite: it lets someone read a real session end to end before writing a line of code.

### 4.5 Negative vectors are the point

Restating, because suites drift positive over time: an implementation that passes every positive vector and no negative vector is not partially conformant. It is a security hazard that produces well-formed messages. Any future addition to the vector set SHOULD add negative cases alongside positive ones, and CS-§9.2 makes a positive-only contribution a reviewable defect.

### 4.6 Testing randomness deterministically

Two MUSTs depend on random generation and cannot be tested by comparing output to a fixed value: code generation with rejection sampling (§5.1), and ephemeral keypair generation (§5.3).

**The wrong approach** is statistical — generate a million codes and chi-square the character distribution. It is slow, it is probabilistic, and it fails to distinguish "no bias" from "bias too small for this sample."

**The specified approach is entropy injection.** `set_entropy` installs a deterministic byte stream that the implementation's test build draws from in place of its CSPRNG (cryptographically secure pseudo-random number generator — the operating system's randomness source). The runner then feeds a crafted stream:

```
stream = [0xF8, 0xFF, 0x00, 0xF9, 0x01, 0x1E, ...]
         (248, 255, 0,   249,  1,   30)
```

Bytes 248, 255, and 249 are ≥ 248 and MUST be rejected outright, not reduced. The correct implementation consumes six bytes and emits three characters (from 0, 1, 30 → alphabet positions 0, 1, 30 → `2`, `3`, `Z`). An implementation doing naive `byte % 31` emits six characters and a different string. The test is exact, deterministic, and instantaneous.

A chi-square smoke test over 100,000 generated codes is specified as a **secondary, advisory** check (`KL-1KD-090`), reported but not claim-voiding, for implementations that cannot expose entropy injection.

**Implementations that cannot support `set_entropy`** report `unsupported` and lose T1 for the KD group. This is deliberate pressure: a test build with an injectable RNG is a small cost and it makes an otherwise-untestable security requirement testable.

### 4.7 Report format

The runner emits one JSON report:

```json
{
  "suite_version": "0.1",
  "vectors_commit": "<git sha>",
  "manifest_sha256": "<hex>",
  "implementation": { "name": "...", "version": "...", "adapter_binding": "stdio" },
  "claimed": { "role": "signer", "bindings": ["websocket"] },
  "started_utc": "...", "duration_ms": 0,
  "totals": { "pass": 0, "fail": 0, "unsupported": 0, "skipped": 0, "advisory_fail": 0 },
  "results": [
    { "id": "KL-1AE-004", "status": "fail",
      "expected": "<hex>", "actual": "<hex>", "spec": "§6.4",
      "diagnostic": "nonce direction byte inverted — see KL-1AE-004D" }
  ]
}
```

The `diagnostic` field is optional and is where the suite earns its keep. A mismatch that just says "expected X got Y" costs an implementer an afternoon. A mismatch that says "your output matches the known wrong-order variant" costs them a minute. Diagnostic vectors (the deliberately-wrong variants noted in the PK and SA groups) exist to make this possible, and the runner MUST compare a failure against them before reporting.

---

## CS-§5 Tier 2 — the interop runner

### 5.1 Model

One **driver** (a known-good implementation of the counterpart role, maintained alongside the spec) and one **implementation under test** (IUT). They speak the real protocol over the real WebSocket binding. The driver is scriptable and, critically, **can be instructed to misbehave**.

The driver is not a neutral peer. Roughly two-thirds of the scenarios exist to make the IUT refuse something, and a driver that can only behave correctly can only test a third of the protocol.

Both directions are required for a coordinator claim: the IUT is driven as a signer (driver plays coordinator) and as a coordinator (driver plays signer).

### 5.2 Environment

- A **loopback relay** ships with the suite: a minimal WebSocket relay implementing §7.1 exactly — channel grouping, two-connection limit, 256 KB frame cap, configurable timers. It runs on localhost. No hosted infrastructure is required to run Tier 2, which matters both for CI (continuous integration — automated test runs on every code change) and for the protocol's own claim that no project-operated infrastructure is needed.
- The relay is additionally the *subject* of a small scenario group, since §7.1 places real obligations on relays and a relay implementer needs something to test against.
- **Injected clock.** Timer scenarios (15-minute idle, 60-minute absolute) run against a virtual clock via `set_clock`. An IUT that cannot accept an injected clock may substitute a configuration override reducing the timers to seconds, declared in the report.
- **Seeded entropy.** Session codes and ephemeral keys come from a fixed seed so a failing run reproduces exactly.

### 5.3 Scenario catalogue

**Happy path** — necessary, not interesting.

| ID | Scenario | IUT role |
|---|---|---|
| S-01 | Full 2-of-3 setup ceremony to SESSION_FINALIZE | signer |
| S-02 | Signing round to PSBT_COMBINE | signer |
| S-03 | Full setup, IUT assembles the descriptor | coordinator |
| S-04 | Signing round, IUT combines | coordinator |

**Layer 1 refusals** — §5.3, §5.5.

| ID | Driver does | IUT must |
|---|---|---|
| S-05 | Hello with a bad MAC | Emit *nothing* — no ERROR, no close. Verified by observing silence for a bounded window. A response is a failure. |
| S-06 | Second hello, same peer, **different** `pk`, mid-session | Ignore it; continue on the existing pairwise key |
| S-07 | Second hello, same peer, **same** `pk`, after a transport drop | Resume with existing keys and counters intact |
| S-08 | Hello with `v = 2` | ERROR `version_mismatch` and leave |
| S-09 | Hello with reserved `caps` bit 5 set | Proceed normally, ignoring the bit |

**Envelope refusals** — §6.1–6.5.

| ID | Driver does | IUT must |
|---|---|---|
| S-10 | Replay a previously accepted envelope verbatim | Discard on counter check, before decryption |
| S-11 | Envelope with `ctr` below the high-water mark | Discard |
| S-12 | **Garbage ciphertext at `ctr` = N, then valid envelope at `ctr` = N** | Reject the first, **accept the second** |
| S-13 | Flip a bit in header field 2 (type) | Decryption fails; no action taken; no state change |
| S-14 | Envelope with non-canonical CBOR (unsorted keys) | ERROR `decode_failure` |
| S-15 | Message type 40 (reserved core range) | ERROR `unsupported_type` |
| S-16 | Message type 200 (private range) | Ignore silently; session proceeds |
| S-17 | Frame exceeding 256 KB | Reject |
| S-18 | Ceremony message from a peer that never completed a hello | Reject (not in PAIRED-or-later state) |

**Ceremony refusals** — §6.6–6.7, and the reason the protocol has a security story at all.

| ID | Driver does | IUT must |
|---|---|---|
| S-19 | DESCRIPTOR_PROPOSAL omitting the IUT's own xpub | Refuse to ACK; ERROR `validation_failure` |
| S-20 | DESCRIPTOR_PROPOSAL substituting a different xpub in the IUT's slot | Refuse to ACK |
| S-21 | DESCRIPTOR_PROPOSAL placing the IUT at a slot it did not expect | Detect and surface; refuse or require explicit confirmation |
| S-22 | `descriptor_hash` that does not match the supplied `bsms_round2` | Refuse to ACK |
| S-23 | SESSION_FINALIZE before any SAS confirmation | Refuse to import the wallet |
| S-24 | SESSION_FINALIZE with a hash differing from the ACKed one | Refuse to import |
| S-25 | **PSBT_REQUEST over a valid session, `descriptor_hash` never finalized** | **Refuse to sign** — the substitute-coordinator attack |
| S-26 | PSBT_REQUEST with an input not derivable from the finalized descriptor | Refuse to sign |
| S-27 | PSBT_REQUEST for a wallet the IUT does hold, but with a tampered output | Sign only after the change/output derivation check; surface the anomaly |

S-25 and S-26 are the two tests that most justify this tier's existence. Both describe an attacker who has done everything right at the transport layer — valid session, valid code, valid encryption — and is defeated only by the descriptor binding. An implementation that signs anything arriving over an authenticated channel has implemented the protocol's mechanics and none of its security.

**Coordinator obligations** — IUT plays coordinator.

| ID | Driver does | IUT must |
|---|---|---|
| S-28 | Two signers ACK with different `first_address` | Mandatory ABORT |
| S-29 | Two signers ACK with different `descriptor_hash` | Mandatory ABORT |
| S-30 | Bridged KEY_CONTRIBUTION with an invalid BSMS signature | Reject the contribution |
| S-31 | One signer never contributes; clock advanced past coordinator timeout | ABORT with `timeout` |
| S-32 | A signer sends ERROR `validation_failure` and will not sign | Coordinator decides — abort or proceed with remaining signers if m is satisfiable. Either is conformant; the test asserts it does not hang. |

**Lifecycle** — §8.

| ID | Scenario | IUT must |
|---|---|---|
| S-33 | Clock advanced 15 min with no traffic | Close session, wipe keys (verified via `dump_key_state`) |
| S-34 | Clock advanced 60 min with periodic traffic | Close on absolute lifetime regardless of activity |
| S-35 | Driver sends ABORT | End session, wipe keys, burn the code |
| S-36 | Attempt a second session with an already-used code | Refuse |

**Relay conformance** — for relay implementers, not wallet implementers.

| ID | Scenario | Relay must |
|---|---|---|
| S-37 | Third connection to a channel already holding two | Reject |
| S-38 | 257 KB frame | Reject |
| S-39 | Idle 15 min / absolute 60 min | Expire the session |
| S-40 | Frame content inspection | Forward verbatim — byte-identical out |
| S-41 | Log inspection after a run | No full IPs, no envelope bodies |

### 5.4 Pass criteria

All scenarios for the claimed role and bindings must pass. There is no partial credit at Tier 2, because every scenario is a MUST and a partially-refusing implementation is the dangerous case, not the almost-there case.

S-27 and S-32 permit more than one conformant behaviour; the report records which branch was taken.

### 5.5 Determinism and reproducibility

Every run is parameterized by a seed, a clock start, and a scenario list, all recorded in the report. A failing run MUST be reproducible from the report alone. Flaky scenarios are defects in the suite and are fixed there, not tolerated with retries — a retry policy in a conformance suite converts an intermittent protocol bug into a passing grade.

---

## CS-§6 Tier 3 — the ceremony harness

### 6.1 Why this tier is not optional

The following are MUSTs in the protocol spec that Tiers 1 and 2 cannot reach at all:

- §6.8 — the SAS MUST be *displayed*, and MUST be rendered *identically* across implementations. A byte-correct SAS shown nowhere satisfies the vector and defeats the mechanism.
- §6.1 — the `note` field MUST be *displayed before any action is taken*.
- §6.6 — the participant MUST *independently derive* the first receive address, and the human MUST be able to compare it.
- §4.3 — the implementation's user-facing security documentation MUST state the residual trust assumptions. This is a conformance requirement about a document.
- §7.4 — a per-transport metadata disclosure table MUST be published. Also a document.
- §5.1 — the code MUST NOT appear in logs, URLs, or transport-visible fields.
- §5.1 — a user-chosen code MUST trigger a warning.
- §7.1 — self-hosting MUST be possible by configuration alone.

Skipping this tier leaves eight normative requirements verified by nobody. Several of them are the requirements a user's actual safety depends on.

The model is Caravan's device test runner: a scripted, known-fixture walkthrough with expected-versus-actual comparison, except that the comparison is made by an operator against a checklist and recorded as an attestation rather than computed.

### 6.2 Form

A guided harness — a document plus a driver script — that:

1. Sets up a fixture session against the loopback relay using the CS-§8 test fixtures.
2. Walks the operator through a full setup ceremony and a full signing round.
3. Pauses at each checkpoint with a specific, falsifiable question and a place to record evidence (screenshot, log excerpt, copied string).
4. Emits a machine-readable attestation.

Questions must be falsifiable. *"Is the SAS displayed clearly?"* is unanswerable. *"Copy the SAS string exactly as displayed, including any separators"* produces a string the harness compares against the vector, which converts a judgment call into a diff.

### 6.3 Checkpoint catalogue

**SAS.**

| ID | Check | Evidence |
|---|---|---|
| C-01 | Copy the displayed SAS verbatim | String — compared against `KL-1SA-001`, character for character including hyphens |
| C-02 | SAS is shown before FINALIZE and the flow cannot continue past it without an explicit user action | Screenshot + attempt to bypass |
| C-03 | The interface instructs comparison over a channel *other than the session* and names examples | Screenshot of the instruction text |
| C-04 | Cross-render: the same fixture session rendered in the IUT and in one other conformant implementation produce identical strings | Both strings |

C-04 is the one that matters and it can only be run once a second implementation exists. Until then it is `blocked`, and that status is itself informative — it marks the exact moment the cross-implementation property becomes verifiable.

**Human-facing ceremony checks.**

| ID | Check |
|---|---|
| C-05 | The `note` field content is displayed before the action it describes, not after and not in a log |
| C-06 | The user's own xpub is located in the proposed descriptor and its fingerprint, derivation path, and slot are shown |
| C-07 | The first receive address is displayed for comparison, and is independently derived (verified by proposing a descriptor whose stated address is wrong — the IUT must show its own derivation, not the coordinator's claim) |
| C-08 | The wallet cannot be imported or used before FINALIZE arrives with a matching hash |
| C-09 | A user-chosen weak code produces a warning, and an entropy estimate is displayed |
| C-10 | A code cannot be reused for a second session, and the refusal survives an application restart |
| C-11 | On ABORT or timeout, the interface reflects a wiped session and the code is marked burned |

C-07 deserves note: it is the one checkpoint that tests a *derivation* through a *human channel*. The coordinator can claim any address; the protocol's defence is that every participant computes it themselves. A UI that displays the coordinator's claimed address, labelled as if it were locally derived, passes every automated test and silently removes the check.

**Leakage.**

| ID | Check |
|---|---|
| C-12 | Run a full ceremony with a distinctive code, then search all application logs, browser storage, URL/history, crash reports, and any telemetry payloads for the code and for `K_code` | Zero hits required |

C-12 is fully mechanical and belongs in Tier 3 only because it needs a real running application rather than an adapter. Automate it.

**Documentation.**

| ID | Check |
|---|---|
| C-13 | Published user-facing security documentation contains the §4.3 residual trust statement — all four items |
| C-14 | Published documentation contains a per-transport metadata disclosure table (§7.4), stating both what the operator observes and what it never observes |
| C-15 | Marketing and documentation do not claim "trustless coordination" or equivalent (§4.3 makes this a conformance matter, not a style preference) |
| C-16 | Relay URL is configurable in shipped builds; a self-hosted relay works with configuration only, no rebuild (§7.1) |
| C-21 | The interface surfaces the §5.6 code-distribution guidance at the moment the code is shown — share out of band, not over the session transport, single use |
| C-22 | If persistent or asynchronous sessions are shipped, the in-session ratchet (Appendix A.4) is implemented. Shipping persistence without it is a conformance failure, not a roadmap item (§7.2) |

C-15 is unusual as a conformance requirement and is worth keeping. §4.3 exists specifically to stop future implementers from marketing away the protocol's honesty. A conformance suite that tests the bytes but not the claims lets exactly that happen.

**Air gap (§7.3), required for the `airgap` binding claim.**

| ID | Check |
|---|---|
| C-17 | An envelope crosses the gap as UR, BBQr, or a `.msp` file and round-trips intact |
| C-18 | A payload injected on behalf of an air-gapped device carries `bridged: true` |
| C-19 | The coordinator verifies the BSMS signature inside a bridged contribution (paired with the automated S-30) |
| C-20 | The bridging interface states that the bridge attests to faithful transcription only, and that SAS plus first-address comparison remain the human backstop |

### 6.4 Operator independence

A Tier 3 attestation signed only by the implementation's own author is weak evidence and the report must say so. The attestation records who performed it and their relationship to the implementation. A second-party attestation — someone from a different implementation running the checklist — is stronger and SHOULD be sought before a T3 claim is published. No mechanism enforces this; visibility is the whole enforcement.

### 6.5 Attestation record

```json
{
  "suite_version": "0.1",
  "implementation": { "name": "...", "version": "...", "commit": "..." },
  "operator": { "name": "...", "affiliation": "...", "independent": false },
  "date_utc": "...",
  "checkpoints": [
    { "id": "C-01", "status": "pass", "evidence": "9F3K-2M7Q-XB4T" },
    { "id": "C-04", "status": "blocked", "reason": "no second implementation available" }
  ],
  "signature": "<detached signature over the canonical JSON>"
}
```

The signature is over the canonicalized record by a key the operator publishes. Not because anyone will verify it today, but because an unsigned attestation is a claim with no author, and this suite's entire enforcement model is public attribution.

---

## CS-§7 What the suite cannot verify

Stated plainly, because a suite that implies more coverage than it has is worse than no suite. The protocol spec's §4.2 sets the precedent: write down what you do not defend against.

### 7.1 Not covered, and not coverable from outside

- **Actual key zeroization (§5.4).** `dump_key_state` reports what the implementation *says* it holds. It cannot prove the bytes are gone from process memory, from a garbage-collected heap, from swap, or from a browser's internal buffers. In a managed-memory language, guaranteed erasure may not even be achievable. The suite tests the API-boundary claim; the property needs source review.
- **RNG quality.** Entropy injection tests the *sampling logic*, not the entropy source. An implementation drawing from a weak source passes every KD vector.
- **Side channels.** Timing, power, cache. Out of scope entirely.
- **Whether the human compares the SAS.** The suite verifies that the string is displayed, correct, and blocking. Whether two people actually read it to each other over the phone is unobservable, and it is the single point on which the man-in-the-middle defence rests. No test will ever change that.
- **Code distribution (§5.6).** Entirely out-of-band by design.
- **Payload correctness.** Per CS-§1.3.

### 7.2 Compensating control: the source review checklist

For each uncoverable item, the suite ships a short reviewer checklist with the specific thing to look for — the line where `sk` is zeroed and whether anything can hold a reference past that point; the RNG call site; where the code string is stored between entry and derivation. The checklist is completed by a human reading the code and is recorded in the T3 attestation as `reviewed` / `not reviewed`, never as `pass`. The distinction is deliberate: `pass` implies a test ran.

---

## CS-§8 Test fixtures

### 8.1 Fixture wallet

The suite requires a fixed set of key material for the descriptor, address, and BSMS vectors.

**Requirements:**

- Derived from a **publicly known** BIP-39 mnemonic, so that no implementer ever believes fixture material is secret. Recommendation: the canonical `abandon abandon … about` test mnemonic, precisely because its compromise is universal knowledge.
- **Testnet and regtest only.** Vectors MUST NOT include mainnet addresses or mainnet descriptors. A conformant runner refuses to execute a vector whose network field is mainnet.
- Every fixture file carries a `DO NOT FUND` banner as a first-class field, not a comment.
- Three wallets: 2-of-3 P2WSH, 2-of-3 P2SH-P2WSH, and 2-of-3 P2TR `multi_a` — covering all three `script_type` registry values in §6.6.
- Per wallet: three xpubs with origins (fingerprint plus derivation path), the BSMS Round-1 records with valid signatures, the BSMS Round-2 descriptor file, the canonical descriptor string, its SHA-256, and the first five receive and change addresses.
- Fixed X25519 keypairs (at least four, so 3-participant sessions are expressible), fixed session codes, fixed `mid` values.

### 8.2 Honesty note on this section

**None of these values are generated yet.** They must be produced by a generator script, checked against at least two independent wallet implementations (a descriptor whose addresses only one implementation agrees with is a fixture that encodes that implementation's bug), and committed with the generator so anyone can reproduce them. Writing plausible-looking hex into this document would be worse than leaving it blank, because it would look authoritative and be wrong. Generating and cross-checking the fixtures is the first build task (CS-§10) and is not a small one.

---

## CS-§9 Governance

### 9.1 Versioning

The suite version is independent of the protocol wire version. Suite `0.1` targets wire version `1`. A suite version declares the wire versions it tests in its manifest.

Vector files are append-mostly. Changing an existing vector's expected output is a **breaking** change requiring a suite minor-version bump and an entry in a changelog naming which implementations' prior claims are void.

### 9.2 Adding tests

A new test requires: an ID, a spec section reference, a stated rationale, and — for any new positive test — at least one accompanying negative case, or a written argument for why none applies. Contributions that add only positive coverage are reviewable defects.

### 9.3 Publishing a claim

Self-declared. An implementation publishes: the JSON report (CS-§4.7), the Tier 2 run log, the Tier 3 attestation if claimed, the suite version and vectors commit, and the implementation commit. The report must be reproducible by a third party from those artifacts alone.

No authority validates claims. The enforcement mechanism is that a false claim is falsifiable in minutes by anyone who runs the suite. That is a stronger mechanism than a certification body, and it is the only one available to a project with one implementation.

### 9.4 When the suite and the spec disagree

**Before freeze:** the protocol spec's prose is authoritative and the vector is presumed wrong. A discrepancy is filed as a defect against *both* documents and resolved by deciding which one is actually wrong — because in practice the discrepancy usually means the prose was ambiguous enough for the vector author to guess wrong, and the fix belongs in the prose. Every such discrepancy found before freeze is a specification defect caught at the cheapest possible moment. Expect several. The HS group (CS-§4.4) already has one.

**After freeze:** vectors are frozen alongside the spec. A discrepancy becomes an erratum requiring a documented spec revision. Vectors never change silently, because implementations pin to a vectors commit and a silent change breaks a passing claim retroactively.

### 9.5 The freeze gate, made mechanical

§13 requires "two independent interoperating implementations of the signer role." Both terms need definitions or the gate is a matter of opinion.

**Independent** means all of:

- Separate codebases with no shared source for the protocol-relevant layers — code derivation, envelope encoding, AEAD framing, SAS. Shared use of *widely deployed general-purpose* libraries (a language's standard CBOR library, libsodium, WebCrypto) does not compromise independence; a shared MSP-specific library does.
- Different primary maintainers.
- Neither derived from the other by translation or port.

**Interoperating** means all of:

- Both publish a passing T1 report against the same vectors commit.
- A Tier 2 run in both directions — each acting as driver counterpart for the other — completes S-01 through S-04.
- Both produce identical SAS strings for the C-04 cross-render fixture.

**Test vectors published** means: manifest with digests, in the public repository, with the generator script, at a tagged version.

Meeting these three is the freeze condition together with the 90-day no-normative-change window. Nothing here is a matter of judgment, which is the point — a freeze criterion you can argue about is a freeze criterion that gets argued about.

---

## CS-§10 Build order

The suite as specified is substantially more work than the protocol document it tests. That is normal and it is not a reason to build it all. Ordered by value per unit of effort:

| Order | Item | Unblocks |
|---|---|---|
| 1 | **Fixtures and generator** (CS-§8) | Everything. Nothing else can start. |
| 2 | **KD, HS, PK, CB, AE, SA vector groups** | Appendix B item 1; the freeze gate's first condition |
| 3 | **Adapter contract + stdio runner** | Any external implementer running anything |
| 4 | **CT counter-ordering scripted test** (S-12 equivalent) | The highest-value single test in the suite |
| 5 | **Transcripts** (CS-§4.4) | Onboarding — the artifact an implementer reads first |
| 6 | **Loopback relay + S-01…S-04** | The freeze gate's second condition |
| 7 | **S-19…S-26 ceremony refusals** | The protocol's actual security properties |
| 8 | **Remaining Tier 2** | Completeness |
| 9 | **Tier 3 checklist as a document** | Cheap; can be a markdown checklist long before it is a harness |
| 10 | **C-12 leakage scrape, automated** | Cheap, mechanical, high signal |
| 11 | **WebSocket adapter binding** | The browser implementation running its own suite |
| 12 | **Tier 3 harness proper** | Last |

**Minimum viable subset: items 1–6.** That is the smallest thing that satisfies §13's freeze gate and gives a wallet team a red/green answer. Items 7 and 9 should follow immediately, because shipping a suite that tests conformance but not refusals invites exactly the failure mode described in CS-§1.2.

A note on sequencing against the protocol itself: item 2 will surface specification ambiguities (CS-§9.4). Do not build items 6 onward until the ambiguities item 2 finds are resolved in the prose, or the interop layer will encode guesses.

---

## CS-§11 Open questions

1. **Code normalization.** ~~§5.1 specifies an uppercase alphabet and display-only separators, but does not say whether lowercase input is normalized or rejected, nor which separator characters are permitted in display form.~~ **Resolved:** §5.1 now defines normalization as lowercase-then-strip-everything-not-in-`[a-z0-9]`, with a length floor and no rejection of the generator's excluded characters (they are valid content in user-chosen codes). This removes the separator-set ambiguity entirely: every non-alphanumeric is a separator, so any display grouping round-trips. KD vectors above pin it down.
2. **Hello MAC input serialization.** §5.3 gives `"MSP-HELLO" || v || caps || kdf || pk` without specifying the byte encoding of `v`, `caps`, and `kdf` in that concatenation — fixed-width, big-endian, and what width? Or CBOR-encoded? This is unambiguous only to the person who wrote it. Blocking for the HS vectors.
3. ~~**`derivation_template` grammar.**~~ Closed 2026-11-05: the protocol spec §6.6 restricts the template to the BIP-48 forms `m/48'/C'/A'/S'` with `C` and `S` tied to `network` and `script_type`. SESSION_INIT vectors can now be written, and the suite MUST include refusals for a mismatched `C`, a mismatched `S`, an `h` hardened marker, a leading zero in `A`, and any non-BIP-48 path.
4. **Coordinator behaviour on partial signer failure** (§8.4). The spec says the coordinator "decides." S-32 accordingly accepts either branch. If interoperability requires a determinate answer, the spec must say so.
5. **Whether Tier 1 alone should be permitted as a published claim.** Currently yes (T1 is a defined level). Argument against: a T1-only claim may read to a wallet team as "conformant" when nothing about the implementation's refusals has been tested. Consider renaming T1 to something that cannot be mistaken for conformance — "vector-compatible" rather than "T1 conformant."
6. **Relay conformance as a separate claim type.** S-37…S-41 test a relay, not a wallet. Relays may warrant their own role in CS-§3.1 rather than living as a scenario group.
7. **Nostr binding tests.** Cannot be written until §7.2 specifies event kinds, gift-wrap parameters, and expiration handling (Appendix B item 2).

---

## CS-Appendix A — Worked vector example

```json
{
  "group": "AE",
  "spec_section": "§6.4",
  "vectors": [
    {
      "id": "KL-1AE-001",
      "desc": "Encrypt SESSION_INIT body, dir=0x00, ctr=1",
      "kind": "positive",
      "op": "encode_envelope",
      "in": {
        "k_ab": "<32 bytes hex>",
        "header": { "1": 1, "2": 1, "3": "<8 bytes>", "4": "<8 bytes>",
                    "5": "<8 bytes>", "6": 1, "7": "<16 bytes>" },
        "pk_sender": "<32 bytes>", "pk_recipient": "<32 bytes>",
        "body_plaintext": "<hex of deterministic-CBOR body>"
      },
      "out": {
        "aad":            "<hex — the exact authenticated header bytes>",
        "nonce":          "000000000000000000000001",
        "envelope_bytes": "<hex>"
      }
    },
    {
      "id": "KL-1AE-011",
      "desc": "Reject envelope with flipped AAD bit in header field 2",
      "kind": "negative",
      "op": "decode_envelope",
      "in": { "k_ab": "<32 bytes>", "envelope_bytes": "<hex, one bit flipped>" },
      "out": { "reject": "decode_failure" }
    }
  ]
}
```

Note that `aad` and `nonce` are published as separate outputs even though they are intermediate values. An implementer whose envelope bytes mismatch needs to know *which* intermediate diverged; publishing only the final ciphertext turns a five-minute fix into a day of bisecting.

---

## CS-Appendix B — Adapter reference (stdio binding)

```
$ ./msp-adapter
< {"id":"1","op":"capabilities"}
> {"id":"1","ok":true,"result":{"roles":["signer"],"bindings":["websocket","airgap"],
                                 "suite":"0.1","wire":[1],
                                 "features":{"set_entropy":true,"set_clock":false}}}
< {"id":"2","op":"derive_kdf","args":{"code":"7k4m2xqtb9"}}
> {"id":"2","ok":true,"result":{"k_code":"<hex>","channel_id":"<hex>"}}
< {"id":"3","op":"verify_hello","args":{"k_code":"<hex>","hello_bytes":"<hex, bad mac>"}}
> {"id":"3","ok":false,"reject":"silent_drop"}
```

Rules: one JSON object per line; no output on stderr is interpreted; exit code ignored; the adapter runs until stdin closes. An adapter reporting `"set_clock": false` causes lifecycle scenarios to fall back to configuration-reduced timers, recorded in the report.

---

## CS-Appendix C — Coverage matrix

Every normative requirement in the protocol spec, mapped to the test that covers it. `—` means no test exists and CS-§7 explains why.

| Spec | Requirement | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|---|
| §4.3 | Publish residual trust statement | — | — | C-13, C-15 |
| §5.1 | Generate ≥10 chars, CSPRNG, rejection sampling | KL-1KD-010…019 | — | — |
| §5.1 | Warn on user-chosen code; display entropy estimate | — | — | C-09 |
| §5.1 | Code never in logs, URLs, transport fields | — | — | C-12 |
| §5.2 | `K_code` and `channel_id` derivation | KL-1KD-001…009 | — | — |
| §5.3 | Verify hello MAC before accepting `pk` | KL-1HS-001…008 | S-05 | — |
| §5.3 | Bad MAC ignored **silently** | KL-1HS-010 | S-05 | — |
| §5.3 | Key-change rule (new `pk` mid-session ignored) | — | S-06 | — |
| §5.4 | Pairwise key derivation | KL-1PK-001…006 | — | — |
| §5.4 | Zero `sk` immediately after derivation | KL-1PK-020 (API claim only) | — | source review |
| §5.5 | Reserved caps bits zero, ignored on receipt | KL-1HS-020 | S-09 | — |
| §5.5 | Version mismatch → ERROR and leave | — | S-08 | — |
| §5.6 | Code single-use | — | S-36 | C-10 |
| §5.6 | Surface out-of-band distribution guidance (SHOULD) | — | — | C-21 |
| §6.1 | Envelope structure and field encoding | KL-1CB-001…020 | — | — |
| §6.1 | `note` displayed before action | — | — | C-05 |
| §6.2 | Reserved-core unknown type → `unsupported_type` | — | S-15 | — |
| §6.2 | Private-range unknown type ignored | — | S-16 | — |
| §6.3 | Deterministic CBOR, produce and **reject non-canonical** | KL-1CB-030…045 | S-14 | — |
| §6.4 | Nonce construction, AAD binding, AEAD | KL-1AE-001…015 | S-13 | — |
| §6.5 | Counter discard before decryption | KL-1CT-001…004 | S-10, S-11 | — |
| §6.5 | **Counter advanced only after success** | KL-1CT-005 | S-12 | — |
| §6.6 | Slot assignment first-come, deterministic | — | S-03, S-21 | — |
| §6.6 | Participant verifies own xpub, fingerprint, path, slot | — | S-19, S-20, S-21 | C-06 |
| §6.6 | Participant independently derives first address | — | — | C-07 |
| §6.6 | Coordinator ABORTs on ACK divergence | — | S-28, S-29 | — |
| §6.6 | No FINALIZE before SAS confirmed by all | — | S-23 | C-02 |
| §6.6 | No wallet import before matching FINALIZE | — | S-23, S-24 | C-08 |
| §6.7 | Signer verifies `descriptor_hash` before signing | — | S-25 | — |
| §6.7 | Signer verifies every input derives from descriptor | — | S-26, S-27 | — |
| §6.8 | SAS computed correctly | KL-1SA-001…008 | — | — |
| §6.8 | SAS **displayed**, identically rendered | — | — | C-01, C-04 |
| §6.8 | Out-of-band comparison instruction | — | — | C-03 |
| §6.9 | ERROR / ABORT bodies and codes | KL-1BD-040…050 | S-35 | — |
| §6.9 | ABORT wipes keys, burns code | — | S-35 | C-11 |
| §7.1 | Frame ≤256 KB; two-connection limit; timers | — | S-17, S-37…S-39 | — |
| §7.1 | Relay forwards verbatim; minimal logging | — | S-40, S-41 | — |
| §7.1 | Self-hosting by configuration only | — | — | C-16 |
| §7.2 | Nostr binding | — | — | — (§7.2 not yet specified in testable detail) |
| §7.2 | MUST NOT ship persistent/async sessions before the ratchet | — | — | C-22 (release gate, not a wire test) |
| §7.3 | Envelope or payload crosses the gap | — | — | C-17 |
| §7.3 | Bridged payloads marked `bridged: true` | KL-1BD-012 | — | C-18 |
| §7.3 | Coordinator verifies bridged BSMS signature | — | S-30 | C-19 |
| §7.4 | Publish per-transport metadata disclosure table | — | — | C-14 |
| §8.1 | Reject ceremony messages from non-PAIRED peers | — | S-18 | — |
| §8.2 | Idle 15 min / absolute 60 min; wipe on expiry | — | S-33, S-34 | — |
| §8.3 | Rejoin same `pk` resumes; new `pk` ignored | — | S-06, S-07 | — |
| §8.4 | Coordinator timeout → ABORT | — | S-31 | — |
| §8.4 | Signer refusal handled without hanging | — | S-32 | — |

**Uncovered by any tier:** §7.2 in full (not yet specified); actual memory zeroization (§5.4, source review only); RNG source quality; whether the human performs the SAS comparison. Four gaps, three of them structural rather than fixable. Naming them here is the point of the matrix.
