# Bug report — Keylay Protocol Spec v0.1 draft: three under-specification defects

**Filed:** 2026-08-18
**Against:** `spec/msp-spec-v0.1-draft.md` (draft dated August 2026)
**Also requires edits to:** `spec/msp-explainer.md` (section numbers are kept in sync between the two documents; a spec change that leaves the explainer stale is an incomplete fix)
**Found by:** writing the conformance suite specification (`spec/conformance-suite-spec-v0.1-draft.md`). Each defect below is a place where the vector author had to guess. Defects 2 and 3 are already listed as open questions CS-§11.1 and CS-§11.2 in that document; defect 1 is new and is more serious than either.

**Read this first if you have no context:** Keylay is a coordination protocol for remote bitcoin multisig setup and signing. Two or more people share a secret *session code* out of band, each derives the same rendezvous channel from it, they perform an ephemeral Diffie-Hellman handshake, and then exchange typed encrypted messages carrying multisig artifacts. The spec is a draft, not frozen, and has exactly one partial implementation. All three defects below are **specification-text** defects — places where two independent implementers reading the same sentence will produce incompatible bytes. None require redesign. All three are blocking for publishing test vectors.

**Do not** resolve any of these by picking an interpretation and implementing it. The whole point is that the text must be unambiguous to someone who did not write it.

---

## Summary

| ID | Section | Severity | One line |
|---|---|---|---|
| **KL-SPEC-001** | §6.8 | **Critical — correctness** | The SAS input binds a per-recipient value, so participants compute different SAS strings in any session with 3+ participants. The mandatory man-in-the-middle check fails closed on legitimate sessions. |
| **KL-SPEC-002** | §5.3 | Blocker — interop | The hello message's wire encoding and its MAC input serialization are both undefined. Two implementations will never authenticate each other. |
| **KL-SPEC-003** | §5.1 | Blocker — interop | Session code normalization is undefined: lowercase handling, legal separator characters, and rejection of excluded characters. Divergence produces a silent, undiagnosable connection failure. |

---

## KL-SPEC-001 — SAS input includes a per-recipient value; n≥3 sessions produce divergent strings

**Severity: critical.** This is the only defect here that is a correctness bug rather than an ambiguity. It breaks a mandatory security check in a way that manifests as legitimate sessions aborting, which trains users to ignore the check.

### The text

§6.8:

```
sas_input = SHA-256("KEYLAY-V1-SAS" || channel_id
                    || concat(sorted list of all participants' pk)
                    || AAD-bytes of SESSION_INIT, if present)
SAS       = first 60 bits of sas_input, rendered as 12 characters of the
            §5.1 alphabet, grouped XXXX-XXXX-XXXX
```

### The problem

Take the literal reading. "AAD-bytes" is a defined term: §6.4 states

> `AAD = deterministic-CBOR encoding of header fields {1..8}`

and §6.1 defines those header fields as including `4: from`, `5: to`, `6: ctr`, and `7: mid`.

SESSION_INIT is `coordinator → all` (§6.2 registry). Encryption is **pairwise** (§5.4) — there is no group key. Therefore the coordinator does not send one SESSION_INIT; it sends one *per recipient*, each a distinct envelope with:

- a different `to` (the recipient's key id),
- an independent `ctr` (the counter is per sender→recipient pair, §6.1),
- a different `mid` (16 random bytes per message, §6.1).

So the AAD bytes of "the" SESSION_INIT are different for every recipient. Each participant hashes a different value into `sas_input`, and every participant displays a different SAS string.

**Consequence.** In a 2-party session the defect is invisible: there is exactly one SESSION_INIT envelope, and the sender and receiver both hash the same AAD. In a 3-of-5 or 2-of-3 setup — the actual use case — the participants get on a phone call, read their strings to each other, and they do not match. §6.8 makes the SAS mandatory and §6.6 forbids the coordinator from sending SESSION_FINALIZE until every participant confirms. So a correct implementation of this text **cannot complete an honest multi-party setup ceremony**.

The failure mode is worse than a hard error. A mismatched SAS means "you are being intercepted, abort." Users who see that on every legitimate session will learn to click past it, which destroys the mechanism the protocol relies on to detect the one attack it cannot prevent (a session code intercepted before the session, §5.6).

**Why this was probably not caught:** the §7.1 WebSocket relay binding is explicitly two-party at v0.1 ("enforce two-connection limit per channel"), and the reference app is two-party. The envelope layer is already n-party, and the SAS is not.

### The likely intent

Almost certainly the intent was to bind the *ceremony parameters* — m, n, script type, derivation template, network — so that a coordinator cannot show different participants different terms. That is a real and worthwhile binding, and it is the **body plaintext** of SESSION_INIT, which is identical for every recipient. The explainer's §6.8 discussion supports this reading: it describes the SAS as computed "from every participant's public key" and never mentions envelope headers.

### Two further ambiguities in the same three lines

Fix these in the same change:

- **`sorted` is undefined here.** §5.4 explicitly states its ordering rule ("byte-wise lexicographic ordering of the two public keys"). §6.8 says only "sorted list" with no rule. The asymmetry is itself the hazard: an implementer who checked §5.4 will assume byte-wise lexicographic, and one who didn't may sort by hex string, by key id, or by join order.
- **"if present" does not say what absent means.** In a signing-only session there is no SESSION_INIT (§6.8 explicitly contemplates this: "before the first PSBT_RESPONSE (signing-only sessions)"). Is the term omitted from the concatenation entirely, or is a zero-length string concatenated? Those produce the same bytes here only because concatenating nothing and concatenating an empty string are identical — but they are *not* identical if the fix introduces a length prefix, which it should. Say which.

### Proposed replacement text for §6.8

```
sas_input = SHA-256("KEYLAY-V1-SAS"
                    || channel_id
                    || concat(pk of every session participant, in byte-wise
                              lexicographic order)
                    || init_bind)

where init_bind =
    the deterministic-CBOR encoding of the SESSION_INIT *body plaintext*
      (§6.6), identical for every recipient, in a setup session; or
    the empty byte string in a signing-only session where no SESSION_INIT
      was sent.

SAS = first 60 bits of sas_input, rendered as 12 characters of the §5.1
      alphabet, grouped XXXX-XXXX-XXXX.
```

Add a sentence of rationale: *"The binding is to the SESSION_INIT body, not to any envelope header. Envelope headers carry per-recipient addressing (`to`, `ctr`, `mid`) and so differ between recipients of the same logical message; binding them would make every participant compute a different SAS."*

That sentence is worth keeping permanently. It is exactly the trap the next person will fall into.

### Consider also

Whether `init_bind` should be length-prefixed. Right now the SAS input is a bare concatenation of a fixed-length domain string, a fixed-length `channel_id`, a variable-length run of fixed-length 32-byte keys, and a variable-length blob. Because the participant-key run is variable in length and the trailing term is variable in length, the concatenation is not injective in general — two different `(key list, init body)` pairs could in principle produce the same byte string. Prepending the participant count and the `init_bind` length removes the question. Cheap; do it.

### Acceptance criteria

- [ ] §6.8 replaced with text that binds the SESSION_INIT body plaintext, not envelope AAD.
- [ ] Sort order stated explicitly in §6.8 (do not rely on the reader importing it from §5.4).
- [ ] Signing-only case stated explicitly.
- [ ] Length-prefixing decided either way, and the decision written down.
- [ ] Explainer §6.8 updated with the "why not the header" rationale.
- [ ] Add to protocol spec Appendix B: this construction is now a *changed* construction and belongs in the list of things for cryptographer review (Appendix B item 6 already names §6.8; confirm it still points at the new text).
- [ ] Worked example added: a 3-participant setup where all three participants compute the same string, with intermediate values.

---

## KL-SPEC-002 — Hello message: neither the wire encoding nor the MAC input serialization is defined

**Severity: blocker for interop.** Two implementations cannot complete a handshake. This is the first message either one sends.

### The text

§5.3:

```
hello = {
  t:    0,                        // message type HELLO
  v:    1,                        // wire version
  caps: uint,                     // capability bitfield, §5.5
  kdf:  1,
  pk:   bytes(32),                // ephemeral X25519 public key
  mac:  HMAC-SHA256(K_code, "KEYLAY-V1-HELLO" || v || caps || kdf || pk)
}
```

### Problem A — the hello's own wire encoding is unspecified

§6.3 states the encoding rule for "all envelopes and bodies": RFC 8949 §4.2 Core Deterministic Encoding. The hello is neither. It is Layer 1, it is unencrypted, and §6.2 marks it as a special case ("Layer 1 (unencrypted, MAC'd)").

Unanswered: Is the hello a deterministic-CBOR map? If so, are its keys the text strings shown (`t`, `v`, `caps`, `kdf`, `pk`, `mac`) or integers, as every Layer-2 envelope uses (§6.1 uses integer keys 1–9 explicitly "to keep envelopes small")? The inconsistency between the hello's named keys and the envelope's integer keys reads as accidental. If the hello is deterministic CBOR with text keys, the canonical key ordering rule sorts them by length then bytewise — which produces `t, v, pk, kdf, mac, caps` — an order no implementer would guess from the listing above.

### Problem B — the MAC input serialization is unspecified

`"KEYLAY-V1-HELLO" || v || caps || kdf || pk` is a concatenation of a 15-byte ASCII string, three integers, and 32 raw bytes. The integers have no stated encoding. Live options an implementer will pick from:

- one byte each (but `caps` has reserved bits through 15, so it needs at least two);
- fixed-width big-endian at some width;
- fixed-width little-endian;
- CBOR-encoded, matching the rest of the protocol;
- decimal ASCII, which sounds absurd until someone does it.

Also unstated: whether the domain-separation string is included as raw ASCII with no terminator and no length prefix (presumably yes), and whether these are the *only* fields — note that `t` appears in the message but not in the MAC input, which may be deliberate or may be an omission. Say which.

A MAC over an ambiguous serialization is not merely non-interoperable. §5.3 requires that **a hello with a bad MAC be ignored silently** — no error response, by design, so that a code-guesser learns nothing. So the symptom of this defect between two implementations is: absolute silence, no error anywhere, on the first message. That is close to the worst possible debugging experience for the wallet team you are trying to recruit.

### Proposed replacement text for §5.3

```
The hello message is encoded as a deterministic-CBOR map (§6.3) with
integer keys, consistent with the Layer-2 envelope:

  hello = {
    1: v,      // uint  wire version
    2: t,      // uint  message type, 0 = HELLO
    3: caps,   // uint  capability bitfield, §5.5
    4: kdf,    // uint  KDF identifier, 1 = PBKDF2-300k
    5: pk,     // bytes(32) ephemeral X25519 public key
    6: mac     // bytes(32)
  }

The MAC is computed over a fixed-width byte string, not over the CBOR
encoding:

  mac_input = ASCII("KEYLAY-V1-HELLO")   // 15 bytes, no terminator
              || uint8(v)                //  1 byte
              || uint16_be(caps)         //  2 bytes, big-endian
              || uint8(kdf)              //  1 byte
              || pk                      // 32 bytes, raw
                                          // = 51 bytes total

  mac = HMAC-SHA256(K_code, mac_input)

The message type `t` is not included in the MAC input; a hello is the
only message carrying this MAC, and the domain-separation string fixes
the context.
```

Fixed-width rather than CBOR for the MAC input is the right call and worth one sentence of rationale: the MAC must be computable before any CBOR decoder has been trusted with attacker-supplied bytes, and a fixed 51-byte input has exactly one valid form, so there is no canonical-encoding argument to have.

Note the key numbering above deliberately places `v` at key 1 to match the envelope (§6.1 field 1 is `v`). If you prefer a different assignment, fine — just assign them.

### Acceptance criteria

- [ ] §5.3 states the hello's wire encoding explicitly, including key type and numbering.
- [ ] §5.3 gives the MAC input as a byte-by-byte layout with widths and endianness, and a total length.
- [ ] The `t`-not-in-MAC question is answered in the text, not left to inference.
- [ ] §6.2's HELLO row cross-references the new §5.3 encoding so the registry does not imply the envelope format applies.
- [ ] Explainer §5.3 gains a note on why the MAC input is fixed-width rather than CBOR.
- [ ] A test vector is produced: fixed `K_code`, fixed `pk`, `v=1`, `caps=0`, `kdf=1` → the 51-byte `mac_input` in hex and the resulting MAC in hex. Publishing the intermediate `mac_input` is the point; an implementer whose MAC is wrong needs to see which byte diverged.

---

## KL-SPEC-003 — Session code normalization is undefined

**Severity: blocker for interop.** Divergence here means two participants never meet at the same rendezvous point, with no error message on either side.

### The text

§5.1:

> **Alphabet:** the 31 characters `23456789ABCDEFGHJKMNPQRSTUVWXYZ` (digits and uppercase letters minus `0 O 1 I L`, which are visually ambiguous).

> Display grouped for readability; separators are display-only and MUST be stripped before use.

> **User-chosen codes:** MAY be accepted for interop with humans...

### The problem

`K_code = PBKDF2(code, ...)` and `channel_id = SHA-256("KEYLAY-V1-CHANNEL" || K_code)` (§5.2). The code string is the sole input. Any difference in how two implementations normalize the user's keystrokes produces a completely different `K_code`, a completely different `channel_id`, and therefore two participants sitting in two different channels, each waiting for someone who will never arrive.

There is no error path for this. Neither side sees a bad MAC, because neither side sees the other at all. The user experience is a spinner.

Four things the text does not answer:

1. **Lowercase.** The alphabet is uppercase-only. A user types `7k4m2xqtb9` — is it uppercased, or rejected? Mobile keyboards, autocorrect, and copy-paste from a chat client all produce case variation. "Reject" is defensible; "normalize to uppercase" is defensible; silence is not.
2. **Which characters are separators.** "Separators are display-only and MUST be stripped" does not say which characters count. Hyphen only? Spaces? Both? Any character not in the alphabet? Note that "strip anything not in the alphabet" and "strip hyphens and spaces, reject anything else" differ on the important case — a user who typed `O` for `0`.
3. **Excluded characters.** `0 O 1 I L` are deliberately absent because they are visually confusable. A user who transcribes from a screen will type them. Reject, or map? Mapping is the Crockford Base32 approach, but it does not transfer here: Crockford maps `O→0` and `I,L→1`, and this alphabet contains neither `0` nor `1`, so there is no target to map to. Rejection with a specific error ("that character is not used in session codes — check for O/0 and I/1/L confusion") is almost certainly the right answer, but the spec has to say so.
4. **Whitespace and invisible characters.** Leading and trailing whitespace from a paste. Non-breaking spaces. Zero-width joiners, which chat clients insert. Unicode homoglyphs — Cyrillic `А` renders identically to Latin `A`. At minimum, state that input is rejected if it contains any codepoint outside the ASCII range after separator stripping.

### Proposed addition to §5.1

```
**Normalization (normative).** Before any derivation in §5.2, an
implementation MUST normalize candidate code input as follows, in order:

1. Reject the input if it contains any codepoint outside U+0020..U+007E.
   (This rejects Unicode homoglyphs and invisible characters, which no
   legitimate code contains.)
2. Remove all occurrences of SPACE (U+0020) and HYPHEN-MINUS (U+002D).
   These are the only permitted display separators; implementations MUST
   NOT emit any other separator when displaying a code.
3. Map ASCII lowercase letters to uppercase.
4. Reject the input if any remaining character is not in the §5.1
   alphabet. Implementations SHOULD report which character was rejected
   and SHOULD note the O/0, I/1 and L/1 confusion cases, because those
   are what a user who transcribed from a screen will have typed.
5. Reject the input if the remaining length is below the minimum for a
   generated code (§5.1) unless the implementation has been explicitly
   configured to accept user-chosen codes.

The result of step 4 is the `code` string used in §5.2. Normalization is
part of the protocol, not a user-interface convenience: two participants
who normalize differently derive different channel identifiers and never
meet, with no error visible to either.
```

That last sentence should survive editing. It is the reason the section exists.

### Acceptance criteria

- [ ] Normalization steps added to §5.1 as an ordered, normative list.
- [ ] The permitted display separator set is stated, and stated as a restriction on *emitting* as well as on *accepting*.
- [ ] The lowercase decision is explicit either way.
- [ ] Excluded-character handling is explicit, and is rejection rather than mapping unless there is a stated reason otherwise.
- [ ] Explainer §5.1 gains a short note on the silent-failure mode, since that is the motivation.
- [ ] Test vectors produced: `7K4M2XQTB9`, `7k4m2xqtb9`, `7K4M-2XQT-B9`, `  7K4M 2XQT B9  ` all normalize to the same `K_code`; and `7K4M2XQTBO`, `7K4M2XQTB1`, and a Cyrillic-А variant are all rejected.

---

## Cross-cutting notes for whoever fixes these

**Fix the class, not just the three instances.** All three defects are the same failure: a construction described in prose or pseudo-code without a byte-level layout. Before closing this report, re-read the spec for every other place a value is concatenated, hashed, or serialized, and check that a stranger could produce the bytes. Candidates worth auditing in the same pass:

- §5.2 — `SHA-256("KEYLAY-V1-CHANNEL" || K_code)`. Same shape as the hello MAC input. Probably fine because both operands are fixed-length, but confirm the ASCII string has no terminator and no length prefix, and say so once, globally.
- §5.4 — the HKDF `info` string `"KEYLAY-V1-PAIR" || channel_id || sort(pk_A, pk_B)`. Fixed-length throughout; state it.
- §6.4 — the AAD is defined as "deterministic-CBOR encoding of header fields {1..8}". When field 8 (`re`) is absent, is it omitted from the encoded map, or present as null? The AAD must be byte-identical on both sides or every decryption fails. This may be an unlisted fourth defect; check it.
- Appendix A.1 — the prekey bundle MAC covers "all fields" with no serialization given. Same defect, deferred scope. Fix it now while the pattern is fresh, or at least record it.

**A global sentence would prevent recurrence.** Consider adding to §3: *"Wherever this specification writes `||`, it denotes concatenation of fixed-width byte strings. Every operand's width and, for integers, endianness is stated at the point of use. ASCII domain-separation strings are included as their bytes, with no terminator and no length prefix."*

**Both documents move together.** `msp-explainer.md` mirrors the spec's section numbering by design. Any edit here that does not have a matching explainer edit creates the drift the two-document structure exists to prevent.

**Sequencing.** KL-SPEC-001 is a security-relevant construction change and should be settled before the cryptographer review named in protocol spec Appendix B item 6 — otherwise the reviewer reviews text that is about to change. KL-SPEC-002 and KL-SPEC-003 block the HS and KD test vector groups respectively, which are items 2 in the conformance suite's build order and therefore block everything downstream of them.
