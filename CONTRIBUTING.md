# Contributing

Issues and review comments are welcome. Please open an issue to discuss before sending a pull request; the specification is a draft under active revision, and a change discussed first is far more likely to land.

**What helps most, in order.** A review of one of the open constructions (issues #1–#4), with reasons. An implementation of the signer role in any language that runs against `vectors/` — a failing vector is a valuable report. Measured QR frame-size and frame-count limits for a named signing device (issue #5). A defect in the spec text: a sentence two implementers could read differently.

**Spec changes.** Every normative change needs a dated entry in `CHANGELOG.md` and in the spec's revision note, and a matching change to the explainer where the explainer discusses that section (section numbers are kept in sync by rule). If a change alters any computed value, regenerate the affected vector with the generator in `vectors/` and confirm `python3 tools/verify-vectors.py` passes.

**Security reports.** If you believe you have found a weakness in the protocol, open an issue — the protocol is a public draft and its weaknesses are meant to be public. If you have found a vulnerability in the Keylay app or relay, email contact@keylay.org instead; see `https://keylay.org/.well-known/security.txt`.

**Licenses.** Specification text and explainer are CC0-1.0; test vectors and tooling are MIT. By contributing you agree your contribution is offered under the same terms.
