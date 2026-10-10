# MSP — Multisig Session Protocol

An encrypted session layer for remote multisig setup and signing: how
cosigners in different places exchange keys, descriptors, and PSBTs
without a coordinator that can read or alter them, while keeping
air-gapped signing devices air-gapped.

**Status:** draft specification, not yet published here. The spec,
explainer, test vectors, and conformance-suite draft will be posted
in late October 2026. Nothing has had external review.

MSP builds on BIP-174 (PSBT), BIP-129 (BSMS), BIP-380 descriptors,
and Blockchain Commons UR. Its reference implementation is
[Keylay](https://app.keylay.org) ([source](https://github.com/KeylayBTC/keylay)),
which today implements an earlier, two-party version of the session layer.

Presented at TABConf 8 (October 2026).
Contact: Stan Reeves (@onedigitmoney) · contact@keylay.org
