# Test vectors

Known-answer tests for the Multisig Session Protocol, version 1 constructions. Each file gives inputs, every intermediate value, and the exact output a correct implementation must produce, so an implementer can check their bytes offline before talking to anyone else's software. A spec without vectors produces implementations that agree in prose and disagree in bytes.

## Files in `v1/`

| File | Spec | What it pins down |
|---|---|---|
| `derivation.json` | §5.1–5.2 | Code normalization (five spellings of one code), `salt_v1`, PBKDF2-HMAC-SHA512 stretching to `K_code`, `channel_id`. One refusal: a code containing a Cyrillic look-alike normalizes too short and is rejected. |
| `hello.json` | §5.3 | The SAS commitment `cm` over `pk` and the nonce `r`, the 77-byte MAC input, the HMAC-SHA256 under `K_code`, and the 109-byte hello as it appears on the wire. |
| `sas.json` | §6.8 | Three participants' keys, nonces, and commitments; the SAS preimage, digest, and rendered 12-character string over the keys and nonces. The descriptor is not in the SAS. |
| `assembly.json` | §6.6a | A full 2-of-3 P2WSH mainnet assembly: three key contributions as received, sorted, the descriptor template with and without its BIP-380 checksum, `descriptor_hash`, first receive and change addresses, and the BSMS Round-2 file. Keys are derived from fixed test seeds — **never fund them.** |

## Running

```
python3 tools/verify-vectors.py
```

Standard library only; exit code 0 means every check passed. The two address checks in `assembly.json` need BIP-32 and secp256k1 and run only if `embit` is installed (`pip install embit`); otherwise they are reported as skipped. CI runs the same command with `embit` on every push.

## Regenerating

`gen-vectors-v1.py` (standard library) writes `derivation.json`, `hello.json`, and `sas.json`. `gen-assembly-vector.py` (needs `embit` and `coincurve`) writes `assembly.json`; the two generators are independent. Regenerate only when a normative change alters a computed value, and record the change in `CHANGELOG.md`.

## Not yet covered

Pairwise key derivation (§5.4), envelope encryption with its nonce and AAD construction (§6.4), a full two-party setup-then-sign transcript with pinned randomness, and the refusal cases (bad MAC, replayed counter, version downgrade, descriptor missing own key, PSBT not spending from the descriptor, the `derivation_template` refusals in §6.6). These are the first milestone of the funded work and are listed in the spec's §1.3 and Appendix B item 1.
