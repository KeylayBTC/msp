#!/usr/bin/env python3
"""Generates the §6.6a descriptor-assembly transcript vector (inputs: plain key expressions, per the 2026-10-08 KEY_CONTRIBUTION format; no BSMS Round-1 signatures) (three cosigners, 2-of-3 P2WSH, mainnet)
(The SAS vector no longer depends on this file; see sas.json.)  Requires: pip install embit coincurve
Deterministic: seeds are fixed test values (DO NOT USE WITH REAL FUNDS).
"""
import hashlib, hmac, json, os, base64
from embit import bip32, bip39, script, ec
from embit.networks import NETWORKS
from embit.descriptor import Descriptor
from embit.descriptor.checksum import add_checksum
import coincurve

NET = NETWORKS["main"]
PATH = "m/48'/0'/0'/2'"              # SESSION_INIT derivation_template, instantiated for mainnet
M, N = 2, 3
ALPHA = "23456789abcdefghjkmnpqrstuvwxyz"
DS = "MSP-V1"

def legacy_sign(priv32: bytes, msg: bytes) -> str:
    """Bitcoin legacy signed-message format (BIP-137 header), base64 — what BSMS Round 1 SIG uses."""
    def varint(n): return bytes([n]) if n < 0xfd else b"\xfd" + n.to_bytes(2, "little")
    h = hashlib.sha256(hashlib.sha256(b"\x18Bitcoin Signed Message:\n" + varint(len(msg)) + msg).digest()).digest()
    sig = coincurve.PrivateKey(priv32).sign_recoverable(h, hasher=None)   # 64 bytes r||s + recid
    r_s, rec = sig[:64], sig[64]
    return base64.b64encode(bytes([27 + 4 + rec]) + r_s).decode()

cosigners = []
for i, name in enumerate(["Alice", "Bob", "Carol"]):
    seed = bip39.mnemonic_to_seed(bip39.mnemonic_from_bytes(bytes([i + 1]) * 16))
    root = bip32.HDKey.from_seed(seed)
    fp = root.child(0).parent_fingerprint if False else root.my_fingerprint.hex()   # master fingerprint
    acct = root.derive(PATH)
    xpub = acct.to_public().to_string(NET["xpub"])
    key_line = f"[{fp}/{PATH[2:]}]{xpub}"
    rec_lines = ["BSMS 1.0", "00", key_line, f"{name} key"]
    sig = legacy_sign(acct.secret, "\n".join(rec_lines).encode())
    record = "\n".join(rec_lines + [sig]) + "\n"
    cosigners.append({"name": name, "fingerprint": fp, "xpub": xpub, "key_line": key_line,
                      "bsms_round1_record": record})

# §6.6a step 2: sort key expressions byte-wise
keys_sorted = sorted(c["key_line"] for c in cosigners)
template = f"wsh(sortedmulti({M},{','.join(k + '/**' for k in keys_sorted)}))"
template_cs = add_checksum(template)
descriptor_hash = hashlib.sha256(template_cs.encode()).hexdigest()

# first address: receive branch /0, index 0.
# NOTE (2026-10-08): an earlier version expanded "/**" to "/0/0" and called .address() directly;
# embit silently ignores the trailing derivation in that form and returns the address of the
# account-level keys. The value published before 2026-10-08 (bc1qs4xwp...) was therefore wrong.
d = Descriptor.from_string(template.replace("/**", "/0/*"))
first_address = d.derive(0).address(NET)
first_change = Descriptor.from_string(template.replace("/**", "/1/*")).derive(0).address(NET)

# Independent cross-check: manual BIP-32 public derivation + BIP-67 sort + P2WSH, no descriptor library.
def _ckd_pub(pub, cc, i):
    I = hmac.new(cc, pub + i.to_bytes(4, "big"), hashlib.sha512).digest()
    P = coincurve.PublicKey.combine_keys([coincurve.PublicKey.from_secret(I[:32]), coincurve.PublicKey(pub)])
    return P.format(True), I[32:]
def _manual_addr(branch, idx):
    from embit.script import p2wsh, Script
    pubs = []
    for c in cosigners:
        hk = bip32.HDKey.from_base58(c["xpub"])
        p, cc = _ckd_pub(hk.key.sec(), hk.chain_code, branch)
        p, cc = _ckd_pub(p, cc, idx)
        pubs.append(p)
    pubs.sort()
    ws = bytes([0x50 + M]) + b"".join(bytes([33]) + p for p in pubs) + bytes([0x50 + N, 0xae])
    return p2wsh(Script(ws)).address(NET)
assert _manual_addr(0, 0) == first_address, (_manual_addr(0, 0), first_address)
assert _manual_addr(1, 0) == first_change, (_manual_addr(1, 0), first_change)
round2 = "BSMS 1.0\n" + template_cs + "\n/0/*,/1/*\n" + first_address + "\n"

out = {
  "suite": "msp-v1", "section": "6.6a", "name": "assembly-2of3-p2wsh-mainnet",
  "warning": "Test keys derived from fixed seeds. Never fund.",
  "inputs": {
    "session_init_body": {"1": M, "2": N, "3": 0, "4": "m/48'/0'/0'/2'", "5": 0},
    "key_contributions": [{"from": c["name"], "key": c["key_line"], "bridged": False} for c in cosigners]
  },
  "intermediate": {
    "key_expressions_as_received": [c["key_line"] for c in cosigners],
    "key_expressions_sorted": keys_sorted,
    "descriptor_template_no_checksum": template
  },
  "expect": {
    "descriptor_template": template_cs,
    "descriptor_hash": descriptor_hash,
    "first_address": first_address,
    "first_change_address": first_change,
    "bsms_round2_file": round2
  }
}
here = os.path.dirname(os.path.abspath(__file__))
json.dump(out, open(f"{here}/v1/assembly.json", "w"), indent=2)
print(template_cs); print("descriptor_hash", descriptor_hash); print("first_address", first_address)

