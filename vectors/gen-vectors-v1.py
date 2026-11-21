#!/usr/bin/env python3
"""Generates the v1 test vectors for §10.1–§10.3 of the spec and writes them as JSON.
Stdlib only. Run: python3 gen-vectors-v1.py  (writes v1/*.json next to this file)

Constructions implemented literally from the spec text:
  salt_v1    = SHA-256("MSP-V1-KDF-SALT")
  K_code     = PBKDF2-HMAC-SHA512(code, salt_v1, 300000, 32)
  channel_id = SHA-256("MSP-V1-CHANNEL" || K_code)
  cm         = SHA-256("MSP-V1-SAS-COMMIT" || pk || r)          r = 32 random bytes, revealed later (rev. 2026-11-09)
  hello mac  = HMAC-SHA256(K_code, "MSP-HELLO" || u8 v || u16be caps || u8 kdf || pk || cm)   (77 bytes)
  hello      = mac_input || mac   (109 bytes, fixed-width, not CBOR; magic "MSP-HELLO" is version-free)
  sas_input  = SHA-256("MSP-V1-SAS" || channel_id || u8 n || (pk_i || r_i) for participants sorted by pk || u16be 0)
  SAS        = (sas_input as a 256-bit integer) mod 31^12, 12 base-31 digits, uppercase, XXXX-XXXX-XXXX
Domain strings: MSP-V1-* (renamed from KEYLAY-V1-* on 2026-10-07).
"""
import hashlib, hmac, json, os, re

DS = "MSP-V1"
ALPHA = "23456789abcdefghjkmnpqrstuvwxyz"   # §5.1 unambiguous set (31 chars)
assert len(ALPHA) == 31
ITERS = 300000

def normalize(s):      # §5.1
    return re.sub(r"[^a-z0-9]", "", s.lower())

def derive(code):      # §5.2
    salt = hashlib.sha256(f"{DS}-KDF-SALT".encode()).digest()
    k = hashlib.pbkdf2_hmac("sha512", code.encode(), salt, ITERS, 32)
    ch = hashlib.sha256(f"{DS}-CHANNEL".encode() + k).digest()
    return salt, k, ch

def commit(pk, r):                               # §5.3
    return hashlib.sha256(f"{DS}-SAS-COMMIT".encode() + pk + r).digest()

def hello_mac(k_code, pk, cm, v=1, caps=0, kdf=1):   # §5.3
    mi = b"MSP-HELLO" + bytes([v]) + caps.to_bytes(2, "big") + bytes([kdf]) + pk + cm
    assert len(mi) == 77
    return mi, hmac.new(k_code, mi, "sha256").digest()

def sas(channel_id, pk_r_pairs):                 # §6.8: pairs sorted by pk; no ceremony_bind
    pairs = sorted(pk_r_pairs, key=lambda t: t[0])
    inp = (f"{DS}-SAS".encode() + channel_id + bytes([len(pairs)])
           + b"".join(pk + r for pk, r in pairs) + (0).to_bytes(2, "big"))
    d = hashlib.sha256(inp).digest()
    n = int.from_bytes(d, "big") % (31 ** 12)
    s = ""
    for _ in range(12):
        s = ALPHA[n % 31] + s; n //= 31
    s = s.upper()
    return inp, d, f"{s[0:4]}-{s[4:8]}-{s[8:12]}"

H = lambda b: b.hex()
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "v1")
os.makedirs(out, exist_ok=True)

# 10.1
spellings = ["7k4m2xqtb9", "7K4M2XQTB9", "7k4m-2xqt-b9", "7k4m · 2xqt · b9", "  7K4M 2XQT B9  "]
codes = {normalize(x) for x in spellings}; assert codes == {"7k4m2xqtb9"}
salt, k, ch = derive("7k4m2xqtb9")
json.dump({
  "suite": f"{DS.lower()}", "section": "5.1-5.2", "name": "derivation-basic",
  "inputs": {"code_as_typed": spellings},
  "expect": {"code": "7k4m2xqtb9", "salt_v1": H(salt), "kdf": 1, "iterations": ITERS,
             "K_code": H(k), "channel_id": H(ch)},
  "refusals": [
    {"code_as_typed": "7k4m2xqtbа", "normalized": normalize("7k4m2xqtbа"), "expect": "REJECT_TOO_SHORT"},
  ],
  "notes": ["'7k4m2xqtbo' and '7k4m2xqtb0' are distinct valid codes, not errors."]
}, open(f"{out}/derivation.json", "w"), indent=2, ensure_ascii=False)

# 10.2
kc = bytes(range(32)); pk = bytes(range(0x20, 0x40)); r = bytes(range(0x40, 0x60))
cm = commit(pk, r)
mi, mac = hello_mac(kc, pk, cm)
json.dump({
  "suite": f"{DS.lower()}", "section": "5.3", "name": "hello-mac",
  "inputs": {"K_code": H(kc), "pk": H(pk), "r": H(r), "v": 1, "caps": 0, "kdf": 1},
  "expect": {"cm": H(cm), "mac_input": H(mi), "mac_input_len": 77, "mac": H(mac), "hello": H(mi + mac), "hello_len": 109},
  "notes": ["The hello on the wire is exactly mac_input || mac (109 bytes); it is not CBOR. Receivers verify the MAC over bytes 0..76 before reading pk or cm. cm = SHA-256('MSP-V1-SAS-COMMIT' || pk || r) commits to the SAS nonce r, which the sender reveals in its first encrypted message; a receiver recomputes cm from the revealed r and aborts on mismatch. The 9-byte magic MSP-HELLO carries no version; the version is the v byte."]
}, open(f"{out}/hello.json", "w"), indent=2)

# 10.3 — three participants, each with a session pk and a revealed SAS nonce r
pks = [bytes([0xa1])*32, bytes([0xb2])*32, bytes([0xc3])*32]
rs  = [bytes([0x11])*32, bytes([0x22])*32, bytes([0x33])*32]
cms = [commit(pk, r) for pk, r in zip(pks, rs)]
inp, d, s = sas(ch, list(zip(pks, rs)))
json.dump({
  "suite": f"{DS.lower()}", "section": "6.8", "name": "sas-three-participants",
  "inputs": {"code": "7k4m2xqtb9", "channel_id": H(ch),
             "participants": [{"pk": H(pk), "r": H(r), "cm": H(cm)} for pk, r, cm in zip(pks, rs, cms)]},
  "expect": {"sas_input_preimage": H(inp), "sas_input": H(d), "SAS": s},
  "notes": ["All three participants must compute the same string. The SAS covers channel_id, n, and every participant's (pk || r) in byte-wise order of pk; it does not cover the descriptor (DESCRIPTOR_CONFIRM does that under the authenticated keys). Each r must open the cm from that participant's hello. The rendering reduces the whole 256-bit digest modulo 31^12."]
}, open(f"{out}/sas.json", "w"), indent=2)

print("K_code    ", H(k)); print("channel_id", H(ch)); print("hello mac ", H(mac)); print("SAS       ", s)
