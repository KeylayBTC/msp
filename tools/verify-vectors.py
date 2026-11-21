#!/usr/bin/env python3
"""Recompute every MSP v1 test vector from the inputs and compare with the expected values.

Standard library only. Run from anywhere:

    python3 tools/verify-vectors.py            # verifies vectors/v1/*.json
    python3 tools/verify-vectors.py path/to/v1 # or another directory

Exit code 0 = every check passed; 1 = at least one mismatch. The first address and
change address in assembly.json need BIP-32 derivation and secp256k1; those two checks
run only if the optional `embit` package is installed (pip install embit) and are
reported as SKIPPED otherwise. Everything else — normalization, key stretching, channel
id, hello commitment and MAC, key-expression sorting, descriptor template, BIP-380
checksum, descriptor_hash, BSMS Round-2 file, SAS over keys and nonces — is checked with the standard library.

Constructions are implemented literally from the specification text (section numbers
in comments). If a check fails, either the vector or this script disagrees with the
spec; read the spec section first.
"""
import hashlib, hmac, json, os, re, sys

DS = "MSP-V1"
ALPHA = "23456789abcdefghjkmnpqrstuvwxyz"          # §5.1 unambiguous set, 31 chars
ITERS = 300000                                      # §5.2
assert len(ALPHA) == 31

# ---------------------------------------------------------------- §5.1 / §5.2
def normalize(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())

def derive(code):
    salt = hashlib.sha256(f"{DS}-KDF-SALT".encode()).digest()
    k = hashlib.pbkdf2_hmac("sha512", code.encode(), salt, ITERS, 32)
    ch = hashlib.sha256(f"{DS}-CHANNEL".encode() + k).digest()
    return salt, k, ch

# ---------------------------------------------------------------- §5.3
def commit(pk, r):
    return hashlib.sha256(f"{DS}-SAS-COMMIT".encode() + pk + r).digest()

def hello_mac(k_code, pk, cm, v, caps, kdf):
    mi = b"MSP-HELLO" + bytes([v]) + caps.to_bytes(2, "big") + bytes([kdf]) + pk + cm
    return mi, hmac.new(k_code, mi, "sha256").digest()

# ---------------------------------------------------------------- §6.8
def sas(channel_id, pk_r_pairs):
    pairs = sorted(pk_r_pairs, key=lambda t: t[0])
    inp = (f"{DS}-SAS".encode() + channel_id + bytes([len(pairs)])
           + b"".join(pk + r for pk, r in pairs) + (0).to_bytes(2, "big"))
    d = hashlib.sha256(inp).digest()
    n = int.from_bytes(d, "big") % (31 ** 12)                 # whole digest, no bias
    s = ""
    for _ in range(12):
        s = ALPHA[n % 31] + s
        n //= 31
    s = s.upper()
    return inp, d, f"{s[0:4]}-{s[4:8]}-{s[8:12]}"

# ---------------------------------------------------------------- BIP-380 checksum
_INPUT = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
_CHK = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _polymod(c, val):
    c0 = c >> 35
    c = ((c & 0x7ffffffff) << 5) ^ val
    if c0 & 1: c ^= 0xf5dee51989
    if c0 & 2: c ^= 0xa9fdca3312
    if c0 & 4: c ^= 0x1bab10e32d
    if c0 & 8: c ^= 0x3706b1677a
    if c0 & 16: c ^= 0x644d626ffd
    return c

def descriptor_checksum(s):
    c, cls, cnt = 1, 0, 0
    for ch in s:
        pos = _INPUT.find(ch)
        if pos < 0:
            raise ValueError(f"character not allowed in descriptor: {ch!r}")
        c = _polymod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        cnt += 1
        if cnt == 3:
            c = _polymod(c, cls); cls = 0; cnt = 0
    if cnt > 0:
        c = _polymod(c, cls)
    for _ in range(8):
        c = _polymod(c, 0)
    c ^= 1
    return "".join(_CHK[(c >> (5 * (7 - j))) & 31] for j in range(8))

# ---------------------------------------------------------------- reporting
results = []
def check(name, got, want):
    ok = got == want
    results.append((name, ok))
    flag = "PASS" if ok else "FAIL"
    print(f"{flag}  {name}")
    if not ok:
        print(f"      expected: {want}")
        print(f"      got:      {got}")
    return ok

def skip(name, why):
    results.append((name, None))
    print(f"SKIP  {name} — {why}")

H = lambda b: b.hex()

# ---------------------------------------------------------------- vectors
def verify_derivation(v):
    codes = {normalize(x) for x in v["inputs"]["code_as_typed"]}
    check("derivation: every spelling normalizes to the same code", codes, {v["expect"]["code"]})
    salt, k, ch = derive(v["expect"]["code"])
    check("derivation: salt_v1", H(salt), v["expect"]["salt_v1"])
    check("derivation: iterations", ITERS, v["expect"]["iterations"])
    check("derivation: K_code", H(k), v["expect"]["K_code"])
    check("derivation: channel_id", H(ch), v["expect"]["channel_id"])
    for r in v.get("refusals", []):
        n = normalize(r["code_as_typed"])
        check(f"derivation refusal: {r['code_as_typed']!r} normalizes to {r['normalized']!r}", n, r["normalized"])
        check(f"derivation refusal: {r['code_as_typed']!r} is too short", len(n) < 10, r["expect"] == "REJECT_TOO_SHORT")

def verify_hello(v):
    i, e = v["inputs"], v["expect"]
    pk, r = bytes.fromhex(i["pk"]), bytes.fromhex(i["r"])
    cm = commit(pk, r)
    check("hello: commitment cm = SHA-256(domain || pk || r)", H(cm), e["cm"])
    mi, mac = hello_mac(bytes.fromhex(i["K_code"]), pk, cm, i["v"], i["caps"], i["kdf"])
    check("hello: mac_input bytes", H(mi), e["mac_input"])
    check("hello: mac_input length is 77", len(mi), e["mac_input_len"])
    check("hello: mac", H(mac), e["mac"])
    check("hello: wire bytes = mac_input || mac", H(mi + mac), e["hello"])
    check("hello: wire length is 109", len(mi + mac), e["hello_len"])

def verify_sas(v):
    i, e = v["inputs"], v["expect"]
    pairs = []
    for p in i["participants"]:
        pk, r = bytes.fromhex(p["pk"]), bytes.fromhex(p["r"])
        check(f"sas: nonce opens commitment for pk {p['pk'][:8]}…", H(commit(pk, r)), p["cm"])
        pairs.append((pk, r))
    inp, d, s = sas(bytes.fromhex(i["channel_id"]), pairs)
    check("sas: preimage", H(inp), e["sas_input_preimage"])
    check("sas: sas_input digest", H(d), e["sas_input"])
    check("sas: rendered string", s, e["SAS"])
    _, _, ch = derive(i["code"])
    check("sas: channel_id matches the code", H(ch), i["channel_id"])

def verify_assembly(v):
    i, m, e = v["inputs"], v["intermediate"], v["expect"]
    body = i["session_init_body"]
    mm, n, script_type, template, network = body["1"], body["2"], body["3"], body["4"], body["5"]
    keys = [k["key"] for k in i["key_contributions"]]
    check("assembly: n key contributions", len(keys), n)
    check("assembly: key expressions as received", keys, m["key_expressions_as_received"])
    srt = sorted(keys)                                                   # §6.6a step 2: bytewise
    check("assembly: sorted key expressions", srt, m["key_expressions_sorted"])
    # §6.6 derivation_template restriction (2026-11-05): m/48'/C'/A'/S'
    mt = re.fullmatch(r"m/48'/([01])'/(0|[1-9][0-9]*)'/([12])'", template)
    check("assembly: derivation_template is a BIP-48 form", bool(mt), True)
    if mt:
        check("assembly: template coin agrees with network", int(mt.group(1)), network)
        check("assembly: template script agrees with script_type", {0: 2, 2: 1}.get(script_type), int(mt.group(3)))
    inner = f"sortedmulti({mm}," + ",".join(k + "/**" for k in srt) + ")"
    if script_type == 0:
        tmpl = f"wsh({inner})"
    elif script_type == 2:
        tmpl = f"sh(wsh({inner}))"
    else:
        check("assembly: script_type is supported in v0.1", script_type, "0 or 2"); return
    check("assembly: descriptor template without checksum", tmpl, m["descriptor_template_no_checksum"])
    full = tmpl + "#" + descriptor_checksum(tmpl)                          # §6.6a step 4
    check("assembly: descriptor template with BIP-380 checksum", full, e["descriptor_template"])
    check("assembly: descriptor_hash", H(hashlib.sha256(full.encode("ascii")).digest()), e["descriptor_hash"])
    r2 = "BSMS 1.0\n" + full + "\n/0/*,/1/*\n" + e["first_address"] + "\n"  # §6.6a step 7
    check("assembly: BSMS Round-2 file", r2, e["bsms_round2_file"])
    try:
        from embit.descriptor import Descriptor
        from embit.networks import NETWORKS
        net = NETWORKS["main" if network == 0 else "test"]
        # BSMS "/**" means "/0/*" for receive and "/1/*" for change (§6.6a step 6); expand before parsing.
        recv = Descriptor.from_string(tmpl.replace("/**", "/0/*"))
        chg = Descriptor.from_string(tmpl.replace("/**", "/1/*"))
        check("assembly: first address (embit)", recv.derive(0).address(net), e["first_address"])
        check("assembly: first change address (embit)", chg.derive(0).address(net), e["first_change_address"])
    except ImportError:
        skip("assembly: first address and change address", "install embit to check (pip install embit)")

HANDLERS = {"derivation": verify_derivation, "hello": verify_hello, "sas": verify_sas, "assembly": verify_assembly}

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    vdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "vectors", "v1")
    files = sorted(f for f in os.listdir(vdir) if f.endswith(".json"))
    if not files:
        print(f"no vector files in {vdir}"); sys.exit(1)
    for f in files:
        v = json.load(open(os.path.join(vdir, f), encoding="utf-8"))
        print(f"\n== {f}  (§{v.get('section')}, {v.get('name')})")
        h = HANDLERS.get(f[:-5])
        if h is None:
            skip(f, "no verifier for this file yet"); continue
        h(v)
    passed = sum(1 for _, ok in results if ok is True)
    failed = sum(1 for _, ok in results if ok is False)
    skipped = sum(1 for _, ok in results if ok is None)
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
