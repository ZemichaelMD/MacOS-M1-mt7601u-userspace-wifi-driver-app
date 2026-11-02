#!/usr/bin/env python3
"""Independent reference implementation used to generate test vectors.

This script re-implements, from the published specifications and the hostap
sources (`hostap-refs/`), the crypto constructions this crate needs:

  * the hostap-style SHA-256 PRF (`sha256_prf_bits`, `src/crypto/sha256-prf.c`),
  * the IEEE 802.11i HMAC-SHA1 PRF (counter from 0),
  * the WPA1 (HMAC-MD5) and WPA2 (HMAC-SHA1) EAPOL-Key MICs,
  * RC4 with the WPA1 key-data skip,
  * SAE (WPA3) group 19 with hunting-and-pecking PWE derivation, from
    `hostap-refs/src/common/sae.c` and `dragonfly.c`.

The P-256 arithmetic here is plain-Python integer math, deliberately sharing
no code with the Rust implementation (which uses the RustCrypto `p256`
crate), so agreement between the two is a genuine cross-check.

Run `python3 scripts/gen-crypto-vectors.py` to reprint the vectors that are
embedded in the Rust unit tests.
"""

import hashlib
import hmac
import struct

# ---------------------------------------------------------------- P-256 math

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

INF = None  # point at infinity


def pt_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def pt_mul(k, pt):
    result = None
    addend = pt
    while k:
        if k & 1:
            result = pt_add(result, addend)
        addend = pt_add(addend, addend)
        k >>= 1
    return result


def pt_neg(pt):
    return None if pt is None else (pt[0], (-pt[1]) % P)


def on_curve(x, y):
    return (y * y - (x * x * x + A * x + B)) % P == 0


def sqrt_mod(val):
    # P % 4 == 3, so the candidate root is val^((P+1)/4).
    y = pow(val, (P + 1) // 4, P)
    return y if (y * y) % P == val else None


# ------------------------------------------------------------- PRFs and MICs


def sha256_prf(key, label, data, out_len_bits):
    """hostap `sha256_prf_bits`: HMAC-SHA256(key, LE16(counter) || label ||
    data || LE16(out_len_bits)), counters from 1."""
    out_len = (out_len_bits + 7) // 8
    out = b""
    counter = 1
    while len(out) < out_len:
        msg = (
            struct.pack("<H", counter)
            + label.encode("ascii")
            + data
            + struct.pack("<H", out_len_bits)
        )
        out += hmac.new(key, msg, hashlib.sha256).digest()
        counter += 1
    out = out[:out_len]
    if out_len_bits % 8:
        mask = (0xFF << (8 - out_len_bits % 8)) & 0xFF
        out = out[:-1] + bytes([out[-1] & mask])
    return out


def sha1_prf(key, label, data, out_len):
    """IEEE 802.11i PRF: HMAC-SHA1(key, label || 0x00 || data || counter),
    counters from 0."""
    out = b""
    counter = 0
    while len(out) < out_len:
        msg = label + b"\x00" + data + bytes([counter])
        out += hmac.new(key, msg, hashlib.sha1).digest()
        counter += 1
    return out[:out_len]


def prf_input(addr1, addr2, nonce1, nonce2):
    data = min(addr1, addr2) + max(addr1, addr2) + min(nonce1, nonce2) + max(nonce1, nonce2)
    return data


def hmac_md5_128(key, msg):
    return hmac.new(key, msg, hashlib.md5).digest()  # already 16 bytes


def rc4_skip(key, skip, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    state = [0, 0]  # i, j

    def rc4_byte():
        state[0] = (state[0] + 1) % 256
        state[1] = (state[1] + s[state[0]]) % 256
        s[state[0]], s[state[1]] = s[state[1]], s[state[0]]
        return s[(s[state[0]] + s[state[1]]) % 256]

    for _ in range(skip):
        rc4_byte()
    return bytes(b ^ rc4_byte() for b in data)


# ---------------------------------------------------------------- SAE (group 19)


def sae_pwe(password, own_mac, peer_mac):
    """Hunting-and-pecking PWE derivation (sae_derive_pwe_ecc, h2e=0)."""
    if own_mac > peer_mac:
        key = own_mac + peer_mac
    else:
        key = peer_mac + own_mac
    prime = P.to_bytes(32, "big")
    for counter in range(1, 201):
        pwd_seed = hmac.new(key, password + bytes([counter]), hashlib.sha256).digest()
        pwd_value = sha256_prf(pwd_seed, "SAE Hunting and Pecking", prime, 256)
        x = int.from_bytes(pwd_value, "big")
        if x >= P:
            continue
        y_sq = (pow(x, 3, P) + A * x + B) % P
        y = sqrt_mod(y_sq)
        if y is None:
            continue
        if (y & 1) != (pwd_seed[-1] & 1):
            y = P - y
        return (counter, (x, y))
    raise RuntimeError("PWE not found")


def sae_commit(rand, mask, pwe):
    scalar = (rand + mask) % N
    element = pt_neg(pt_mul(mask, pwe))
    return scalar, element


def sae_encode_scalar(v):
    return v.to_bytes(32, "big")


def sae_encode_point(pt):
    return pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


def sae_k(rand, peer_scalar, peer_element, pwe):
    kp = pt_add(pt_mul(peer_scalar, pwe), peer_element)
    return pt_mul(rand, kp)


def sae_derive_keys(own_scalar, peer_scalar, k):
    """keyseed/KCK/PMK/PMKID from the shared point."""
    kx = k[0].to_bytes(32, "big")
    keyseed = hmac.new(bytes(32), kx, hashlib.sha256).digest()
    val = ((own_scalar + peer_scalar) % N).to_bytes(32, "big")
    keys = sha256_prf(keyseed, "SAE KCK and PMK", val, 64 * 8)
    return keys[:32], keys[32:64], val[:16], val


def sae_confirm(kck, send_confirm, scalar1, elem1, scalar2, elem2):
    msg = (
        struct.pack("<H", send_confirm)
        + sae_encode_scalar(scalar1)
        + sae_encode_point(elem1)
        + sae_encode_scalar(scalar2)
        + sae_encode_point(elem2)
    )
    return hmac.new(kck, msg, hashlib.sha256).digest()


def hexs(b):
    return b.hex()


def rust_array(name, b):
    lines = [f"const {name}: [u8; {len(b)}] = ["]
    for i in range(0, len(b), 12):
        chunk = ", ".join(f"0x{x:02x}" for x in b[i : i + 12])
        lines.append(f"    {chunk},")
    lines.append("];")
    return "\n".join(lines)


def main():
    print("=" * 72)
    print("1. hostap sha256_prf (key 16B, 64-byte output)")
    key = bytes(range(16))
    data = bytes(range(16, 32))
    out = sha256_prf(key, "Pairwise key expansion", data, 64 * 8)
    print("out =", hexs(out))

    print()
    print("2. WPA2/WPA1 PTK vector (IEEE 802.11i example, TK 32 bytes for TKIP)")
    pmk = bytes.fromhex("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e")
    aa = bytes.fromhex("000fb5fdfbc2")
    spa = bytes.fromhex("000fb5fdfbc1")
    anonce = bytes.fromhex(
        "7ef83aa063cbcfd4f65f8532423a112f2c3d4e5f60718293a4b5c6d7e8f90123"
    )
    snonce = bytes.fromhex(
        "0e1f22456d4e1a0ff412275a1d1f2e3a4b5c6d7e8f901234567890abcdef0123"
    )
    ptk64 = sha1_prf(pmk, b"Pairwise key expansion",
                     prf_input(aa, spa, anonce, snonce), 64)
    print("kck =", hexs(ptk64[0:16]))
    print("kek =", hexs(ptk64[16:32]))
    print("tk  =", hexs(ptk64[32:64]))

    ptk48s = sha256_prf(pmk, "Pairwise key expansion",
                        prf_input(aa, spa, anonce, snonce), 48 * 8)
    print("sha256 kck =", hexs(ptk48s[0:16]))
    print("sha256 kek =", hexs(ptk48s[16:32]))
    print("sha256 tk  =", hexs(ptk48s[32:48]))

    print()
    print("3. WPA1 EAPOL-Key MIC (HMAC-MD5-128) over a synthetic frame")
    frame = bytearray((i * 7 + 3) % 251 for i in range(99))
    frame[81:97] = bytes(16)  # MIC field zeroed
    kck = ptk64[0:16]
    print("frame =", hexs(bytes(frame)))
    print("mic   =", hexs(hmac_md5_128(kck, bytes(frame))))

    print()
    print("4. RC4 skip 256 (WPA1 key-data decryption)")
    ek = bytes.fromhex("00112233445566778899aabbccddeeff" + "f0e1d2c3b4a5968778695a4b3c2d1e0f")
    data = bytes(range(64))
    print("ek   =", hexs(ek))
    print("data =", hexs(data))
    print("out  =", hexs(rc4_skip(ek, 256, data)))

    print()
    print("5. SAE group 19 full exchange")
    password = b"12345678"
    own_mac = bytes.fromhex("020000000001")
    peer_mac = bytes.fromhex("020000000002")
    rand_a = bytes.fromhex("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00")
    mask_a = bytes.fromhex("2233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011")
    rand_b = bytes.fromhex("33445566778899aabbccddeeff00112233445566778899aabbccddeeff001122")
    mask_b = bytes.fromhex("445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233")

    counter, pwe = sae_pwe(password, own_mac, peer_mac)
    print("pwe_counter =", counter)
    print("pwe_x =", hexs(sae_encode_scalar(pwe[0])[:32]))
    print("pwe_y =", hexs(sae_encode_scalar(pwe[1])[:32]))

    scalar_a, elem_a = sae_commit(int.from_bytes(rand_a, "big"), int.from_bytes(mask_a, "big"), pwe)
    scalar_b, elem_b = sae_commit(int.from_bytes(rand_b, "big"), int.from_bytes(mask_b, "big"), pwe)

    commit_a = struct.pack("<H", 19) + sae_encode_scalar(scalar_a) + sae_encode_point(elem_a)
    commit_b = struct.pack("<H", 19) + sae_encode_scalar(scalar_b) + sae_encode_point(elem_b)
    print("commit_a =", hexs(commit_a))
    print("commit_b =", hexs(commit_b))

    k_a = sae_k(int.from_bytes(rand_a, "big"), scalar_b, elem_b, pwe)
    k_b = sae_k(int.from_bytes(rand_b, "big"), scalar_a, elem_a, pwe)
    assert k_a == k_b, "K mismatch"
    print("k =", hexs(k_a[0].to_bytes(32, "big")))

    kck, pmk_out, pmkid, val = sae_derive_keys(scalar_a, scalar_b, k_a)
    print("val =", hexs(val))
    print("kck =", hexs(kck))
    print("pmk =", hexs(pmk_out))
    print("pmkid =", hexs(pmkid))

    print("confirm_a(sc=1) =", hexs(sae_confirm(kck, 1, scalar_a, elem_a, scalar_b, elem_b)))
    print("confirm_b(sc=2) =", hexs(sae_confirm(kck, 2, scalar_b, elem_b, scalar_a, elem_a)))

    print()
    print("6. hostap test_sae.py valid commit (group 19) for parser checks")
    hostap_commit = bytes.fromhex(
        "1300"
        "033d3635b39666ed427fd4a3e7d37acec2810afeaf1687f746a14163ff0e6d03"
        "559cb8928db4ce4e3cbd6555e837591995e5ebe503ef36b503d9ca519d63728d"
        "d3c7c676b8e8081831b6bc3a64bdf136061a7de175e17d1965bfa41983ed02f8"
    )
    x = int.from_bytes(hostap_commit[34:66], "big")
    y = int.from_bytes(hostap_commit[66:98], "big")
    print("on_curve =", on_curve(x, y))


if __name__ == "__main__":
    main()
