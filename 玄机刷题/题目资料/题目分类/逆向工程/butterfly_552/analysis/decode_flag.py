from pathlib import Path
import hashlib

ROOT = Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\butterfly_552\analysis\extracted")
ct = (ROOT / "encode.dat").read_bytes()
keyfile = (ROOT / "encode.dat.key").read_bytes()
key = keyfile[:8]  # main() loads the first 8 bytes as the MMX lane key

print("input bytes:", len(ct))
print("key file length:", len(keyfile))
print("key file repr:", repr(keyfile))
print("lane key:", key, key.hex())
print("ciphertext:", ct.hex())
print("sha256 ciphertext:", hashlib.sha256(ct).hexdigest().upper())

# Inverse of the analyzed main loop:
# C = byte_add(ROL64(swap16(P XOR K), 1), K)
# undo byte_add, ROL64, adjacent-byte swap, then XOR K.
def inv_block(block):
    assert len(block) == 8
    x = [(block[i] - key[i]) & 0xff for i in range(8)]
    # ROR64 by one bit, expressed as little-endian bytes.
    w = [(x[i] >> 1) | ((x[(i + 1) & 7] & 1) << 7) for i in range(8)]
    z = [w[i ^ 1] for i in range(8)]
    return bytes(z[i] ^ key[i] for i in range(8))

def fwd_block(block):
    assert len(block) == 8
    z = [block[i] ^ key[i] for i in range(8)]
    w = [z[i ^ 1] for i in range(8)]
    q = int.from_bytes(bytes(w), "little")
    q = ((q << 1) | (q >> 63)) & ((1 << 64) - 1)
    x = list(q.to_bytes(8, "little"))
    return bytes((x[i] + key[i]) & 0xff for i in range(8))

full = len(ct) // 8
rem = len(ct) % 8
plain = bytearray()
for i in range(full):
    c = ct[i*8:(i+1)*8]
    p = inv_block(c)
    assert fwd_block(p) == c
    plain.extend(p)
    print(f"block {i}: c={c.hex()} p={p!r} forward_match=True")

print("remainder length:", rem)
if rem:
    c = ct[full*8:]
    # The incomplete block is missing transformed bytes. In ROR64, plaintext
    # byte 2 here depends on bit 0 of missing ciphertext-derived byte x[4].
    x = [(c[i] - key[i]) & 0xff for i in range(rem)]
    choices = []
    for x4_lsb in (0, 1):
        # Only indices 0..3 are emitted. For rem == 4, only P[2] is ambiguous.
        xext = x + [x4_lsb] + [0] * (8 - rem)
        w = [(xext[i] >> 1) | ((xext[i+1] & 1) << 7) for i in range(8)]
        z = [w[i ^ 1] for i in range(8)]
        p = bytes(z[i] ^ key[i] for i in range(rem))
        choices.append((x4_lsb, p))
    print("remainder ciphertext:", c.hex())
    for x4_lsb, p in choices:
        print(f"partial candidate (unknown x[4].lsb={x4_lsb}): {p!r} hex={p.hex()}")
        # Re-encode known plaintext fragment, retaining only written output bytes.
        # Padding after the 4 written input bytes cannot affect ciphertext bytes 0..3.
        z = [(p[i] ^ key[i]) for i in range(rem)] + [0] * (8-rem)
        w = [z[i ^ 1] for i in range(8)]
        q = int.from_bytes(bytes(w), "little")
        q = ((q << 1) | (q >> 63)) & ((1 << 64) - 1)
        xx = list(q.to_bytes(8, "little"))
        cc = bytes((xx[i] + key[i]) & 0xff for i in range(rem))
        print(f"  forward emitted bytes={cc.hex()} match={cc == c}")

print("decoded complete blocks:", bytes(plain))
for x4_lsb, frag in choices:
    candidate = bytes(plain) + frag
    print(f"candidate[{x4_lsb}]={candidate!r}")
    print(f"candidate[{x4_lsb}] hex={candidate.hex()}")
    print(f"candidate[{x4_lsb}] printable={all(32 <= b < 127 for b in candidate)}")

