from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'analysis' / 'extracted' / 'encode.dat'
KEYFILE = ROOT / 'analysis' / 'extracted' / 'encode.dat.key'
KEY = KEYFILE.read_bytes()[:8]
MASK64 = (1 << 64) - 1

def rol(x: int) -> int:
    return ((x << 1) | (x >> 63)) & MASK64

def ror(x: int) -> int:
    return ((x >> 1) | (x << 63)) & MASK64

def swap(b: bytes) -> bytes:
    return bytes(v for i in range(0, 8, 2) for v in (b[i + 1], b[i]))

cipher = DATA.read_bytes()
print(f'K = {KEY.hex()} = {KEY!r}')
print('Each step is 8 raw bytes in memory order; arithmetic on bytes is modulo 256.')
for off in range(0, len(cipher) // 8 * 8, 8):
    c = cipher[off:off + 8]
    sub = bytes((a - k) & 0xff for a, k in zip(c, KEY))
    rotate_right = ror(int.from_bytes(sub, 'little')).to_bytes(8, 'little')
    pair_unswap = swap(rotate_right)
    p = bytes(a ^ k for a, k in zip(pair_unswap, KEY))
    # Forward, following MMX instructions in order.
    xor_key = bytes(a ^ k for a, k in zip(p, KEY))
    pair_swap = swap(xor_key)
    rotate_left = rol(int.from_bytes(pair_swap, 'little')).to_bytes(8, 'little')
    add_key = bytes((a + k) & 0xff for a, k in zip(rotate_left, KEY))
    print(f'block +{off:02d}: C={c.hex()}')
    print(f'  C-K       = {sub.hex()}')
    print(f'  ROR64(1)  = {rotate_right.hex()}')
    print(f'  pair swap = {pair_unswap.hex()}')
    print(f'  XOR K     = {p.hex()} -> {p!r}')
    print(f'  forward: P^K={xor_key.hex()} swap={pair_swap.hex()} '
          f'ROL64(1)={rotate_left.hex()} +K={add_key.hex()} '
          f'match={add_key == c}')
end = (len(cipher) // 8) * 8
print(f'tail unchanged [{end}:{len(cipher)}] = {cipher[end:].hex()} ({cipher[end:]!r})')
