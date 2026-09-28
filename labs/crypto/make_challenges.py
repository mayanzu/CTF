"""Regenerate the two small ciphertext files; no external packages needed."""

from pathlib import Path

here = Path(__file__).resolve().parent

message = b"flag{xor_is_not_magic}"
key = 0x37
(here / "xor.hex").write_text(bytes(x ^ key for x in message).hex() + "\n", encoding="ascii")

message = b"flag{rsa_small_modulus}"
n, e = 61 * 53, 17
ciphertext = [pow(byte, e, n) for byte in message]
(here / "rsa.txt").write_text(
    f"n={n}\ne={e}\nciphertext={ciphertext}\n", encoding="ascii"
)
