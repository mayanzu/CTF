from pathlib import Path
p = Path(__file__).parent / "extracted" / "checker.exe"
data = p.read_bytes()
cipher = data[0x3220:0x3220 + 43]
assert len(cipher) == 43
plain = bytes(b ^ 0x23 for b in cipher)
print("idx | target(hex) | XOR key | decoded")
print("----|------------|---------|--------")
for i, (c, q) in enumerate(zip(cipher, plain)):
    char = chr(q)
    shown = char if char.isprintable() and char not in "|\\" else repr(char)
    print(f"{i:02d}  | {c:02X}         | 23      | {shown}")
print("decoded=" + plain.decode("ascii"))
