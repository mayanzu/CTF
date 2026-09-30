cipher = bytes.fromhex(
    "45 4f 42 44 58 46 4d 53 12 14 6a 17 53 1b 77 79 "
    "4e 62 51 4a 42 4c 11 4f 52 16 57 62 62 51 79 11 "
    "73 12 54 5b 61 76 54 7b 76 11 5e"
)
key = 0x23
plain = bytes(value ^ key for value in cipher)
recovered_cipher = bytes(value ^ key for value in plain)
print(f"cipher length: {len(cipher)}")
print(f"key: 0x{key:02x}")
print(f"recovered: {plain.decode('ascii')}")
print(f"re-encryption matches: {recovered_cipher == cipher}")
assert plain.startswith(b"flag{") and plain.endswith(b"}")
assert recovered_cipher == cipher
