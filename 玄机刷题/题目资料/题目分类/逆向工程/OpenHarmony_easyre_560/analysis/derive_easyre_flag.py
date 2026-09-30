#!/usr/bin/env python3
"""Reproduce the string transformation visible in OpenHarmony easyre #560 bytecode."""
from __future__ import annotations

import base64


def from_char_code(value: int) -> str:
    """JavaScript String.fromCharCode keeps the low 16 bits."""
    return chr(value & 0xFFFF)


def reverse_str(value: str) -> str:
    return value[::-1]


hint1 = "`d^ba_^YZZZVWXRRT"
encoded_magic = "NzAyZDBlODgxZDNjNzNjOWIzOTBkZjIwNTRiZGQxNWNjY2I"

# Index button transform, first loop: charCodeAt(i) + hint1.length, then reverse.
first_forward = "".join(from_char_code(ord(ch) + len(hint1)) for ch in hint1)
first = reverse_str(first_forward)

# Index button transform, second loop: first.charCodeAt(i) - i, then reverse.
second_forward = "".join(from_char_code(ord(ch) - i) for i, ch in enumerate(first))
hint1_final = reverse_str(second_forward)

# Flag page's getH2 delegates to Coder.decodeToString; the encoded property is Base64.
magic_padded = encoded_magic + "=" * (-len(encoded_magic) % 4)
magic_decoded = base64.b64decode(magic_padded).decode("ascii")
flag_body = hint1_final + magic_decoded
flag = f"flag{{{flag_body}}}"

print(f"hint1 source = {hint1!r} (length {len(hint1)})")
print(f"loop 1 before reverse = {first_forward!r}")
print(f"loop 1 after reverse  = {first!r}")
print(f"loop 2 before reverse = {second_forward!r}")
print(f"route param hint1     = {hint1_final!r}")
print(f"magic base64 decoded  = {magic_decoded!r}")
print(f"flag body             = {flag_body!r}")
print(f"candidate flag        = {flag}")
