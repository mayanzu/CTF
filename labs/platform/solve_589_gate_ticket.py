"""Solve 玄机 2026 安网杯「闸机票根」附件 (challenge 589).

Usage: python solve_589_gate_ticket.py [path/to/gate_ticket]

The challenge binary uses RC4 twice: first to validate an 11-byte ticket, then
with that ticket as the key to decrypt the flag. This script reads the relevant
constants from the ELF's .rodata section, so no Linux runtime is required.
"""

from pathlib import Path
import struct
import sys


def rc4(key: bytes, data: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(out)


def elf_section(path: Path, wanted: str) -> bytes:
    blob = path.read_bytes()
    if blob[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected a little-endian ELF64 binary")
    section_offset = struct.unpack_from("<Q", blob, 40)[0]
    section_size = struct.unpack_from("<H", blob, 58)[0]
    section_count = struct.unpack_from("<H", blob, 60)[0]
    names_index = struct.unpack_from("<H", blob, 62)[0]
    headers = [blob[section_offset + n * section_size: section_offset + (n + 1) * section_size]
               for n in range(section_count)]
    names_header = headers[names_index]
    names_offset, names_size = struct.unpack_from("<QQ", names_header, 24)
    names = blob[names_offset:names_offset + names_size]
    for header in headers:
        name_offset = struct.unpack_from("<I", header, 0)[0]
        end = names.find(b"\0", name_offset)
        name = names[name_offset:end].decode("ascii")
        if name == wanted:
            offset, size = struct.unpack_from("<QQ", header, 24)
            return blob[offset:offset + size]
    raise ValueError(f"section {wanted!r} not found")


def main() -> None:
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "attachments/589-gate-ticket/gate_ticket"
    data = elf_section(binary, ".rodata")
    # These offsets are within .rodata and are corroborated by the GTK1 marker.
    marker = data.find(b"GTK1")
    if marker < 0:
        raise ValueError("GTK1 data marker was not found")
    key = data[marker + 5:marker + 21]
    encrypted_ticket = data[marker + 21:marker + 32]
    # The disassembly references the encrypted flag at 0x402080 and GTK1 at
    # 0x4020c0; relative to the marker, the ciphertext begins 0x40 bytes earlier.
    encrypted_flag = data[marker - 0x40:marker - 0x40 + 38]
    ticket = rc4(key, encrypted_ticket)
    if len(ticket) != 11 or not all(0x20 <= byte <= 0x7E for byte in ticket):
        raise ValueError("decrypted ticket is not the expected printable 11-byte value")
    if rc4(key, ticket) != encrypted_ticket:
        raise ValueError("ticket verification failed")
    flag = rc4(ticket, encrypted_flag)
    print("ticket:", ticket.decode("ascii"))
    print("flag:", flag.decode("ascii"))


if __name__ == "__main__":
    main()
