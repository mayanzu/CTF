from pathlib import Path
from hashlib import sha256
from struct import unpack_from
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
ZIP_PATH = ROOT / "originals" / "ez_vm.zip"
EXE_PATH = ROOT / "analysis" / "ez_vm.exe"
TARGET = "z8nO0NTOntKdop6dloqh1Q=="
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
EXPECTED_ZIP_SHA256 = "B9B280302A0B975F272CFCA88B59CFFB0EDE4DE3529D56A1BB328CE0D0ED071E"
EXPECTED_EXE_SHA256 = "918ACDAA4DF332FC53C0D8F2B0FC281D5B2710753C5C27BFC53F97E530572E91"


def decode_base64_bits(text: str) -> tuple[bytes, int]:
    """Decode complete bytes without relying on the prior candidate script."""
    accumulator = 0
    bit_count = 0
    decoded = bytearray()
    for char in text:
        if char == "=":
            break
        accumulator = (accumulator << 6) | ALPHABET.index(char)
        bit_count += 6
        while bit_count >= 8:
            bit_count -= 8
            decoded.append((accumulator >> bit_count) & 0xFF)
    return bytes(decoded), bit_count


def transform(data: bytes) -> bytes:
    return bytes((((value ^ 0xAA) + 5 - 2) & 0xFF) for value in data)


def standard_base64(data: bytes) -> str:
    chunks: list[str] = []
    for offset in range(0, len(data), 3):
        chunk = data[offset:offset + 3]
        first = chunk[0]
        second = chunk[1] if len(chunk) > 1 else 0
        third = chunk[2] if len(chunk) > 2 else 0
        sextets = (
            first >> 2,
            ((first & 0x03) << 4) | (second >> 4),
            ((second & 0x0F) << 2) | (third >> 6),
            third & 0x3F,
        )
        chars = "".join(ALPHABET[index] for index in sextets)
        if len(chunk) == 1:
            chars = chars[:2] + "=="
        elif len(chunk) == 2:
            chars = chars[:3] + "="
        chunks.append(chars)
    return "".join(chunks)


def binary_bug_base64(data: bytes) -> tuple[str, int, str]:
    standard = standard_base64(data)
    output_length = 4 * ((len(data) + 2) // 3)
    assert len(standard) == output_length
    pad_count = (output_length - (len(data) % 3)) & 3
    if pad_count:
        result = standard[:output_length - pad_count] + ("=" * pad_count)
    else:
        result = standard
    return result, pad_count, standard


def main() -> None:
    archive_bytes = ZIP_PATH.read_bytes()
    exe_bytes = EXE_PATH.read_bytes()
    zip_hash = sha256(archive_bytes).hexdigest().upper()
    exe_hash = sha256(exe_bytes).hexdigest().upper()
    assert zip_hash == EXPECTED_ZIP_SHA256, "original attachment hash changed"
    assert exe_hash == EXPECTED_EXE_SHA256, "saved PE hash changed"

    with ZipFile(ZIP_PATH) as archive:
        names = archive.namelist()
        assert names == ["ez_vm.exe"], f"unexpected archive members: {names!r}"
        member_bytes = archive.read(names[0])
    assert member_bytes == exe_bytes, "saved PE is not byte-identical to ZIP member"

    pe_offset = unpack_from("<I", exe_bytes, 0x3C)[0]
    assert exe_bytes[pe_offset:pe_offset + 4] == b"PE\0\0"
    machine, section_count = unpack_from("<HH", exe_bytes, pe_offset + 4)
    optional_size = unpack_from("<H", exe_bytes, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    optional_magic = unpack_from("<H", exe_bytes, optional_offset)[0]
    assert machine == 0x8664 and section_count == 11 and optional_magic == 0x20B
    image_base = unpack_from("<Q", exe_bytes, optional_offset + 24)[0]
    entry_rva = unpack_from("<I", exe_bytes, optional_offset + 16)[0]
    assert image_base == 0x140000000 and entry_rva == 0x1125
    assert optional_size > 0

    assert TARGET.encode("ascii") in exe_bytes, "comparison constant not found in attachment"
    transformed_prefix, leftover_bits = decode_base64_bits(TARGET)
    assert len(transformed_prefix) == 16 and leftover_bits == 4
    prefix = bytes((((byte - 3) & 0xFF) ^ 0xAA) for byte in transformed_prefix)
    assert prefix == b"flag{a1e05109-4x"

    accepted: list[bytes] = []
    for last_byte in range(0x100):
        candidate = prefix + bytes([last_byte])
        encoded, pad_count, standard = binary_bug_base64(transform(candidate))
        if encoded == TARGET:
            accepted.append(candidate)
            print(
                f"accepted_input_bytes={candidate!r} "
                f"input_hex={candidate.hex()} transformed_last=0x{transform(candidate)[-1]:02x} "
                f"standard_b64={standard} pad_count={pad_count} bug_b64={encoded}"
            )
    accepted_printable = [candidate for candidate in accepted if 0x20 <= candidate[-1] <= 0x7E]
    expected_printable = [b"flag{a1e05109-4xT", b"flag{a1e05109-4xU", b"flag{a1e05109-4xW"]
    assert accepted_printable == expected_printable, f"printable accepted set differs: {accepted_printable!r}"
    assert len(accepted) == 16, f"expected 16 byte-level suffixes, got {len(accepted)}"

    closed = prefix + b"}"
    closed_encoding, closed_pad, _ = binary_bug_base64(transform(closed))
    print(f"archive_sha256={zip_hash}")
    print(f"archive_members={names!r}")
    print(f"zip_member_equals_saved_pe={member_bytes == exe_bytes}")
    print(f"saved_pe_bytes={len(exe_bytes)} sha256={exe_hash}")
    print(f"pe_machine=0x{machine:04x} sections={section_count} optional_magic=0x{optional_magic:04x} image_base=0x{image_base:x} entry_rva=0x{entry_rva:x}")
    print(f"target_b64={TARGET} decoded_prefix_bytes={transformed_prefix.hex()} decoded_bytes={len(transformed_prefix)} leftover_bits={leftover_bits}")
    print(f"inverse_vm_prefix={prefix.decode('ascii')!r}")
    print(f"input_length=17 standard_encoded_length={4 * ((17 + 2) // 3)} bug_pad_count=(24-2)&3={(24-2)&3}")
    print(f"accepted_byte_suffix_values={[format(candidate[-1], '#04x') for candidate in accepted]}")
    print(f"accepted_printable_input_count={len(accepted_printable)}")
    print(f"closed_candidate={closed.decode('ascii')!r} bug_b64={closed_encoding} matches_target={closed_encoding == TARGET}")
    print("RESULT: three distinct printable 17-byte inputs pass the embedded comparison; no unique complete platform flag is proved.")


if __name__ == "__main__":
    main()
