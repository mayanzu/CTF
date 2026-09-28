"""Reproduce Xuanji challenge 581 from its local PCAP attachment.

Requires Pillow: python -m pip install pillow
Usage: python solve_581_network_forensics.py [attachment.zip] [output.png]
"""

from __future__ import annotations

import re
import struct
import sys
import zipfile
from pathlib import Path

from PIL import Image


HERE = Path(__file__).parent
DEFAULT_ZIP = HERE / "attachments" / "581-network-forensics.zip"
DEFAULT_IMAGE = HERE / "attachments" / "581-network-forensics" / "screenshot.png"
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",  # classic pcap, little endian, microseconds
    b"\xa1\xb2\xc3\xd4": ">",  # classic pcap, big endian, microseconds
    b"\x4d\x3c\xb2\xa1": "<",  # classic pcap, little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": ">",  # classic pcap, big endian, nanoseconds
}


def pcap_tcp_payloads(data: bytes) -> dict[tuple[str, str, int, int], list[tuple[int, bytes]]]:
    if len(data) < 24 or data[:4] not in PCAP_MAGICS:
        raise ValueError("input is not a classic PCAP file")
    endian = PCAP_MAGICS[data[:4]]
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    if linktype != 1:
        raise ValueError(f"expected Ethernet link type 1, got {linktype}")
    flows: dict[tuple[str, str, int, int], list[tuple[int, bytes]]] = {}
    offset = 24
    while offset + 16 <= len(data):
        _, _, incl_len, _ = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        frame = data[offset:offset + incl_len]
        if len(frame) != incl_len:
            raise ValueError("truncated PCAP packet")
        offset += incl_len
        if len(frame) < 14:
            continue
        ether_type = struct.unpack_from("!H", frame, 12)[0]
        layer3 = 14
        while ether_type in (0x8100, 0x88A8):
            if len(frame) < layer3 + 4:
                break
            ether_type = struct.unpack_from("!H", frame, layer3 + 2)[0]
            layer3 += 4
        if ether_type != 0x0800 or len(frame) < layer3 + 20:
            continue
        version_ihl = frame[layer3]
        if version_ihl >> 4 != 4:
            continue
        ip_header_len = (version_ihl & 0x0F) * 4
        ip_total_len = struct.unpack_from("!H", frame, layer3 + 2)[0]
        if frame[layer3 + 9] != 6 or ip_header_len < 20:
            continue
        ip_end = min(len(frame), layer3 + ip_total_len)
        tcp_start = layer3 + ip_header_len
        if tcp_start + 20 > ip_end:
            continue
        src = ".".join(str(value) for value in frame[layer3 + 12:layer3 + 16])
        dst = ".".join(str(value) for value in frame[layer3 + 16:layer3 + 20])
        src_port, dst_port, seq = struct.unpack_from("!HHI", frame, tcp_start)
        tcp_header_len = (frame[tcp_start + 12] >> 4) * 4
        payload_start = tcp_start + tcp_header_len
        payload = frame[payload_start:ip_end]
        if not payload:
            continue
        syn = frame[tcp_start + 13] & 0x02
        data_seq = (seq + int(bool(syn))) & 0xFFFFFFFF
        key = (src, dst, src_port, dst_port)
        flows.setdefault(key, []).append((data_seq, payload))
    return flows


def reassemble(segments: list[tuple[int, bytes]]) -> bytes:
    ordered = sorted(segments, key=lambda item: item[0])
    if not ordered:
        return b""
    base = ordered[0][0]
    stream = bytearray()
    for seq, payload in ordered:
        relative = seq - base
        if relative > len(stream):
            raise ValueError(f"TCP stream has a {relative - len(stream)}-byte gap")
        overlap = len(stream) - relative
        if overlap < len(payload):
            stream.extend(payload[max(0, overlap):])
    return bytes(stream)


def extract_png(stream: bytes) -> tuple[str, bytes]:
    marker = b"\r\n\r\n"
    header_end = stream.find(marker)
    if header_end < 0:
        raise ValueError("reassembled TCP stream has no complete HTTP header")
    headers = stream[:header_end]
    if not headers.startswith(b"POST /upload.php "):
        raise ValueError("expected the challenge's POST /upload.php request")
    match = re.search(rb"(?im)^Content-Type:\s*multipart/form-data;\s*boundary=(?:\"([^\"]+)\"|([^;\s]+))", headers)
    if not match:
        raise ValueError("multipart boundary not found")
    boundary = match.group(1) or match.group(2)
    body = stream[header_end + len(marker):]
    for part in body.split(b"--" + boundary):
        part = part.lstrip(b"\r\n")
        part_head, separator, content = part.partition(marker)
        filename = re.search(rb'(?i)filename="([^"]+)"', part_head)
        if separator and filename:
            name = filename.group(1).decode("utf-8", errors="replace")
            image = content.removesuffix(b"\r\n")
            if image.startswith(b"\x89PNG\r\n\x1a\n"):
                return name, image
    raise ValueError("PNG upload part not found in multipart request")


def recover_flag(image_path: Path) -> bytes:
    with Image.open(image_path) as source:
        image = source.convert("RGB")
    pixels = image.tobytes()
    bits = [pixels[index] & 1 for index in range(0, len(pixels), 3)]
    raw = bytes(
        sum(bits[index + bit] << (7 - bit) for bit in range(8))
        for index in range(0, len(bits) - 7, 8)
    )
    return raw.split(b"\x00", 1)[0]


def main() -> None:
    archive_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_ZIP
    image_path = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_IMAGE
    with zipfile.ZipFile(archive_path) as archive:
        pcap_names = [name for name in archive.namelist() if name.lower().endswith(".pcap")]
        if len(pcap_names) != 1:
            raise ValueError(f"expected one PCAP in attachment, found {len(pcap_names)}")
        capture = archive.read(pcap_names[0])
    flows = pcap_tcp_payloads(capture)
    for key, segments in flows.items():
        stream = reassemble(segments)
        if not stream.startswith(b"POST /upload.php "):
            continue
        filename, png = extract_png(stream)
        image_path.parent.mkdir(parents=True, exist_ok=True)
        image_path.write_bytes(png)
        with Image.open(image_path) as image:
            print("flow:", f"{key[0]}:{key[2]} -> {key[1]}:{key[3]}")
            print("upload:", filename)
            print("image:", image.size, image.mode)
        print("flag:", recover_flag(image_path).decode("ascii"))
        print("saved:", image_path)
        return
    raise ValueError("challenge HTTP upload was not found in the TCP streams")


if __name__ == "__main__":
    main()
