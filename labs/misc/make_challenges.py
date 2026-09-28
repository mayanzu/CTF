"""Generate a PNG metadata challenge and a tiny valid Ethernet/IPv4/UDP PCAP."""

from base64 import b64encode
from pathlib import Path
import struct
import zlib

here = Path(__file__).resolve().parent


def chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


png = b"\x89PNG\r\n\x1a\n"
png += chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
png += chunk(b"tEXt", b"Comment\x00" + b64encode(b"flag{metadata_has_clues}"))
png += chunk(b"IDAT", zlib.compress(b"\x00\x80\x80\x80"))
png += chunk(b"IEND", b"")
(here / "pixel.png").write_bytes(png)


def ip_checksum(data: bytes) -> int:
    words = struct.unpack("!10H", data)
    total = sum(words)
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def packet(payload: bytes, ident: int) -> bytes:
    ethernet = bytes.fromhex("0200000000020200000000010800")
    source = bytes([10, 10, 0, 1])
    target = bytes([10, 10, 0, 2])
    ip0 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(payload), ident, 0, 64, 17, 0, source, target)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(payload), ident, 0, 64, 17, ip_checksum(ip0), source, target)
    udp = struct.pack("!HHHH", 40000 + ident, 9000, 8 + len(payload), 0)
    return ethernet + ip + udp + payload


pieces = [b"flag{follow_", b"the_packets", b"}"]
order = [2, 0, 1]
pcap = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
for tick, index in enumerate(order):
    frame = packet(f"part {index + 1}/3: ".encode() + pieces[index], tick + 1)
    pcap += struct.pack("<IIII", 1_700_000_000 + tick, 0, len(frame), len(frame)) + frame
(here / "fragments.pcap").write_bytes(pcap)
