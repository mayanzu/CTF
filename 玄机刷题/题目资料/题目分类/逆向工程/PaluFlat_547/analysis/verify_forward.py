from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parent.parent
exe=ROOT/"analysis"/"extracted"/"PaluFlat.exe"
head=ROOT/"analysis"/"PaluFlat_head_0x5000.bin"
with exe.open("rb") as f:
    prefix=f.read(0x5000)
assert prefix==head.read_bytes()
# Independently transcribed from the 19 immediate byte stores at 0x4020b4.
expected=bytes.fromhex("f3548423a474d4c3305f3243f054f474002243")
candidate=b"flag{bdm23Ne6ljz5O}"
key_pattern=b"pllt"
def forward(candidate):
    out=bytearray()
    for i,value in enumerate(candidate):
        x=value^key_pattern[i%4]
        x=((x<<4)|(x>>4))&0xff
        x=(x-0x55)&0xff
        out.append((~x)&0xff)
    return bytes(out)
actual=forward(candidate)
print("candidate:",candidate.decode("ascii"))
print("candidate length:",len(candidate))
print("key pattern:",key_pattern.hex())
print("expected bytes:",expected.hex())
print("forward bytes:",actual.hex())
print("complete 19-byte match:",actual==expected)
print("target NUL byte indices:",[i for i,b in enumerate(expected) if b==0])
# The main function checks strlen(output)==19 before its 19-byte compare.
print("strlen/output contradiction: target byte 16 is NUL, yet required output length is 19")
assert len(candidate)==19 and actual==expected and candidate.startswith(b"flag{") and candidate.endswith(b"}")
