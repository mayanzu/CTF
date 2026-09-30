from pathlib import Path
import struct

path = Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\checker_562\checker.exe')
data = path.read_bytes()
if data[:2] != b'MZ':
    raise SystemExit('错误：缺少 MZ 头')
peoff = struct.unpack_from('<I', data, 0x3C)[0]
if data[peoff:peoff + 4] != b'PE\0\0':
    raise SystemExit('错误：缺少 PE 签名')
coff = peoff + 4
machine, section_count, timestamp, _, _, optional_size, characteristics = struct.unpack_from('<HHIIIHH', data, coff)
opt = coff + 20
magic = struct.unpack_from('<H', data, opt)[0]
if magic != 0x10B:
    raise SystemExit(f'暂不支持可选头类型 0x{magic:x}')
image_base = struct.unpack_from('<I', data, opt + 28)[0]
sections = []
sec_off = opt + optional_size
for i in range(section_count):
    sh = sec_off + i * 40
    name = data[sh:sh + 8].split(b'\0', 1)[0].decode('ascii', 'replace')
    virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from('<IIII', data, sh + 8)
    sections.append((name, virtual_size, virtual_address, raw_size, raw_offset))

# objdump 符号表和反汇编显示 encrypted_flag 的虚拟地址是 0x404020。
va = 0x404020
for name, virtual_size, virtual_address, raw_size, raw_offset in sections:
    delta = va - (image_base + virtual_address)
    if 0 <= delta < raw_size:
        file_offset = raw_offset + delta
        break
else:
    raise SystemExit(f'错误：无法将 VA 0x{va:08x} 映射到文件区段')
end = data.index(b'\0', file_offset)
cipher = data[file_offset:end]
key = 0x23
candidate = bytes(b ^ key for b in cipher)
recovered_cipher = bytes(b ^ key for b in candidate)
input_line_length = len(candidate) + 1  # 末尾换行
print(f'PE machine=0x{machine:04x}, sections={section_count}, image_base=0x{image_base:08x}')
print(f'encrypted_flag VA=0x{va:08x}, file_offset=0x{file_offset:x}, section={name}')
print(f'cipher length={len(cipher)} bytes')
print(f'cipher hex={cipher.hex()}')
print(f'candidate bytes={candidate!r}')
print(f'candidate text={candidate.decode("ascii", "backslashreplace")}')
print(f'candidate length={len(candidate)}; no NUL={b"\0" not in candidate}; no newline={b"\n" not in candidate}')
print(f'line length with newline={input_line_length}; fits fgets(buffer, 50)={input_line_length <= 49}')
print(f'forward XOR match={recovered_cipher == cipher}')
print(f'flag prefix/suffix={candidate.startswith(b"flag{") and candidate.endswith(b"}")}')
