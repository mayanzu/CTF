from pathlib import Path
import hashlib
import re
import struct
import subprocess
import zipfile

root = Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\checker_562')
archive = root / 'originals' / 'checker_platform_download_20260929_051349.zip'
binary = root / 'checker.exe'
prior_output = root / '正向复算输出.txt'
zip_bytes = archive.read_bytes()
with zipfile.ZipFile(archive) as zf:
    names = zf.namelist()
    exe_bytes = zf.read('checker.exe')
if names != ['checker.exe']:
    raise SystemExit(f'附件成员不符合预期: {names!r}')
if exe_bytes != binary.read_bytes():
    raise SystemExit('独立提取文件与 ZIP 内 checker.exe 不相同')
if exe_bytes[:2] != b'MZ':
    raise SystemExit('不是 PE/MZ 文件')
peoff = struct.unpack_from('<I', exe_bytes, 0x3C)[0]
if exe_bytes[peoff:peoff + 4] != b'PE\0\0':
    raise SystemExit('PE 签名错误')
coff = peoff + 4
machine, section_count, _, _, _, optional_size, _ = struct.unpack_from('<HHIIIHH', exe_bytes, coff)
opt = coff + 20
image_base = struct.unpack_from('<I', exe_bytes, opt + 28)[0]
section_table = opt + optional_size
target_va = 0x404020
for i in range(section_count):
    sh = section_table + 40 * i
    section_name = exe_bytes[sh:sh + 8].split(b'\0', 1)[0].decode('ascii')
    _, virtual_address, raw_size, raw_offset = struct.unpack_from('<IIII', exe_bytes, sh + 8)
    delta = target_va - (image_base + virtual_address)
    if 0 <= delta < raw_size:
        file_offset = raw_offset + delta
        break
else:
    raise SystemExit('目标 VA 不属于任何文件内节')
end = exe_bytes.index(b'\0', file_offset)
cipher = exe_bytes[file_offset:end]
candidate = bytes(byte ^ 0x23 for byte in cipher)
prior_text = re.search(r'^candidate text=(.*)$', prior_output.read_text(encoding='utf-16'), re.M).group(1)
expected_input = candidate + b'\n'
if b'\0' in candidate or b'\n' in candidate or b'\r' in candidate:
    raise SystemExit('候选含 fgets/C 字符串不允许的字节')
if len(expected_input) > 49:
    raise SystemExit('带换行输入超出 fgets(50) 可读取的最大 49 字节')
proc = subprocess.run([str(binary)], input=expected_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
stdout = proc.stdout.decode('ascii', 'replace')
stderr = proc.stderr.decode('ascii', 'replace')
print(f'archive_sha256={hashlib.sha256(zip_bytes).hexdigest()}')
print(f'binary_sha256={hashlib.sha256(exe_bytes).hexdigest()}')
print(f'zip_members={names!r}; independent_extract_matches=True')
print(f'PE machine=0x{machine:04x}; image_base=0x{image_base:08x}; section_count={section_count}')
print(f'encrypted_global_va=0x{target_va:08x}; file_offset=0x{file_offset:x}; bytes={len(cipher)}')
print(f'prior_candidate_matches_independent_decode={prior_text.encode("ascii") == candidate}')
print(f'candidate_length={len(candidate)}; input_bytes_with_LF={len(expected_input)}; fgets50_safe={len(expected_input) <= 49}')
print(f'local_checker_exit_code={proc.returncode}')
print(f'local_checker_stdout={stdout!r}')
print(f'local_checker_stderr={stderr!r}')
print(f'local_checker_accepts_input={"Correct! You have the flag." in stdout}')
