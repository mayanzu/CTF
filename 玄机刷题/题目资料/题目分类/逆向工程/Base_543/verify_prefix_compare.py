from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import runpy

solver = Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\Base_543\solve_base_offline.py")
with redirect_stdout(StringIO()):
    ns = runpy.run_path(str(solver))
target = ns["ENCODED_TARGET"]
alphabet = ns["alphabet"]
recovered = ns["decoded"]
fixed = recovered[:18]
need_top6 = recovered[18] >> 2
choices = [value for value in range(0x21, 0x7f)
           if value >> 2 == need_top6 and value not in (ord("{"), ord("}"))]
suffix = b"A" * 10 + b"}"
print("Target compare width: 30 Base32 symbols = 150 bits")
print("150 bits cover: 18 complete bytes (144 bits) + high 6 bits of byte 19")
print("Unconstrained portion of byte 19: low 2 bits")
print("Recovered byte 19:", hex(recovered[18]), repr(bytes([recovered[18]])))
print("ASCII byte choices with the same high 6 bits:", [hex(value) for value in choices], [bytes([value]).decode("ascii") for value in choices])
print("Input prefix fixed by this comparison:", repr(fixed))
results = []
for value in choices:
    candidate = fixed + bytes([value]) + suffix
    encoded = ns["encode_base32_custom"](candidate, alphabet)
    prefix_ok = encoded[:30] == target[:30]
    full_ok = encoded == target
    results.append((candidate, prefix_ok, full_ok))
    print("candidate=", candidate.decode("ascii"), "length=", len(candidate),
          "first30_equal=", prefix_ok, "full48_equal=", full_ok)
assert len(results) == 4
assert all(prefix_ok for _, prefix_ok, _ in results)
assert not any(full_ok for _, _, full_ok in results)
assert len({candidate for candidate, _, _ in results}) == 4
print("Distinct comparison-only candidates demonstrated:", len(results))
print("This is a local comparator model only; no candidate was submitted to the platform.")
