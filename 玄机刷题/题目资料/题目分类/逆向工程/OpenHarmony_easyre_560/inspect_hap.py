import base64, hashlib, json, pathlib, re, zipfile
root = pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\OpenHarmony_easyre_560")
hap_dir = root / "hap_extracted"
source_map = json.loads((hap_dir / "ets/sourceMaps.map").read_text(encoding="utf-8"))
print("SOURCE MAP KEYS")
for key, value in source_map.items():
    print(f"key={key}\n file={value.get('file')} sources={value.get('sources')} names={len(value.get('names', []))} mappings_chars={len(value.get('mappings', ''))} sourcesContent={bool(value.get('sourcesContent'))}")
abc_path = hap_dir / "ets/modules.abc"
data = abc_path.read_bytes()
print(f"ABC size={len(data)} SHA256={hashlib.sha256(data).hexdigest()}")
print("ASCII RUNS (>=4 bytes)")
for match in re.finditer(rb"[ -~]{4,}", data):
    raw = match.group().decode("ascii", "replace")
    print(f"0x{match.start():06x}: {raw}")
print("BASE64-LIKE TOKENS AND DECODE ATTEMPTS")
text = "\n".join(m.group().decode("ascii", "replace") for m in re.finditer(rb"[A-Za-z0-9_+/=-]{8,}", data))
seen = set()
for token in re.findall(r"[A-Za-z0-9_+/=-]{8,}", text):
    if token in seen: continue
    seen.add(token)
    normalized = token.replace("-", "+").replace("_", "/")
    normalized += "=" * ((-len(normalized)) % 4)
    try:
        decoded = base64.b64decode(normalized, validate=True)
    except Exception:
        continue
    print(f"{token!r} -> {decoded!r} hex={decoded.hex()}")
