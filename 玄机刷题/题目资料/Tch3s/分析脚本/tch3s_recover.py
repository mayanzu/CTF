from pathlib import Path
import os, subprocess, datetime, hashlib
src=Path(__file__).resolve().parents[1] / "附件" / "Tch3s"
dst=Path(__file__).resolve().parents[1] / "分析产物" / "Tch3s-recover.bin"
data=bytearray(src.read_bytes())
seed=1753843495
assert data[0x15c1:0x15c6] == bytes.fromhex("e8eafbffff")
assert data[0x17a8:0x17ad] == bytes.fromhex("e80d190000")
assert data[0x1b53:0x1b57] == bytes.fromhex("9f860100")
data[0x15c1:0x15c6] = bytes.fromhex("b8") + seed.to_bytes(4,"little")
data[0x17a8:0x17ad] = bytes.fromhex("e8f4190000")
data[0x1b53:0x1b57] = bytes(4)
dst.write_bytes(data); dst.chmod(0o755)
cipher=bytes.fromhex("B789EB607A91D08888E2C4C4E4D9573FF5333E4783390B91EDB9D2B4FD2A5FC0")
env=os.environb.copy(); env[b"FLAG"]=cipher
r=subprocess.run([str(dst)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
print("seed utc",datetime.datetime.fromtimestamp(seed,datetime.timezone.utc).isoformat())
print("patched binary sha256",hashlib.sha256(data).hexdigest())
print("exit code",r.returncode,"captured bytes",len(r.stdout))
print(r.stdout.decode("ascii","replace"))
