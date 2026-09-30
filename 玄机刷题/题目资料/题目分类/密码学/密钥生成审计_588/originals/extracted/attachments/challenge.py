import random
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# FLAG is secret, this script shows how output.txt was generated
FLAG = b"???"  # hidden

rng = random.Random()
rng.seed(int.from_bytes(os.urandom(16), 'big'))

# First 624 numbers are published for transparency (audit log)
public_nums = [rng.getrandbits(32) for _ in range(624)]

# Next 4 outputs are combined to derive the AES-128 key (16 bytes)
key = b"".join(rng.getrandbits(32).to_bytes(4, 'big') for _ in range(4))
ct = AES.new(key, AES.MODE_ECB).encrypt(pad(FLAG, 16))

# output.txt format:
# Line 1-624: public random numbers (decimal)
# Line 625:   encrypted flag (hex)
