"""Recover the CIFAR-10 trigger and write a 32x32 challenge image.

Usage: python3 solve_cifar_trigger.py path/to/challenge.zip trigger.png

The script reproduces the unique bit vectors from buffers.npz. Submit the
generated image only to the matching, authorized challenge environment.
"""

import io
import sys
import zipfile

import numpy as np
from PIL import Image


def read_buffers(path):
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            with archive.open("buffers.npz") as source:
                return np.load(io.BytesIO(source.read()))
    return np.load(path)


def recover(A, y):
    solutions = []
    vectors = [np.array([(value >> i) & 1 for i in range(8)], dtype=np.int64)
               for value in range(256)]
    for ri, r in enumerate(vectors):
        rA0 = r @ A[0]
        rA2 = r @ A[2]
        for gi, g in enumerate(vectors):
            if (rA0 @ g) % 256 != int(y[0]):
                continue
            gA1 = g @ A[1]
            for bi, b in enumerate(vectors):
                if (gA1 @ b) % 256 == int(y[1]) and (rA2 @ b) % 256 == int(y[2]):
                    solutions.append((r, g, b))
                    if len(solutions) > 1:
                        raise ValueError("constraints are not unique")
    if len(solutions) != 1:
        raise ValueError(f"expected one solution, found {len(solutions)}")
    return solutions[0]


def main(archive_path, image_path):
    data = read_buffers(archive_path)
    r, g, b = recover(data["A"], data["y"])
    print("R bits (left to right):", "".join(map(str, r.tolist())))
    print("G bits (left to right):", "".join(map(str, g.tolist())))
    print("B bits (left to right):", "".join(map(str, b.tolist())))

    image = Image.new("RGB", (32, 32), (0, 0, 0))
    pixels = image.load()
    for column, bit in enumerate(r):
        pixels[column, 0] = (255 if bit else 0, 0, 0)
    for column, bit in enumerate(g):
        pixels[column, 1] = (0, 255 if bit else 0, 0)
    for column, bit in enumerate(b):
        pixels[column, 2] = (0, 0, 255 if bit else 0)
    image.save(image_path)
    print("wrote", image_path)
    detail = image.crop((0, 0, 8, 3)).resize((256, 96), Image.Resampling.NEAREST)
    detail_path = image_path.rsplit(".", 1)[0] + "-detail.png"
    detail.save(detail_path)
    print("wrote trigger detail", detail_path)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} CHALLENGE_ZIP_OR_NPZ OUTPUT.png")
    main(sys.argv[1], sys.argv[2])
