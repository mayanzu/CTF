from pathlib import Path
from PIL import Image
import cv2, numpy as np
im = np.array(Image.open(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png')).convert('RGB'))
for color in np.unique(im.reshape(-1, 3), axis=0):
    mask = np.all(im == color, axis=2).astype(np.uint8)
    n, labels, stats, centroids = cv2.connectedComponentsWithStats(mask, 8)
    parts = [(tuple(map(int, s[:4])), int(s[4])) for s in stats[1:] if s[4] > 10]
    if parts:
        print(tuple(map(int, color)), parts)
