from pathlib import Path
from PIL import Image
import cv2, numpy as np
im=np.array(Image.open(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png')).convert('RGB'))
gray=cv2.cvtColor(im,cv2.COLOR_RGB2GRAY)
circles=cv2.HoughCircles(gray,cv2.HOUGH_GRADIENT,dp=1,minDist=25,param1=100,param2=25,minRadius=16,maxRadius=45)
print('Hough circles (x,y,r):')
print(None if circles is None else sorted([(round(x),round(y),round(r)) for x,y,r in circles[0]],key=lambda x:x[0]))
