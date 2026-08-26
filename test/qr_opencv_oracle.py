#!/usr/bin/env python3
import json
import subprocess

import cv2
import numpy as np

# OpenCV is a decoder oracle, not a bit-for-bit encoder oracle. Keep symbols
# inside the product's documented v12 scanning ceiling; larger conforming
# symbols are covered by the qrcode matrix comparison instead.
VECTORS = [
    ("test", 1, "M", 0),
    ("heatdeath:" + "x" * 20, 3, "M", 1),
    ("heatdeath:" + "x" * 100, 7, "M", 3),
    ("heatdeath:" + "x" * 210, 11, "M", 4),
]

detector = cv2.QRCodeDetector()
for text, version, ecc, mask in VECTORS:
    ours = json.loads(
        subprocess.check_output(
            ["node", "test/qr-oracle-dump.mjs", text, str(version), ecc, str(mask)]
        )
    )
    size = ours["size"]
    assert size == 17 + 4 * version, (version, size)
    modules = np.array(ours["modules"], dtype=np.uint8).reshape((size, size))
    quiet = 4
    scale = 10
    image = np.full((size + quiet * 2, size + quiet * 2), 255, dtype=np.uint8)
    image[quiet : quiet + size, quiet : quiet + size] = (1 - modules) * 255
    image = np.repeat(np.repeat(image, scale, axis=0), scale, axis=1)
    decoded, points, _ = detector.detectAndDecode(image)
    assert points is not None, f"OpenCV did not detect QR v{version}"
    assert decoded == text, (version, decoded, text)

print(f"OpenCV {cv2.__version__} decoded {len(VECTORS)} HEATDEATH symbols")
