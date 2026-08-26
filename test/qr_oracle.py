#!/usr/bin/env python3
import json
import subprocess

import qrcode

LEVELS = {"L": qrcode.constants.ERROR_CORRECT_L, "M": qrcode.constants.ERROR_CORRECT_M}
VECTORS = [
    ("test", 1, "M", 0),
    ("x" * 30, 3, "M", 1),
    ("x" * 120, 7, "M", 3),
    ("x" * 230, 11, "M", 4),
    ("x" * 380, 15, "M", 5),
    ("x" * 470, 17, "M", 7),
]

for text, version, ecc, mask in VECTORS:
    ours = json.loads(subprocess.check_output([
        "node", "test/qr-oracle-dump.mjs", text, str(version), ecc, str(mask)
    ]))
    qr = qrcode.QRCode(
        version=version, error_correction=LEVELS[ecc], box_size=1, border=0,
        mask_pattern=mask,
    )
    qr.add_data(qrcode.util.QRData(
        text.encode("utf-8"), mode=qrcode.util.MODE_8BIT_BYTE,
    ), optimize=0)
    qr.make(fit=False)
    expected = [cell for row in qr.get_matrix() for cell in row]
    assert ours["size"] == len(qr.get_matrix())
    assert ours["modules"] == expected, (version, ecc, mask)

print(
    f"QR oracle matched qrcode "
    f"{qrcode.__version__ if hasattr(qrcode, '__version__') else '8.2'} "
    f"for {len(VECTORS)} matrices"
)
