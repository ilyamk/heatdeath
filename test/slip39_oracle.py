#!/usr/bin/env python3
import json
import subprocess

from shamir_mnemonic import combine_mnemonics, generate_mnemonics

# HEATDEATH -> the independent Trezor reference implementation.
ours = json.loads(subprocess.check_output(
    ["node", "test/slip39-oracle-dump.mjs", "--oracle"]
))
recovered = combine_mnemonics(ours["mnemonics"])
assert recovered.hex() == ours["secret"]

# Trezor reference implementation -> HEATDEATH. This direction prevents a
# shared encoder defect from being hidden by our own decoder.
secret = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
groups = generate_mnemonics(
    2,
    [(1, 1), (2, 3), (2, 3)],
    secret,
    passphrase=b"",
    extendable=True,
    iteration_exponent=1,
)
payload = json.dumps({"mnemonics": [groups[0][0], groups[1][0], groups[1][1]]})
decoded = subprocess.check_output(
    ["node", "test/slip39-oracle-combine.mjs", "--oracle"], input=payload.encode()
)
assert decoded.decode() == secret.hex()

print("SLIP-39 oracle matched shamir-mnemonic 0.3.0 in both directions")
