#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""Generate www/error-codes.json from the Caliptra and MCU error source files.

This walks the cargo registry to find the active checkout of caliptra-sw
and caliptra-mcu-sw and parses the `(NAME, 0xHEX, "doc")` tuples from
error/src/lib.rs in each.

Usage:
    ./tools/build-error-codes.py [--caliptra-sw PATH] [--mcu-sw PATH] [-o PATH]
"""

import argparse
import glob
import json
import os
import re
import sys

PATTERN = re.compile(
    r'\(\s*([A-Z_][A-Z0-9_]*)\s*,\s*(0x[0-9a-fA-F_]+)\s*,\s*"([^"]+)"\s*\)',
    re.MULTILINE | re.DOTALL,
)


def find_default_paths():
    """Search ~/.cargo/git/checkouts for the latest caliptra-sw and caliptra-mcu-sw checkouts.

    Picks the most recently modified file when multiple checkouts exist.
    """
    home = os.path.expanduser("~")
    base = os.path.join(home, ".cargo", "git", "checkouts")
    cap = glob.glob(os.path.join(base, "caliptra-sw-*", "*", "error", "src", "lib.rs"))
    mcu = glob.glob(os.path.join(base, "caliptra-mcu-sw-*", "*", "error", "src", "lib.rs"))
    cap.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    mcu.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return (cap[0] if cap else None, mcu[0] if mcu else None)


def extract(path, source_label):
    with open(path) as f:
        text = f.read()
    out = {}
    for m in PATTERN.finditer(text):
        name, val, desc = m.group(1), m.group(2).replace("_", ""), m.group(3)
        try:
            v = int(val, 16)
        except ValueError:
            continue
        out[f"0x{v:08x}"] = {"name": name, "desc": desc, "source": source_label}
    return out


def main():
    cap_default, mcu_default = find_default_paths()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--caliptra-sw", default=cap_default,
                   help="Path to caliptra-sw error/src/lib.rs")
    p.add_argument("--mcu-sw", default=mcu_default,
                   help="Path to caliptra-mcu-sw error/src/lib.rs")
    p.add_argument("-o", "--output", default="www/error-codes.json",
                   help="Output JSON path (default: www/error-codes.json)")
    args = p.parse_args()

    if not args.caliptra_sw or not os.path.exists(args.caliptra_sw):
        print(f"error: caliptra-sw error file not found: {args.caliptra_sw}", file=sys.stderr)
        sys.exit(1)
    if not args.mcu_sw or not os.path.exists(args.mcu_sw):
        print(f"error: caliptra-mcu-sw error file not found: {args.mcu_sw}", file=sys.stderr)
        sys.exit(1)

    print(f"Reading {args.caliptra_sw}")
    cap = extract(args.caliptra_sw, "CaliptraError")
    print(f"Reading {args.mcu_sw}")
    mcu = extract(args.mcu_sw, "McuError")
    combined = {**cap, **mcu}
    print(f"Caliptra errors: {len(cap)}, MCU errors: {len(mcu)}, combined: {len(combined)}")

    with open(args.output, "w") as f:
        json.dump(combined, f, indent=1, sort_keys=True)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
