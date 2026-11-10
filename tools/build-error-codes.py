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


def pinned_revs():
    """Return the (caliptra-sw, caliptra-mcu-sw) git revs pinned in Cargo.toml."""
    cargo_toml = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Cargo.toml")
    try:
        with open(cargo_toml) as f:
            text = f.read()
    except OSError:
        return (None, None)

    def rev_for(repo):
        m = re.search(r'git\s*=\s*"[^"]*/' + re.escape(repo) + r'(?:\.git)?"\s*,\s*rev\s*=\s*"([0-9a-f]+)"', text)
        return m.group(1) if m else None

    return (rev_for("caliptra-sw"), rev_for("caliptra-mcu-sw"))


def find_default_paths():
    """Search ~/.cargo/git/checkouts for the caliptra-sw and caliptra-mcu-sw checkouts.

    Prefers the checkout matching the rev pinned in Cargo.toml (cargo names
    checkout directories after the first 7 hex digits of the commit), and
    falls back to the most recently modified checkout.
    """
    home = os.path.expanduser("~")
    base = os.path.join(os.environ.get("CARGO_HOME", os.path.join(home, ".cargo")), "git", "checkouts")
    cap_rev, mcu_rev = pinned_revs()

    def pick(repo_glob, rev):
        paths = glob.glob(os.path.join(base, repo_glob, "*", "error", "src", "lib.rs"))
        if rev:
            exact = [p for p in paths if os.path.basename(p.split(os.sep + "error" + os.sep)[0]) == rev[:7]]
            if exact:
                return exact[0]
        paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return paths[0] if paths else None

    return (pick("caliptra-sw-*", cap_rev), pick("caliptra-mcu-sw-*", mcu_rev))


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
