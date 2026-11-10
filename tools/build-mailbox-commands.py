#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""Generate mailbox-commands.json: the Caliptra mailbox command IDs a release supports.

Parses the `pub const NAME: Self = Self(0x...)` entries in `impl CommandId`
in caliptra-sw's api/src/mailbox.rs. The emulator page compares these lists
across releases to mark commands that only some releases support, e.g.
"(2.1+)".

Usage:
    ./tools/build-mailbox-commands.py --caliptra-sw PATH -o OUTPUT
"""

import argparse
import json
import os
import re
import sys

CONST = re.compile(r"pub const ([A-Z][A-Z0-9_]*): Self = Self\((0x[0-9a-fA-F_]+)\)")


def command_ids(mailbox_rs):
    with open(mailbox_rs) as f:
        text = f.read()
    start = text.find("impl CommandId {")
    if start < 0:
        raise SystemExit(f"error: no `impl CommandId` block in {mailbox_rs}")
    # The impl block ends at the first line that is just "}".
    end = text.find("\n}", start)
    block = text[start:end if end >= 0 else len(text)]
    out = {}
    for name, val in CONST.findall(block):
        out[f"0x{int(val.replace('_', ''), 16):08x}"] = name
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--caliptra-sw", required=True, help="caliptra-sw checkout (repository root)")
    p.add_argument("-o", "--output", required=True, help="output JSON path")
    args = p.parse_args()

    mailbox_rs = os.path.join(args.caliptra_sw, "api", "src", "mailbox.rs")
    if not os.path.exists(mailbox_rs):
        print(f"error: {mailbox_rs} not found", file=sys.stderr)
        sys.exit(1)
    ids = command_ids(mailbox_rs)
    if not ids:
        print(f"error: no command IDs found in {mailbox_rs}", file=sys.stderr)
        sys.exit(1)
    with open(args.output, "w") as f:
        json.dump(ids, f, indent=1, sort_keys=True)
    print(f"Wrote {args.output} ({len(ids)} commands)")


if __name__ == "__main__":
    main()
