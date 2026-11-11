#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""Download and verify the official Caliptra 1.x ROM and firmware releases.

Reads a release list (versions/<release>/firmware.json), downloads each
GitHub release zip once into a cache directory, and extracts the ROM and
firmware bundle files into the output directory, checking every file against
the hashes in the list (taken from the release history table in
caliptra-sw's README):

  * ROM: SHA-384 of the whole ROM binary.
  * Firmware bundle: the FMC and runtime SHA-384 digests in the image
    manifest's TOC entries, and that each digest matches the SHA-384 of the
    FMC / runtime image bytes it describes.

Writes rom-<version>.bin and fw-<version>.bin, default-rom.bin and
default-fw.bin (copies of the default choices), and firmware.json, the index
the emulator page reads to offer the ROM and firmware pickers. For firmware
entries with a "commit", the index also lists the mailbox commands that
runtime defines (from api/src/mailbox.rs at that commit), so the page can
offer only the commands the picked runtime supports.

Usage:
    ./tools/fetch-firmware.py versions/1.1/firmware.json OUTPUT_DIR [--cache DIR]
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import urllib.request
import zipfile

RELEASE_URL = "https://github.com/chipsalliance/caliptra-sw/releases/download/{tag}/{asset}"
SOURCE_URL = "https://raw.githubusercontent.com/chipsalliance/caliptra-sw/{commit}/{path}"

# `pub const NAME: Self = Self(0x...)` entries in `impl CommandId`, as in
# tools/build-mailbox-commands.py.
COMMAND_ID = re.compile(r"pub const ([A-Z][A-Z0-9_]*): Self = Self\((0x[0-9a-fA-F_]+)\)")

# Caliptra 1.x ImageManifest: marker (u32), size (u32), preamble, header, then
# the FMC and runtime ImageTocEntry, which end the manifest. An ImageTocEntry
# is id, image_type, revision ([u8; 20]), version, svn, reserved, load_addr,
# entry_point, offset, size (u32s) and digest (12 u32 words).
TOC_ENTRY_SIZE = 104
TOC_OFFSET_FIELD = 48
TOC_DIGEST_FIELD = 56


def fetch(tag, asset, cache_dir):
    """Return the path of the cached release zip, downloading it if needed."""
    path = os.path.join(cache_dir, tag, asset)
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        url = RELEASE_URL.format(tag=tag, asset=asset)
        print(f"Downloading {url}")
        with tempfile.NamedTemporaryFile(dir=os.path.dirname(path), delete=False) as tmp:
            with urllib.request.urlopen(url) as resp:
                shutil.copyfileobj(resp, tmp)
        os.replace(tmp.name, path)
    return path


def mailbox_commands(commit, cache_dir):
    """The {"0x...": NAME} command IDs defined at a caliptra-sw commit."""
    path = os.path.join(cache_dir, "sources", commit, "mailbox.rs")
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        url = SOURCE_URL.format(commit=commit, path="api/src/mailbox.rs")
        print(f"Downloading {url}")
        with urllib.request.urlopen(url) as resp:
            data = resp.read()
        with open(path, "wb") as f:
            f.write(data)
    text = open(path).read()
    start = text.find("impl CommandId {")
    block = text[start:text.find("\n}", start)]
    ids = {f"0x{int(v.replace('_', ''), 16):08x}": n for n, v in COMMAND_ID.findall(block)}
    if not ids:
        raise SystemExit(f"error: no mailbox command IDs at caliptra-sw {commit}")
    return ids


def read_member(zip_path, name):
    with zipfile.ZipFile(zip_path) as z:
        return z.read(name)


def word_digest(words_le):
    """A digest stored as little-endian u32 words, as a big-endian hex string."""
    return "".join(f"{w:08x}" for w in struct.unpack("<12I", words_le))


def verify_rom(data, entry):
    got = hashlib.sha384(data).hexdigest()
    if got != entry["sha384"]:
        raise SystemExit(f"error: ROM {entry['version']}: SHA-384 {got} != {entry['sha384']}")


def verify_bundle(data, entry):
    (manifest_size,) = struct.unpack_from("<I", data, 4)
    tocs = {"fmc": manifest_size - 2 * TOC_ENTRY_SIZE, "runtime": manifest_size - TOC_ENTRY_SIZE}
    for name, toc in tocs.items():
        offset, size = struct.unpack_from("<II", data, toc + TOC_OFFSET_FIELD)
        stored = word_digest(data[toc + TOC_DIGEST_FIELD:toc + TOC_DIGEST_FIELD + 48])
        expected = entry[f"{name}_sha384"]
        if stored != expected:
            raise SystemExit(f"error: firmware {entry['version']}: {name} TOC digest {stored} != {expected}")
        actual = hashlib.sha384(data[offset:offset + size]).hexdigest()
        if actual != expected:
            raise SystemExit(f"error: firmware {entry['version']}: {name} image hashes to {actual}, TOC says {expected}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("release_list", help="versions/<release>/firmware.json")
    p.add_argument("output_dir", help="e.g. www/v1.1")
    p.add_argument("--cache", default=os.path.join(
        os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "caliptra-wasm", "releases"),
        help="where downloaded release zips are kept")
    args = p.parse_args()

    with open(args.release_list) as f:
        spec = json.load(f)
    os.makedirs(args.output_dir, exist_ok=True)

    index = {"roms": [], "firmware": [], "default_rom": spec["default_rom"],
             "default_firmware": spec["default_firmware"]}
    for kind, verify, prefix in (("roms", verify_rom, "rom"), ("firmware", verify_bundle, "fw")):
        for entry in spec[kind]:
            data = read_member(fetch(entry["tag"], entry["asset"], args.cache), entry["file"])
            verify(data, entry)
            out_name = f"{prefix}-{entry['version']}.bin"
            with open(os.path.join(args.output_dir, out_name), "wb") as f:
                f.write(data)
            print(f"Verified {kind[:-1] if kind == 'roms' else kind} {entry['version']} -> {out_name}")
            item = {
                "id": entry["id"], "version": entry["version"], "file": out_name,
                "tag": entry["tag"], "url": f"https://github.com/chipsalliance/caliptra-sw/releases/tag/{entry['tag']}",
            }
            if "rtl" in entry:
                item["rtl"] = entry["rtl"]
            if "commit" in entry:
                item["mailbox_commands"] = mailbox_commands(entry["commit"], args.cache)
            index[kind].append(item)

    for kind, default_key, out_name in (("roms", "default_rom", "default-rom.bin"),
                                         ("firmware", "default_firmware", "default-fw.bin")):
        chosen = [e for e in index[kind] if e["id"] == spec[default_key]]
        if not chosen:
            raise SystemExit(f"error: {default_key} {spec[default_key]} is not in {kind}")
        shutil.copyfile(os.path.join(args.output_dir, chosen[0]["file"]), os.path.join(args.output_dir, out_name))

    with open(os.path.join(args.output_dir, "firmware.json"), "w") as f:
        json.dump(index, f, indent=1)
        f.write("\n")
    print(f"Wrote {os.path.join(args.output_dir, 'firmware.json')}")


if __name__ == "__main__":
    sys.exit(main())
