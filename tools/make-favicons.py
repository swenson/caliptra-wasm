#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""Render www/favicon.ico and www/apple-touch-icon.png from www/favicon.svg.

favicon.svg is the source. Browsers that support SVG icons use it directly;
the ICO (16, 32 and 48 px) covers the rest and requests for /favicon.ico.
The 16 px image uses the SVG's small-size style, which browsers pick with
its `max-width: 24px` media query. cairosvg ignores @media rules, so this
script resolves that block itself before rendering.

Run this after editing favicon.svg and commit the outputs.

Requires cairosvg and Pillow (pip install cairosvg pillow).

Usage:
    ./tools/make-favicons.py [--www PATH]
"""

import argparse
import io
import os
import sys

import cairosvg
from PIL import Image

SMALL_QUERY = "@media (max-width: 24px)"

# Background for the Apple touch icon, which must be opaque. Matches --bg in
# www/style.css.
TOUCH_BG = (245, 246, 248, 255)


def apply_small_query(svg, small):
    """Unwrap the small-size @media block (small) or remove it (not small).

    cairosvg skips @media rules, so the block has to be resolved here.
    """
    start = svg.index(SMALL_QUERY)
    open_brace = svg.index("{", start)
    depth = 0
    for end in range(open_brace, len(svg)):
        depth += {"{": 1, "}": -1}.get(svg[end], 0)
        if depth == 0:
            break
    body = svg[open_brace + 1 : end] if small else ""
    return svg[:start] + body + svg[end + 1 :]


def render(svg, size, small):
    """Render svg (text) to a size x size RGBA image."""
    svg = apply_small_query(svg, small)
    png =cairosvg.svg2png(bytestring=svg.encode(), output_width=size, output_height=size)
    return Image.open(io.BytesIO(png)).convert("RGBA")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--www",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "www"),
        help="site directory holding favicon.svg (default: www/)",
    )
    args = parser.parse_args()

    with open(os.path.join(args.www, "favicon.svg")) as f:
        svg = f.read()
    if SMALL_QUERY not in svg:
        sys.exit(f"favicon.svg has no '{SMALL_QUERY}' block")

    ico = os.path.join(args.www, "favicon.ico")
    images = [render(svg, 48, small=False), render(svg, 32, small=False), render(svg, 16, small=True)]
    # Pillow drops sizes larger than the base image, so the base is the 48.
    images[0].save(ico, format="ICO", append_images=images[1:], sizes=[(i.width, i.height) for i in images])
    print(f"wrote {ico}")

    # 180 px with the monitor inset on an opaque square; iOS rounds the
    # corners itself.
    touch = Image.new("RGBA", (180, 180), TOUCH_BG)
    touch.alpha_composite(render(svg, 148, small=False), (16, 16))
    path = os.path.join(args.www, "apple-touch-icon.png")
    touch.convert("RGB").save(path, optimize=True)
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
