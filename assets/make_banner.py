#!/usr/bin/env python3
"""Render the terminal banner to assets/checkhook-banner.png for the README.

Text-based ASCII art breaks on GitHub: characters such as ╲ ╱ ╳ ● have
different widths in different fonts, and font glyphs leave seams between rows.
So the art is drawn as geometry instead: every character occupies one grid
cell; █ is a filled cell and ═ ║ ╔ ╗ ╚ ╝ are double strokes that reach the cell
edges. CHECK is drawn in steel, HOOK in the logo's red.

  python3 assets/make_banner.py        (needs Pillow)
"""
import os
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))

S = 2                      # supersampling for a crisp result
CW, CH = 13 * S, 26 * S    # cell size (terminal cells are ~1:2)
PAD = 30 * S
BG = (13, 17, 23)          # GitHub dark
RED = (226, 59, 46)        # the logo's red (#e23b2e)
STEEL = (208, 208, 208)

WORD = [
    " ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗",
    "██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝",
    "██║     ███████║█████╗  ██║     █████╔╝ ███████║██║   ██║██║   ██║█████╔╝ ",
    "██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══██║██║   ██║██║   ██║██╔═██╗ ",
    "╚██████╗██║  ██║███████╗╚██████╗██║  ██╗██║  ██║╚██████╔╝╚██████╔╝██║  ██╗",
    " ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝",
]
SPLIT = 40                  # columns 0..39 = CHECK (steel), 40.. = HOOK (red)

# double-line glyphs: (horizontal direction, vertical direction)
DOUBLE = {"═": (2, 0), "║": (0, 2), "╔": (1, 1), "╗": (-1, 1), "╚": (1, -1), "╝": (-1, -1)}


def draw_cell(d, x, y, ch, color):
    if ch == " ":
        return
    if ch == "█":
        d.rectangle([x, y, x + CW, y + CH], fill=color)   # +1px overlap: no seams
        return
    g = CW * 0.2              # half gap between the two strokes
    lw = max(2, round(CW * 0.11))
    cx, cy = x + CW / 2, y + CH / 2
    h, v = DOUBLE[ch]
    if (h, v) == (2, 0):
        for o in (-g, g):
            d.line([(x, cy + o), (x + CW, cy + o)], fill=color, width=lw)
    elif (h, v) == (0, 2):
        for o in (-g, g):
            d.line([(cx + o, y), (cx + o, y + CH)], fill=color, width=lw)
    else:                     # corner: outer and inner L
        ex = cx + h * CW / 2  # horizontal edge it reaches
        ey = cy + v * CH / 2  # vertical edge it reaches
        for s in (-1, 1):     # -1 outer, +1 inner
            px, py = cx + s * h * g, cy + s * v * g
            d.line([(px, ey), (px, py), (ex, py)], fill=color, width=lw, joint="curve")


def main():
    cols = len(WORD[0])
    width = PAD * 2 + cols * CW
    height = PAD * 2 + len(WORD) * CH          # name only: CHECK + HOOK
    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)
    for r, line in enumerate(WORD):
        for c, ch in enumerate(line):
            draw_cell(d, PAD + c * CW, PAD + r * CH, ch, STEEL if c < SPLIT else RED)

    img = img.resize((width // S, height // S), Image.LANCZOS)
    out = os.path.join(HERE, "checkhook-banner.png")
    img.save(out, optimize=True)
    print(f"wrote {out} ({img.width}x{img.height})")


if __name__ == "__main__":
    main()
