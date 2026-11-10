"""Build ClaudeMascot.ttf: the Claude Code mascot as one glyph at U+E4A0 (private use area).

Used as the icon of waybar's custom/claude module (theme-scripts/claude-usage) and of the
claude-osd overlay (src/claude-osd). U+E4A0 is unused by Nerd Fonts and the other installed
fonts, so fontconfig falls back to this font for it anywhere.

    python build.py OUT.ttf        (needs fonttools: pip install fonttools)

Edit GRID to change the shape; each '#' is one square pixel.
"""
import sys
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

CP = 0xE4A0
GRID = [
    "..########..",
    "..#.####.#..",
    "..#.####.#..",
    "############",
    "############",
    "..########..",
    "..########..",
    "..#.#..#.#..",
    "..#.#..#.#..",
]
PX = 100           # 12 cols * 100 = 1200 wide, 9 rows = 900 tall
ADV = 1240
TOP = 830          # spans 830 .. -70, centred on the text x-height
X0 = (ADV - len(GRID[0]) * PX) // 2

def glyph(rows):
    pen = TTGlyphPen(None)
    for r, row in enumerate(rows):
        y1 = TOP - r * PX
        y0 = y1 - PX
        c = 0
        while c < len(row):
            if row[c] == "#":
                s = c
                while c < len(row) and row[c] == "#":
                    c += 1
                x0, x1 = X0 + s * PX, X0 + c * PX
                pen.moveTo((x0, y0)); pen.lineTo((x0, y1))
                pen.lineTo((x1, y1)); pen.lineTo((x1, y0)); pen.closePath()
            else:
                c += 1
    return pen.glyph()

fb = FontBuilder(1000, isTTF=True)
fb.setupGlyphOrder([".notdef", "claude"])
fb.setupCharacterMap({CP: "claude"})
empty = TTGlyphPen(None).glyph()
fb.setupGlyf({".notdef": empty, "claude": glyph(GRID)})
fb.setupHorizontalMetrics({".notdef": (ADV, 0), "claude": (ADV, X0)})
fb.setupHorizontalHeader(ascent=800, descent=-200)
fb.setupNameTable({"familyName": "Claude Mascot", "styleName": "Regular"})
fb.setupOS2(sTypoAscender=800, sTypoDescender=-200, usWinAscent=800, usWinDescent=200)
fb.setupPost()
fb.save(sys.argv[1])
print("saved", sys.argv[1])
