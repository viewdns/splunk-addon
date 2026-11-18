"""Generates the Splunk app icons/logos in package/static from the ViewDNS wordmark (dev tool, not shipped)."""
import base64
import io
import os
import re
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SVG = os.path.join(ROOT, "tools", "assets", "viewdns_wordmark.svg")
OUT = os.path.join(ROOT, "package", "static")
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

svg = open(SVG).read()
wordmark = Image.open(io.BytesIO(base64.b64decode(re.search(r"base64,([^\"]+)", svg).group(1)))).convert("RGBA")
wordmark = wordmark.crop(wordmark.getbbox())

# Brand green: the most common strongly-green opaque pixel of the wordmark.
counts = {}
for r, g, b, a in wordmark.getdata():
    if a > 200 and g > 100 and g > r + 40 and g > b + 40:
        counts[(r, g, b)] = counts.get((r, g, b), 0) + 1
green = max(counts, key=counts.get) if counts else (60, 150, 40)
print("brand green", green)


def logo(width, height):
    canvas = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    mark = wordmark.copy()
    mark.thumbnail((width, height), Image.LANCZOS)
    canvas.paste(mark, ((width - mark.width) // 2, (height - mark.height) // 2), mark)
    return canvas


def icon(size, inverted=False):
    scale = 4  # draw large, then downsample for smooth edges
    big = size * scale
    background = (255, 255, 255, 255) if inverted else green + (255,)
    foreground = green + (255,) if inverted else (255, 255, 255, 255)
    image = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle([0, 0, big - 1, big - 1], radius=big // 5, fill=background,
                           outline=green + (255,) if inverted else None, width=max(1, big // 24))
    font = ImageFont.truetype(FONT, int(big * 0.42))
    left, top, right, bottom = draw.textbbox((0, 0), "dns", font=font)
    draw.text(((big - (right - left)) / 2 - left, (big - (bottom - top)) / 2 - top), "dns", font=font, fill=foreground)
    return image.resize((size, size), Image.LANCZOS)


os.makedirs(OUT, exist_ok=True)
icon(36).save(os.path.join(OUT, "appIcon.png"))
icon(72).save(os.path.join(OUT, "appIcon_2x.png"))
icon(36, inverted=True).save(os.path.join(OUT, "appIconAlt.png"))
icon(72, inverted=True).save(os.path.join(OUT, "appIconAlt_2x.png"))
logo(160, 40).save(os.path.join(OUT, "appLogo.png"))
logo(320, 80).save(os.path.join(OUT, "appLogo_2x.png"))
os.makedirs(os.path.join(ROOT, "package", "appserver", "static"), exist_ok=True)
icon(48).save(os.path.join(ROOT, "package", "appserver", "static", "alerticon.png"))
print("written to", OUT, file=sys.stderr)
