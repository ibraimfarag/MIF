"""Prints size/mode info for the icon sources (avoids shell quoting pain)."""

import sys
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
ICONS = ROOT / "assets" / "icons"

for name in ["Desktop.png", "task.png", "mics.png", "mics.ico"]:
    path = ICONS / name
    if not path.exists():
        print(f"{name}: missing")
        continue
    with Image.open(path) as im:
        has_alpha = "A" in im.mode
        ratio = im.size[0] / im.size[1] if im.size[1] else 0
        extra = ""
        if path.suffix == ".ico":
            extra = f" sizes={sorted(im.info.get('sizes', []))}"
        print(f"{name}: {im.size[0]}x{im.size[1]} mode={im.mode} "
              f"alpha={has_alpha} ratio={ratio:.3f}{extra}")

for name in ["Desktop.svg", "task.svg"]:
    path = ICONS / name
    if not path.exists():
        print(f"{name}: missing")
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    head = text[:400].replace("\n", " ")
    print(f"{name}: {len(text)} bytes | {head[:220]}")
