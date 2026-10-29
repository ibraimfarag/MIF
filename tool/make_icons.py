"""Injects the MI CS icon into every Windows surface that carries one.

Canonical art: ``assets/icons/mics.png`` (RGBA master). From it the script
renders every standard Windows size into two ICOs:

* ``windows/runner/resources/app_icon.ico`` — embedded in ``mics_app.exe``.
  This is what Explorer, the taskbar, Alt-Tab, the window title bar and the UAC
  dialog actually display.
* ``assets/icons/mics.ico`` — the tray icon and any packaged copies.

Usage:
    python tool/make_icons.py                     # master -> both icons
    python tool/make_icons.py path/to/art.png     # use new art as the master

The first run also creates the master from the existing ``mics.ico`` if no
``mics.png`` exists yet, so nothing is lost.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
ICONS = ROOT / "assets" / "icons"
MASTER = ICONS / "mics.png"
EXE_ICON = ROOT / "windows" / "runner" / "resources" / "app_icon.ico"
TRAY_ICON = ICONS / "mics.ico"

# Every size Windows asks for: Explorer at all zoom levels, taskbar, Alt-Tab,
# small title bars, jumbo icons and the 256 px thumbnail cache.
SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]


def frames(path: Path) -> list[tuple[int, int]]:
    """Sizes actually stored inside an .ico file."""
    with Image.open(path) as ico:
        return sorted(set(ico.info.get("sizes", [ico.size])))


def ensure_master() -> Image.Image:
    """Returns the RGBA master, creating it from the shipping .ico if needed."""
    if len(sys.argv) > 1:
        source = Path(sys.argv[1]).resolve()
        image = Image.open(source).convert("RGBA")
        image.save(MASTER)
        print(f"master updated from {source} -> {MASTER.relative_to(ROOT)}")
        return image
    if MASTER.exists():
        return Image.open(MASTER).convert("RGBA")
    if not TRAY_ICON.exists():
        raise SystemExit(f"no art found: neither {MASTER} nor {TRAY_ICON}")
    # Promote the largest frame of the existing icon to a lossless master.
    largest = max(frames(TRAY_ICON), key=lambda size: size[0] * size[1])
    with Image.open(TRAY_ICON) as ico:
        ico.size = largest
        ico.load()
        ico.convert("RGBA").save(MASTER)
    print(f"master created from {TRAY_ICON.name} at {largest[0]}x{largest[1]}")
    return Image.open(MASTER).convert("RGBA")


def write_ico(master: Image.Image, target: Path) -> None:
    """Writes a multi-size ICO containing every size in SIZES.

    Pillow generates each frame from the image it is handed, so the master is a
    256×256 RGBA PNG: small frames are downscaled with its default high-quality
    filter.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    if master.width < max(SIZES):
        master = master.resize((max(SIZES), max(SIZES)), Image.LANCZOS)
    master.save(target, format="ICO", sizes=[(s, s) for s in SIZES])


def main() -> int:
    master = ensure_master()
    if master.width != master.height:
        print(f"WARNING: art is not square ({master.width}x{master.height})")

    write_ico(master, EXE_ICON)
    write_ico(master, TRAY_ICON)

    ok = True
    for target in (EXE_ICON, TRAY_ICON):
        sizes = frames(target)
        found = {size[0] for size in sizes}
        missing = [s for s in SIZES if s not in found]
        print(f"\n{target.relative_to(ROOT)}  ({target.stat().st_size:,} bytes)")
        print(f"  {', '.join(f'{s[0]}x{s[1]}' for s in sizes)}")
        if missing:
            print(f"  MISSING: {missing}")
            ok = False

    print("\nOK: every standard size present" if ok else "\nFAILED: incomplete icon set")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
