"""Turns the rendered masters into the three shipping Windows icon files.

Pipeline (step 1 is tool/rasterize_icons.ps1):

    1. rasterize_icons.ps1   task.svg / Desktop.svg -> 1024px transparent PNGs
    2. make_icons.py         trim the empty border, centre the art on a square
                             canvas, then write every standard icon size

Why the trim matters: an SVG canvas usually carries padding, so the artwork can
sit at ~55 % of the frame and the icon then looks tiny next to other taskbar
icons.

Outputs (all ten sizes: 16/20/24/32/40/48/64/96/128/256):

    windows/runner/resources/app_icon.ico   embedded in mics_app.exe  (TASK art)
    assets/icons/mics.ico                   tray icon + packaged copy  (TASK art)
    assets/icons/desktop.ico                desktop shortcut only      (DESKTOP art)

The desktop can show different art from the taskbar because a .lnk keeps its own
icon location — see scripts/create-shortcuts.ps1.

Usage:
    python tool/make_icons.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
ICONS = ROOT / "assets" / "icons"

TASK_MASTER = ICONS / "task.png"
DESKTOP_MASTER = ICONS / "Desktop.png"

EXE_ICON = ROOT / "windows" / "runner" / "resources" / "app_icon.ico"
TRAY_ICON = ICONS / "mics.ico"
DESKTOP_ICON = ICONS / "desktop.ico"

SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
# How much of the square the artwork should fill: Windows icons look right when
# the glyph nearly touches the edge, with a hair of margin for soft shadows.
FILL = 0.94


def square_art(path: Path, canvas: int = 1024) -> Image.Image:
    """Crops the transparent border, then centres the art on a square canvas."""
    with Image.open(path) as raw:
        art = raw.convert("RGBA")
    box = art.getchannel("A").getbbox()
    if box is None:
        raise SystemExit(f"{path.name} is fully transparent — render it first")
    art = art.crop(box)

    target = int(canvas * FILL)
    scale = min(target / art.width, target / art.height)
    size = (max(1, round(art.width * scale)), max(1, round(art.height * scale)))
    art = art.resize(size, Image.LANCZOS)

    out = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    out.paste(art, ((canvas - size[0]) // 2, (canvas - size[1]) // 2), art)
    return out


def write_ico(master: Image.Image, target: Path) -> list[int]:
    target.parent.mkdir(parents=True, exist_ok=True)
    master.save(target, format="ICO", sizes=[(s, s) for s in SIZES])
    with Image.open(target) as ico:
        return sorted(size[0] for size in ico.info.get("sizes", []))


def main() -> int:
    for master in (TASK_MASTER, DESKTOP_MASTER):
        if not master.exists():
            raise SystemExit(
                f"{master.name} is missing — run tool/rasterize_icons.ps1 first"
            )

    task = square_art(TASK_MASTER)
    desktop = square_art(DESKTOP_MASTER)
    task.save(TASK_MASTER)
    desktop.save(DESKTOP_MASTER)

    jobs = [
        ("exe: taskbar, Alt-Tab, Explorer, title bar", task, EXE_ICON),
        ("tray icon + packaged assets", task, TRAY_ICON),
        ("desktop shortcut only", desktop, DESKTOP_ICON),
    ]
    ok = True
    for label, art, target in jobs:
        sizes = write_ico(art, target)
        missing = [s for s in SIZES if s not in sizes]
        print(f"{target.relative_to(ROOT)}  ({target.stat().st_size:,} bytes)")
        print(f"  {label}: {', '.join(str(s) for s in sizes)}")
        if missing:
            print(f"  MISSING: {missing}")
            ok = False
    print("\nOK" if ok else "\nFAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
