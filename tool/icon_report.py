"""Reports which art each shipping icon file currently contains.

Compares the 32x32 frame of every .ico against a downscale of the two masters:

* ``assets/icons/task.png``    -> taskbar, Alt-Tab, Explorer, tray, exe icon;
* ``assets/icons/Desktop.png`` -> the desktop shortcut icon.
"""

from pathlib import Path

from PIL import Image, ImageChops

ROOT = Path(__file__).resolve().parent.parent
ICONS = ROOT / "assets" / "icons"

MASTERS = {
    "task": ICONS / "task.png",
    "desktop": ICONS / "Desktop.png",
}

CANDIDATES = [
    ICONS / "mics.ico",
    ICONS / "desktop.ico",
    ROOT / "windows" / "runner" / "resources" / "app_icon.ico",
]


def frame32(path: Path) -> Image.Image:
    with Image.open(path) as ico:
        ico.size = (32, 32)
        ico.load()
        return ico.convert("RGB")


def reference(path: Path) -> Image.Image:
    with Image.open(path) as im:
        return im.convert("RGBA").resize((32, 32), Image.LANCZOS).convert("RGB")


def mean_diff(a: Image.Image, b: Image.Image) -> float:
    diff = ImageChops.difference(a, b)
    pixels = list(diff.getdata())
    return sum(sum(pixel) for pixel in pixels) / (len(pixels) * 3)


def main() -> int:
    refs = {
        name: reference(path) for name, path in MASTERS.items() if path.exists()
    }
    for name, path in MASTERS.items():
        state = "found" if path.exists() else "MISSING"
        print(f"master {name:8s} {path.name:12s} {state}")

    print()
    for candidate in CANDIDATES:
        if not candidate.exists():
            print(f"{candidate.name:14s} missing")
            continue
        frame = frame32(candidate)
        line = [f"{candidate.name:14s}"]
        for name, ref in refs.items():
            line.append(f"{name}={mean_diff(frame, ref):6.2f}")
        with Image.open(candidate) as ico:
            sizes = sorted(ico.info.get("sizes", []))
        line.append(f"sizes={len(sizes)}")
        print("  ".join(line))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
