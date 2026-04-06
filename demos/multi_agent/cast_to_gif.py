#!/usr/bin/env python3
"""
.cast (asciicast v2) to GIF converter.
Uses pyte for terminal emulation and Pillow for frame rendering.
"""

import json
import sys
from pathlib import Path

import pyte
from PIL import Image, ImageDraw, ImageFont


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CELL_W = 8          # character width (px)
CELL_H = 16         # character height (px)
PADDING = 16        # image padding (px)
FPS_CAP = 8         # max frames per second
MAX_DELAY = 2.0     # max delay between frames (seconds)
BG_COLOR = (30, 30, 46)
FG_COLOR = (205, 214, 244)

ANSI_COLORS = {
    "black":   (69, 71, 90),
    "red":     (243, 139, 168),
    "green":   (166, 227, 161),
    "yellow":  (249, 226, 175),
    "blue":    (137, 180, 250),
    "magenta": (245, 194, 231),
    "cyan":    (148, 226, 213),
    "white":   (205, 214, 244),
    "default": FG_COLOR,
    # Bright variants
    "brightblack":   (88, 91, 112),
    "brightred":     (243, 139, 168),
    "brightgreen":   (166, 227, 161),
    "brightyellow":  (249, 226, 175),
    "brightblue":    (137, 180, 250),
    "brightmagenta": (245, 194, 231),
    "brightcyan":    (148, 226, 213),
    "brightwhite":   (255, 255, 255),
}

# xterm-256 color palette (first 16 entries mapped above, 16-255 below)
_XTERM_256: dict[int, tuple[int, int, int]] = {}
# 16-231: 6x6x6 color cube
for _i in range(216):
    _r = (_i // 36) * 51
    _g = ((_i % 36) // 6) * 51
    _b = (_i % 6) * 51
    _XTERM_256[16 + _i] = (_r, _g, _b)
# 232-255: grayscale
for _i in range(24):
    _v = 8 + _i * 10
    _XTERM_256[232 + _i] = (_v, _v, _v)


def get_color(name, fallback=FG_COLOR):
    if not name or name == "default":
        return fallback
    # pyte stores color as str name, or str int for 256-color, or tuple for 24-bit
    if isinstance(name, tuple):
        return name
    if isinstance(name, str):
        # Try named color
        if name in ANSI_COLORS:
            return ANSI_COLORS[name]
        # Try numeric (256-color index)
        try:
            idx = int(name)
            if idx < 16:
                names = ["black", "red", "green", "yellow", "blue",
                         "magenta", "cyan", "white",
                         "brightblack", "brightred", "brightgreen",
                         "brightyellow", "brightblue", "brightmagenta",
                         "brightcyan", "brightwhite"]
                return ANSI_COLORS.get(names[idx], fallback)
            return _XTERM_256.get(idx, fallback)
        except (ValueError, IndexError):
            pass
    return fallback


def render_frame(screen: pyte.Screen, width: int, height: int) -> Image.Image:
    img_w = width * CELL_W + PADDING * 2
    img_h = height * CELL_H + PADDING * 2
    img = Image.new("RGB", (img_w, img_h), BG_COLOR)
    draw = ImageDraw.Draw(img)

    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 13)
    except (OSError, IOError):
        font = ImageFont.load_default()
    try:
        bold_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 13)
    except (OSError, IOError):
        bold_font = font

    for row in range(height):
        line = screen.buffer.get(row, {})
        for col in range(width):
            char_data = line.get(col)
            if char_data is None:
                continue
            ch = char_data.data
            if ch == " " or ch == "":
                continue
            fg = get_color(getattr(char_data, "fg", "default"))
            is_bold = getattr(char_data, "bold", False)
            x = PADDING + col * CELL_W
            y = PADDING + row * CELL_H
            draw.text((x, y), ch, fill=fg, font=bold_font if is_bold else font)

    return img


def cast_to_gif(cast_path: str, gif_path: str):
    cast_file = Path(cast_path)
    lines = cast_file.read_text().strip().split("\n")

    # Parse header
    header = json.loads(lines[0])
    cols = header.get("width", 100)
    rows = header.get("height", 40)

    # Setup terminal emulator
    screen = pyte.Screen(cols, rows)
    stream = pyte.Stream(screen)

    # Parse events
    events = []
    for line in lines[1:]:
        try:
            ts, etype, data = json.loads(line)
            if etype == "o":
                events.append((ts, data))
        except (json.JSONDecodeError, ValueError):
            continue

    if not events:
        print("No events found")
        sys.exit(1)

    # Generate frames — sample at key intervals
    frames: list[Image.Image] = []
    durations: list[int] = []
    min_interval = 1.0 / FPS_CAP
    last_frame_time = 0.0

    for i, (ts, data) in enumerate(events):
        stream.feed(data)

        is_last = (i == len(events) - 1)
        next_ts = events[i + 1][0] if not is_last else ts + 1
        gap = next_ts - ts

        # Capture frame if enough time has passed or it's the last event
        if (ts - last_frame_time >= min_interval) or is_last:
            frame = render_frame(screen, cols, rows)
            frames.append(frame)

            delay = min(gap, MAX_DELAY)
            delay = max(delay, min_interval)
            durations.append(int(delay * 1000))
            last_frame_time = ts

    if not frames:
        print("No frames generated")
        sys.exit(1)

    # Hold last frame longer
    durations[-1] = 3000

    # Save GIF
    frames[0].save(
        gif_path,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    print(f"GIF created: {gif_path} ({len(frames)} frames)")


if __name__ == "__main__":
    base = Path(__file__).parent.parent.parent
    cast_file = base / "demo_multi_agent.cast"
    gif_file = base / "demo_multi_agent.gif"

    if len(sys.argv) >= 2:
        cast_file = Path(sys.argv[1])
    if len(sys.argv) >= 3:
        gif_file = Path(sys.argv[2])

    cast_to_gif(str(cast_file), str(gif_file))
