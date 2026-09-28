#!/usr/bin/env python3
"""term2png.py — 把 termcap.py 生成的终端实录文本渲染成「终端窗口截图」PNG。

用法：
    python tools/term2png.py figures/raw/web-curl.txt figures/fig-web-01-curl.png --title "curl 对照实验"

参数：
    输入实录txt输出png [--title 窗口标题] [--cols 每行最大字符数(默认100)]
    [--fontsize 字号(默认17)] [--theme dark|ubuntu(默认dark)]

渲染规则：提示符行绿色、命令白色、输出浅灰；# 开头的注释行不渲染。
所有文字来自真实执行的输出，本脚本只做排版，不生成任何内容。
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONT_LATIN = "C:/Windows/Fonts/consola.ttf"
FONT_CJK = "C:/Windows/Fonts/msyh.ttc"

THEMES = {
    "dark": {
        "bg": (12, 12, 12),
        "bar": (45, 45, 45),
        "bar_text": (200, 200, 200),
        "prompt": (120, 205, 135),
        "cmd": (242, 242, 242),
        "out": (204, 204, 204),
        "dim": (110, 110, 110),
    },
    "ubuntu": {
        "bg": (48, 10, 36),
        "bar": (32, 8, 26),
        "bar_text": (230, 210, 220),
        "prompt": (170, 220, 120),
        "cmd": (255, 255, 255),
        "out": (230, 220, 225),
        "dim": (150, 130, 140),
    },
}

PROMPT_RE = re.compile(r"^(PS .*?> |mzj@[^ ]*:[^$]*\$ |# |\$ )")


def load_fonts(size: int):
    latin = ImageFont.truetype(FONT_LATIN, size)
    cjk = ImageFont.truetype(FONT_CJK, size)
    return latin, cjk


def char_font(ch: str, latin, cjk):
    return latin if ord(ch) < 0x2E80 else cjk


def line_width(line: str, latin, cjk) -> float:
    w = 0.0
    for ch in line:
        w += char_font(ch, latin, cjk).getlength(ch)
    return w


def wrap(line: str, cols: int) -> list[str]:
    if len(line) <= cols:
        return [line]
    out, cur = [], ""
    for ch in line:
        cur += ch
        if len(cur) >= cols:
            cut = cur.rfind(" ")
            if cut > cols // 2:
                out.append(cur[:cut])
                cur = cur[cut + 1:]
            else:
                out.append(cur)
                cur = ""
    if cur:
        out.append(cur)
    return out


def draw_line(draw, x, y, line, latin, cjk, colors):
    """逐字符绘制：提示符绿色、命令白色、输出浅灰。"""
    m = PROMPT_RE.match(line)
    cursor = x
    if m:
        prompt = m.group(1)
        rest = line[len(prompt):]
        for seg, col in ((prompt, colors["prompt"]), (rest, colors["cmd"])):
            for ch in seg:
                f = char_font(ch, latin, cjk)
                draw.text((cursor, y), ch, font=f, fill=col)
                cursor += f.getlength(ch)
    else:
        col = colors["dim"] if line.startswith("[") and line.endswith("]") else colors["out"]
        for ch in line:
            f = char_font(ch, latin, cjk)
            draw.text((cursor, y), ch, font=f, fill=col)
            cursor += f.getlength(ch)


def main() -> int:
    ap = argparse.ArgumentParser(description="终端实录 → 终端窗口截图")
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--title", default="Terminal")
    ap.add_argument("--cols", type=int, default=100)
    ap.add_argument("--fontsize", type=int, default=17)
    ap.add_argument("--theme", choices=sorted(THEMES), default="dark")
    args = ap.parse_args()

    colors = THEMES[args.theme]
    raw_lines = Path(args.src).read_text(encoding="utf-8").split("\n")
    lines: list[str] = []
    for ln in raw_lines:
        if ln.startswith("#") or not ln.strip():
            continue
        lines.extend(wrap(ln.rstrip(), args.cols))
    if not lines:
        print("实录为空，没有可渲染的内容", file=sys.stderr)
        return 1

    latin, cjk = load_fonts(args.fontsize)
    line_h = int(args.fontsize * 1.6)
    pad = 24
    bar_h = 44

    text_w = max(line_width(ln, latin, cjk) for ln in lines)
    width = int(text_w + pad * 2)
    height = bar_h + pad * 2 + line_h * len(lines)

    img = Image.new("RGB", (width, height), colors["bg"])
    draw = ImageDraw.Draw(img)

    # 标题栏
    draw.rectangle([0, 0, width, bar_h], fill=colors["bar"])
    for i, cx in enumerate((width - 30, width - 58, width - 86)):
        draw.ellipse([cx - 8, bar_h // 2 - 8, cx + 8, bar_h // 2 + 8],
                     fill=(220 - i * 40, 90, 80) if i == 0 else (120, 120, 120))
    draw.text((16, bar_h // 2 - args.fontsize // 2 - 1), args.title,
              font=latin, fill=colors["bar_text"])

    y = bar_h + pad
    for ln in lines:
        draw_line(draw, pad, y, ln, latin, cjk, colors)
        y += line_h

    out = Path(args.dst)
    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out)
    print(f"[ok] {out}  ({width}x{height}, {len(lines)} 行)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
