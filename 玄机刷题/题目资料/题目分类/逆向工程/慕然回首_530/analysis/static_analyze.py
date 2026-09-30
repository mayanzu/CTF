#!/usr/bin/env python3
"""Read-only static inspection for challenge #530's ZIP and PE32+ executable.

This script never launches or loads Jerry.exe. It reads bytes, parses selected
PE structures, extracts the embedded maze from its raw .data bytes, and solves
the grid as a graph. Run from any directory with Python 3:

    python analysis/static_analyze.py

The human-readable report is printed and saved next to this script.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
import zipfile
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANALYSIS = Path(__file__).resolve().parent
ZIP_PATH = ROOT / "originals" / "tom.zip"
EXE_PATH = ROOT / "extracted" / "Jerry.exe"
MAZE_RVA = 0x3040
MAZE_WIDTH = 10  # main's index arithmetic computes row * 10 + column.


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def c_string(data: bytes, off: int) -> str:
    end = data.find(b"\0", off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("ascii", errors="replace")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def parse_pe(data: bytes) -> dict:
    if data[:2] != b"MZ":
        raise ValueError("DOS MZ signature missing")
    pe_off = u32(data, 0x3C)
    if data[pe_off : pe_off + 4] != b"PE\0\0":
        raise ValueError("PE signature missing")

    coff = pe_off + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    timestamp = u32(data, coff + 4)
    symbol_table_ptr = u32(data, coff + 8)
    symbol_count = u32(data, coff + 12)
    optional_size = u16(data, coff + 16)
    characteristics = u16(data, coff + 18)
    opt = coff + 20
    magic = u16(data, opt)
    if magic != 0x20B:
        raise ValueError(f"expected PE32+ (0x20b), found {magic:#x}")

    entry_rva = u32(data, opt + 16)
    image_base = u64(data, opt + 24)
    section_alignment = u32(data, opt + 32)
    file_alignment = u32(data, opt + 36)
    size_image = u32(data, opt + 56)
    size_headers = u32(data, opt + 60)
    subsystem = u16(data, opt + 68)
    dll_characteristics = u16(data, opt + 70)
    directory_count = u32(data, opt + 108)
    dirs = []
    for i in range(min(directory_count, 16)):
        rva, size = struct.unpack_from("<II", data, opt + 112 + 8 * i)
        dirs.append((rva, size))

    section_off = opt + optional_size
    sections = []
    for i in range(section_count):
        off = section_off + i * 40
        raw_name = data[off : off + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace")
        virtual_size, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        flags = u32(data, off + 36)
        raw = data[raw_ptr : raw_ptr + raw_size]
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "rva": rva,
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
                "flags": flags,
                "entropy": entropy(raw),
            }
        )

    def rva_to_offset(rva: int) -> int:
        if rva < size_headers:
            return rva
        for section in sections:
            span = max(section["virtual_size"], section["raw_size"])
            if section["rva"] <= rva < section["rva"] + span:
                off = section["raw_ptr"] + (rva - section["rva"])
                if off >= len(data):
                    raise ValueError(f"RVA {rva:#x} has no raw bytes")
                return off
        raise ValueError(f"RVA {rva:#x} is not mapped to a section")

    imports = []
    if len(dirs) > 1 and dirs[1][0]:
        imp_off = rva_to_offset(dirs[1][0])
        for desc_i in range(4096):
            desc = imp_off + 20 * desc_i
            oft, stamp, chain, name_rva, first = struct.unpack_from("<IIIII", data, desc)
            if not (oft or stamp or chain or name_rva or first):
                break
            dll = c_string(data, rva_to_offset(name_rva))
            thunk_rva = oft or first
            thunk_off = rva_to_offset(thunk_rva)
            names = []
            for thunk_i in range(8192):
                thunk = u64(data, thunk_off + 8 * thunk_i)
                if thunk == 0:
                    break
                if thunk & (1 << 63):
                    names.append(f"ordinal:{thunk & 0xffff}")
                else:
                    name_off = rva_to_offset(thunk)
                    hint = u16(data, name_off)
                    names.append(f"{c_string(data, name_off + 2)} (hint {hint})")
            imports.append({"dll": dll, "symbols": names})

    security_dir = dirs[4] if len(dirs) > 4 else (0, 0)
    raw_end = max((s["raw_ptr"] + s["raw_size"] for s in sections), default=size_headers)
    symbol_string_table_size = None
    symbol_table_end = None
    if symbol_table_ptr and symbol_count:
        string_table_off = symbol_table_ptr + symbol_count * 18
        if string_table_off + 4 <= len(data):
            symbol_string_table_size = u32(data, string_table_off)
            if symbol_string_table_size >= 4:
                symbol_table_end = string_table_off + symbol_string_table_size
    return {
        "pe_offset": pe_off,
        "machine": machine,
        "section_count": section_count,
        "timestamp": timestamp,
        "symbol_table_ptr": symbol_table_ptr,
        "symbol_count": symbol_count,
        "optional_size": optional_size,
        "characteristics": characteristics,
        "magic": magic,
        "entry_rva": entry_rva,
        "image_base": image_base,
        "section_alignment": section_alignment,
        "file_alignment": file_alignment,
        "size_image": size_image,
        "size_headers": size_headers,
        "subsystem": subsystem,
        "dll_characteristics": dll_characteristics,
        "directories": dirs,
        "security_directory": security_dir,
        "sections": sections,
        "imports": imports,
        "raw_end": raw_end,
        "symbol_string_table_size": symbol_string_table_size,
        "symbol_table_end": symbol_table_end,
        "rva_to_offset": rva_to_offset,
    }


def solve_maze(grid: list[str]) -> dict:
    h, w = len(grid), len(grid[0])
    starts = [(r, c) for r in range(h) for c in range(w) if grid[r][c] == "S"]
    ends = [(r, c) for r in range(h) for c in range(w) if grid[r][c] == "E"]
    if len(starts) != 1 or len(ends) != 1:
        raise ValueError(f"maze must contain one S and one E: S={starts}, E={ends}")
    start, end = starts[0], ends[0]
    moves = (("w", -1, 0), ("a", 0, -1), ("s", 1, 0), ("d", 0, 1))
    queue = deque([start])
    previous: dict[tuple[int, int], tuple[tuple[int, int], str] | None] = {start: None}
    distance = {start: 0}
    shortest_count = {start: 1}
    while queue:
        pos = queue.popleft()
        for key, dr, dc in moves:
            nxt = (pos[0] + dr, pos[1] + dc)
            if (
                0 <= nxt[0] < h
                and 0 <= nxt[1] < w
                and grid[nxt[0]][nxt[1]] != "#"
            ):
                candidate_distance = distance[pos] + 1
                if nxt not in distance:
                    distance[nxt] = candidate_distance
                    shortest_count[nxt] = shortest_count[pos]
                    previous[nxt] = (pos, key)
                    queue.append(nxt)
                elif distance[nxt] == candidate_distance:
                    shortest_count[nxt] += shortest_count[pos]
    if end not in previous:
        raise ValueError("E is unreachable from S")
    route = []
    cursor = end
    while cursor != start:
        parent, move = previous[cursor]  # type: ignore[misc]
        route.append(move)
        cursor = parent
    route.reverse()
    return {
        "start": start,
        "end": end,
        "route": "".join(route),
        "length": len(route),
        "shortest_path_count": shortest_count[end],
    }


def simulate_route(grid: list[str], start: tuple[int, int], route: str) -> dict:
    moves = {"w": (-1, 0), "a": (0, -1), "s": (1, 0), "d": (0, 1)}
    pos = start
    trajectory = [pos]
    for step, key in enumerate(route, start=1):
        if key not in moves:
            raise ValueError(f"route step {step} is not one of w/a/s/d: {key!r}")
        dr, dc = moves[key]
        nxt = (pos[0] + dr, pos[1] + dc)
        if not (0 <= nxt[0] < len(grid) and 0 <= nxt[1] < len(grid[0])):
            raise ValueError(f"route step {step} leaves the maze at {nxt}")
        if grid[nxt[0]][nxt[1]] == "#":
            raise ValueError(f"route step {step} hits a wall at {nxt}")
        pos = nxt
        trajectory.append(pos)
    return {
        "trajectory_rc_zero_based": trajectory,
        "final_cell": grid[pos[0]][pos[1]],
        "reaches_E": grid[pos[0]][pos[1]] == "E",
    }


def main() -> None:
    zip_bytes = ZIP_PATH.read_bytes()
    exe_bytes = EXE_PATH.read_bytes()
    pe = parse_pe(exe_bytes)

    with zipfile.ZipFile(ZIP_PATH) as archive:
        zip_bad_member = archive.testzip()
        zip_members = [
            {
                "name": info.filename,
                "uncompressed_size": info.file_size,
                "compressed_size": info.compress_size,
                "crc32": f"{info.CRC:08x}",
                "dos_timestamp_local": datetime(*info.date_time).isoformat(),
            }
            for info in archive.infolist()
        ]
        member_bytes = archive.read("Jerry.exe")

    maze_off = pe["rva_to_offset"](MAZE_RVA)
    maze_bytes = exe_bytes[maze_off : maze_off + MAZE_WIDTH * MAZE_WIDTH]
    if len(maze_bytes) != MAZE_WIDTH * MAZE_WIDTH:
        raise ValueError("embedded maze is truncated")
    if any(b not in b"#*SE" for b in maze_bytes):
        raise ValueError(f"unexpected byte in maze at RVA {MAZE_RVA:#x}: {maze_bytes!r}")
    maze = [
        maze_bytes[i : i + MAZE_WIDTH].decode("ascii")
        for i in range(0, len(maze_bytes), MAZE_WIDTH)
    ]
    solution = solve_maze(maze)
    simulation = simulate_route(maze, solution["start"], solution["route"])

    prompt_literals = [
        b"Welcome to the Maze Game!",
        b"Find the path from 'S' to 'E' using w/a/s/d to move.",
        b"Enter your moves (e.g., 'wasd'):",
        b"Invalid move!",
        b"You are so clever! This is Jerry!",
        b"xixi Now enter the flag in the format 'flag{your_path} ':",
        b"%c",
    ]
    literal_offsets = {
        literal.decode("ascii"): f"file offset {exe_bytes.find(literal):#x}"
        for literal in prompt_literals
    }

    report = {
        "scope": "Read-only byte parsing. Jerry.exe was not launched or loaded.",
        "files": {
            "zip": {
                "path": "originals/tom.zip",
                "size": len(zip_bytes),
                "sha256": hashlib.sha256(zip_bytes).hexdigest().upper(),
                "members": zip_members,
                "testzip_bad_member": zip_bad_member,
            },
            "exe": {
                "path": "extracted/Jerry.exe",
                "size": len(exe_bytes),
                "sha256": hashlib.sha256(exe_bytes).hexdigest().upper(),
                "zip_member_byte_identical": member_bytes == exe_bytes,
            },
        },
        "pe": {
            **{k: v for k, v in pe.items() if k not in ("rva_to_offset",)},
            "timestamp_utc_as_encoded": datetime.fromtimestamp(
                pe["timestamp"], tz=timezone.utc
            ).isoformat(),
            "entry_va": f"{pe['image_base'] + pe['entry_rva']:#x}",
            "bytes_after_section_data": len(exe_bytes) - pe["raw_end"],
            "coff_symbol_table_bytes": 18 * pe["symbol_count"],
            "coff_string_table_bytes_including_length_dword": pe["symbol_string_table_size"],
            "coff_symbol_and_string_tables_end_offset": pe["symbol_table_end"],
            "unaccounted_bytes_after_coff_tables": (
                len(exe_bytes) - pe["symbol_table_end"]
                if pe["symbol_table_end"] is not None
                else None
            ),
            "directory_names": [
                "export",
                "import",
                "resource",
                "exception",
                "security/certificate",
                "base_relocation",
                "debug",
                "architecture",
                "global_ptr",
                "tls",
                "load_config",
                "bound_import",
                "iat",
                "delay_import",
                "clr",
                "reserved",
            ],
        },
        "embedded_literals_file_offsets": literal_offsets,
        "maze": {
            "rva": f"{MAZE_RVA:#x}",
            "file_offset": f"{maze_off:#x}",
            "dimensions": f"{MAZE_WIDTH}x{MAZE_WIDTH}",
            "rows": maze,
            "start_rc_zero_based": solution["start"],
            "end_rc_zero_based": solution["end"],
            "shortest_route_wasd": solution["route"],
            "shortest_route_length": solution["length"],
            "number_of_shortest_routes": solution["shortest_path_count"],
            "candidate_flag_from_prompt_template": f"flag{{{solution['route']}}}",
            "simulation": simulation,
        },
    }

    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    out = ANALYSIS / "static_analysis.json"
    out.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    print(f"\nSaved: analysis/{out.name}")


if __name__ == "__main__":
    main()
