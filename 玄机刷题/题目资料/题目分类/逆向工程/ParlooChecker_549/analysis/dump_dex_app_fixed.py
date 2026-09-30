#!/usr/bin/env python3
"""Run the local DEX dumper with correct widths for DEX switch/array payloads."""
from pathlib import Path
import sys

template = Path(__file__).with_name("dump_dex_app.py").read_text(encoding="utf-8-sig")
old = "  if op in (0x00,) and w>>8 in (1,2,3):wid={1:4,2:2,3:4}[w>>8]\n"
new = """  if op == 0 and (w >> 8) in (1, 2, 3):
   ident = w >> 8
   if ident == 1:
    wid = 4 + 2 * words[pc + 1]
   elif ident == 2:
    wid = 2 + 4 * words[pc + 1]
   else:
    element_width = words[pc + 1]
    element_count = words[pc + 2] | (words[pc + 3] << 16)
    wid = 4 + (element_width * element_count + 1) // 2
"""
if old not in template:
    raise SystemExit("template payload-width patch point not found")
template = template.replace(old, new)
old = "  raw=' '.join(f'{x:04x}' for x in words[pc:pc+wid])\n"
new = """  if op == 0 and (w >> 8) in (1, 2, 3):
   ident = w >> 8
   print(f'    {pc:04x}: payload ident={ident} code_units={wid}')
   pc += wid
   continue
  raw=' '.join(f'{x:04x}' for x in words[pc:pc+wid])
"""
if old not in template:
    raise SystemExit("template payload-output patch point not found")
template = template.replace(old, new)
code = compile(template, str(Path(__file__).with_name("dump_dex_app.py")), "exec")
exec(code, {"__name__": "__main__", "__file__": str(Path(__file__).with_name("dump_dex_app.py")), "sys": sys})
