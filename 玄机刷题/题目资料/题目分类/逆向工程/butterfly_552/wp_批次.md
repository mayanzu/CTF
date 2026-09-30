# 第九届“强网杯”全国网络安全挑战赛 Butterfly（玄机 ID 552）

> 状态：**玄机平台已接受候选，题目显示已完成 1/1。**本子代理没有操作平台；主线程在 2026-09-29 通过前台 UI 提交候选并确认完成。静态分析只使用本批新归档 `originals/butterfly.7z`；没有读取旧 WP、旧缓存或题库答案，也没有执行题目 ELF。

## 1. 结果

候选 flag（不含文本文件末尾换行）：

```text
flag{66eec38e269e0e267849a1f7b708i}
```

候选本体是 **35 个 ASCII 字节**。解密后的完整输出是 36 字节，最后一个字节 `0a` 是文件末尾换行；候选最后的 `i}` 来自 `encode.dat` 未变换的尾部，不能删掉 `i`。平台提交时应提交上面的 35 字节文本，不附加换行。

静态 solver 把每个完整 8 字节块反解，再按附件中的变换正向运算。重建的 36 字节密文与 `encode.dat` **逐字节完全相同**，输出 `forward closure = True`。之后主线程将不含末尾换行的 35 字节候选提交至玄机平台，页面从 `0/1` 更新为“已完成”，并显示步骤 `1/1`。

## 2. 附件与来源核验

原始附件：`originals/butterfly.7z`，260,238 字节，SHA-256：

```text
85FDF4CEC63C0A33F2D8A144D2652B63188BE015907F5C2A78559FD469B43228
```

先用系统 `tar.exe -tf/-tvf` 列出成员；确认成员都是根目录普通文件后才解包。归档只有以下 3 个成员：

| 成员 | 字节数 | SHA-256 |
|---|---:|---|
| `butterfly` | 710,352 | `B8D977D9540F8AF606F0CB0604C932BBEFA5D2FF202422616B06C7FA32DFDB75` |
| `encode.dat` | 36 | `2EF3E3CCDB4DF9AE7B39EBCE677818EABCE3ACB78802E01AEACA56572734D2B1` |
| `encode.dat.key` | 32 | `3DEBC947A1A9073F7A9D2E82C2AF39C721B61764F33066CEDCCA2385694E278F` |

解包副本保存在 `analysis\extracted\`。散列值来自原归档解包件；完整命令记录见 `analysis/command_transcript_20260929.txt`。

## 3. 安全检查与 ELF 结构

附件 `butterfly` 的 magic bytes 是 `7f 45 4c 46`，`readelf -h` 显示：

- ELF64、little-endian、x86-64；
- `ET_EXEC`，入口地址 `0x401b70`；
- 无动态段，是静态链接文件；
- `.text` 位于 VA `0x401180` / 文件偏移 `0x1180`，大小 `0x7df20`；
- `.rodata` 位于 VA `0x480000` / 文件偏移 `0x80000`，大小 `0x1c2b4`；
- ELF 符号已剥离，`objdump -t` 报告 `no symbols`。

全程没有执行 ELF。用 `strings` 观察到 `MMXEncode2024`、`Encoding file: %s`、`Original size: %zu bytes`、`Successfully encoded to: %s`、`Encoded size: %zu bytes`、`%s.key`、`Key saved to: %s` 等字符串。主流程在 `0x4018d0`，其参数检查要求程序名以外有两个参数；反汇编显示输入文件以只读方式打开，取长度、读取到缓冲区，然后对缓冲区处理并写出结果文件和 `.key` 文件。此流程判断来自静态控制流与字符串，不依赖运行样本。

Windows 的 `7z` 不在 PATH，故改用系统 `tar.exe`。MSYS2 的 `nm/objdump` 通过含中文目录的路径读取时报告路径不存在；将同一个 ELF 暂存复制到 ASCII 路径 `C:\CTF_552\butterfly` 后可供静态工具读取，复制前后 SHA-256 相同。临时暂存只用于分析，项目内的原始附件与解包件均保留。PowerShell 的 `Get-Content -Encoding Byte` 也不适用；后续直接由 Python `Path.read_bytes()` 读取字节。失败尝试及输出已如实记入 transcript。

## 4. Key 的确定

程序在 `0x4019cf` 和 `0x4019dc` 使用 `movdqu` 从 `.rodata` 地址 `0x4825b6` 和 `0x4825c6` 连续加载 32 字节。ELF 的 VA `0x4825b6` 对应文件偏移 `0x825b6`。该处 32 字节为：

```text
4d4d58456e636f64653230323400456e636f64696e672066696c653a2025730a
```

`encode.dat.key` 也是完全相同的 32 字节，solver 对两者执行逐字节相等比较，结果 `keyfile == rodata first 32 = True`。随后主流程把栈上第一个 8 字节加载到 MMX 寄存器，故实际每块使用的 8 字节 key 为：

```text
hex:   4d4d58456e636f64
ASCII: MMXEncod
```

完整 32 字节文件不是 32 字节轮换 key；反汇编中的 `movq mm1,QWORD PTR [rsp+0x20]` 明确只取前 8 字节，并在循环里复用。

## 5. 反汇编确定的加密操作

主循环从 `0x401a49` 开始，使用 MMX 指令逐个处理 8 字节块。对块内第 `i` 个字节 `P[i]`，key 字节为 `K[i]`：

1. `pxor mm0,mm1`：各字节与 key 异或。
2. `psllw 8`、`psrlw 8`、`por`：每个 16-bit word 内交换相邻字节。
3. `psllq 1`、`psrlq 63`、`por`：把 64-bit 小端 word 循环左移 1 bit。
4. `paddb mm0,mm1`：每个字节加 key，按模 256 截断。

令 `swap` 为字节序列 `[b0,b1,b2,b3,b4,b5,b6,b7]` 到 `[b1,b0,b3,b2,b5,b4,b7,b6]` 的映射，`rol64` 将以 little-endian 解释的 64-bit 数循环左移一位。则：

```text
C = (rol64(swap(P XOR K)) + K) mod 256    # 加法逐字节
```

逆变换按照可逆步骤反序执行：

```text
X = (C - K) mod 256                       # 逐字节减法
Y = ror64(X, 1)
Z = swap(Y)                               # 相邻字节交换是自身的逆
P = Z XOR K
```

## 6. 尾部为何有 `i}`

代码先检查长度是否大于 7，再按 8 字节地址推进。循环边界计算中，`(length-1)>>3` 和 `(length-8)>>3` 限定处理完整块；输入长度为 36，因此只处理偏移 `0, 8, 16, 24` 共 32 字节。剩下 4 字节不会进入 MMX 循环，保持原样：

```text
encode.dat[32:36] = 38 69 7d 0a = b"8i}\n"
```

因此，未变换的尾部中 `8` 与 `i}` 属于恢复文本，最后 `0a` 是文本文件的结尾换行。不能因为 `i` 不是十六进制字符就删除它；删除会破坏由附件恢复出的原文。

## 7. 逐块解密与正向闭环

输入密文：

```text
8fa39cb7188d7116a99d521b10792916479d46bf16130f12a5359e177015171438697d0a
```

下表的中间值均为内存顺序的 8 个字节；`C-K` 为逐字节模 256 减法：

| 块偏移 | 密文 `C` | `C-K` | `ROR64(1)` | 相邻字节交换 | `XOR K` 得明文 |
|---:|---|---|---|---|---|
| 0 | `8fa39cb7188d7116` | `42564472aa2a02b2` | `212b223955150159` | `2b21392215555901` | `666c61677b363665` = `flag{66e` |
| 8 | `a99d521b10792916` | `5c50fad6a216bab2` | `2e287d6b510b5d59` | `282e6b7d0b51595d` | `6563333865323639` = `ec38e269` |
| 16 | `479d46bf16130f12` | `fa50ee7aa8b0a0ae` | `7d28773d54585057` | `287d3d7758545750` | `6530653236373834` = `e0e26784` |
| 24 | `a5359e1770151714` | `58e846d202b2a8b0` | `2c74236901595458` | `742c692359015854` | `3961316637623730` = `9a1f7b70` |

前 32 字节拼接为 `flag{66eec38e269e0e267849a1f7b70`，接着原样接上尾部 `8i}\n`，得到：

```text
明文 bytes (36): 666c61677b36366565633338653236396530653236373834396131663762373038697d0a
明文文本       : flag{66eec38e269e0e267849a1f7b708i}\n
候选本体 (35)  : flag{66eec38e269e0e267849a1f7b708i}
```

正向闭环将表中每个 `P` 再按 `P XOR K`、交换相邻字节、`ROL64(1)`、逐字节 `+K` 处理。每块比较均为 `match=True`；整文件输出：

```text
forward closure = True
forward hex      = 8fa39cb7188d7116a99d521b10792916479d46bf16130f12a5359e177015171438697d0a
```

这与归档成员 `encode.dat` 的 36 字节完全相同。主线程通过前台页面确认提交前 `0/1`、提交后“已完成”和步骤 `1/1`，这是平台接受的最终确认。成功 toast 在页面加载后消失；截图仅显示在工具输出中，没有保存成本地 PNG。主线程的提交核验记录为 `../../../../记录/批次记录/第10批/原始分件/提交核验_20260929_第十批.md`。

## 8. 可复现文件与输出

- 静态求解器：`analysis/solve_butterfly_static.py`。只读三个附件文件、按上面的逆变换还原并正向校验；**不调用附件 ELF**。
- 单块中间运算追踪：`analysis/trace_butterfly_blocks.py`。
- 解出原文：`analysis/recovered_plaintext.bin`。
- 候选：`analysis/candidate.txt`（文件自身以换行结束；提交时使用不带该行尾换行的 flag 本体）。
- 求解器完整输出：`analysis/reports/solver_output.txt`。
- 每块的逆运算及正向运算：`analysis/reports/block_trace.txt`。
- ELF header、段表、字符串和完整反汇编：`analysis/reports/elf_header.txt`、`elf_program_headers.txt`、`elf_sections.txt`、`elf_dynamic.txt`、`strings_offsets.txt`、`disassembly_intel.txt`。
- 主流程反汇编摘录：`analysis\reports\main_disassembly_excerpt.txt`。
- 所有命令及其输出/输出文件索引与失败尝试：`analysis/command_transcript_20260929.txt`。

用项目根目录为当前目录时，可这样复现：

```powershell
python .\题目资料\题目分类\逆向工程\butterfly_552\analysis\solve_butterfly_static.py
python .\题目资料\题目分类\逆向工程\butterfly_552\analysis\trace_butterfly_blocks.py
```

命令会执行我们编写的 Python 静态求解器，不会执行 `butterfly`。平台提交与接收状态由主线程确认，详见 `../../../../记录/批次记录/第10批/原始分件/提交核验_20260929_第十批.md`。
