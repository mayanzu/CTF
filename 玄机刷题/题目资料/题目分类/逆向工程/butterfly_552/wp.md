# 第九届强网杯 butterfly（ID 552）静态分析记录

## 当前状态

附件的加密流程已从 ELF 静态反汇编中复原。4 个完整 8 字节分组经过逆变换后，正向重算逐字节吻合；开头恢复为 `flag{66eec38e269e0e267849a1f7b70`。附件剩余 4 字节无法在已确认的算法和密钥下组成合法的标准 flag 后缀：末块约束给出非文本字节，穷举 `3 个十六进制字符 + }` 也没有密文匹配项。因此本题目前**未解决**，没有可提交的 flag 候选；恢复出的前缀不是完整 flag，不应提交。

本记录只做了本地静态分析，没有联网、没有打开玄机平台，也没有执行附件 ELF。

## 文件与完整性

原始附件：`originals/butterfly.7z`

SHA-256：`85FDF4CEC63C0A33F2D8A144D2652B63188BE015907F5C2A78559FD469B43228`。

先用 7-Zip 的只读列表模式查看目录，再抽取。归档仅有三个平面文件名，没有绝对路径、盘符或 `..` 路径：

| 文件 | 归档长度 | 抽取后的 SHA-256 |
|---|---:|---|
| `butterfly` | 710352 | `B8D977D9540F8AF606F0CB0604C932BBEFA5D2FF202422616B06C7FA32DFDB75` |
| `encode.dat` | 36 | `2EF3E3CCDB4DF9AE7B39EBCE677818EABCE3ACB78802E01AEACA56572734D2B1` |
| `encode.dat.key` | 32 | `3DEBC947A1A9073F7A9D2E82C2AF39C721B61764F33066CEDCCA2385694E278F` |

解压目录：`analysis\extracted\`。`butterfly` 的 ELF 头为 ELF64、little-endian、x86-64、`EXEC`。样本从未在宿主机运行。

## 复现命令

以下命令均在 PowerShell 前台执行；完整 stdout/stderr、反汇编摘要、哈希与错误尝试记录在 [commands_output.log](analysis/commands_output.log)。

```powershell
$base = 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\butterfly_552'
$z = 'C:\Program Files\AMD\CIM\Bin64\7z.exe'
& $z l -slt (Join-Path $base 'originals\butterfly.7z')
& $z x -y ('-o' + (Join-Path $base 'analysis\extracted')) (Join-Path $base 'originals\butterfly.7z')
Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $base 'originals\butterfly.7z')
& 'C:\msys64\mingw64\bin\readelf.exe' -h -S -s -r -d (Join-Path $base 'analysis\extracted\butterfly')
python (Join-Path $base 'analysis\inspect_static.py')
python (Join-Path $base 'analysis\inspect_io_paths.py')
python (Join-Path $base 'analysis\decode_flag.py')
python (Join-Path $base 'analysis\enumerate_tail.py')
python (Join-Path $base 'analysis\independent_verify.py')
```

实际使用的归档程序是本机已有的 AMD 随附 7-Zip 25.01：`C:\Program Files\AMD\CIM\Bin64\7z.exe`，其 SHA-256 为 `53D459CA98F5651FCC3B448068C695365385FF4AF803EC3FF4DD8167D91B467B`。它只执行了 `l` 和 `x`，没有启动归档中的二进制。

## 逆向过程

### 1. 识别输入输出流程

从 ELF 入口 `0x401b70` 可见启动代码把 `0x4018d0` 作为 `main` 交给 `__libc_start_main`。`main` 检查 `argc == 3`，并从 `argv[1]`、`argv[2]` 取得输入和输出路径。静态字符串还给出：

```text
Usage: %s <input_file> <output_file>
Example: %s plaintext.txt encoded.dat
Encoding file: %s
Successfully encoded to: %s
Encoded size: %zu bytes
```

主流程打开输入文件，定位到末尾取得文件长度 `n`，回到开头并分配 `n + 8` 字节缓冲区；读取 `n` 字节后，在 `buffer[n]` 和 `buffer[n+1]` 写入 `n` 的低、高字节。附件 `encode.dat` 长度为 36，因此这两字节是 `24 00`。

主流程只要 `n > 7` 就逐个处理 8 字节块，块指针每轮加 8，直到处理起始偏移 `floor((n-1)/8)*8`。所以长度 36 时会处理偏移 0、8、16、24、32 共 5 个块；最后一个块实际只有 4 个密文输出字节，其余位置是缓冲区尾部。

写出路径的反汇编在 `analysis\inspect_io_paths.py` 中：调用 `0x401ca0` 前 `rdx=rbx`（长度）、`rsi=rbp`（缓冲区）、`rdi=r13`（输出路径）。该 helper 以 `fopen(..., "wb")` 创建输出，再以 `fwrite(buffer, 1, n, file)` 写出，并比较写入数量和 `n`。所以写出长度严格等于输入长度 36；不会把缓冲区尾部额外输出成第 5、第 6 个末块密文字节。

### 2. 还原密钥与块变换

主函数从 `.rodata` 地址 `0x4825b6` 装载 16 字节常量；其内容以 `MMXEncode2024` 开始。随后把首个 64 位值复制到栈上，循环内用 `movq mm1, [rsp+0x20]` 取作 MMX lane key。因此每个 8 字节块使用：

```text
K = b"MMXEncod"
hex = 4d 4d 58 45 6e 63 6f 64
```

单个明文块 `P[0..7]` 的正向处理顺序由机器指令确认：

1. `pxor mm0, mm1`：每字节与 key XOR。
2. `psllw 8`、`psrlw 8`、`por`：每个 16 位字内交换相邻字节。
3. `psllq 1`、`psrlq 63`、`por`：将 64 位小端整数循环左移 1 位。
4. `paddb mm0, mm1`：各字节加 key，模 256。

令 `A_i = P_i XOR K_i`，交换结果为 `B_i = A_{i XOR 1}`。把 B 按 little-endian 组成 64 位数后左循环移 1 位得到 R，最后 `C_i = (R_i + K_i) mod 256`。

反变换为：

```text
R_i = (C_i - K_i) mod 256
B_i = (R_i >> 1) | ((R_(i+1 mod 8) & 1) << 7)
A_i = B_(i XOR 1)
P_i = A_i XOR K_i
```

注意 `B_i` 的最高位需要下一个密文字节 `R_(i+1)` 的最低位；因此不完整块不能像完整块一样独立逆变换。

### 3. 逆变换完整分组

`analysis\decode_flag.py` 和独立实现 `analysis\independent_verify.py` 分别完成逐块逆变换及正向复算。两个脚本的四个完整分组结果如下：

| 偏移 | 密文块 | 逆变换结果 | 正向重算 |
|---:|---|---|---|
| 0 | `8fa39cb7188d7116` | `flag{66e` | `8fa39cb7188d7116`，吻合 |
| 8 | `a99d521b10792916` | `ec38e269` | `a99d521b10792916`，吻合 |
| 16 | `479d46bf16130f12` | `e0e26784` | `479d46bf16130f12`，吻合 |
| 24 | `a5359e1770151714` | `9a1f7b70` | `a5359e1770151714`，吻合 |

因此可确认的 32 字节前缀是：

```text
flag{66eec38e269e0e267849a1f7b70
```

它没有闭合花括号，不能当作 flag 提交。

### 4. 尾部数据与严格校验

末块可见密文只有：

```text
38 69 7d 0a
```

按 key 相减后的前四个 R 字节为 `eb 1c 25 c5`。按逆变换公式枚举缺失的 `R[4]` 最低位，得到：

```text
R[4].bit0 = 0 -> P[0..3] = c3 38 3a d7
R[4].bit0 = 1 -> P[0..3] = c3 38 ba d7
```

前缀 `c3 38 ? d7` 含非文本字节，不符合标准 flag 后缀。由于程序只输出 36 字节，不能臆造缺失的密文高四字节，再据此声称恢复成功。

我额外按首32字节的形状穷举末尾 3 个十六进制字符及 `}`，并把程序写入缓冲区的长度尾字节 `24 00` 纳入。对每种后缀构造 8 字节末块 `[suffix4, 24, 00, 00, 00]`，用独立正向算法加密，并逐字节比较实际可见的 4 个末块密文。结果为 **0 个匹配**。例如后缀 `000}` 加长度/零填充后得到完整 8 字节密文 `4747c81534f73742`，可见前四字节 `4747c815` 与目标 `38697d0a` 不同。

完整反变换脚本曾先用零填充缺失的末块字节做前向检查，因末块密文第 0 字节还取决于未知填充的最高位而出现不匹配。随后改为显式枚举该位，并使用独立函数穷举合法后缀；不匹配结果仍成立。脚本第一次构造临时字节邻接数组时少补一个字节并触发 `IndexError`，补足访问位后重新运行。以上失败尝试也保留在命令日志中。

## 文件清单

- 原始附件：`originals\butterfly.7z`
- 抽取文件：`analysis\extracted\`
- 初步 Capstone 静态扫描：`analysis\inspect_static.py`
- 输入/输出长度路径反汇编：`analysis\inspect_io_paths.py`
- 逆变换及逐块回算：`analysis\decode_flag.py`
- 合法尾缀严格穷举：`analysis\enumerate_tail.py`
- 独立正向/逆向公式校验：`analysis\independent_verify.py`
- 完整命令及 stdout/stderr：`analysis\commands_output.log`

## 结论

静态分析确认前 32 字节前缀以及四个完整块的逆/正向一致性；现有附件的尾部数据与标准 flag 后缀约束矛盾。当前没有可高置信提交的候选 flag，平台验证也未进行。需要额外的原始输入、未截断密文或出题方对数据格式的说明，才能判断是附件尾块异常、编码数据不完整，还是 flag 使用了非标准二进制尾缀。

## 第二轮尾块与文件完整性审计（2026-09-29）

### 归档与静态地址复核

对原始归档执行 `7z t -bb1`，结果为 `Everything is Ok`，逐项测试 `butterfly`、`encode.dat`、`encode.dat.key` 均通过。提取后用 Python 独立计算的 CRC32 分别为 `E7857853`、`336055F0`、`0F8168A2`，与 7-Zip `l -slt` 列出的条目 CRC 一致。`encode.dat` 的物理长度为 36 字节、SHA-256 为 `2EF3E3CCDB4DF9AE7B39EBCE677818EABCE3ACB78802E01AEACA56572734D2B1`。

`readelf -l -S` 显示首个 `LOAD` 将文件偏移 `0` 映射到虚拟地址 `0x400000`；`.rodata` 段文件偏移 `0x80000` 对应虚拟地址 `0x480000`。因此反汇编引用的虚拟地址 `0x4825b6` 对应文件偏移 `0x825b6`。该处连续 32 字节为 `4d4d58456e636f64653230323400456e636f64696e672066696c653a2025730a`，恰好与 `encode.dat.key` 32 字节逐字节相同；其前 8 字节 key 为 `4d4d58456e636f64`（`MMXEncod`）。核对脚本和输出见 `analysis\inspect_offsets.py` 与 `analysis\commands_output.log`。

### 文件长度、内存尾部与写出长度

反汇编确认 `n = 36` 时分配 `n+8 = 44` 字节；在读取的 36 字节后，程序只初始化 `buffer[36]=0x24`、`buffer[37]=0x00`。`buffer[38]`、`buffer[39]` 未在主函数中初始化。块循环会处理起始偏移 0、8、16、24、32；最后一个 8 字节块含 4 个文件数据字节、2 个长度字节和 2 个未初始化字节。

调用输出 helper 前，主函数将长度 36 放入 `rdx`、缓冲区放入 `rsi`、输出路径放入 `rdi`。helper 将 36 保存到局部变量，并调用参数形态为 `fwrite(buffer, 1, 36, file)` 的函数，之后检查返回写入数是否等于 36。因此处理后的末块确有 8 个字节，但文件仅保存末块前 4 字节；`encode.dat` 并没有可供读取的 `C[36..39]`。

### 对完整 36 字节的正向复核

`analysis\verify_full_36.py` 依据反汇编重新生成 36 字节文件，而不是只比较完整块。前 32 字节由四个完整分组唯一恢复；末四个文件字节有两个可见密文兼容值：

```text
c3 38 3a d7
c3 38 ba d7
```

将程序写入的长度尾部 `24 00` 放在内存偏移 36、37，并取一个满足观测密文的未初始化尾部实例 `buffer[38:40]=80 00`，对五个 8 字节块逐一正向处理后只保留 36 字节。两种末块都能逐字节复现整个附件：

| 输入末块（偏移 32..39） | 正向处理所得完整 8 字节 | 实际写出末 4 字节 | 与 `encode.dat[32..35]` |
|---|---|---|---|
| `c3 38 3a d7 24 00 80 00` | `38 69 7d 0a 34 f7 37 42` | `38 69 7d 0a` | 完全一致 |
| `c3 38 ba d7 24 00 80 00` | `38 69 7d 0a 35 f7 37 42` | `38 69 7d 0a` | 完全一致 |

这说明当前 36 字节密文确实能由该程序的变换和长度框架生成，但其兼容明文的末尾含 `c3` 与 `d7` 等非文本字节，不是常规 `flag{...}`。两种输入末块只在未写出的密文 `C[36]` 上不同，故附件不包含足够信息判定 `P[34]` 的最高位。这里的 `80 00` 是展示一组精确复算实例，不代表能证明原运行中分配器尾字节的原值。

严格格式搜索仍按长度 36 的常见格式，即前缀后 30 个十六进制字符和闭合 `}`；已知前 32 字节之后恰剩 3 个十六进制字符加 `}`。`analysis\enumerate_tail.py` 同时枚举 `buffer[38]` 最高位 0/1，`buffer[39]` 固定为 0（其值不影响已写出的 `C[0..3]`），并比较四个实际存在的密文字节，匹配数为 0。前文方括号 `[suffix4, 24, 00, 00, 00]` 只是零填充示例；完整穷举还覆盖了 `buffer[38]` 的最高位设置为 1 的情况。

### 是否为附件截断或损坏

7-Zip 测试与归档 CRC 证明抽取内容没有在归档或本地提取过程中发生字节损坏。样本本身的输出逻辑有意只写 `n` 字节，因此不保存末块剩下的 4 个变换字节；这是程序的写出行为，不是 7-Zip 丢失数据。若出题者原本期望常规文本 flag，则当前 `encode.dat` 与该预期不一致；仅凭现有压缩包无法判断这种不一致是在生成输入文件、运行编码器还是打包前产生的，也无法证明打包前是否曾有不同的原始附件。

第二轮结论保持不变：算法和可见密文可以完整正向复现，但现有文件没有恢复出标准完整 flag。没有可提交候选，也没有执行平台提交。

新增复核脚本：`analysis\verify_full_36.py`、`analysis\inspect_offsets.py`。本轮所有命令和 stdout/stderr 已追加到 `analysis\commands_output.log`。

### 第二轮对分配与读取路径的补查

`analysis\inspect_buffer_calls.py` 进一步检查了 `main` 调用的两个 helper：

- `0x401979` 只把 `n+8` 作为一个参数传给 `0x412620`，返回值空指针会触发 `Error: Memory allocation failed` 分支；该函数是静态链接 glibc 的单参数 `malloc` 分配路径，不是清零分配。
- `0x41cc80` 接收目标缓冲区、容量 `n+8`、元素大小 `1`、元素数 `n` 和 `FILE*`。它计算并检查 `1*n <= n+8`，随后只把 `n` 字节交给底层读取函数；未对 `n+8` 区域执行 `memset` 或其他清零操作。主函数后续只明确写入偏移 `n`、`n+1` 两个长度字节。

因此偏移 `n+2`、`n+3`（本附件为 38、39）的值确实来自未初始化的 malloc 缓冲区。已观测的密文允许其中偏移 38 的最高位为 1；`80 00` 是可复现该文件的一组具体取值，但不能仅从附件证明原进程的低位/偏移 39 取值。这个边界不改变对可见 flag 字节的结论。

本次补查命令和完整 Capstone 输出位于 `analysis\inspect_buffer_calls.py` 与 `analysis\commands_output.log`。

### 位依赖方向的勘误记录

末块环回位的字节索引需要特别注意：令 `A_i=P_i XOR K_i`，相邻字节交换为 `B_i=A_(i XOR 1)`。64 位左旋后，最低字节为 `R_0=(B_0<<1) | (B_7>>7)`；而 `B_7=A_6`，因此写出的首字节 `C_0` 依赖 `P_6` 的最高位（本附件即 `buffer[38]`），不是 `P_7`（`buffer[39]`）。`P_7` 不影响本末块已写出的 `C[0..3]`。

尾部逆变换手算核对：对 `C[32..35]=38 69 7d 0a` 减去 key 得 `R[0..3]=eb 1c 25 c5`。公式分别给出 `P_0=c3`、`P_1=38`、`P_2=3a/ba`（取决于未保存的 `R_4` 最低位）、`P_3=d7`。`P_6` 最高位取 0 时正向末块首字节为 `37`；取 1 时变为 `38`，与附件吻合。这也独立确认了边界位应由 `buffer[38]` 控制。


## 独立尾块审计（2026-09-29）

第二次静态审计核对了尾块缓冲区分配、读取、长度尾标记、块循环和写出长度，并重新按小端 64 位循环左移逐位追踪末块依赖。对输入长度 $n=36$，程序分配 $n+8$ 字节，只读取 $n$ 字节，在 `buffer[36]`、`buffer[37]` 写入 `24 00`；末次变换从偏移 32 处理完整的 8 字节窗口，但写出 helper 的实参仍为 `fwrite(buffer, 1, n, file)`，因此最终文件只含 36 字节，最后一块只有密文偏移 32–35 可见。`buffer[38]`、`buffer[39]` 没有初始化。

对该变换，先令 $z_i=P_i/oplus K_i$，交换相邻字节得 $w_i=z_{i/oplus1}$，再对小端 64 位整数做 `ROL64(...,1)`。因此循环左移时由 $w_7$ 的最高位环回到结果第 0 字节；而 $w_7=z_6$，故可见密文末块第 0 字节受 `buffer[38]`（块内 $P_6$）最高位影响。$P_7$ 不影响可见的四个末块字节。这与前文脚本对 `P[6].MSB` 的枚举一致；单独以零填充尾部进行前向核对时，第 0 字节不匹配不能单独用作附件异常证据。

直接对可见尾块密文 `38 69 7d 0a` 逆算，固定得到 `P[0]=c3`、`P[1]=38`、`P[3]=d7`；`P[2]` 随缺失的密文字节低位有两种可能 `3a` 或 `ba`。根据前 32 字节已恢复的格式，剩余四字节必须是三个 ASCII 十六进制字符和 `}`，但 `P[0]` 不属于十六进制字符，`P[3]` 也不是 `}`。这一矛盾不依赖未知的尾部填充字节或程序写入的长度标记。

独立复算脚本 `analysis\audit_tail_math.py` 遍历大小写十六进制字符构成的全部 $22^3$ 个后缀组合（具体为 22 个字符取 3 位，共 10,648 项），对每种末尾格式分别测试 `buffer[38]` 最高位为 0 和 1，并仅比较程序实际写出的四个尾块密文字节；精确匹配数为 0。脚本同时验证非标准二进制片段 `c3 38 3a d7` 在 `buffer[38].MSB=1` 时可产生目标末块密文 `38 69 7d 0a`，说明此前的零填充差异确由缓冲区未初始化位导致。

以上结果排除了常见的分块、文件长度尾标记、EOF 截断和 `fwrite` 长度解释对标准 ASCII flag 尾缀的补救。原 7z 通过归档 CRC 测试，仅说明当前归档自洽；现有证据更符合“附件内容与常见 `flag{...}` 格式假设不一致或题目数据不匹配”，尚不足以证明具体是哪一环出错。题目仍未解决，未提交平台。

勘误说明：本独立审计脚本的第一版曾把 ROL64 环回位误记到块内 $P_7$；随后按交换字节后的 `w[7]=z[6]` 关系修正为 $P_6$ 并完整重跑。第一版的错误输出在 `analysis\commands_output.log` 中保留，紧随其后的勘误注明应忽略；请以修正版脚本和末次输出为准。

