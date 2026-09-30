# 第二届 Parloo 杯 PaluGOGOGO（玄机 ID 548）WP

## 结论

- **候选 flag：** `flag{bg92Oejpfgl}`
- **结果状态：** 2026-09-29 在玄机题目页前台提交后平台接受；页面显示“已完成”、步骤 1/1。
- **置信度：高。** Go 伪随机种子和状态更新从程序自身的反汇编及内嵌常量恢复；逆变换所得字符串具有 `flag{...}` 格式；Python 脚本重新执行正向变换后，84 个字节与程序硬编码目标逐字节相同。
- **安全范围：** 没有运行或加载陌生 EXE。附件只通过 ZIP 元数据、PE 结构、字符串和反汇编进行静态分析；平台提交由协调者通过 Computer Use 前台完成。

平台验证候选：`flag{bg92Oejpfgl}`。提交步骤与页面回执见 `../../../../记录/批次记录/第09批/原始分件/提交核验_20260929_第九批.md`。浏览器截图在当次 Computer Use 工具输出中展示，没有保存为本地 PNG。

## 资料与完整记录

- 原附件：`originals\palugogogo_flag.zip`
- ZIP SHA-256：`420820830348B3791655E6912DE1DBF84C066F876F9AAC0859F19E91A6A92FF1`
- 安全提取后的附件：`analysis\palugogogo_flag.exe`
- EXE SHA-256：`5DEF2E11E28DB1899B8F5808FBFD6F874CCA7E517D8DC5913D88BE332B17301D`
- 静态工具读取副本：`analysis\palu548_static_copy.exe`；其 SHA-256 与提取件相同。该副本只交给 `objdump` 读取，未执行。
- PowerShell 命令与完整 stdout/stderr 顺序记录：`analysis\commands_output.log`
- 核心反汇编：`analysis\disasm_checkFlag.txt`、`disasm_complexEncrypt.txt`、`disasm_GetValue.txt`、`disasm_WhatAreYouDoing.txt`
- Go 随机数相关反汇编：`analysis\disasm_mathRand_Seed.txt`、`disasm_mathRand_rngSource_Seed.txt`、`disasm_mathRand_rngSource_Int63.txt`、`disasm_mathRand_Int31n.txt`、`disasm_mathRand_Intn.txt`、`disasm_mathRand_globalRand.txt`
- 静态分析及复现脚本：`analysis\inspect_go_pe.py`、`analysis\decode_go_constants.py`、`analysis\solve_static.py`
- 关键输出：`analysis\go_pclntab_functions.txt`、`go_rand_symbols.txt`、`go_symbols_and_constants.txt`、`decoded_constants.txt`、`solve_static_output.txt`

## 1. 核对 ZIP 与附件

先计算 ZIP 的 SHA-256，再只读列出归档条目。归档只有一个根目录文件 `palugogogo_flag.exe`，没有 `..` 路径段、绝对路径或嵌套目录，因此没有路径穿越风险。核对条目名称后，脚本通过 .NET `ZipArchiveEntry.Open()` 将该单一条目流式写入 `analysis`，没有调用通用解压程序。

核心命令：

```powershell
Get-FileHash -LiteralPath 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluGOGOGO_548\originals\palugogogo_flag.zip' -Algorithm SHA256
[System.IO.Compression.ZipFile]::OpenRead($zipPath)
```

关键输出：

```text
Hash      : 420820830348B3791655E6912DE1DBF84C066F876F9AAC0859F19E91A6A92FF1
Entry count: 1
Name                 Length CompressedLength
palugogogo_flag.exe 1456640           702384
```

提取后对 EXE 计算 SHA-256 为 `5DEF2E11E28DB1899B8F5808FBFD6F874CCA7E517D8DC5913D88BE332B17301D`。副本 `analysis\palu548_static_copy.exe` 同哈希，确认静态工具读取的文件内容与原始附件一致。

## 2. 识别文件类型与 Go 程序符号

对文件仅执行静态工具：`objdump -f`、`objdump -h`、`objdump -x`、`strings`，并用 Python 读取 PE 头及 Go `pclntab`。PE 信息表明它是 Windows x64 控制台 PE。内嵌构建信息显示 Go `go1.22.4`、模块名 `palugogogo`，并含原构建源码路径 `F:/CTF/reverse/palu/PaluGOGOGO/main.go`。

PE 段的关键数据：

```text
.text   RVA=0x1000  raw=0x600
.rdata  RVA=0x96000 raw=0x94c00
.data   RVA=0x14f000 raw=0x14d400
file format pei-x86-64
```

Go 函数名虽被 `-ldflags="-s -w"` 去掉普通符号表，运行时函数表仍在。解析 `pclntab` 得到：

```text
main.WhatAreYouDoing: 0x494e80-0x494f40
main.complexEncrypt:  0x494f40-0x4950a0
main.GetValue:        0x4950a0-0x495180
main.checkFlag:       0x495180-0x495500
main.main:            0x495500-0x495518
```

`main.main` 只调用 `main.checkFlag`，所以继续静态反汇编这些关键函数及 `math/rand` 的函数。

## 3. 理清校验流程

`checkFlag` 的反汇编（`analysis\disasm_checkFlag.txt`）显示：

1. 首先调用 `WhatAreYouDoing`。该函数通过 `kernel32.dll` 的 `IsDebuggerPresent` 检查调试器；返回真时显示 `Debugger detected! Exiting...` 并退出校验。
2. 没有检测到调试器时显示 `Please Input Flag: `。
3. 使用 `bufio.Reader.ReadString('\n')` 读取输入，再用 `strings.TrimSpace` 去掉首尾空白。
4. 栈上构造十个整数 `[1,2,3,4,5,6,7,8,9,0]`，交给 `GetValue` 得到变换用的整数 key。
5. 调用 `complexEncrypt(input, key)`。
6. 先要求变换结果长度是 `0x54`（84），再与地址 `0x4bf204` 上的 84 字节常量比较。相等输出 `Success!`，否则输出 `Failed!`。

本次没有触发反调试分支，因为目标程序没有被运行。

## 4. 还原 `complexEncrypt`

反汇编 `analysis\disasm_complexEncrypt.txt` 表明函数逐个处理输入 Unicode 码点。对每个码点，它将下式转换为十六进制字符串，再用逗号连接：

```text
变换值[i] = Unicode码点[i] + key + (当前UTF-8字节偏移 mod 5)
输出项[i] = "0x" + 小写十六进制(变换值[i])
```

在函数循环中，`rdx` 是当前 UTF-8 字节偏移；`rdx % 5` 通过乘魔数 `0xcccccccccccccccd` 实现。对 ASCII 输入，字节偏移与字符索引相同。格式常量从地址 `0x4b5de3` 开始，前五字节恰为 `0x%x,`。函数先为每一项添加逗号，返回时去掉最后一个逗号。因此最终字符串形如：

```text
0xb5,0xbc,0xb2,...
```

反汇编还显示，非 ASCII 字符走 `runtime.decoderune` 分支；本题候选全部为 ASCII，故反推时每个码点的 UTF-8 偏移就是其字符索引。

## 5. 还原 `GetValue` 得到的 key

`analysis\disasm_GetValue.txt` 中的控制流为：

1. 调用 `math/rand.Seed(0x3e4)`，即 seed `996`。
2. 对传入的 10 个槽位逐个调用 `math/rand.Intn(100)` 并覆盖槽位。
3. 调用 `math/rand.Intn(2)`，结果为 0 时返回第一个槽位，为 1 时返回第二个槽位。

不能假定 Go 的随机数与 Python、C 的 PRNG 一致。因此从附件本身继续恢复 Go 1.22.4 的 `math/rand`：

- `rngSource.Seed` 反汇编显示状态表长度 `607`（`0x25f`），初始 tap 为 0、feed 为 334（`0x14e`），seed 规范化模数为 `2^31-1`，零 seed 替换值为 `89482311`。
- seed 扩展使用乘数 `48271`、除数 `44488`、余数常量 `3399`，即 Go `seedrand` 递推。
- `rngSource.Int63` 每次将 tap、feed 各减一（负值回绕 607），将状态的两个 int64 项相加并保存，返回值清除最高位。
- `Int31n(100)` 从 `Int63() >> 32` 取 31 位值，按反汇编实现的拒绝采样上限过滤后取模 100；`Intn(2)` 取下一次 `Int31()` 的最低位。
- `rngCooked` 数组从 `rngSource.Seed` 中的 RIP 相对地址解析为虚拟地址 `0x551de0`，在 PE 文件偏移 `0x1501e0`，共 607 个 int64。脚本从附件读取该表，不硬编码猜测值。

`analysis\solve_static.py` 按上述算法复现得到：

```text
rand.Seed(996) -> Intn(100) array=[79, 81, 91, 5, 94, 91, 49, 65, 40, 8]
next Intn(2) index=0; GetValue key=79
```

## 6. 反推目标常量

`checkFlag` 将 84 字节预期输出放在虚拟地址 `0x4bf204`。脚本按 PE 段映射换算到文件偏移 `0xbde04`，读到：

```text
0xb5,0xbc,0xb2,0xb9,0xce,0xb1,0xb7,0x8a,0x84,0xa2,0xb4,0xba,0xc1,0xb8,0xba,0xbb,0xcd
```

共有 17 项。逐项套用逆变换：

```text
码点[i] = int(目标项[i], 16) - key - (i mod 5)
```

例如用已知 flag 前缀交叉核对 key：

```text
0xb5 - ord('f') - 0 = 79
0xbc - ord('l') - 1 = 79
0xb2 - ord('a') - 2 = 79
```

这与 Go PRNG 复现的 key 一致。完整逆变换为：

```text
U+0066 U+006C U+0061 U+0067 U+007B U+0062 U+0067 U+0039 U+0032
U+004F U+0065 U+006A U+0070 U+0066 U+0067 U+006C U+007D
```

得到候选：

```text
flag{bg92Oejpfgl}
```

## 7. 正向复核

执行保存在项目中的静态复现脚本（它只读取 PE 文件字节，不加载或运行 EXE）：

```powershell
python 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluGOGOGO_548\analysis\solve_static.py' 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluGOGOGO_548\analysis\palugogogo_flag.exe'
```

脚本输出：

```text
rand.Seed(996) -> Intn(100) array=[79, 81, 91, 5, 94, 91, 49, 65, 40, 8]
next Intn(2) index=0; GetValue key=79
target bytes=84, tokens=17
candidate=flag{bg92Oejpfgl}
forward=0xb5,0xbc,0xb2,0xb9,0xce,0xb1,0xb7,0x8a,0x84,0xa2,0xb4,0xba,0xc1,0xb8,0xba,0xbb,0xcd
forward_matches_target=True
flag_prefix_ok=True
```

正向输出与程序常量完全一致，长度也满足 `checkFlag` 的 84 字节条件。候选是由代码路径和常量逆向导出，并经正向变换验证；2026-09-29 协调者在玄机题目页通过前台 Computer Use 提交后，平台接受并显示“已完成”、步骤 1/1。静态审计没有运行该 PE，也没有访问平台。

## 8. 失败尝试与工具限制记录

1. GNU `objdump` 直接打开中文目录中的 EXE 时，Mingw 路径编码错误，显示 `No such file or directory`。先尝试 Windows 短路径，但中文父目录没有短路径别名，仍失败。
2. `go` 命令不在 PATH 中，因此没有使用 `go tool`。改为自行解析 Go 1.22.4 的 `pclntab` 和 PE 结构。
3. 第一次 PRNG 脚本将状态容器写成不可变 tuple，运行时报 `TypeError: 'tuple' object does not support item assignment`。将状态改为 list 后重跑成功；失败和修正都保留在命令日志中。
4. 为绕过 `objdump` 的中文路径问题，曾把哈希一致的静态副本临时写到系统 Temp；随后将其移动回本题 `analysis\palu548_static_copy.exe` 并保留。后续用临时 `subst Z:` 盘符别名供 `objdump` 读取，分析结束后仅解除盘符映射，没有删除文件。
5. `strings` 对 Go 运行时的大块相邻字符串输出不便阅读；改用 Go 函数表解析、地址反汇编及定向常量读取。

完整命令、错误、修正与输出均按发生顺序见 `analysis\commands_output.log`；每份定向反汇编和脚本的标准输出也分别保存在同目录，便于复核。


## 9. 独立静态复核与平台核验

为排除只照抄先前 `solve_static.py` 输出的可能，另写 `analysis\audit_independent.py`，未导入旧脚本。它直接读取原始 ZIP 字节，核对 ZIP SHA-256 与唯一归档成员，再在内存中读取成员并与已有提取件逐字节比较；后续均只把 PE 当作数据解析，没有加载或执行 EXE。

独立复核从保存的 rngSource.Seed 反汇编地址定位 PE 内 607 项 rngCooked，重新实现 Go 的 seed 扩展、20 轮预热、607 槽状态更新、Int63/Int31，以及 Int31n 拒绝采样 cutoff。另从 checkFlag 的静态反汇编地址读取 84 字节比较常量，再逆推候选并做全长正向编码比较。

独立脚本输出的关键值：

~~~text
ZIP_SHA256=420820830348B3791655E6912DE1DBF84C066F876F9AAC0859F19E91A6A92FF1
INNER_PE_SHA256=5DEF2E11E28DB1899B8F5808FBFD6F874CCA7E517D8DC5913D88BE332B17301D
RNG_COOKED_VA=0x551de0; file_offset=0x1501e0; entries=607
RNG_COOKED_SHA256=1928503B93A563E491119A5889BABA73D1605B90B63634C14A408805797A7C7B
GO_SEED=996; modulus=2147483647; warmup=20; tap=0; feed=334
INTN100_VALUES=[79, 81, 91, 5, 94, 91, 49, 65, 40, 8]
NEXT_INTN2_INDEX=0; GETVALUE_KEY=79
CANDIDATE=flag{bg92Oejpfgl}
FORWARD_MATCHES_ALL_84_BYTES=True
PREFIX_CROSSCHECK_KEYS=[79, 79, 79, 79, 79]
~~~

每次 Intn(100) 的原始 31 位抽样、cutoff 与结果，以及目标常量、解出的全部码点和完整正向字符串，见 `analysis\audit_independent_output.txt`。可复现命令、stdout、退出码 0 保存在 `analysis\audit_independent_transcript.txt`。审计脚本只做离线字节解析；平台接受状态来自协调者的前台提交回执，页面显示“已完成”、1/1。
