# Xuanji #562 `checker` 逆向 WP（平台验证待核）

## 结论与当前状态

本地附件中的校验逻辑可以直接逆出候选 flag：

```text
flag{enp17I4p8TZmAriao2lq5tAArZ2P1wxBUwXU2}
```

候选共有 43 个 ASCII 字符，是从本地附件比较目标逐字节异或 0x23 得到的；与附件 SHA-256 相同的本地 checker 输出 Correct! You have the flag. 父任务记录该候选此前在平台被拒绝。本次已重新核对登录后的 #562 详情页：显示免费、中等、0/1；从该页前台重新下载的 ZIP 和唯一成员 checker.exe 哈希都与本地分析附件一致。因此当前页面附件版本不一致已排除，但此前拒绝的具体原因仍未知；本轮没有再次提交 flag。

## 附件与复核范围

- 挑战页面：<https://xj.edisec.net/challenges/562>
- 原始附件 ZIP：`checker_platform_20260929.zip`
- ZIP 内唯一文件：`checker.exe`，42,857 字节
- ZIP SHA-256：`598E457DCDFFCB89F4A1B5CF56133E1D8A194E737B8C25C6C0EA722854426D36`
- ZIP 成员 SHA-256：`449D9F4569A0ED70FCB9BC8B96737719B62CFD8AE7C1E99D2864A3999887FDF5`
- 解压附件和用于本机运行的 ASCII 临时副本 SHA-256 均为 `449D9F4569A0ED70FCB9BC8B96737719B62CFD8AE7C1E99D2864A3999887FDF5`。
- 文件格式：PE32 i386，ImageBase `0x00400000`。

原 ZIP 成员哈希与解压文件哈希逐字节一致，故下面的分析针对题目附件本身，而不是旧目录里名称相同但来源不明的文件。

## 解题步骤

### 1. 确认程序入口和 flag 比较流程

`checker_strings_ascii.txt` 中可见提示 `Enter the flag:`、成功提示 `Correct! You have the flag.`、失败提示 `Incorrect flag.`。反汇编中的 `_main`（`0x40152a`）先读取输入，再调用 `_check_flag`；根据返回值打印成功或失败信息。

`_check_flag`（`0x4014f0`）调用 `_encrypt_flag`，并将结果与地址 `0x404020` 指向的全局字节串传给 `strcmp`。因此该地址的 NUL 结尾字符串就是程序要求的密文。

反汇编的关键调用关系：

```text
_main -> _check_flag -> _encrypt_flag -> strcmp(encrypted_input, 0x404020)
```

`_fake_check` 只打印“Performing initial checks...”和“Checks completed.”，中间调用 `Sleep(1000)`；这是延时干扰，不参与 flag 判定。

### 2. 从汇编确认加密方式与 key

`_encrypt_flag` 在 `0x401496` 执行：

```asm
c7 45 f0 23 00 00 00    mov DWORD PTR [ebp-0x10],0x23
```

也就是固定 key 为 `0x23`。主循环读取输入第 `i` 个字节，执行 `byte ^ 0x23` 后写到输出第 `i` 个字节；循环长度由 `strlen(input)` 控制。循环结束后在输出尾部写 NUL。它是单字节、固定 key 的 XOR，没有索引递增 key，也没有额外哈希或字符变换。

对应伪代码：

```c
for (i = 0; i < strlen(input); i++)
    encrypted[i] = input[i] ^ 0x23;
encrypted[strlen(input)] = '\0';
```

`_check_flag` 通过 `strcmp(encrypted, (char *)0x404020) == 0` 判定，比较区分大小写。

### 3. 从 PE section 定位密文字节

`objdump -h` 显示 `.data` 的虚拟地址为 `0x404000`，文件偏移为 `0x3200`。目标地址 `0x404020` 相对 `.data` 起始地址偏移 `0x20`，所以对应文件偏移是：

```text
0x3200 + (0x404020 - 0x404000) = 0x3220
```

`.data` 从 `0x404020` 开始的字节为：

```text
45 4F 42 44 58 46 4D 53 12 14 6A 17 53 1B 77 79
4E 62 51 4A 42 4C 11 4F 52 16 57 62 62 51 79 11
73 12 54 5B 61 76 54 7B 76 11 5E 00
```

末尾 `00` 是字符串终止符，不参与解密。有效密文长度为 43 字节。

### 4. XOR 解密并核对 flag 格式

对密文每个有效字节执行 `cipher[i] ^ 0x23`，得到：

```text
plaintext hex:
66 6C 61 67 7B 65 6E 70 31 37 49 34 70 38 54 5A 6D 41 72 69 61 6F
32 6C 71 35 74 41 41 72 5A 32 50 31 77 78 42 55 77 58 55 32 7D

ASCII:
flag{enp17I4p8TZmAriao2lq5tAArZ2P1wxBUwXU2}
```

解密结果 43 字节，包含 `flag{` 前缀和 `}` 后缀。再对解密结果逐字节 XOR `0x23`，完整得到原 43 字节密文，往返校验为真。

### 5. 检查长度与输入处理

`_main` 调用 `fgets(input, 0x32, stdin)`。`0x32` 是十进制 50，`fgets` 最多读取 49 个输入字符再补 NUL。候选长度为 43，连同输入换行共 44 个字符，能完整读入。

随后 `_main` 用 `strcspn(input, "\n")` 把换行改为 NUL。因此通过终端输入或 PowerShell 管道提交完整 43 字符候选均不会被截断。`_check_flag` 的栈输出区也足以容纳 43 字节结果和终止符。长度及换行处理不能解释平台拒绝。

### 6. 用原始附件本机验证

从 ZIP 成员复核的脚本 `solve_checker_from_pe.py` 只依赖 Python 标准库：解析 PE section 表，将 VA `0x404020` 映射到文件偏移 `0x3220`，读出 NUL 终止字节串并逐字节 XOR `0x23`。完整命令和输出保存在 `checker_audit_terminal_20260929.txt`。

将候选通过管道交给与 ZIP 成员 SHA-256 完全相同的 Windows PE 程序，得到：

```text
Enter the flag:
Performing initial checks...
Checks completed.
Correct! You have the flag.
```

## 二次核对：输入边界、编码与隐藏校验

这次复核针对“是否因为输入格式/终端编码/缓冲区边界，导致已逆出的字符串不能通过 checker”逐条检查：

1. **入口读取。** `_main` 调用 `fgets(input, 0x32, stdin)`。第二个参数 `0x32` 是 50，因此最多读入 49 个非 NUL 字节，并保留结尾 NUL。读取后调用 `strcspn(input, "\n")`，把首个换行处改为 NUL。候选为 43 个 ASCII 字节；即使考虑 CRLF 输入占两个换行字节，仍小于 49 字节上限。Windows CRT 文本模式也会将 CRLF 规整为 LF。
2. **比较逻辑。** `_check_flag` 的唯一真假分支是 `_encrypt_flag` 的结果与 `0x404020` 处密文执行 `strcmp`。`_encrypt_flag` 对输入字符串逐字节 XOR 固定 `0x23`，不识别或剥除前缀，也不做哈希、Base64、UTF-8 转码或其他归一化。`strcmp` 区分大小写；花括号与 `flag` 前缀都是比较数据的一部分。
3. **容量。** `_check_flag` 将输出区地址设为 `[ebp-0x3a]`，局部缓冲区容量足以保存最长 49 字节输入及 NUL。候选长 43 字节，输入、变换结果及密文长度均为 43，没有截断或缓冲区边界问题。
4. **实机复核。** 复核原 ZIP 的唯一成员 `checker.exe` 与提取文件 SHA-256 均为 `449D9F4569A0ED70FCB9BC8B96737719B62CFD8AE7C1E99D2864A3999887FDF5`。将同一候选直接管道给这份提取文件，输出 `Correct! You have the flag.`。因此目前证据排除了 checker 本地端的输入格式、编码与长度问题；它不能证明玄机服务端采用相同附件或相同 flag。

本轮没有尝试大小写变形、去掉 `flag{}` 或猜测其他格式，也没有再次向平台提交。唯一可由附件证明的本地答案仍是前述候选。平台拒绝与本地成功相互矛盾，单凭本地二进制无法判断是题面附件与平台校验值不同、平台题目版本不同，还是别的服务端数据问题；需要对照平台当前下载附件哈希和题目后台校验数据才能定因。

## 可复现命令

在 PowerShell 中从 `题目资料\checker_562` 目录执行：

```powershell
python .\analysis\solve_checker_from_pe.py .\附件_20260929\checker.exe
$flag = 'flag{enp17I4p8TZmAriao2lq5tAArZ2P1wxBUwXU2}'
$flag | & '.\附件_20260929\checker.exe'
```

如需从原始 ZIP 本身复核成员哈希，完整 PowerShell 操作已保存在终端记录；ZIP 列出的唯一成员为 `checker.exe`，大小 42,857 字节，成员 SHA-256 与附件相同。

## 为什么还不能记为“平台已完成”

本地证据闭环支持该候选是这份二进制的正确输入：附件哈希可复核、密文位置由 PE 节表和比较调用确认、XOR 结果符合格式、往返还原匹配、原程序打印 `Correct!`。但此前 Xuanji #562 页面拒绝过这一候选。本复核没有再次向平台提交，也没有把本地成功误写成平台成功。

本次已复核当前玄机 #562 详情页和平台下载附件：页面仍为免费、中等、0/1，平台 ZIP 与唯一 checker.exe 成员的 SHA-256 均和本地分析对象一致。由此排除“当前页面下载了另一版附件”这一解释。此前候选被拒绝的具体原因仍需平台提交回执、当时实际输入内容或后端判分数据才能确认；此轮未再次提交，也不把本地成功记录为平台完成。

## 附件与分析记录清单

- 原始附件：`../checker_platform_20260929.zip`
- 解压附件：`../附件_20260929/checker.exe`
- 旧脚本（硬编码 XOR 字节）：`../solve_checker.py`
- 新脚本（直接解析 PE，便于从附件复现）：`solve_checker_from_pe.py`
- 完整反汇编：`checker_disassembly.txt`
- ASCII 字符串：`checker_strings_ascii.txt`
- 初始命令、哈希、解密输出和本地运行记录：`checker_audit_terminal_20260929.txt`
- 本轮独立复核 transcript（附件哈希、相关反汇编、长度边界、原附件执行结果）：`checker_562_reaudit_transcript_20260929.txt`

## 当前平台页与附件复核（2026-09-29）

本次在已登录的玄机平台前台打开 #562 详情页（https://xj.edisec.net/challenges/562）并重新下载附件。页面当前显示：免费、中等难度、完成进度 0/1。没有在本次核对中提交 flag。

平台重新下载的原始压缩包已保存至：

    ../originals/checker_platform_download_20260929_051349.zip

核验结果：

- ZIP 大小：17,498 字节
- ZIP SHA-256：598E457DCDFFCB89F4A1B5CF56133E1D8A194E737B8C25C6C0EA722854426D36
- ZIP 唯一成员：checker.exe，42,857 字节
- 成员 SHA-256：449D9F4569A0ED70FCB9BC8B96737719B62CFD8AE7C1E99D2864A3999887FDF5
- 成员哈希与项目附件和之前逆向所用文件完全一致；平台当前下载 ZIP 哈希也与原项目 ZIP 完全一致。

平台前台下载、压缩包/成员哈希命令与输出见[根批次 PowerShell transcript](../../../../../记录/批次记录/综合协调/原始分件/批次_20260929_继续协调.txt)。在该 transcript 中搜索“当前玄机 #562 平台附件哈希与 ZIP 成员”可定位对应过程。页面状态与批次摘要另见[第二/选题与核对记录](../../../../../记录/批次记录/第02批/原始分件/批次_20260929_第二批选题与核对.md)。本次独立复核与成员重算记录见[附件证据 transcript](agent_checker562_platform_attachment_evidence_20260929.txt)。

这项证据确认了当前 #562 页面提供的附件与本地候选分析对象相同，故“当前平台页附件版本与本地附件不同”不能解释现有矛盾。由于页面仍显示 0/1、没有保存此前拒绝时的原始页面回执，平台拒绝的剩余具体原因尚不能由附件哈希推断。当前状态应记录为：本地 checker 已验证候选；平台进度仍 0/1；未完成平台验证。

## 平台拒绝原因独立复核（2026-09-29）

本轮没有访问玄机网站或接口，也没有运行附件可执行文件；仅静态读取项目副本。使用 analysis\checker_rejection_audit_static.py 对项目内四份附件 ZIP 逐一核对，完整 ZIP 字节流全部相同（SHA-256 598E457DCDFFCB89F4A1B5CF56133E1D8A194E737B8C25C6C0EA722854426D36），ZIP 唯一成员 checker.exe 也全部相同（42,857 字节，SHA-256 449D9F4569A0ED70FCB9BC8B96737719B62CFD8AE7C1E99D2864A3999887FDF5）。成员与解压副本逐字节一致。

独立 PE 静态解析再次将比较目标 VA 0x00404020 定位到 .data 偏移 0x3220，固定 XOR 0x23 得到同一 43 字符候选；往返异或与嵌入密文逐字节相同。没有发现第二个候选或附件版本差异。

已有前台操作文字记录称，2026-09-27 在 /challenges/562 提交了上述完整候选，AX 回报“FLAG 不正确”且进度为 0/1。该拒绝记录没有提交时截图或输入框快照，故本轮无法独立核对当时字段最终内容。现存证据只能说明本地 PE 接受此字符串、此前平台记录拒绝该字符串；不能推断具体后端原因。本题继续标记为本地附件已逆出，平台未验证，不计入完成题目，也不猜测或提交变体。

复现脚本与完整命令/输出见 analysis\checker_rejection_audit_static.py 和 analysis/checker_rejection_audit_transcript_20260929.txt；本轮未更改原始附件。
