# CatchPalu（玄机题目 #545）静态逆向 WP

## 结论

静态分析得到题目比较器要求的候选 flag：

```text
flag{PcdrJzml9i7nr2HEC}
```

结论来自可复现的两部分证据：程序把用户输入与 PE `.data` 中 `0x404078` 处的 NUL 结尾字符串逐字节比较；该字符串正是上面的 flag。独立复现脚本还验证了输入格式、比较器反汇编地址，以及隐藏在消息框 hook 中的另一段加密文本。没有运行附件，也没有向平台提交候选，因此这是静态分析候选，尚未获得平台接受回执。

## 文件与证据

- 原始附件：`originals/CatchPalu_flag.zip`，6506 字节，SHA-256 `1273957e92a1fee2b711c48af4ac47dee305233d6425a635a9e7f3dab8ef2c4b`。
- ZIP 只含 `CatchPalu_flag.exe`，解压大小 11776 字节，CRC32 `464771f1`。`analysis/archive_check.py` 读 ZIP 数据并比对解压副本，结果为 `MATCHES_EXTRACTED_EXE=True`。
- 解压附件：`extracted/CatchPalu_flag.exe`，SHA-256 `6cbeb646b6d7c26dda1b0abe17b7918f46eb930b4d8b05f3f9f589a54de2053f`。
- 关键复现材料：`analysis/inspect_pe.py`、`analysis/pe_static_report.txt`、`analysis/disassembly.txt`、`analysis/data_dump.txt`、`analysis/solve_static.py`、`analysis/solve_static_output.txt`、`analysis/archive_check.py`、`analysis/archive_check_output.txt`、`analysis/input_path_branch_target.txt`。
- PowerShell 命令及输出按执行顺序追加记录在 `analysis/commands_output.log`。日志保留了初次 Unicode 绝对路径传给 MinGW `objdump` 失败、切换到附件目录后用相对路径成功，以及脚本第一次误把 KSA 的 `j` 在每轮重置、修正后得到正确静态输出的过程。

## 1. 识别附件类型

首先检查 ZIP 与解压文件大小及 SHA-256，并用只读 ZIP 检查确认压缩包内的 EXE 与已有解压件逐字节相同。`MZ` 和 `PE\0\0` 签名均存在，PE 头的关键字段如下：

- Machine `0x014c`：32 位 x86。
- Optional Header Magic `0x010b`：PE32。
- `e_lfanew = 0xf0`。
- ImageBase `0x400000`，入口 RVA `0x1a2b`。
- 5 个 section：`.text`、`.rdata`、`.data`、`.rsrc`、`.reloc`。

导入表包含 `VirtualProtect`、`LoadLibraryA`、`MessageBoxA/W` 等 API，以及 CRT 的输入输出函数。`analysis/inspect_pe.py` 只打开并解析字节，不加载或执行 EXE。之后使用 GNU `objdump -d -M intel` 静态反汇编，完整结果写入 `analysis/disassembly.txt`。

复现命令（均在题目目录执行；本批所有实际 PowerShell 命令和输出见 transcript）：

```powershell
python .\analysis\archive_check.py
python .\analysis\inspect_pe.py .\extracted\CatchPalu_flag.exe
Push-Location .\extracted
& 'C:\msys64\mingw64\bin\objdump.exe' -d -M intel .\CatchPalu_flag.exe | Tee-Object -FilePath ..\analysis\disassembly.txt
Pop-Location
python .\analysis\solve_static.py
```

## 2. 从程序主流程定位输入检查

启动/运行库代码最终在 `0x40199e` 调用题目主逻辑 `0x401560`。主逻辑先保存 `MessageBoxA` 的原始 IAT 地址到全局变量 `0x404468`，打印欢迎文本，并安装/准备消息框 hook；随后进入控制台输入检查路径。

与输入和验证有关的静态指令链：

1. 分支流有重叠指令：`0x40171a` 的 JE 和 `0x40171c` 的 JNE 都跳到 `0x40171f`；此位置位于线性反汇编把 `0x40171e` 当作 E9 长跳转时的位移区中。若按入口线性阅读，会误以为程序跳走。以实际分支目标 `0x40171f` 重新反汇编（结果保存为 `analysis/input_path_branch_target.txt`）可见它是 `push 0x4040ac`，接着调用输出包装函数显示 `Enter your flag:`，再进入输入流程。这样确认了后续 scanf 和比较确实在这个可达路径上。`analysis/disassembly.txt` 保留全段线性结果。`0x401732` 把格式字符串 `0x4040a4`（数据内容 `%25s`）传给 CRT 扫描函数，并把栈上缓冲区 `ebp-0x20` 作为输入目标。旁边的 `0x1a` 是安全扫描函数所需的缓冲区大小参数。
2. `0x401743` 以 `0x404090`（`You entered: %s\n`）输出刚读入的字符串。
3. `0x401750` 将 `0x404078` 写为预期字符串指针。
4. 比较循环从 `0x40175d` 读取用户输入；`0x401768` 执行 `cmp al, BYTE PTR [ecx]`，逐字节与 `0x404078` 指向的内容比较。后续指令一次检查两个字节，并在遇到 NUL 后结束；任一位置不同便走不匹配分支。
5. 相等分支在 `0x4017ae` 起调用 `MessageBoxA`；不等分支跳过该提示并返回。消息框的静态文本是 `Correct?` 与 `NoSuccess?`，措辞虽然古怪，但判断依据是前面的字节比较。

这是决定 flag 的关键：比较器使用的目标地址直接指向 `.data` 中的完整明文，而不是由前述 hook 解密结果生成。

## 3. 提取实际比较目标

PE `.data` 的 Virtual Address 从 `0x404000` 起，Raw Pointer 为 `0x2800`。因此 VA `0x404078` 映射到文件偏移 `0x2878`。`.data` dump 与 `analysis/solve_static_output.txt` 中解析结果一致：

```text
地址       内容
0x404060   Correct?\0
0x40406c   NoSuccess?\0
0x404078   flag{PcdrJzml9i7nr2HEC}\0
0x404090   You entered: %s\n\0
0x4040a4   %25s\0
0x4040ac   Enter your flag: \0
0x404108   forpalu\0
```

候选的原始十六进制为：

```text
66 6c 61 67 7b 50 63 64 72 4a 7a 6d 6c 39 69 37 6e 72 32 48 45 43 7d
```

共 23 个可见 ASCII 字节，末尾紧跟 NUL。它符合 `flag{...}` 格式，也能完整装入 `%25s` 的输入上限。比较循环逐字节检查到终止符，故不应附加空格、换行或其他字符。

## 4. 复核 hook 中的加密干扰数据

程序还包含一个消息框 hook（`0x401360`）。它接收 `MessageBoxA` 的四个参数，构造 25 字节数据，使用 `.data` 中 `0x404108` 的 7 字节 key `forpalu` 对数据进行流变换，再调用之前保存的原始 `MessageBoxA`。这一段容易把解密文本误认成 flag，因此单独复现并与输入比较目标区分。

### 4.1 静态还原密文

在 `0x4013bf` 起连续 25 条 `mov BYTE PTR [...], imm8` 指令写入密文：

```text
0d b0 bf 0a 8d 2f 02 38 6f 19 ae 99 19 c7 6e f7 4f cb 90 4e 55 8e d1 10 c0
```

调用点 `0x4014fa` 调用 `0x401100`，参数为 256 字节状态表、key 地址及 key 长度。接着 `0x401517` 调用 `0x401270`，对刚才的 25 字节数据做 XOR keystream 变换。

### 4.2 KSA（0x401100）

反汇编可见：

1. 将状态表 `S` 初始化为 `S[i] = i`，`i=0..255`。
2. key 临时区按 `key[i mod 7]` 重复填充。
3. 外层循环执行 3 轮；内部 `i=0..255`。
4. `j` 在整段 KSA 开始时清零一次，并跨三轮保留。每一步按 `j = (S[i] + j + key[i mod 7]) mod 233` 更新，再交换 `S[i]` 与 `S[j]`。常数 `0xe9`（233）来自 `idiv` 指令。

注意 `j` 不是每轮重置。脚本首次按标准 RC4 的轮次习惯重置了它，断言失败；查看外层循环的栈变量后确认 `j` 只在进入 KSA 时置零，修正后得到与程序静态指令一致的结果。失败和修正过程都保留在命令日志中。

### 4.3 PRGA（0x401270）

对每个密文字节执行：

```text
i = (i + 1) & 0xff
j = (j + S[i]) & 0xff
swap(S[i], S[j])
t = (S[i] + S[j]) & 0xff
plain[k] = cipher[k] XOR S[t]
```

由此复现出的 keystream 与明文为：

```text
keystream:
7d d1 d3 7f f6 68 32 08 0b 46 fe a8 78 b2 31 bc 21 fb e7 11 1d be e1 5b bd

decoded bytes:
70 61 6c 75 7b 47 30 30 64 5f 50 31 61 75 5f 4b 6e 30 77 5f 48 30 30 4b 7d

decoded text:
palu{G00d_P1au_Kn0w_H00K}
```

这段内容是 hook 内部处理的文本。它与 `0x404078` 的比较目标不同，开头也不是本题比较器要求的 `flag{`；调用链中没有把这段解密结果传给输入比较器。因此不以它作为提交候选。纯静态复现脚本会断言该解密结果等于此文本，并断言它与 `.data` 中的 flag 不相同。

## 5. 复现结果与最终候选

在项目目录运行：

```powershell
python .\analysis\solve_static.py
```

脚本只读取 PE 文件和 `disassembly.txt`，解析密文字节、key 与 `.data` 常量，按上述 KSA/PRGA 逐步计算，并检查比较器的反汇编引用。关键输出：

```text
PE_SHA256=6cbeb646b6d7c26dda1b0abe17b7918f46eb930b4d8b05f3f9f589a54de2053f
KEY=forpalu (7 bytes)
DECODED_TEXT=palu{G00d_P1au_Kn0w_H00K}
FLAG_FILE_OFFSET=0x2878
FLAG_LITERAL=flag{PcdrJzml9i7nr2HEC}
COMPARE_ASSEMBLY_EVIDENCE=PASS (input at 0x401732, echo at 0x401743, expected pointer at 0x401750, byte compare at 0x401768)
COMPARATOR_SIMULATION=PASS (exact match true; one-byte mutation and trailing byte false)
DECRYPTED_TEXT_MATCH=True
DECRYPTED_TEXT_IS_FLAG=False
FORMAT_CHECK=PASS (flag{...}; exact comparator target)
```

因此本地静态分析所得候选为：

```text
flag{PcdrJzml9i7nr2HEC}
```

候选由二进制比较常量和比较指令共同支持；本记录没有运行 EXE，也没有进行平台提交或验证。


