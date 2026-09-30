# 湘岚杯 maybesignin（玄机 #540）完整解题记录

> **状态：本地解题成功，玄机平台未提交验证。** 原始 `ezsignin.exe` 接收候选 `flag{wlascJDAFS}` 时输出 `success` 并以退出码 0 返回。根据本批任务约定，没有在玄机页面提交。

## 1. 题目信息与材料

- 平台题目：玄机 #540「湘岚杯maybesignin」
- 类型 / 难度 / 费用：REVERSE / 中等 / 免费
- 当前页面状态：任务开始时为 `0/1`；本次仅做本地验证，未改变平台状态。
- 附件包：`附件\MaybeSignin_platform_20260929.zip`
- 附件包 SHA-256：`79D0749B152E8A886AF6911CAEF49730CCC29067D66BF30739B89D2EAE13F8A2`
- 解包文件：`附件解包\ezsignin.exe`
- EXE SHA-256：`DA87C9A85AB1E99370891AEBC6494A97B4AA1BB6694AF415DC455D68F5E18AE5`
- 完整 PowerShell 命令和输出：`analysis\maybesignin_540_transcript_20260929.txt`
- SM4 解题脚本及可复查输出：`analysis\solve_maybesignin_540.py`、`analysis\solve_maybesignin_540_output.txt`
- 原始 EXE 回放验证脚本及输出：`analysis\verify_maybesignin_540.py`、`analysis\verify_maybesignin_540_output.txt`
- 静态分析材料：`analysis\disassembly_full.txt`、`analysis\objdump_headers_imports.txt`、`analysis\strings_ascii_offsets.txt`、`analysis\objdump_sections.txt`

附件是 Windows x64 PE32+ console 程序。它没有可用符号；提示字符串显示 `plz input your flag:`，并包含 `success`。反汇编由 GNU `objdump` 产生。

## 2. 先定位输入、验证和成功分支

程序主校验路径位于虚拟地址 `0x140001560` 附近：

1. 输出提示字符串 `plz input your flag:`（RVA `0x3270`）。
2. 通过格式串 `%s`（RVA `0x3288`）读入字符串。主函数先将 16 字节输入缓冲区清零。
3. 调用变换函数 `0x1400010e0`，传入固定 16 字节 key、本地输入缓冲区和输出缓冲区。按 Windows x64 调用约定，主函数在调用前设置 `RDX=key`、`R8=input`、`R9=output`；没有重新设置 `RCX`。
4. 将变换结果与主函数栈上常量逐字节比较。循环从 0 计数到 `0x10`，即只比较 16 字节。
5. 全部相同则打印 `success`；不同时调用 `ExitProcess(0xdeadbeef)`。

需要单独澄清 `RCX`：变换函数入口没有保存或读取该寄存器。函数先执行序言，随后在 `0x140001112` 明确把 `ECX` 覆盖为 `0x32`，用作 `malloc(0x32)` 的大小；同时将 `R9/R8/RDX` 保存到 `R14/R13/RBX`。因此函数等价于 `transform(key, input, output)`，不存在根据 `RCX` 选择加密/解密的 mode 参数。输入包装函数的返回值遵循 ABI 放在 `RAX`，不能把未设置的 `RCX` 当作 `scanf` 返回值。

成功提示是静态字符串，因此仅靠字符串提取不能得到 flag。需要从变换函数反推出输入。

## 3. 识别加密算法

变换函数对一个 16 字节 block 做 32 轮处理。静态数据和轮函数对应 SM4：

- S-box：RVA `0x32a0`，文件偏移 `0x1aa0`，长度 256 字节。提取后与标准 SM4 S-box 完全一致。
- FK：RVA `0x33a0`，文件偏移 `0x1ba0`，内存字节为 `c6bab1a35033aa5697917d67dc2270b2`。按小端 word 解释分别为标准 FK：`a3b1bac6 56aa3350 677d9197 b27022dc`。
- CK：RVA `0x33b0`，文件偏移 `0x1bb0`，每个 32-bit 常量以小端存放；例如内存首 4 字节 `15 0e 07 00` 解释为 `0x00070e15`。序列与 SM4 的 CK 常量吻合。

反汇编的 key schedule 先逐字节把输入 key 组为 4 个大端 word，再与 FK 异或；每一轮按下式生成下一个扩展 key：

```text
K[i+4] = K[i] XOR T'(K[i+1] XOR K[i+2] XOR K[i+3] XOR CK[i])
T'(x)  = tau(x) XOR ROL13(tau(x)) XOR ROL23(tau(x))
```

其中 `tau` 是逐字节查 SM4 S-box。之后输入 block 被组为 4 个大端 word，执行 32 轮：

```text
X[i+4] = X[i] XOR T(X[i+1] XOR X[i+2] XOR X[i+3] XOR rk[i])
T(x)   = tau(x) XOR ROL2(x) XOR ROL10(x) XOR ROL18(x) XOR ROL24(x)
```

结果按 `X[35], X[34], X[33], X[32]` 逆 word 顺序写出。这与标准 SM4 block 加密结构一致。脚本先通过公开标准测试向量自检，再用于解密附件常量。

## 4. 恢复目标密文和固定 key

主函数在 `0x14000157f` 至 `0x14000158c` 通过四条 `mov dword ptr` 指令初始化 key 所在的连续 16 字节。必须注意这些立即数是**十六进制整数**，内存又按小端写入：

| 指令立即数 | 小端内存字节 |
|---|---|
| `0x04030201` | `01 02 03 04` |
| `0x08070605` | `05 06 07 08` |
| `0x12111009` | `09 10 11 12` |
| `0x16151413` | `13 14 15 16` |

所以真实 key 的十六进制字节是：

```text
01020304050607080910111213141516
```

**本次实际发生的误读：**最初曾把 key 猜成连续字节 `01 02 ... 0f 10`（十六进制），而没有逐条按 DWORD 立即数的小端内存布局读取。用错误 key 解密得到候选字节 `8d8ed47a1eddc5c9a2875e2ada595746`；原 EXE 拒绝该候选，进程退出码为 `3735928559`（`0xdeadbeef`），stdout 只有提示而没有 `success`。因此这一支被实测否定。逐条修正为立即数实际的小端内存字节后，才得到下述正常 flag。错误推导、候选和失败输出保留在 transcript 与 `analysis\verify_maybesignin_540_output.txt` 中。

校验目标位于 `0x1400015b4` 起的四条指令立即数字节中。按栈内存顺序读取其前 16 字节：

```text
1c84be5145ce1af31fa3f75e3a38d0be
```

后续另有 16 字节常量初始化，但比较循环上限是 `0x10`，因此它们没有参与本题成功比较。

## 5. 解密并得到 flag

将目标 block 作为 SM4 密文，使用固定 key 逆向 32 轮。完整可复现实现位于 `analysis\solve_maybesignin_540.py`。脚本输出如下：

```text
key bytes (from main local buffer) = 01020304050607080910111213141516
target bytes (first 16 compared)  = 1c84be5145ce1af31fa3f75e3a38d0be
SM4 known vector                  = OK
decrypted plaintext hex           = 666c61677b776c6173634a444146537d
decrypted plaintext repr          = b'flag{wlascJDAFS}'
SM4 re-encrypt                    = 1c84be5145ce1af31fa3f75e3a38d0be
round-trip                        = True
```

候选 flag：

```text
flag{wlascJDAFS}
```

明文长度为 16 字节，和程序处理的 block 长度、实际比较长度一致。

## 6. 原始附件本地验证

为了确认推导结果符合程序本身，而不是只有 Python 逆运算自洽，将候选和换行符送入未修改的原始附件程序 `附件解包\ezsignin.exe`。复现脚本 `analysis\verify_maybesignin_540.py` 顺序重放错误 key 和正确 flag 两种输入；完整命令与输出在 `analysis\maybesignin_540_transcript_20260929.txt`、`analysis\verify_maybesignin_540_output.txt`。原 EXE 的 SHA-256 为 `DA87C9A85AB1E99370891AEBC6494A97B4AA1BB6694AF415DC455D68F5E18AE5`，与附件解包文件一致。正确候选的关键输出：

```text
case: correct little-endian immediate decoding
candidate bytes hex: 666c61677b776c6173634a444146537d
stdin bytes repr: b'flag{wlascJDAFS}\n'
exit code: 0
stdout repr: b'Press any key to continue . . . \r\nplz input your flag:\r\nsuccess'
stderr repr: b''
```

原始 EXE 输出 `success` 且退出码为 0，说明候选通过本地校验。这个结果不是玄机平台提交回执；平台 flag 尚未提交。

## 7. 复现命令

在项目根目录 `C:\Users\mzj\Desktop\CTF\玄机刷题` 的 PowerShell 中执行 SM4 解题和原 EXE 本地验证：

```powershell
py -3 "C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\Maybesignin_540\analysis\solve_maybesignin_540.py"
py -3 "C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\Maybesignin_540\analysis\verify_maybesignin_540.py"
```

纯 Python 实现包含 SM4 的 S-box、FK/CK、轮密钥扩展、加密和解密；不依赖第三方密码学包。解题脚本包含已知测试向量及重新加密闭环断言。验证脚本直接运行原始附件，分别显示错误候选被拒和正确候选得到 `success`。

## 8. 过程和资料清单

- `附件\MaybeSignin_platform_20260929.zip`：原始附件包。
- `附件解包\ezsignin.exe`：未修改的题目程序。
- `analysis\maybesignin_540_transcript_20260929.txt`：PowerShell 命令和完整输出，包括 MSYS `objdump` 首次无法处理中文路径、初始 key 误读、纠正和最终验证过程。
- `analysis\solve_maybesignin_540.py`：纯 Python SM4 解题脚本。
- `analysis\solve_maybesignin_540_output.txt`：脚本成功输出。
- `analysis\verify_maybesignin_540.py`：针对未修改原 EXE 重放旧错误候选与正确 flag 的验证脚本。
- `analysis\verify_maybesignin_540_output.txt`：上述两次原 EXE 执行的输入、退出码、stdout/stderr；旧候选以 `0xdeadbeef` 失败，正确候选显示 `success`。
- `analysis\disassembly_full.txt`：完整反汇编。
- `analysis\objdump_headers_imports.txt`：PE 头、导入和节区信息。
- `analysis\strings_ascii_offsets.txt`：ASCII 字符串及文件偏移。
- `analysis\objdump_sections.txt`：节区信息。

**最终状态：**`flag{wlascJDAFS}` 已通过题目原始 EXE 的本地验证；玄机平台未提交，平台侧仍需单独验证后才能登记为平台已完成。
