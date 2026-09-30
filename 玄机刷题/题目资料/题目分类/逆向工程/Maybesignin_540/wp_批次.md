# 湘岚杯 maybesignin（玄机 ID 540）

## 题目信息与结果

- 平台题目页：<https://xj.edisec.net/challenges/540>
- 分类/难度：REVERSE / 中等；下载时页面为免费、0/1。
- 附件：`附件/MaybeSignin_platform_20260929.zip`，内含 `ezsignin.exe`。
- 当前状态：已解决。候选 `flag{wlascJDAFS}` 经本地两种实现复核；根代理通过玄机前台页面提交后，平台显示 1/1 完成。
- 本文只把本地分析、复核和平台状态分开记录；附件 PE 未运行，也没有用脚本与平台交互。

## 附件识别与完整性

先核对压缩包 SHA-256：

```text
79D0749B152E8A886AF6911CAEF49730CCC29067D66BF30739B89D2EAE13F8A2
```

`tar.exe -tf` 确认归档只有一个成员 `ezsignin.exe`。解压到 `analysis/unpacked/` 后得到 12,800 字节的 PE32+ x86-64 控制台程序，SHA-256 为：

```text
DA87C9A85AB1E99370891AEBC6494A97B4AA1BB6694AF415DC455D68F5E18AE5
```

原始 ZIP 保存在 `originals/`。本次只静态分析 PE 头、字符串、常量和反汇编，没有启动该可执行文件。

## 分析过程

### 1. 先从字符串和 PE 结构确定程序行为

ASCII 字符串中能看到：

```text
plz input your flag:
success
pause
```

PE 导入包含 CRT 的格式化输入输出、`malloc`/`free` 和 `system`，但没有外部密码学 DLL。PE 是 Visual Studio x64 控制台构建。字符串本身没有泄露明文 flag，因此继续查看比较函数和数据区。

### 2. 还原检查流程和目标密文

检查函数从 `0x140001560` 开始。它在 `0x14000158F` 附近调用打印函数，参数指向 `0x140003270` 的提示字符串；随后在 `0x1400015F5` 调用输入函数，格式串位于 `0x140003288`，内容是 `%s`。输入放入栈上的缓冲区。

函数在 `0x1400015B4` 到 `0x1400015E9` 写入一组常数，前四个 dword 按 x86-64 小端序在内存中的字节为：

| 指令中的 dword | 内存字节 |
|---|---|
| `0x51BE841C` | `1C 84 BE 51` |
| `0xF31ACE45` | `45 CE 1A F3` |
| `0x5EF7A31F` | `1F A3 F7 5E` |
| `0xBED0383A` | `3A 38 D0 BE` |

因此比较所用的首个 16 字节目标块是：

```text
1C84BE5145CE1AF31FA3F75E3A38D0BE
```

虽然后面还有四个 dword 常量，循环在 `0x140001620` 至 `0x140001632` 明确只检查 16 个字节（`cmp al, 0x10`）。成功分支打印 `success`，之后调用 `system("pause")`；不匹配则退出。题目要解的是一个 16 字节块的明文。

### 3. 识别为标准 SM4

反汇编中的变换函数位于 `0x1400010E0`。它先按大端序将 16 字节 key 组成四个 32 位字，再进行 32 轮展开与数据变换。继续查看 `.rdata` 可确认：

- RVA `0x32A0` 是标准 256 字节 SM4 S-box，首 16 字节为 `D6 90 E9 FE CC E1 3D B7 16 B6 14 C2 28 FB 2C 05`。
- RVA `0x33A0` 的字节对应标准 SM4 FK（以 32 位大端字解释）：`A3B1BAC6 56AA3350 677D9197 B27022DC`。
- RVA `0x33B0` 起的序列是标准 SM4 CK。
- 汇编中 key schedule 的线性层使用 `rol 13` 与 `rol 23`；数据轮使用 SM4 的 `rol 2/10/18/24` 线性层。

据此可将程序的 16 字节变换还原为标准 SM4 单块变换。比较的是 ECB 单块输出；题目没有再套一层编码或填充。

### 4. 精确抄出 key（容易弄错的步骤）

函数将以下四个立即数写入相邻的栈位置：

```asm
mov dword ptr [rbp-0x9],  0x04030201
mov dword ptr [rbp-0x5],  0x08070605
mov dword ptr [rbp-0x1],  0x12111009
mov dword ptr [rbp+0x3],  0x16151413
```

由于小端存储，逐 dword 展开后 key 字节是：

```text
01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16
```

这里的 `10` 至 `16` 是十六进制字节值，不是十进制十至十六。最终 key hex：

```text
01020304050607080910111213141516
```

### 5. 解密并本地复核

以标准 SM4 逆序 round keys 解密目标首块，得到：

```text
目标密文：1C84BE5145CE1AF31FA3F75E3A38D0BE
明文 hex：666C61677B776C6173634A444146537D
明文 ASCII：flag{wlascJDAFS}
```

`analysis/solve_sm4.py` 从 PE `.rdata` 读取 S-box，按标准 FK/CK 和轮函数实现 SM4；将候选正向加密回去，结果逐字节等于目标块。随后又用 OpenSSL 3.5.2 的 SM4-ECB 独立解密同一密文，得到相同 16 字节明文：

```text
666C61677B776C6173634A444146537D
flag{wlascJDAFS}
```

两种本地验证分别记录在 `analysis/command_transcript_20260929.txt`。复现脚本读取已解压的样本数据，不会执行 `ezsignin.exe`。

### 6. 首次误读与纠正

第一次把注释式字节序列 `01 02 ... 16` 误当成连续的十六进制数 `01 02 ... 0F 10 11 ... 16`，也就是错误地把 key 设成 `0102030405060708090A0B0C0D0E0F10111213141516`。解出的数据不可打印。尽管错误 key 的 Python 实现仍能自洽地重加密回目标，这只能证明程序内部实现前后一致，不能证明 key 抄对了。

随后回到四个 `mov dword` 立即数，按小端序逐项还原成实际内存字节。修正后的 key 仅为 16 字节 `01020304050607080910111213141516`；解密得到规范 flag 格式的 16 字节 ASCII，并通过 OpenSSL 独立复核。错误候选已明确保留在 transcript，未提交平台。

## 最终 flag 与平台验证

```text
flag{wlascJDAFS}
```

根代理在玄机页面进行前台提交，平台返回该题已完成 `1/1`。这是平台验收状态；它与本地 SM4 重加密及 OpenSSL 解密结果相互独立。

## 文件索引

- 原始附件副本：`附件/MaybeSignin_platform_20260929.zip`
- 解压样本：`附件解包/ezsignin.exe`（仅静态读取）
- PE 结构：`analysis/pe_headers_full.txt`
- 反汇编：`analysis/disasm_140001000_140001800.txt`
- 常量区：`analysis/rdata_3260_3480.txt`
- 字符串：`analysis/strings_ascii.txt`、`analysis/strings_wide.txt`
- Python 复核：`analysis/solve_sm4.py`
- OpenSSL 输入/输出：`analysis/cipher_block.bin`、`analysis/openssl_plaintext.bin`
- 命令和输出记录：`analysis/command_transcript_20260929.txt`
