# #558「R.exe」独立静态审计

- 日期：2026-09-29（本地时区 Asia/Shanghai）
- 审计方式：PE 静态检查、反汇编、对照可复现 Python 模型。
- 安全边界：未运行 `R.exe`，未向玄机平台提交 flag，未查阅公开 writeup；没有安装或下载工具。
- 本记录只描述独立审计结论。完整命令与工具原始输出见同目录 `independent_reverse_558_transcript_20260929.txt`，复现代码见 `independent_reverse_558.py`。

## 附件与完整性

| 文件 | SHA-256 |
| --- | --- |
| 题目附件 ZIP | `CD7967ECD4DA09A57F544E14C28CEAF016272D8B7EC095B949D141D096C408DB` |
| `attachment/R.exe` | `E2B0CA7ED72159F82649C33F373E3B38C0E9C9283AA1DAEC627018A328F08651` |

上述值与主审计提供的附件哈希一致；独立 PowerShell `Get-FileHash` 输出保存在 transcript。

## 工具

本次使用现有 Windows PowerShell、Python 3.12.10、MSYS2 `objdump.exe` 和 `strings.exe`。没有安装新工具。GNU 工具不能直接处理含中文目录路径，所以为静态读取复制了一份临时 ASCII 路径副本；分析完成后尝试删除该副本，但本地命令执行策略拒绝删除操作，所以临时副本 `C:\Users\mzj\Desktop\CTF\R558_audit_temp.exe` 暂时留在工作区根目录。其 SHA-256 与原附件一致，未执行。

## PE 与可见字符串

- `R.exe` 为 x86-64 PE32+ Windows 控制台程序；ImageBase `0x140000000`，入口 VA `0x14001ea70`。
- 主要节区：`.text` RVA `0x1000`（RX），`.rdata` RVA `0x21000`（R），`.data` RVA `0x2d000`（RW），`.pdata` RVA `0x2e000`，`.reloc` RVA `0x30000`。
- 导入中可见调试器检测及控制台 I/O API；未见显式网络或密码学库导入。程序以静态 Rust 运行时形式链接。
- ASCII 字符串位于文件偏移 `0x20aa8`、`0x20ad0`、`0x20af0`：`input your flag:\n`、`wrong...\n`、`right!!!\n`。RVA 到 VA 映射后分别为 `0x140021ca8`、`0x140021cd0`、`0x140021cf0`。

## 校验链定位

主检查函数位于约 `0x1400040e0–0x14000440f`。它打印输入提示，创建长度为 8 的 key 向量，创建长度为 19 的目标字节向量，调用加密闭包处理用户输入，再比较两段字节；相等时走 `right!!!` 分支，否则走 `wrong...` 分支。

### Key 的预处理（容易漏掉）

在 `0x1400041cd–0x1400041ec` 硬编码的原始 key 为 ASCII `lntfvpus`。随后对 8 个元素逐个做 `key[i] ^= i`：

- 循环索引在 `0x14000429b` 取得；索引访问取出 `key[i]`。
- `0x1400043ff`: 读取元素地址。
- `0x140004403`: 读取当前索引 `i`。
- `0x140004406`: `xor cl, BYTE PTR [rax]`，即 `i XOR key[i]`。
- `0x140004408`: 将结果写回 `key[i]`。

因此传入 KSA 的 key 是 `loverust`。若直接使用原始 `lntfvpus`，能构造出自洽但不可读的逆向结果；那不是 flag。

### 256 字节状态向量和 KSA

在 `0x140003cba–0x140003d1a` 创建 `0..=255` 的 inclusive range，并收集到状态向量 S。调用链中 RangeInclusive 的结束值为 `0xff`；集合 size hint 计算 `end-start+1=256`，Vec 预留 256 个元素并逐项收集。因此 S 的逻辑长度为 256，初始内容依次为 `0x00..0xff`。

KSA 的循环按 S 中的 256 个迭代元素执行。反汇编显示：

1. 通过 `i % key_len` 选取 key 字节（`0x140003e19–0x140003e34`）。
2. 对 key 字节执行 `XOR 0x66`（`0x140003e34`）。
3. `j = (j + S[i] + (key[i % 8] XOR 0x66)) mod 256`。
4. 交换 `S[i]` 与 `S[j]`。

KSA 完成后，PRGA 闭包上下文持有相同 S Vec 的地址（`0x140003dd1–0x140003dea`），所以 PRGA 从 KSA 结束时的状态继续运行，没有重新初始化 S。

### PRGA 与输出字节变换

PRGA 的 `i`、`j` 字段分别在 `0x140003d80`、`0x140003d86` 清零。每次调用闭包时：

1. `i = (i + 1) mod 256`。
2. `j = (j + S[i]) mod 256`。
3. 交换 `S[i]` 与 `S[j]`。
4. 查 `K = S[(S[i] + S[j]) mod 256]`。
5. 对 K 做 4-bit nibble swap：`N = ((K << 4) | (K >> 4)) mod 256`。
6. `mask = (N + 1) mod 256`，返回字节 `out = ((input XOR mask) + 1) mod 256`。

以上顺序对应闭包 `0x140003f40–0x1400040c7`：状态更新在 `0x3f4f–0x400e`，取表字节后 nibble swap / 加一 / XOR / 再加一在 `0x40ac–0x40c1`。相邻的寄存器和栈内存取值均见 transcript 原始反汇编。

### 内置目标

主函数将以下 19 字节写入目标向量（`0x1400042dc–0x140004340`）：

```text
18 59 07 28 f4 ad c8 c3 b6 3f 2d 39 ca 34 d1 8e f5 03 b0
```

比较函数检查长度一致并逐字节相等；匹配结果进入输出 `right!!!` 的成功分支。

## 逆向与可复现验证

从输出关系

```text
out = ((input XOR mask) + 1) mod 256
```

逐字节反解：

```text
input = ((out - 1) mod 256) XOR mask
```

脚本 `independent_reverse_558.py` 按上述静态逻辑构造 KSA/PRGA，反解目标，再用独立重建的初始状态重新正向加密候选。脚本输出：

```text
key literal ASCII: lntfvpus
key after byte[i] ^= i: loverust
KSA byte formula: key[i % 8] ^ 0x66
target length: 19
candidate hex: 666c61677b386131633261373363323962327d
candidate repr: b'flag{8a1c2a73c29b2}'
candidate ASCII: flag{8a1c2a73c29b2}
starts flag{: True
forward hex: 18590728f4adc8c3b63f2d39ca34d18ef503b0
full target match: True
```

### 结论和验证状态

静态逆向候选为 `flag{8a1c2a73c29b2}`。19 个输出字节逐一正向复算，与程序硬编码目标完全相同，因此候选具有高置信度。未运行未知的 `R.exe`，也未在玄机平台提交；平台是否接受仍未验证。

## 复现文件

- 完整 PowerShell transcript：`analysis/independent_reverse_558_transcript_20260929.txt`
- 纯 Python 复现：`analysis/independent_reverse_558.py`
- 本独立审计：`analysis/independent_static_audit_20260929.md`

