# PaluArray（玄机 ID 546）独立静态审计

## 审计结论

独立审计发现，现有 `wp.md`、`solve_paluarray.py` 和 `solve_paluarray_546_static.py` 使用的字符表起点错了：它们把 RVA `0x5e66` 解作 UTF-16 字符串 `gPalu_996!?`，但该位置的 `g\0` 实际是前一条 ASCII 错误消息 `string too long\0` 的结尾。程序的静态初始化代码把 RVA `0x5e68` 传给字符表全局对象；验证器随后查询该全局对象。因此程序实际使用的表是 **`Palu_996!?`**，没有 `g`。

按真实字符表还原并正向重算后：

```text
candidate input: aa_9a_a?a?!aP
MD5 (ASCII):     1b501325fc96d5a845cbdd2ba4f01cd7
constructed flag: palu{1b501325fc96d5a845cbdd2ba4f01cd7}
```

旧候选 `PPu_PuP!P!6Pg` 不满足程序的实际索引校验：`g` 不在真实表中，`find('g')` 返回 `-1`；其正向编码结果是 `003403080870-1`，与目标串不符。旧报告中的 MD5 `c530...` 是对错误输入求出的摘要，不能作为本题候选 flag。

没有运行、加载或调用任何挑战 EXE，没有联网查 Writeup，也没有提交平台。以下是对附件、已有的静态解包副本和代码字节的独立只读审计。

## 1. 绑定原附件与分析文件

- 原 ZIP 内只有 `PaluArray_flag.exe`，大小 89,088 字节。
- ZIP 内文件与 `extracted/PaluArray_flag.exe` 字节完全相同。
- 原 EXE SHA-256：`CD8E2BE79AAA454F295132B7ECE6AE30D0CC05FF24DA7541639F05F76D482A4D`。
- 静态解包副本 `analysis/PaluArray_flag_unpacked_repro.exe` SHA-256：`8B1263DE36EDA3E5E3F1183C2D08C520ECAE09649B1A04891F597033FDF842A5`。
- 已有标记恢复副本与原件相比，仅在 `0x208`、`0x230`、`0x3E0` 三处各改变 4 字节：`PALU` → `UPX0`、`UPX1`、`UPX!`。原文件未被改写。

独立解析解包副本 PE 节表后确认：ImageBase `0x140000000`，`.rdata` RVA `0x5000` 对应 raw offset `0x4200`，故本报告使用的 RVA→文件偏移关系为：

```text
file_offset = 0x4200 + (RVA - 0x5000)
```

本节、下述 RVA 和反汇编都可由 `analysis/independent_audit_546.py` 与 `analysis/independent_audit_output.txt` 复核。

## 2. 重新判定字符表起点

关键原始字节：

```text
RVA 0x5e58 起的 ASCII：string too long\0
RVA 0x5e66..0x5e67：     67 00      # 上述 ASCII 文本最后的 'g' 与 NUL
RVA 0x5e68 起的 UTF-16LE：50 00 61 00 6c 00 75 00 5f 00 39 00 39 00 36 00 21 00 3f 00 00 00
                            P     a     l     u     _     9     9     6     !     ?
```

如果从 `0x5e66` 强行按 UTF-16LE 解码，前两个字节 `67 00` 会看起来像字符 `g`，后面再接上 `0x5e68` 的真表，于是得到误导性的 `gPalu_996!?`。但这两个字节本属于 ASCII 字符串 `string too long\0`，不能作为另一个宽字符串首字符。

代码交叉引用进一步确定了实际起点：

- RVA `0x1040`：`lea rdx, [rip + 0x4e21]`；下一指令地址是 `0x1047`，故 `RDX = 0x5e68`。
- RVA `0x1047`：`lea rcx, [rip + 0x8afa]`；下一指令地址是 `0x104e`，故 `RCX = 0x9b48`，即字符表全局对象。
- RVA `0x104e` 调用 IAT RVA `0x5428`（静态导入解析为 `mfc140u.dll!ordinal_286`），把 `0x5e68` 的字符串交给 `0x9b48` 对象初始化。
- 验证函数 RVA `0x1994` 的循环在 RVA `0x19ee` 再次把 `0x9b48` 放入 `RCX`，对当前字符执行查找。

所以这里真正用于查找的字符表是从 `0x5e68` 开始的 UTF-16 字符串：

```text
Palu_996!?
```

字符到索引如下；重复字符 `9` 的首次匹配索引为 5：

| 索引 | 字符 | 索引 | 字符 |
|---:|:---:|---:|:---:|
| 0 | `P` | 5 | `9` |
| 1 | `a` | 6 | `9` |
| 2 | `l` | 7 | `6` |
| 3 | `u` | 8 | `!` |
| 4 | `_` | 9 | `?` |

## 3. 目标串与验证循环

目标串位于 RVA `0x5ea0`，按 UTF-16LE 解码为 `1145141919810`，长度 13。验证函数的静态指令流如下：

1. 用 `EBX` 作为当前输入字符索引，循环读取原输入中的宽字符。
2. `movzx edx, ax` 取得当前字符；`xor r8d, r8d` 将查找起始位置设为 0；`RCX` 指向 RVA `0x9b48` 的字符表全局对象。
3. RVA `0x19f5` 调用 MFC 字符串查找函数（静态 IAT 名称为 `mfc140u.dll!ordinal_4510`），返回首次匹配位置。
4. 如果返回值为 `-1`，分支跳过索引追加；否则把索引交给输出串构造逻辑。
5. 主校验流程在 RVA `0x1e54` 直接引用目标串 RVA `0x5ea0`，比较构造结果；相等进入 `Success` 分支，不等进入 `Failed` 分支。

按实际表反查目标各位，得到：

| 位次 | 目标数字 | 表索引 | 输入字符 | `find` 首次结果 |
|---:|---:|---:|:---:|---:|
| 0 | 1 | 1 | `a` | 1 |
| 1 | 1 | 1 | `a` | 1 |
| 2 | 4 | 4 | `_` | 4 |
| 3 | 5 | 5 | `9` | 5 |
| 4 | 1 | 1 | `a` | 1 |
| 5 | 4 | 4 | `_` | 4 |
| 6 | 1 | 1 | `a` | 1 |
| 7 | 9 | 9 | `?` | 9 |
| 8 | 1 | 1 | `a` | 1 |
| 9 | 9 | 9 | `?` | 9 |
| 10 | 8 | 8 | `!` | 8 |
| 11 | 1 | 1 | `a` | 1 |
| 12 | 0 | 0 | `P` | 0 |

拼接得到唯一的直接反查输入：

```text
aa_9a_a?a?!aP
```

独立脚本逐字符重新执行首个匹配查找，编码结果是 `1145141919810`，与二进制常量完全相同。候选中没有表外字符，重复字符 `9` 也正好使用首次索引 5。

### 对旧候选的反证

旧候选 `PPu_PuP!P!6Pg` 是从错误的 `gPalu_996!?` 表反查出的。用程序实际表 `Palu_996!?` 正向编码时：

```text
P P u _ P u P ! P ! 6 P g
0 0 3 4 0 3 0 8 0 8 7 0 -1
```

末尾 `g` 的查找失败，且前面的索引也与目标不符。因此旧候选不会通过这段输入校验。

## 4. 独立核对 MD5 与实际包装

主流程在验证索引串相等后，取**原输入文本**进入后续成功路径；它没有把索引目标串送入摘要函数。RVA `0x1f6c` 调用 `WideCharToMultiByte`，传入 CodePage `3`（`CP_THREAD_ACP`）；对于此候选所含的 ASCII 字符，窄字节值与 ASCII 编码相同。随后 RVA `0x1ec5` 调用摘要函数 RVA `0x1a48`。

从解包 EXE 重新反汇编摘要路径可见：

- RVA `0x1a48` 初始化 MD5 状态为标准四个初值：`0x67452301`、`0xefcdab89`、`0x98badcfe`、`0x10325476`；随后传入输入数据长度/字节并进入块更新与填充路径。
- 该函数调用 RVA `0x2d70` 生成摘要文本。
- RVA `0x2eca` 引用小写十六进制表 `0123456789abcdef`；后续循环迭代 16 个摘要字节，分别取高、低 4 位，因此写出 32 个小写十六进制字符。

用 Python 标准库独立计算：

```text
MD5(ASCII("aa_9a_a?a?!aP")) = 1b501325fc96d5a845cbdd2ba4f01cd7
```

程序包装字符串也经代码引用确认，不是从 flag 前缀猜测：

- 后缀 `}` 在 RVA `0x5e8c`；摘要/包装函数 RVA `0x1b24` 直接引用它。
- 前缀 `palu{` 在 RVA `0x5e90`；同一函数 RVA `0x1b6d` 与 `0x1b84` 引用它并将其与摘要字符串合并。
- 拼接辅助函数 RVA `0x14d8` 的参数是两个字符串对象；其指令先取两串长度、分配合并长度并依次复制。调用点 RVA `0x1c2e` 把已形成的 `palu{` + 摘要串作为第一部分、`}` 作为第二部分传入。
- 最终字符串经 `MessageBoxW` 显示，窗口标题取自 RVA `0x5e80` 的 `flag`。

因此程序构造的内容为 `palu{<MD5(input)>}`，候选 flag 是：

```text
palu{1b501325fc96d5a845cbdd2ba4f01cd7}
```

## 5. 可复核材料

- `analysis/independent_audit_546.py`：独立 ZIP/PE 静态提取、RVA 映射、实际字符表反查、正向验证和 MD5 计算。
- `analysis/independent_audit_output.txt`：上述脚本的完整输出。
- `analysis/independent_global_xrefs.py`、`analysis/independent_global_xrefs_output.txt`：字符表全局对象和初始化/验证代码的静态交叉引用。
- `analysis/independent_wrapper_disasm.py`、`analysis/independent_wrapper_disasm_output.txt`：前缀、摘要、后缀字符串拼接路径的静态反汇编。
- `analysis/independent_audit_commands_output.log`：所有独立审计 PowerShell 命令、输出及被修正的脚本错误记录。

审计中有一次脚本尝试从 `0x5e66` 解 UTF-16，随后发现该处与 ASCII 错误字符串重叠；最终结论改用代码初始化参数 `0x5e68` 与验证器使用的同一个全局对象 `0x9b48` 交叉确认。该失败尝试及修正均如实保存在独立命令日志中。

## 状态

静态审计确认的候选输入为 `aa_9a_a?a?!aP`，由程序静态构造的 flag 为 `palu{1b501325fc96d5a845cbdd2ba4f01cd7}`。没有运行附件或平台验证；这只是从静态代码路径及独立摘要计算得出的本地候选。
