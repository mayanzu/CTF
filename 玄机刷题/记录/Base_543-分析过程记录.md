# 玄机平台 #543「你知道Base么」续攻分析记录

记录时间：2026-09-28（Asia/Shanghai）
当前结论：附件静态解码得到一个完整 flag 候选，但该值此前已被平台拒绝；本轮没有提交新的 flag，也没有把模拟比较器结果写成平台通过。

## 题目材料与取证范围

本次只检查 #543 附件和已经保存的本地分析资料，不访问网页 writeup。题目目录为 `题目资料/Base_543/`，原附件文件为 `你知道Base么/你知道Base么.exe`，已有离线解题器为 `solve_base_offline.py`。该目录最初只有 EXE 和解题器；本轮另加了 `verify_prefix_compare.py`，用于严格复现比较器的前缀等价关系。

对 `D:\Downloads` 中两份 `你知道Base么-20250521104202-am92t17*.rar` 计算 SHA256，二者大小均为 14603 字节，哈希均为 `3FEC5E1930230660DCABDF0F31F4D97F8BB980D67306242D48A4377B74590801`。本地 EXE 的 SHA256 为 `EF7DEACF6594E9353E934564B38761E8AAF614EBF39DCB17EFED36263DF2C773`。既有 `代理-base-终端记录.txt` 也记录了平台重新下载附件的哈希与本地 RAR 一致。现有证据不支持“本机附件和平台下载附件不同”的解释。

## 1. 查看 EXE 元数据与可见字符串

使用 `objdump -x` 检查 EXE，识别为 x86-64 PE。时间戳为 2025-05-02 20:56:54，ImageBase 为 `0x140000000`。Debug Directory 中的 CodeView 记录指向 `D:\1\x64\Debug\1.pdb`，PDB age 为 3；本机 `D:\1` 不存在，在题目目录和 `D:\Downloads` 也没有找到 `.pdb`、C/C++ 源文件、Visual Studio 工程文件。

检查窄字符字符串得到程序交互提示：

- `Where is my Base_Table???`
- `Plz input your found Table:`
- `Plz input Your flag:`

PE 版本资源字段为空；可见字符串里没有明文 flag 或帮助文本。调试符号只暴露了原构建路径，没有找到能追溯 flag 原文或生成脚本的附加数据。

## 2. 从 XTEA 常量恢复第一层输入

离线解题器记录的 XTEA 参数如下：

- Delta：`0x9e3779b9`，迭代 32 轮。
- Key words：`0x12345678, 0x3456789a, 0x89abcdef, 0x12345678`。
- 目标 words：`0xa92f3865, 0x9e60e953`。

按标准逆序撤销 XTEA 的 32 轮运算，得到输入 words `0x6f753079, 0x6165546b`。按照程序使用的 little-endian 字节序拼接，得到 8 字节 `79 30 75 6f 6b 54 65 61`，ASCII 为 `y0uokTea`。将它重新送入 XTEA 加密后，结果精确回到两个目标 words，说明逆运算方向和字节序一致。

## 3. 恢复 64 字节 Base_Table

程序将上一步得到的 8 字节作为循环密钥，执行 RC4 风格的 KSA，再执行 PRGA 生成 64 字节密钥流。对 EXE 中的 64 字节目标表逐字节减去密钥流，模 256，得到：

```text
gVxwoFhPyT/YM0BKcHe4b8GCUZtlnLW2SJO51IErk+q6vzpamdARX9siND3uQfj7
```

恢复出的表长 64 字节，全部是可打印 ASCII 且没有重复字符。将其逐字节加回同一密钥流可精确重建 EXE 中的目标表，解密/加密两方向均通过断言。

程序使用的 32 字符 Base32 字母表是恢复表的 `raw_table[1:33]`：

```text
VxwoFhPyT/YM0BKcHe4b8GCUZtlnLW2S
```

脚本检查其长度为 32 且字符互异。

## 4. 解码完整静态目标

EXE 中的编码目标为 48 个字符：

```text
0tCPwtnncFZyYUlSK/4Cw0/echcG2lteBWnG2Ulw0htCYTMW
```

使用上述自定义 Base32 字母表建立反向映射，每 8 个符号组合成 40 bit，再拆成 5 字节；6 组一共恢复 30 字节：

```text
flag{y0u__rea11y__k1ow__Base!}
```

把这 30 字节按同一规则重新编码，结果与 48 字符目标完全一致。该候选有完整静态常量和双向变换作为依据。此前根线程已将它提交到 #543，玄机页面返回 flag 错误且进度仍为 0/1。因此本手册将它记作“完整附件逆解候选、平台未通过”，不记为已解决。

## 5. 确认程序比较器只检查 30 个编码符号

本轮核对的控制流为 `0x14001756f -> 0x1400113a2 -> 0x140012400`。在 `0x140012400` 开始的比较循环中：

- `0x140012435` 将循环下标与 `0x1e` 比较；达到 30 就退出。
- `0x140012459` 比较两个字节，遇到不同值即进入失败分支。
- 循环范围是下标 0 到 29，所以成功分支只证明前 30 个 Base32 符号一致。

每个 Base32 符号携带 5 bit，30 个符号总共覆盖 150 bit。150 bit 等于 18 个完整字节（144 bit）加上第 19 个字节的高 6 bit。比较器本身没有检查该字节剩余的 2 bit，也没有检查后续字节。因此“通过本地前缀比较”不能证明输入是完整 flag。

## 6. 可复现的比较前缀等价类实验

运行 `题目资料/Base_543/verify_prefix_compare.py`。脚本从正式逆解器导入目标、字母表和编码函数，枚举第 19 字节中高 6 bit 与目标相同的可打印字符，再将其余部分替换成 `A` 并保留右花括号。输出中这四个完整字符串的前 30 个编码字符都相同，但完整 48 字符编码都不同：

```text
flag{y0u__rea11y__hAAAAAAAAAA}  first30_equal=True  full48_equal=False
flag{y0u__rea11y__iAAAAAAAAAA}  first30_equal=True  full48_equal=False
flag{y0u__rea11y__jAAAAAAAAAA}  first30_equal=True  full48_equal=False
flag{y0u__rea11y__kAAAAAAAAAA}  first30_equal=True  full48_equal=False
```

这四个值只是按已恢复编码规则对“前 30 符号比较器”做的本地模拟样例，用于证明比较器存在多解；它们不是平台 flag，也没有提交平台。此实验不尝试扩大候选集合或猜测完整 flag。

## 7. 本地运行限制与结论边界

为验证原 EXE，临时复制了相邻题目工作区的 `ucrtbased.dll` 和 `VCRUNTIME140D.dll` 到 `tmp`，将恢复出的 64 字符表和完整候选作为两行输入运行。原 EXE 在初始化阶段退出，PowerShell 记录 `native_exit=-1073741511`（`0xC0000139`，入口点不存在）。这些 DLL 是另一题目使用的 shim，接口与本 EXE 所需的 MSVC 调试 CRT 不兼容。因此该尝试没有产生程序的成功/失败提示，不构成原 EXE 的运行验证；原命令、DLL 哈希和退出码均保存在终端记录中。

目前可确认：附件静态数据完整支持上述 30 字节解码；本地目标比较代码只验证前 30 个 Base32 符号；平台拒绝过完整解码候选；本轮没有找到原始 PDB、源码、字典、额外提示或数据生成脚本，也没有新的平台侧证据解释拒绝原因。#543 仍未通过平台验证，状态保持未解决。

## 记录文件

- 全部命令和输出：`记录/续攻-Base-终端记录.txt`
- 正式离线解码器：`题目资料/Base_543/solve_base_offline.py`
- 比较前缀多解模拟：`题目资料/Base_543/verify_prefix_compare.py`
- 先前分析记录：`记录/代理-base-终端记录.txt`