# 湘岚杯 ezbase（玄机 ID 537）WP

## 结论与验证状态

附件静态逆向与前台平台提交均已完成。玄机平台返回 `FLAG 正确`，本题显示 `已完成 1/1`，并获一血。最终 flag：

```text
flag{2qOrxQfRmDEdSkGt2mFoyilZQFU4BQDxBsuc}
```

候选由附件验证逻辑唯一逆变换得到，并通过本地正向重编码与二进制中 56 字节比较目标完全相等；随后 root 在玄机前台提交并观察到接受结果。分析**没有运行未知 EXE**，也没有连接靶机。平台核验摘要见本目录 `平台核验.md`；没有本地导出的截图文件。

## 附件与分析边界

- 题目附件：`originals\ezbase.zip`，30016 bytes，SHA256 `24E646D8337FE6284DDAACEFB05D3ACEAFA01EAE746CF1CBB872046F3A9EBECB`。
- ZIP 内唯一成员：`ezbase.exe`，40719 bytes。解压副本在 `analysis\ezbase.exe`，SHA256 `AEE861E105AFD0DDA6DDBACD27865FAFDC91E2FA225105920DB88DB38A30CAA0`。
- 识别为 PE32 / i386 / Windows CUI，MinGW C++ 构建。分析只使用 PE 头解析、静态字符串、objdump 和 UPX 静态解包，不执行样本。
- 所有命令和工具输出逐次保存在 `analysis\537_static_analysis_transcript.txt`；反汇编/节表/符号/字符串的完整导出也保存在 `analysis`。

## 1. 识别壳并静态解包

### 1.1 PE 与打包线索

文件头以 `MZ` 开始，`objdump -x` 识别为 `pei-i386`、PE32、ImageBase `0x00400000`。原始节名为 `PXU0`、`PXU1`、`UXP2`，字符串中有 `UPX!`，入口点为 `0x0041d430`。入口反汇编呈现 UPX NRV 风格的位流解压过程：源数据从 `0x417015` 读取，目标缓冲起自 `0x401000`，解压/导入修复结束后跳至原程序入口 `0x4012d0`。

### 1.2 第一次解包失败及定位

直接对原件执行 UPX `-t` 与 `-d` 均返回：

```text
CantUnpackException: file is modified/hacked/protected; take care!!!
```

这是一个失败假设：起初只知道附件是 UPX 变体，尚未知道失败原因。静态 PE 解析显示各节名是反写/扰动形式 `PXU0/PXU1/UXP2`。只在分析副本 `ezbase_names_restored.exe` 中把三处节名恢复为 `UPX0/UPX1/UPX2`，原附件和 `analysis\ezbase.exe` 保持不变。副本 SHA256 为 `980511BD89790CB490E1E833D2452130C27725C250D121C459F8D80D88C6E516`。此后 UPX `-l` 正确报告 `82703 -> 40719`，`-t` 返回 `[OK]`，`-d` 成功生成解包副本。

- 解包后的静态文件：`analysis\ezbase_unpacked.exe`，82703 bytes。
- SHA256：`C1A01D1D1C1AA849DA7EDACC239853A4CF9FB3E846C6D6D9915EF460DD95913F`。
- 修复脚本：`analysis\restore_upx_section_names.py`。

注意：这里的 UPX `-t` 是文件完整性测试，`-d` 是静态解压；没有启动目标程序。

## 2. 从主函数恢复校验流程

在解包文件的完整反汇编 `analysis\ezbase_unpacked_disassembly_full.txt` 中，`_main` 位于 `0x4015d7`，Base64 编码函数位于 `0x401410`。有关逻辑如下：

1. 用格式串 `%42s` 读取输入（`0x4016c2`、`0x4016ca`）；`strlen` 必须等于 `0x2a`，即 42 字节，否则打印失败信息并退出（`0x4016dd`–`0x4016f8`）。
2. 对 42 个输入字节逐一执行 `XOR 0x10`（`0x401705`–`0x40173c`）。
3. 调用自定义 Base64 编码器 `base64_encode`（`0x401789`）。查表地址 `0x406060`，实际 64 字节字母表为：

   ```text
   Fvm/RkQucZNVyYABpS2w6enjdtGPO8UalxrbD45Ci07MT9KLEJo1h3zHgfX+WqsI
   ```

   该表恰有 64 个互不重复的字节。不能用标准 Base64 字母表替代。
4. 编码结果第 `0x0c` 与第 `0x12` 个字节互换（分别在 `0x401792`–`0x40179a` 和 `0x40179e`–`0x4017b7`）。
5. 将结果与栈上构造的比较串做 `memcmp`。14 条 `mov [esp+offset], imm32` 指令按小端序拼出 56 字节目标；终止 NUL 位于偏移 `0x76`。比较相等走成功分支 `0x4017e1`，不等则走失败分支 `0x4017ef`。

因此验证关系为：

```text
T = Swap( CustomBase64( P XOR 0x10 ), indexes 12 and 18 )
```

其中 `P` 是 42 字节输入，`T` 是栈上 56 字节目标。

## 3. 反向计算候选

### 3.1 比较目标

由主函数十四条立即数存储按小端序还原出的片段依次为：

```text
8CJJ | 8zTr | deqr | 3Rkz | pCG6 | ejS/ | U38D | cC3n
az4f | aR0v | eD6D | 6Dk6 | GkZb | tjY9
```

拼接得到长度 56 的目标：

```text
8CJJ8zTrdeqr3RkzpCG6ejS/U38DcC3naz4faR0veD6D6Dk6GkZbtjY9
```

### 3.2 撤销末尾交换并按自定义字母表解码

先交换目标串的索引 12 与 18，撤销程序编码后的置换，得到：

```text
8CJJ8zTrdeqrGRkzpC36ejS/U38DcC3naz4faR0veD6D6Dk6GkZbtjY9
```

使用自定义表建立 `字符 -> 6-bit 值` 映射，逐四字符解码为 42 字节。解码后、撤销 XOR 前的十六进制为：

```text
767c71776b22615f62684176427d545574437b5764227d567f69797c4a4156452452415468526365736d
```

每个字节再 XOR `0x10`，得到：

```text
666c61677b32714f72785166526d444564536b4774326d466f79696c5a5146553442514478427375637d
```

按 ASCII 解码即：

```text
flag{2qOrxQfRmDEdSkGt2mFoyilZQFU4BQDxBsuc}
```

## 4. 独立正向复核

可复现脚本 `analysis\solve_537_from_static.py` 从解包副本重新读取 PE 节表、提取 `0x406060` 处恰好 64 字节的字母表，并从 `_main` 的 14 条立即数存储自动重建比较目标。脚本执行以下验证：

1. 逆向自定义 Base64；
2. XOR `0x10` 得到候选；
3. 将候选逐字节 XOR `0x10` 后重新编码；
4. 再交换编码结果索引 12 与 18；
5. 与自动提取的 56 字节目标逐字节比较。

输出关键行：

```text
target_encoded=8CJJ8zTrdeqr3RkzpCG6ejS/U38DcC3naz4faR0veD6D6Dk6GkZbtjY9 length=56
plaintext_ascii=flag{2qOrxQfRmDEdSkGt2mFoyilZQFU4BQDxBsuc}
forward_reencode_match=True
```

脚本用 `assert` 强制检查字母表长度及唯一性、目标立即数数量、相邻提示区内容与最终正向重编码相等；断言通过才输出候选。

## 5. 失败假设与修正记录

- **直接 UPX 解包：失败。** 原件节名被改动导致 UPX 拒绝识别；恢复分析副本的节名后，`upx -t` 与解包成功。原件未更改。
- **把字母表当成 NUL 结尾字符串：失败。** 第一版脚本从 `0x406060` 扫描到 NUL，误把紧邻的提示字符串也算入，得到 76 字节并触发 `len==64` 断言。主函数的索引只在 `0..63`，且主函数提示串使用地址 `0x4060a0`，恰比表首 `0x406060` 高 `0x40`；所以应按固定 64 字节截取。修正后断言通过。
- **把提示文案起点理解为 `Find me!`：修正。** 表后字节实际从 `You Find me!` 开始，提示串地址正好指向这个 `You ` 前缀。该文案不参与编码；此观察只用来核验数组边界。
- **没有进行包装格式、标准 Base64 或其他 flag 包装猜测。** 算法与目标串一致，正向复核严格相等，所以候选有直接静态证据。

## 6. 命令复现与项目文件

完整逐条命令及终端输出见 `analysis\537_static_analysis_transcript.txt`。其中也如实记录了以上失败和修正。主要命令类别：

```text
Get-FileHash / Format-Hex / ZIP 成员列表
strings -a -n 3
objdump -h / objdump -x / objdump -d -Mintel
python restore_upx_section_names.py
upx -l / upx -t / upx -d
python solve_537_from_static.py
```

完整证据文件：

- `analysis\ezbase_unpacked_headers_symbols_full.txt`
- `analysis\ezbase_unpacked_disassembly_full.txt`
- `analysis\ezbase_unpacked_strings_full.txt`
- `analysis\537_base64_main_disassembly.txt`
- `analysis\restore_upx_section_names.py`
- `analysis\solve_537_from_static.py`
- `analysis\537_static_analysis_transcript.txt`

平台核验结果：root 在玄机前台提交上述候选，页面显示 `FLAG 正确`、`已完成 1/1`，并显示一血。该结果由 root 的前台页面观察确认；本题目录没有截图副本，因此本文不声称保存了截图。

