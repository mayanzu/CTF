# 玄机 #541：ezBase-20250521104055-dq14shk 完整 WP

## 当前结论

本题本地附件的静态校验链得到候选：

```text
flag{Y0u_@R3_Upx_4nd_b45364_m4st3r!}
```

候选共 36 个 ASCII 字节，满足程序主函数要求的 `strlen(input) == 0x24`，从程序的比较目标和自定义 Base64 字母表逆向得到。把候选按程序算法正向编码，48 字节输出与运行时比较目标逐字节一致。

玄机页面当前为 `0/1`。本次只做本地静态复核，没有向平台提交，也没有重新运行平台提供的 EXE。该候选已由原始附件哈希、已有解包内存映像、反汇编输入门槛和正向往返计算共同确认；平台是否接受尚未验证。

## 1. 从平台原始 RAR 确认样本

本次复核使用刚下载的原包：

```text
附件_平台原件\ezBase_platform_20260929.rar
SHA-256 0A7420F1D2D832474AD09EA55825900AF75EBA30DEA46DFB63F9A1AD17F0AF18
```

Windows 自带 `tar.exe` 能列出和解开该 RAR5 文件。包内只有 `ezBase/ezre.exe`，大小 9,216 字节。解压副本 SHA-256 为：

```text
607BD3E8E5D7E715F7A9B819C8D5CC235C8DCC22F06A4AE77D0383E46BBDDACE
```

该值与项目里旧副本 `ezBase/ezre.exe` 及 `runshim\ezre.exe` 完全一致。因此本轮确认了旧分析使用的 PE 样本与新下载的平台原包相同。

原始 PE 为 64 位 UPX 打包程序。节表中 `upx0` 的 RVA 为 `0x1000`、虚拟大小 `0xb000`、无磁盘原始节数据；`upx1` 从 RVA `0xc000` 开始，磁盘原始数据位于 `0x200`。压缩文件的原始字符串区在 `...M5` 与 `C~I4...` 之间可见 `1F 92 FF FF` 等压缩流字节；这些不能直接当成解包后的比较串。

项目留存的 `unpacked_runtime.bin` 是旧调试转储程序从进程映像 `base+0x1000` 读取的 `0xb000` 字节内存区。转储程序源码 `debug_dump.c` 记录了该读取范围。该映像中可见已解包程序的目标串、字母表、输入逻辑和函数代码。其 SHA-256 为 `16A11C873808BB3FDB2EA94C134FC3EA1E9E26624FD837E803AA112D23C12C80`。本次没有重新运行 EXE；静态复核使用项目现存的内存转储，并单独从平台原包重新解包、核对 PE 样本哈希。旧转储没有内嵌原始样本哈希字段，因此它的来源关系依赖项目中既有调试记录和文件布局，不能把转储 SHA 当作原始 EXE 的哈希。

## 2. 从入口还原输入规则

`分析产物\2026-09-27\_ezdisasm_all.txt` 的解包代码以映像地址 `0x140001000` 为入口。关键指令显示：

1. 在 `0x140001040` 调用输入函数，第二个参数为 `0x80`，也就是最多读入 127 字节并以 NUL 结尾。
2. 在 `0x14000106a` 调用 `strcspn(input, "\n")`，随后在换行位置写入 NUL。
3. 在 `0x140001089` 将输入长度与 `0x24` 比较。只有长度正好为 36 的输入才继续编码；其他长度跳到长度错误提示。
4. 在 `0x1400010c1` 调用编码函数 `0x140001130`，将编码结果放入临时输出缓冲区。
5. 在 `0x1400010d2` 调用 `strcmp` 导入跳板 `0x140003990`，比较该缓冲区和 `0x140004000` 处的目标串。相同则走成功分支，提示 `Yes you are right`；不同则提示 `Wrong! Try again!`。长度不等于 36 时，提示 `Length wrong. Must be 36`。

因此，候选必须保留 `flag{}` 的全部字符，且总长度必须正好是 36。输入末尾的终端换行会被程序移除；它不属于候选。

## 3. 还原程序的编码函数

程序在 `0x140001130` 实现 Base64 编码：

1. 每次读取最多 3 个输入字节，按标准 Base64 方式拆成 6 位索引。
2. 索引不是映射到标准表，而是映射到 `0x140004040` 的自定义 64 字节表：

   ```text
   AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789+/
   ```

3. 生成编码串之后，再逐字节 XOR `0x04`；唯一例外是实际 Base64 填充字符 `=` 不做 XOR。

主函数要求输入长度为 36，36 能被 3 整除，所以正确候选的 Base64 编码没有填充字符。目标串最后的 `=` 并不是 Base64 填充；它是自定义编码字符 `9` 经 `XOR 0x04` 后得到的字节。逆向时目标串所有 48 字节都应 XOR `0x04`。

## 4. 从运行时比较目标逆向 flag

`unpacked_runtime.bin` 是从 `0x140001000` 开始的内存映像片段，因此：

- VA `0x140004000` 对应转储偏移 `0x3000`，是 48 字节比较目标：

  ```text
  iP}ui7siC`otMgA~h5o]Tg<4jPmtIvM5C~I4h644K7M~KVg=
  ```

- VA `0x140004040` 对应转储偏移 `0x3040`，是 64 字节自定义 Base64 字母表。

先对目标串逐字节 XOR `0x04`：

```text
mTyqm3wmGdkpIcEzl1kYPc80nTipMrI1GzM0l200O3IzORc9
```

然后按自定义字母表的索引位置，把每个字符替换为标准 Base64 字母表中相同索引的字符：

```text
ZmxhZ3tZMHVfQFIzX1VweF80bmRfYjQ1MzY0X200c3QzciF9
```

用标准 Base64 解码，得到：

```text
flag{Y0u_@R3_Upx_4nd_b45364_m4st3r!}
```

解码结果为 36 字节，符合入口处的长度检查。

## 5. 正向往返验证

把解出的候选按程序流程重新编码：

```text
候选长度：             36
标准 Base64：           ZmxhZ3tZMHVfQFIzX1VweF80bmRfYjQ1MzY0X200c3QzciF9
自定义字母表编码：      mTyqm3wmGdkpIcEzl1kYPc80nTipMrI1GzM0l200O3IzORc9
逐字节 XOR 0x04：       iP}ui7siC`otMgA~h5o]Tg<4jPmtIvM5C~I4h644K7M~KVg=
目标串完全相同：        True
```

复现脚本从保存的运行时内存映像中读取目标串和字母表，而不是把结果字符串写死在脚本中：`analysis\derive_flag_from_memory_dump.py`。脚本只使用 Python 标准库，会检查目标长度、字母表、输入长度和正向往返结果。

## 6. 旧候选文件为什么有一个必然失败

本题目录中保存了两个旧候选文本：

- `candidate_35byte_prefix.txt`：内容为 `flag{Y0u_@R3_Upx_4nd_b45364_m4st3r!`，不含最后的 `}`，有效输入长 35 字节。主函数要求长度恰好为 `0x24`（36），所以这个截断版本会在长度分支被拒绝，甚至到不了编码和比较步骤。
- `candidate_36byte_flag.txt`：内容为 `flag{Y0u_@R3_Upx_4nd_b45364_m4st3r!}`，有效输入长 36 字节；文件末尾另有一个换行，程序会移除换行。它与本轮从目标串逆出的候选一致。

旧记录没有保存当时究竟提交了哪个文件的内容或提交页面截图，因此可以确定 35 字节截断版失败的具体原因，但不能断言平台先前拒绝的就是它。如果提交的是完整 36 字节版本，本地样本的静态逻辑支持该输入；仅凭本地附件无法解释平台拒绝，可能需要核对页面当时对应的题目版本、输入内容和平台服务端校验数据。

## 7. 本轮状态与限制

- 玄机题目：#541 `轩辕杯云盾砺剑CTF挑战赛 ezBase-20250521104055-dq14shk`
- 平台状态：`0/1`，本轮没有提交。
- 候选状态：由原包样本身份、入口约束、运行时目标和正向编码一致性静态确认；平台尚未验证。
- 本轮没有查公开 Writeup，也没有运行下载的 EXE 或安装工具。
- 旧 UPX 自制解码器 `decode_upx.py` 曾在输出仅 65 字节时因错误回引用 `off=705 > outlen=65` 退出；这份部分输出不能作为完整解包结果。本轮使用已保存的运行时内存转储，并把其读取依据和样本哈希一并记录。

## 8. 可复现命令和材料索引

## 9. 2026-09-30 平台复验

在登录的玄机账号 `slu_mzj` 下打开 `https://xj.edisec.net/challenges/541`，页面仍为 `0/1`。通过页面“提交FLAG”输入并提交本 WP 从运行时比较目标正向复算的完整 36 字节候选：

```text
flag{Y0u_@R3_Upx_4nd_b45364_m4st3r!}
```

提交弹窗关闭后，详情页仍显示 `0/1`，没有出现成功回执；因此本题继续标记未完成。这里记录的是平台验证结果，不能把本地程序的正向复算等同于平台接受。页面操作与观察见 `记录/未解题续攻_20260930.md`。

在 PowerShell 中从 `题目资料\ezBase_541` 目录执行：

```powershell
Get-FileHash -Algorithm SHA256 .\附件_平台原件\ezBase_platform_20260929.rar
tar.exe -xf .\附件_平台原件\ezBase_platform_20260929.rar -C .\附件_平台原件\解压复核_20260929
Get-FileHash -Algorithm SHA256 .\附件_平台原件\解压复核_20260929\ezBase\ezre.exe
python .\analysis\derive_flag_from_memory_dump.py
```

独立 transcript 保存本轮命令和实际输出：`analysis\ezbase541_reaudit_transcript_20260929.txt`。

主要材料：

- 平台原始包：`附件_平台原件\ezBase_platform_20260929.rar`
- 从原始包提取的样本：`附件_平台原件\解压复核_20260929\ezBase\ezre.exe`
- 历史 UPX 解包内存映像：`unpacked_runtime.bin`
- 入口和全部反汇编：`分析产物\2026-09-27\_ezdisasm_all.txt`
- 入口附近反汇编副本：`分析产物\2026-09-27\_ezcode_oep.txt`
- 自制 UPX 解码器及其旧失败结果：`decode_upx.py`、`分析产物\2026-09-27\_ezdecode_output.txt`
- 本轮从内存映像重建目标并正向核验的脚本：`analysis\derive_flag_from_memory_dump.py`
- 上述脚本的逐项输出副本：`analysis\derive_flag_from_memory_dump_output.txt`
- 本轮完整命令和输出：`analysis\ezbase541_reaudit_transcript_20260929.txt`
