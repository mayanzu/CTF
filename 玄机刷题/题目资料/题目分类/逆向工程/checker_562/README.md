# 玄机 ID 562：第一届启航杯checker

本目录保存该题附件、静态逆向证据、复现材料、平台拒绝后的重新核验结果，以及按执行顺序记录的 PowerShell 命令和终端输出。

## 当前状态：未解决

主代理通过玄机前台提交了由本地附件反算的候选，页面原文返回“FLAG 不正确”，题目仍为 0/1。独立读取原始 ZIP 并对其中 checker.exe 进行一次本地输入验证时，该 checker 回显 `Correct! You have the flag.`。这证明该候选符合附件自带程序的比较逻辑，但与平台验证结果冲突；不能据此将题目标记为已解，也不再重复提交或尝试猜值。

目前证据指向“附件内 checker 接受值”和“平台题目接受值”并不一致；具体是附件与线上题目配置不对应，还是平台使用外部动态 flag，现有材料无法判定。题目页下载关联由主代理前台操作确认。主代理报告平台拒绝结果，但没有可写入本地的截图文件，因此本目录记录其提供的原文状态，不伪造截图。

没有使用公开 Writeup 或网络搜索。

## 文件

- `originals\checker_platform_download_20260929_051349.zip` — 最新下载 ZIP 的原样副本。
- `checker.exe` — ZIP 中唯一的文件。
- `checker.exe` — 从保存的原始 ZIP 第二次独立解压，用于独立读取和一次本地输入验证。
- `WP_第一届启航杯checker.md` — 附件分析、提交冲突、证据和未解决结论。
- `solve_checker.py` — 标准库脚本，解析 PE 并从内嵌数据反算附件 checker 所接受的字符串。
- `independent_forward_check.py` — 直接读取 ZIP 成员、独立映射 PE 节并执行一次附件本地核验；输出会隐藏候选文本。
- `正向复算输出.txt` — 首次解码和输入长度检查的 stdout。
- `独立执行复核输出.txt` — 独立解码、原始附件校验及本地 checker 执行结果。
- `strings_ascii.txt` — ASCII 字符串输出。
- `sections.txt`、`symbols_full.txt`、`data_区段.txt` — PE 节表、符号表和数据节。
- `关键函数反汇编.txt` — `_fake_check`、`_encrypt_flag`、`_check_flag`、`_main` 反汇编。
- `SHA256SUMS.txt` — 材料校验清单（不含自身与命令 transcript）。
- `命令与输出记录.txt` — PowerShell 命令、标准输出、错误输出和复核过程；包括本地 checker 执行回显及首次脚本错误/修正。

## 附件摘要

- 下载位置：`D:\Downloads\checker (5).zip`
- ZIP SHA256：`598E457DCDFFCB89F4A1B5CF56133E1D8A194E737B8C25C6C0EA722854426D36`
- `checker.exe` SHA256：`449D9F4569A0ED70FCB9BC8B96737719B62CFD8AE7C1E99D2864A3999887FDF5`

后续若要继续解决，应先核验玄机 ID 562 的当前题面/下载对象是否确实对应此 ZIP，或取得平台所需的动态环境与 flag 来源。不得把本地 checker 的成功误当作线上提交成功。
