# 玄机 CTF #536：遇事不决，可问春风

## 题目信息与状态

- 题目：商丘师范学院第四届网络安全及信息对抗大赛《遇事不决，可问春风》
- 平台题页状态（任务开始时）：免费、中等、未完成、1 步 0/1
- 静态分析状态：已从 APK 的应用代码恢复修正后的候选 flag，并用本地脚本复现字节码中的转换与 flag 拼接逻辑。
- 平台验证：修正版已由 root 在玄机前台接受，页面显示“FLAG 正确~，恭喜你完成此挑战~”，题目状态 1/1 完成；一血栏显示 35分14秒。第一版候选曾被拒绝，原因已追溯为 DEX opcode 名称表错误。
- APK 处理约束：只作静态分析，未安装、未启动或以其他方式运行 APK。

## 哈希与原始归档

| 文件 | 大小 | SHA256 |
|---|---:|---|
| `originals/app-debug.zip` | 4,419,022 bytes | `A366F7C8B031940BC96016811BBD441A17B3473F8B9D288511E02CC63E6A1D59` |
| ZIP 内 `app-debug.apk`（未压缩） | 4,609,869 bytes | `BA82DA14824377E2CCCB085B7A6871FAAB9C3B0CCB3E02EB555DBC8B92C1EFD7` |
| APK 内 `classes3.dex` | 3,556 bytes | `29DCC3110E4B13F6AB3C9B009EAD33362C1D324351CF6AD4BD0EE5BB87E24553` |
| APK 内 `AndroidManifest.xml` | 5,336 bytes | `1A8ED86F458F5451F889CF7C776DE78EA602669B3EDCF9CC6182AFD9419304AF` |

ZIP 只含一个文件：`app-debug.apk`（压缩后 4,418,898 bytes）。APK 共 863 个条目，完整路径、长度和压缩长度见 [`analysis/apk_contents_index.txt`](analysis/apk_contents_index.txt)。原始 ZIP 和其中 APK 的哈希、DEX 与 manifest 的索引见本 README 与命令记录。

## 文件索引

- [`wp.md`](wp.md)：完整逐步中文解题过程、DEX 证据、候选 flag 与限制。
- [`analysis/command_transcript_20260929.txt`](analysis/command_transcript_20260929.txt)：本题本地检查命令和对应完整 stdout/stderr（PowerShell 成功/错误流合并记录）。
- [`analysis/app-debug.apk`](analysis/app-debug.apk)：从原 ZIP 提取的 APK，仅作为静态分析输入。
- [`analysis/apk_contents_index.txt`](analysis/apk_contents_index.txt)：APK 内全部 863 个条目的路径和大小。
- [`analysis/dex_static/AndroidManifest.xml`](analysis/dex_static/AndroidManifest.xml)：从 APK 提取的二进制 manifest。
- [`analysis/dex_static/classes.dex`](analysis/dex_static/classes.dex)、[`analysis/dex_static/classes2.dex`](analysis/dex_static/classes2.dex)、[`analysis/dex_static/classes3.dex`](analysis/dex_static/classes3.dex)：从 APK 提取的 DEX 文件；自有校验逻辑位于 `classes3.dex`。
- [`analysis/parse_axml.py`](analysis/parse_axml.py) 与 [`analysis/manifest_report.txt`](analysis/manifest_report.txt)：最小只读 binary-XML 解析器及 manifest 摘要。
- [`analysis/analyze_dex.py`](analysis/analyze_dex.py) 与 [`analysis/dex_report.txt`](analysis/dex_report.txt)：针对 DEX 结构和相关 opcode 的只读解析/反汇编脚本及输出。
- [`analysis/recover_candidate.py`](analysis/recover_candidate.py) 与 [`analysis/recovery_report.txt`](analysis/recovery_report.txt)：从 DEX 常量和指令提取转换、复现候选，并输出逐字符映射。
- [`analysis/audit_apk.py`](analysis/audit_apk.py) 与 [`analysis/apk_audit_report.txt`](analysis/apk_audit_report.txt)：静态扫描 APK ZIP 的条目类别与 flag/校验标记。

## 候选与限制

已接受的 flag 是 `flag{f8f06f2b-60ee-43ca-8e3a-1048042edddd}`。root 的最终前台流程：进入 [#536 题页](https://xj.edisec.net/challenges/536) → 点击“提交FLAG” → 在“提交 FLAG”弹窗输入修正候选 → 点击“提 交”。页面即时显示“FLAG 正确~，恭喜你完成此挑战~”，详情页标记“已完成”、步骤 1/1；一血栏显示 35分14秒。此前提交的第一版 `flag{fzfrvfrbovrggovsccozgscosrvzrvrgffff}` 被拒绝，原文为“FLAG 不正确~”。拒绝原因已定位：上一版自写 opcode 表将 DEX `0xdf` 误标为 `or-int/lit8`；DEX 实际定义为 `xor-int/lit8`。更新后的 `analysis/dex_report.txt` 与 `analysis/recovery_report.txt` 以 `xor-int/lit8 #66`（0x42）复现，得出 UUID 形态密码 `f8f06f2b-60ee-43ca-8e3a-1048042edddd`。`checkPassword()` 将输入与解密结果比较，`buildFlag()` 使用 `flag{` 与 `}` 拼接结果。

本地恢复脚本检查这些关键字节码和字符串并验证逐字符变换。APK 全包扫描未发现 `assets/`、`lib/`、`res/raw/` 等额外 payload；flag/校验相关字符串只出现在应用自有 `classes3.dex`，Android 证书元数据包含竞赛签名 `Reflag Signing`。未在 Android 上动态运行。前台页面已接受修正版。解析器是为本题相关 DEX/manifest 字段编写的最小只读工具，不是通用完整 Android 反编译器；未联网或参考公开 writeup。
