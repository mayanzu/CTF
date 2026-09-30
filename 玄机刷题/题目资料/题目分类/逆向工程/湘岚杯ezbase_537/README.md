# 湘岚杯 ezbase（玄机 ID 537）

本目录记录本题附件、静态分析与完整 WP。

- 附件归档：`originals\ezbase.zip`
- WP：`wp.md`
- 分析证据、脚本和逐命令 transcript：`analysis/`
- 静态逆解候选：`flag{2qOrxQfRmDEdSkGt2mFoyilZQFU4BQDxBsuc}`
- 平台状态：前台已提交并接受（FLAG 正确、已完成 1/1、一血）。本地正向重编码也与二进制目标相等。

未运行样本。直接 UPX 解包由于 section names 被改写而失败；保留原样本，仅在分析副本恢复节名后通过 `upx -t` 并静态解包。完整过程及失败假设记录于 `analysis\537_static_analysis_transcript.txt` 和 `wp.md`。

重要文件：

- `analysis\ezbase.exe` — 从 ZIP 提取的原始分析副本，SHA256 `AEE861E105AFD0DDA6DDBACD27865FAFDC91E2FA225105920DB88DB38A30CAA0`
- `analysis\ezbase_names_restored.exe` — 仅修复 UPX 节名的副本
- `analysis\ezbase_unpacked.exe` — UPX 静态解包结果，SHA256 `C1A01D1D1C1AA849DA7EDACC239853A4CF9FB3E846C6D6D9915EF460DD95913F`
- `analysis\solve_537_from_static.py` — 从解包 PE 恢复字母表/比较目标并逆解、正向验证
- `analysis\537_static_analysis_transcript.txt` — 分析命令与输出


平台核验记录：平台核验.md。
