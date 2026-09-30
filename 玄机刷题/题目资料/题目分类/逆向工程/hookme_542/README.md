# 玄机 ID 542：hookme

- 类别：REVERSE（Android APK / JNI）
- 来源：本批新归档 `..\..\..\原始下载附件\hookme.rar`，SHA-256 `1DC981B273CB80A32863B9A89A09CFA82B731F6D4BC8E37D72C445DEB29E993F`
- 本地分析：静态脚本得到候选 `flag{ee9fb062624c1e527fab36d3a27484d1}`，自编解码前向闭环与 APK 中的密文逐字节相同；但该候选已被玄机平台拒绝，不能视为正确 flag。
- 平台状态：2026-09-29 主线程通过 Chrome Computer Use 在玄机题页提交上述候选，页面返回“FLAG 不正确~”，状态仍为 0/1；本题未解决。详见[批次提交核验记录](../../../../记录/批次记录/第10批/原始分件/提交核验_20260929_第十批.md)。
- 完整过程：见 [wp.md](wp.md)。

目录：

- `originals/`：原始 RAR，原样保留。
- `extracted/`：从 RAR 提取的 APK。
- `analysis/`：APK 成分、静态分析脚本、DEX/ELF反汇编、资源解析和求解脚本。
- `records\`：PowerShell transcript、失败尝试及更正后的复现记录。

安全边界：附件分析只做离线静态检查；没有安装或运行 APK / so。平台提交由主线程通过 Chrome Computer Use 完成，且已被平台拒绝。
