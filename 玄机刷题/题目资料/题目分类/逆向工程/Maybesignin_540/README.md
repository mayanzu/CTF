# 540 — 湘岚杯maybesignin

- 平台：https://xj.edisec.net/challenges/540
- 类型/难度：REVERSE / 中等
- 平台状态（下载时）：免费，步骤 0/1
- 原始附件：`附件/MaybeSignin_platform_20260929.zip`（保留下载原件的副本）
- SHA-256：`79D0749B152E8A886AF6911CAEF49730CCC29067D66BF30739B89D2EAE13F8A2`
- 压缩包成员：`ezsignin.exe`
- 解题状态：已解决；平台前台验证显示 1/1
- WP：`wp.md`
- 命令及输出：`analysis/command_transcript_20260929.txt`
- 静态分析产物：`analysis/pe_headers_full.txt`、`analysis/disasm_140001000_140001800.txt`、`analysis/rdata_3260_3480.txt`、`analysis/strings_ascii.txt`
- 复现代码：`analysis/solve_sm4.py`（只分析数据文件，不运行题目 PE）
- 本地独立复核：Python SM4 解密并重加密回目标块；OpenSSL 3.5.2 SM4-ECB 解密得到同一候选
- flag：`flag{wlascJDAFS}`（玄机平台已验收）
