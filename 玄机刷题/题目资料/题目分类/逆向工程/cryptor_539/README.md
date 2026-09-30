# 539 — 湘岚杯cryptor

- 平台：https://xj.edisec.net/challenges/539
- 类型/难度：REVERSE / 中等
- 平台状态：已接受，步骤 1/1；主线程前台提交后页面显示正确并显示一血（2026-09-29）
- 原始附件：originals/cryptor.zip（原件副本保留）
- SHA-256：EF999BBF17CD64D9962C2FDC040D6258396FBC594227325404FC729A766D781E
- 压缩包成员：cryptor.cp310-win_amd64.pyd、main.py
- 本地分析：AES-128-CBC + ZeroPadding 得到候选 flag{AtYpXBh38fNvc1ymsQ7vL}
- 状态：平台已验证完成；主线程负责更新全局指南
- WP：wp.md
- 命令及输出：analysis/command_transcript_20260929.txt
- 独立复核脚本：analysis/verify_independent.py
- 其他分析脚本：analysis/decrypt_static.ps1（算法/填充模式试算）、analysis/decrypt_static.py（PyCryptodome 缺失的失败尝试）

