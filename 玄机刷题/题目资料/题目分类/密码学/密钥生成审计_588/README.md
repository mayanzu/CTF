# 密钥生成审计 #588 资料

- `originals/密钥生成审计附件.zip`：原始下载 ZIP 的逐字节副本。
- `originals/extracted/attachments/challenge.py`、`output.txt`：归档 ZIP 解压所得附件；源码仅作为文本阅读。
- `wp.md`：完整中文分析、推导、限制及复现命令。
- `analysis/solve_588.py`：MT19937 状态克隆及密钥推导（Python 标准库）。
- `analysis/decrypt_588.ps1`：Windows .NET AES-ECB 解密、PKCS#7 校验及加密回环验证。
- `analysis/derived_material.json`：推导出的四个输出、AES 密钥和密文。
- `analysis/*_output.txt`：两步脚本的最终标准输出。
- `analysis/session_transcript.txt`：文件核验、命令输入标签、完整输出及修正过程的 PowerShell transcript。
- `analysis/SHA256SUMS.txt`：原始附件和分析交付文件的 SHA-256 清单（清单不对自身求哈希）。
- `status.md`：平台状态说明。

静态候选：`flag{2db163a20ecc0e6a27ce588669211a2e}`。本子任务没有操作平台，因此候选仍待平台验证。