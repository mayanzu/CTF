# 圣人当仁不让（玄机 #533）

**状态：已完成，2026-09-30 获玄机平台验证。**

最终 flag：`flag{a1e05109-4x}`。

附件 `ez_vm.exe` 的校验流程为 17 字节输入、逐字节 VM 变换和 Base64 比较。其填充实现有错误，覆盖了应保留的编码字符，所以本地程序能接受三个没有闭合花括号的可打印输入，却不能接受平台确认的完整 flag。完整静态分析、正反向计算、失败候选与最终验证见 [wp.md](wp.md)。

## 资料索引

- `originals/ez_vm.zip`：原始附件。
- `analysis/ez_vm.exe`：解包得到的 Windows 程序，仅静态分析。
- `analysis/derive_candidate.py`、`analysis/independent_verify.py`：逆推和独立复核脚本。
- `evidence/independent_verification.txt`：复核输出。
- `533_static_analysis_transcript.txt`、`533_reproduction_transcript.txt`：终端命令与输出记录。
- [wp.md](wp.md)：详细技术 WP。
