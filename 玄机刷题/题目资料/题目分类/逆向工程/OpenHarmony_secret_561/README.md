# 第一届 OpenHarmony secret（玄机 #561）

**状态：已完成，2026-09-30 获玄机平台验证。**

最终 flag：`flag{871f72716d85a6374f438ea70c2fd62c}`。

附件为 OpenHarmony HAP。通过分析 `modules.abc`、native `libsecret.so` 与 `resources.index`，恢复资源提示。最终答案直接写在提示末尾。提示中的 MD5 计算示例与实际计算结果不符，完整复核过程见 [WP.md](WP.md)。

## 资料索引

- `secret_platform_20260929.zip`：原始下载件；SHA-256 为 `77177B600FEA6DA73C41935763ED555047F15CB7F17B7A707550BBD9E633080F`。
- `hap_contents/`：HAP 解包内容。
- `analysis/`：XXTEA、SM4、资源索引与提示恢复的复核脚本和输出。
- `记录/转存完整transcript操作.txt`：终端转录。
- [WP.md](WP.md)：详细技术解题过程和最终验证。
