# 湘岚杯 1997（玄机 #538）

**状态：未完成 / 未提交。** 该附件程序的 32-byte expected 值在按其实际非标准 AES 轮函数求逆后，只对应一个非 ASCII 输入；输入中含 scanf("%s") 会终止读取的空格字节 0x20，因此无法作为完整 32-byte token 输入。没有生成或提交文本 flag，也没有把本题列入已完成清单。

## 文件

- originals/1997.zip：平台原始附件，SHA256 832F1BA75D90A93FF2B8D867483CE8612CF42157685976C4FD665ED4AC07193B
- analysis/123.exe：题目程序，63228 bytes，SHA256 5046A87DE6DAC33CE11CD139D06A4A0797E63BE3A70757AEB1224A3ACC151078
- wp.md：完整静态分析、轮函数求逆过程与所有失败假设
- analysis/538_static_transcript_20260929.txt：命令输入/输出记录
- analysis/538_custom_aes_verify.py：按反汇编还原的自定义轮函数和正反向复核
- analysis/538_objdump_*.txt：静态反汇编和 PE 数据证据

所有分析均未执行附件、未联网、未看公开 Writeup、未向平台提交 flag。
