# 湘岚杯 1997（玄机题目 #538）静态分析记录

## 结论与状态

**状态：未解出可提交的文本 flag；没有向平台提交。**

附件中的程序要求输入恰好 32 字节。静态反汇编表明，它使用一个非标准 AES 变换加密输入，再与硬编码的 32 字节常量比较。按反汇编逐步还原该变换并求逆后，唯一匹配的 32 字节输入是：

- 十六进制：f0f1a0e7b57ebbf87ca9111468ca5971ed5fa6aef9802f8990c8ec1720d644bb
- repr：b'\xf0\xf1\xa0\xe7\xb5~\xbb\xf8|\xa9\x11\x14h\xcaYq\xed_\xa6\xae\xf9\x80/\x89\x90\xc8\xec\x17 \xd6D\xbb'

该结果含大量非 ASCII 字节，并在偏移 28（从 0 开始）包含 0x20 空格。程序通过 scanf("%s") 读入，空格会终止输入，因此该字节串不可能作为一个完整的 32 字节 token 被程序读入。它也不是平台可用的常规文本 flag。故结论是附件本身的检查逻辑与可提交文本输入存在矛盾；在找到与题目说明相符的另一份附件或官方格式证据前，不继续猜测包装格式，也不把这题记为已完成。

## 附件与证据

- 原始附件：originals/1997.zip
- ZIP 内唯一成员：123.exe，63228 字节
- SHA256（ZIP）：832F1BA75D90A93FF2B8D867483CE8612CF42157685976C4FD665ED4AC07193B
- SHA256（EXE）：5046A87DE6DAC33CE11CD139D06A4A0797E63BE3A70757AEB1224A3ACC151078
- 分析副本：C:\CTFwork\xj538.exe；复制前后 SHA256 相同
- **没有运行或安装 EXE；没有联网；没有查看公开 writeup；没有提交候选 flag。**

附件清单、PE 头和 section 信息、符号表、反汇编及脚本均保存在 analysis/。所有本次终端命令标记与主要输出记录在 analysis/538_static_transcript_20260929.txt；较长反汇编完整输出分别保存在 analysis/538_objdump_*.txt。

## 解题过程

### 1. 清点附件并确认输入

题目附件目录中包含原始 ZIP 和 root 提供的解压文件 analysis/123.exe。用 SHA256 确认输入对象，并读取 ZIP central directory，确认压缩包只有一个成员 123.exe。该步骤只读文件元数据，没有启动样本。

ZIP 哈希：
832F1BA75D90A93FF2B8D867483CE8612CF42157685976C4FD665ED4AC07193B

EXE 哈希：
5046A87DE6DAC33CE11CD139D06A4A0797E63BE3A70757AEB1224A3ACC151078

### 2. 确认文件类型和可用符号

按字节解析 DOS/PE 头，得到：

- DOS magic：MZ
- PE 签名：PE\\0\\0
- machine：0x8664（AMD64）
- PE32+ optional header：0x20B
- 15 个 sections
- 编译器字符串：GCC x86_64 MinGW-W64 8.1.0
- 符号表保留 main、aes_key_schedule_128、aes_encrypt_128、shift_rows、mul2 等调试符号

调试符号使得无需运行程序即可针对 main 和 AES 相关函数进行静态反汇编。初次把含中文的绝对路径直接交给 MSYS objdump 时，路径编码被破坏并出现 “No such file or directory”；随后将分析副本复制到纯 ASCII 路径 C:\CTFwork\xj538.exe，哈希保持一致，再使用该副本完成 objdump 静态分析。失败命令及输出已如实写入 transcript。

### 3. 从 main 恢复输入校验流程

main 中可见以下流程：

1. 输出提示语。
2. 使用 scanf 格式串 %s 读取输入。
3. 调用 strlen，并要求结果等于 0x20，即 32 字节；否则输出错误并退出。
4. 在栈上逐字节构造 AES key，字节对应 ASCII 字符串 Welcome_to_ctf!!，共 16 字节。
5. 在栈上逐字节构造 expected 值，共 32 字节：
   24 f9 64 b9 90 b4 90 b5 3a 1f 2c 87 19 9b 02 84
   6d 65 ad 1c 65 4e 01 5c 06 18 a3 fd b4 6c 83 eb
6. 调用 aes_key_schedule_128 生成轮密钥。
7. 对输入的第 1 个 16 字节块、第 2 个 16 字节块分别调用 aes_encrypt_128。
8. 对 32 个输出字节逐字节比较 expected；完全相等才输出 success!!!。

这说明程序接受值由输入字节本身决定；没有发现额外前缀、后缀、哈希或网络交互校验。

### 4. 识别程序实际使用的 AES 变体

最初尝试把数据当作标准 AES-128-ECB 密文，用同一硬编码 key 解密。结果为非 ASCII：
4d651b6f709d9fe5cee2bee49cc1ea78fdf0632b9ff353fc104f7d81321bb425
这个假设与可读文本 flag 不符，所以停止使用标准 AES 结果，转而按二进制代码恢复真实算法。失败结果与 UnicodeDecodeError 已记录在 transcript。

静态反汇编显示：

- key schedule 使用 SBOX 与轮常量表 RC，按 AES-128 的轮密钥扩展方式从 16 字节 key 生成 11 组 round key。
- aes_encrypt_128 的初始步骤是输入块与 K0 按字节 XOR。
- 主轮数值为 1 到 9。每轮依次执行 INV_SBOX 查表、shift_rows、MixColumns、与对应轮密钥 XOR。
- 最后一轮执行 INV_SBOX、shift_rows、与 K10 XOR，不做 MixColumns。
- 这与标准 AES 的字节代换方向不同；shift_rows 也不是通常教科书中的 ShiftRows。

由 shift_rows 的静态指令恢复的精确字节变换如下。对进入函数的 16 字节数组 old，输出位置为：

- [0,4,8,12] 变为 [old12,old0,old4,old8]；
- [1,9] 互换；
- [5,13] 互换；
- [2,6,10,14] 变为 [old14,old2,old6,old10]；
- [3,7,11,15] 未被该函数修改。

MixColumns 按相邻四字节分组。对每组 a,b,c,d，代码等价于标准正向 MixColumns：
- out0 = 2a xor 3b xor c xor d
- out1 = a xor 2b xor 3c xor d
- out2 = a xor b xor 2c xor 3d
- out3 = 3a xor b xor c xor 2d

其中乘法在 GF(2^8) 上按 AES 多项式 0x11B 计算。相关汇编保存在 analysis/538_objdump_aes_encrypt.txt、analysis/538_objdump_shift_rows.txt、analysis/538_objdump_mul2.txt；key schedule 汇编在 analysis/538_objdump_key_schedule.txt。

### 5. 求逆并复核

分析脚本 analysis\538_custom_aes_verify.py 从 EXE 的 .data section 读取实际 SBOX、INV_SBOX、RC 表，并从 main 反汇编中读取逐字节初始化的密钥与 expected 常量。随后按 AES 轮密钥扩展生成 K0 到 K10，反向执行：

1. 与 K10 XOR。
2. 应用 shift_rows 的逆置换。
3. 对 INV_SBOX 查表结果应用 SBOX。
4. 对主轮 9 到 1 依次执行：与 Kr XOR、逆 MixColumns、逆 shift_rows、SBOX。
5. 与 K0 XOR。
6. 将两个块拼接为唯一 32 字节输入。

最后将所得输入重新送入脚本内按静态代码重建的正向变换，输出与硬编码 expected 完全一致，ROUNDTRIP_MATCH=True。这个复核只是在 Python 中处理数据和自编的轮函数，没有启动 123.exe。

标准 AES 假设和实际程序算法的求逆结果都不是可读 flag。实际算法结果中 0x20 位于第 29 个输入字节，scanf("%s") 会在该空格处结束读取，因此实际程序不可能读到这个 32 字节结果。当前最有证据支持的根因是附件的 expected 常量、AES 实现或题目附件版本彼此不匹配；不能据此声称已经得到平台 flag。

## 被排除的假设

| 假设 | 检查结果 | 结论 |
|---|---|---|
| 将 32 字节 expected 当标准 AES-128-ECB 解密 | 输出 32 字节非 ASCII | 不支持文本 flag |
| 直接把程序字符串 Welcome_to_ctf!! 当 flag | main 明确将其作为 16 字节轮密钥输入 | 排除 |
| 给解密结果随意添加 flag 前后缀 | 程序按 32 字节输入执行固定加密比较，没有包装拼接逻辑 | 无证据，停止猜测 |
| 将实际求逆输出作为普通键盘输入 | 结果包含空格 0x20 且含控制/高位字节，scanf("%s") 无法完整读入 | 不可行 |
| 将该题列为已完成 | 没有可提交文本 flag，也无平台 accepted 结果 | 不成立 |

## 可复现文件

- analysis/538_static_analysis.ps1：清点附件、计算哈希、解析 PE 头并抽取静态字符串。
- analysis/538_objdump_main.txt：main 完整反汇编。
- analysis/538_objdump_aes_encrypt.txt：aes_encrypt_128 反汇编。
- analysis/538_objdump_key_schedule.txt：aes_key_schedule_128 反汇编。
- analysis/538_objdump_shift_rows.txt：shift_rows 反汇编。
- analysis/538_objdump_mul2.txt：GF(2^8) 乘 2 实现。
- analysis/538_objdump_data.txt：SBOX、INV_SBOX 和轮常量所在 .data section。
- analysis/538_decrypt_verify.py：标准 AES 假设的失败复核。
- analysis/538_custom_aes_verify.py：按静态指令复现并反向求解的脚本。
- analysis/538_static_transcript_20260929.txt：命令标记、输入/输出摘要及失败记录。
- analysis/538_objdump_headers.txt、analysis/538_objdump_symbols.txt、analysis/538_objdump_rdata.txt：PE 头、符号与只读数据证据。
