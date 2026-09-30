# 玄机 #543《轩辕杯”云盾砺剑CTF挑战赛 你知道Base么》完整 WP

> 状态：静态逆向与端到端正向闭环已完成，但题目尚未解决。主线程于 2026-09-29 在玄机前台提交候选 flag{y0u__rea11y__k1ow__Base!} 后，页面明确提示“FLAG 不正确”，进度仍为 0/1。详见[第十/平台提交记录](../../../../记录/批次记录/第10批/原始分件/提交核验_20260929_第十批.md)。
>
> 题型：Reverse。附件只有一个 Windows x64 控制台程序，程序交互分为 8 字节密钥、64 字符 Base_Table、flag 三步。

## 1. 题目附件与安全检查

本批从新下载归档的 originals/Base.rar 开始分析，没有借用旧题目录、旧 WP 或缓存答案。

| 项目 | 结果 |
|---|---|
| 原附件 | originals/Base.rar |
| RAR SHA-256 | 3FEC5E1930230660DCABDF0F31F4D97F8BB980D67306242D48A4377B74590801 |
| 文件格式 | RAR5，头部字节 52 61 72 21 1A 07 01 00 |
| 压缩成员 | 你知道Base么/你知道Base么.exe（70,144 字节）以及一个同名空目录项 |
| 成员路径检查 | 共 2 项；无绝对路径、盘符路径或 .. 路径 |
| 解包后 EXE SHA-256 | EF7DEACF6594E9353E934564B38761E8AAF614EBF39DCB17EFED36263DF2C773 |
| 执行策略 | 仅用 tar 列目录/解包，用 strings、objdump 和自写解析脚本读取字节；没有运行 EXE |

第一次 tar.exe -tf 的控制台把中文显示成乱码。通过捕获 stdout 原始字节、按 GBK 解码，确认真实成员名为“你知道Base么”。列目录清单与安全路径判定在 records/543_inventory_transcript.txt；实际只解压了清单中的两个成员，输出在 records/543_extraction_transcript.txt。

## 2. PE 静态信息与程序交互

静态 PE 头信息：

- PE32+，机器类型 0x8664（AMD64）。
- ImageBase 0x140000000，入口 RVA 0x11299，入口 VA 0x140011299。
- Windows CUI 程序，文件时间戳显示 2025-05-02。
- Debug 构建；导入包含 VCRUNTIME140D.dll 与 ucrtbased.dll。这也进一步说明不需要为解题尝试执行附件。

字符串和反汇编发现如下交互提示：

1. Hello CTFer!
2. give me your key，格式 %8s。
3. 密钥正确时提示 You have passed the first level!!!。
4. Where is my Base_Table???，提示输入 Base_Table，格式 %64s。
5. Plz input Your flag:，格式 %29s。
6. Base32 变换结果比较成功时输出 Successful!，失败时输出 error! 或失败提示。

完整 PE sections、导入表、strings 和约 1 MB Intel 反汇编分别保存于 analysis/objdump_*.txt、analysis/strings_*.txt。字符串 RVA/VA 映射和直接代码引用在 analysis/pe_layout_string_map.txt。

## 3. 第一关：反算 8 字节密钥

### 3.1 确定输入与常数

主函数约位于 0x140016f80。密钥读取后，主函数把四个 DWORD 设成：

    k[0] = 0x12345678
    k[1] = 0x3456789a
    k[2] = 0x89abcdef
    k[3] = 0x12345678

另把 8 字节输入作为两个小端 DWORD 送入变换。最后与下列两个目标 DWORD 比较：

    target[0] = 0xa92f3865
    target[1] = 0x9e60e953

输入是 8 个字节，因此若把第一个 DWORD 写成 0x11223344，内存中的四个字节顺序是 44 33 22 11。这里必须按 little-endian 还原字符串。

### 3.2 从汇编还原轮函数

函数 0x140012740 中设置 32 轮，delta 为 0x9e3779b9。汇编逐条对应：

    sum = 0
    repeat 32 times:
        sum = (sum + 0x9e3779b9) mod 2^32
        v0 = (v0 + mix(v1, sum, k0, k1)) mod 2^32
        v1 = (v1 + mix(v0, sum, k2, k3)) mod 2^32

    mix(y, sum, a, b) =
        (((y << 4) + a) mod 2^32)
        XOR ((y + sum) mod 2^32)
        XOR (((y >> 5) + b) mod 2^32)

注意第二个更新使用刚更新后的 v0。这与标准 TEA/XXTEA 不能直接混为一谈；这里按本程序的固定四个子密钥和更新顺序实现。

### 3.3 逆运算和正向校验

每轮逆序执行：

    v1 = v1 - mix(v0, sum, k2, k3)  (mod 2^32)
    v0 = v0 - mix(v1, sum, k0, k1)  (mod 2^32)
    sum = sum - 0x9e3779b9           (mod 2^32)

从 32 轮结束时的 sum = 0xc6ef3720 递减回零，逆算得到：

    v0 = 0x6f753079
    v1 = 0x6165546b

按 little-endian 拼回 8 字节：

    79 30 75 6f 6b 54 65 61
    ASCII: y0uokTea

然后重新执行 32 轮前向变换，精确得到 0xa92f3865, 0x9e60e953。所以第一关输入密钥是 y0uokTea。

解密实现与每轮关键状态在 analysis\decrypt_543_key.py 和 records/543_key_decrypt_trace.txt。

## 4. 第二关：还原 Base_Table

### 4.1 识别程序实际用的 RC4 变体

调用链中，主函数把第一关的 8 字节密钥作为第二关密钥，把 64 字节 Base_Table 输入送入 0x140011ea0。它先调用 0x140011d10 做状态初始化和 KSA：

    S[i] = i, i = 0..255
    j = (j + S[i] + key[i mod key_length]) mod 256
    swap(S[i], S[j])

之后 PRGA 每次执行：

    i = (i + 1) mod 256
    j = (j + S[i]) mod 256
    swap(S[i], S[j])
    stream = S[(S[i] + S[j]) mod 256]
    output = (input + stream) mod 256

关键点：在本程序的反汇编里，输入字节与 keystream 通过 add 相加后写回，不是通常 RC4 的 XOR。因此求逆必须用减法：

    input[i] = (target[i] - stream[i]) mod 256

若按普通 RC4 XOR 求逆，会得到错误的表。

### 4.2 从主函数抽取 64 字节目标并逆出输入表

主函数把目标 64 字节逐个立即数写到栈数组 [rbp+0x220..0x25f]。自写脚本从完整反汇编自动提取这些值，再用密钥 y0uokTea 重建 KSA/PRGA。目标密文字节为：

    d4592376b4bfe32c588f5619daf0c0bd
    363d7b461bb8171fe3d00345cd04edc9
    67e6ab29a7bc0bde5c3071d7d55ac69f
    4065c471a9c3aed9b5e5128c80523436

由 (target - stream) mod 256 得到 64 个可打印 ASCII 字符：

    gVxwoFhPyT/YM0BKcHe4b8GCUZtlnLW2SJO51IErk+q6vzpamdARX9siND3uQfj7

将这 64 字节重新执行程序里的“加 keystream”变换，逐字节得到原始目标密文，64/64 字节完全一致。

主函数要求提交 64 个字符是合理的：即使 Base32 编码实际只用其中 32 个字符，完整 64 字节仍会被第二关的 RC4 检查比较。Base32 编码器按索引 [rbp+index+1] 取字符，因此其真实 32 字符字母表是完整 Base_Table 的 table[1:33]：

    VxwoFhPyT/YM0BKcHe4b8GCUZtlnLW2S

长度为 32，字符全部唯一。这是一个自定义 Base32 字母表；不要把它误认为标准 RFC 4648 字母表。

## 5. 第三关：逆出 flag

### 5.1 从汇编还原自定义 Base32 分组

函数 0x140012ae0 每次读 5 个输入字节，按大端位序组成 40 bit 整数。若不足 5 字节，未提供的位置保持零。之后依次从高位到低位抽取 8 个 5-bit 数：

    q = b0<<32 | b1<<24 | b2<<16 | b3<<8 | b4
    indices = [
      (q>>35)&31, (q>>30)&31, (q>>25)&31, (q>>20)&31,
      (q>>15)&31, (q>>10)&31, (q>> 5)&31, q&31
    ]
    output_byte = Base_Table[index + 1]

所以每 5 字节输入生成 8 个自定义 Base32 字符。第三关的 48 字节目标串来自主函数写入 [rbp+0x2d8..0x307] 的立即数字节：

    0tCPwtnncFZyYUlSK/4Cw0/echcG2lteBWnG2Ulw0htCYTMW

### 5.2 用自定义字母表解码

对目标串中的每个字符，先在上述 32 字符字母表中查其索引，写为 5 位二进制，再把位流每 8 位还原为字节。完整 48 个字符共 240 bit，恰好还原 30 字节：

    flag{y0u__rea11y__k1ow__Base!}

注意拼写细节：rea11y 与 k1ow 使用数字 1，y0u 使用数字 0；双下划线分隔各片段。完整候选长度为 30 个 ASCII 字节。

### 5.3 端到端前向闭环

analysis/verify_543_end_to_end.py 独立重建并验证整条链：

1. 候选密钥 y0uokTea 的 32 轮结果精确等于两个嵌入 DWORD。
2. 用密钥执行 KSA 与加法 PRGA，64 字符 Base_Table 正向变换 64/64 字节等于目标。
3. 用 table[1:33] 编码完整 30 字节候选，得到 48 字符 0tCPwtnncFZyYUlSK/4Cw0/echcG2lteBWnG2Ulw0htCYTMW，48/48 字节与主函数常量完全一致。
4. 从这 48 字符逆解出的 30 字节重新编码，仍完整匹配目标。

这条从目标常量反算再前向还原的闭环支持完整候选，不依赖程序运行结果。

## 6. 本地检查器的长度问题

反汇编还显示两个值得记录的实现问题：

- flag 输入格式是 %29s，最多读取 29 个非空白字节，但完整候选长度为 30 字节，所以完整候选不能原样通过这个 scanf 输入。
- 输出比较函数 0x140012400 的循环条件是 i < 0x1e，只比较 Base32 输出前 30 字节；而主函数硬编码的目标串长 48 字节。

静态前向复算显示，29 字节前缀 flag{y0u__rea11y__k1ow__Base! 编码后的前 30 字符正好也匹配目标前 30 字符。因此本地程序的交互验证只验证了很短的前缀，无法证明完整 flag。完整 30 字节候选来自内嵌的完整 48 字符目标串的逆解，但该候选已于 2026-09-29 在玄机前台提交并被明确拒绝（“FLAG 不正确”，页面仍为 0/1）。它目前只能记为未通过平台验证的静态候选，不能作为本题已解决的依据。

本 WP 记录了这个本地边界条件；没有运行附件来触发该检查器，也没有把局部前缀匹配冒充成平台成功。

## 7. 复现命令与保存文件

从 C:\Users\mzj\Desktop\CTF 执行：

    python .\玄机刷题\题目资料\题目分类\逆向工程\Base_543\analysis\inventory_543.py
    python .\玄机刷题\题目资料\题目分类\逆向工程\Base_543\analysis\extract_543.py
    python .\玄机刷题\题目资料\题目分类\逆向工程\Base_543\analysis\static_543.py
    python .\玄机刷题\题目资料\题目分类\逆向工程\Base_543\analysis\static_543_ascii_retry.py
    python .\玄机刷题\题目资料\题目分类\逆向工程\Base_543\analysis\pe_layout_543.py
    python .\玄机刷题\题目资料\题目分类\逆向工程\Base_543\analysis\decrypt_543_key.py
    python .\玄机刷题\题目资料\题目分类\逆向工程\Base_543\analysis\derive_543_table_flag.py
    python .\玄机刷题\题目资料\题目分类\逆向工程\Base_543\analysis\verify_543_end_to_end.py
    python ./玄机刷题/题目资料/题目分类/逆向工程/Base_543/analysis/assemble_543_transcript.py

主要材料：

- 原始压缩包：originals/Base.rar
- 按安全清单提取的附件：analysis/unpacked/你知道Base么/你知道Base么.exe
- PE 头、节、导入表、字符串和完整反汇编：analysis/objdump_pe_header_ascii.txt、objdump_sections_ascii.txt、objdump_imports_ascii.txt、strings_ascii_ascii.txt、strings_utf16le_ascii.txt、objdump_disassembly_intel_ascii.txt
- 密钥和 table/flag 求解脚本：analysis/decrypt_543_key.py、analysis/derive_543_table_flag.py、analysis/verify_543_end_to_end.py
- 统一命令记录：records/543_command_transcript.txt
- 算法轮次、表逆解、端到端输出：records/543_key_decrypt_trace.txt、records/543_table_flag_derivation.txt、records/543_final_verification.txt

逐命令原始输出分别保留在 records/543_inventory_transcript.txt、records/543_extraction_transcript.txt、records/543_static_analysis_transcript.txt、records/543_static_analysis_retry_transcript.txt。统一记录汇总了失败分支和对应纠正办法。

## 8. 静态候选与最终平台状态

- 第一关密钥：y0uokTea
- 64 字符 Base_Table：gVxwoFhPyT/YM0BKcHe4b8GCUZtlnLW2SJO51IErk+q6vzpamdARX9siND3uQfj7
- 未通过平台的静态候选：flag{y0u__rea11y__k1ow__Base!}
- 平台结果：2026-09-29 前台提交后提示“FLAG 不正确”，页面仍为 0/1；本题未解决，不能列入已完成题目。
- 静态验证范围：程序内嵌第一关目标、64 字节 table 目标和完整 48 字节 Base32 目标均已正向闭环；这只能证明样本内部运算一致，不能推翻平台明确的拒绝结果。
- 提交记录：[记录/提交核验_20260929_第十批.md](../../../../记录/批次记录/第10批/原始分件/提交核验_20260929_第十批.md)
