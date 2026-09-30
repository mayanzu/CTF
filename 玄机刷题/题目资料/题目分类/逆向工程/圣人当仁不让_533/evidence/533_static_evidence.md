# #533 静态证据摘要：圣人当仁不让

## 附件与处理范围

- 玄机题号 533；题名：商丘师范学院第四届网络安全及信息对抗大赛「圣人当仁不让」。
- 附件 originals/ez_vm.zip；SHA-256 B9B280302A0B975F272CFCA88B59CFFB0EDE4DE3529D56A1BB328CE0D0ED071E。
- 解压 PE analysis/ez_vm.exe；82,661 bytes；SHA-256 918ACDAA4DF332FC53C0D8F2B0FC281D5B2710753C5C27BFC53F97E530572E91。
- ZIP 内只有 ez_vm.exe；解压结果与 ZIP 成员逐字节一致。
- PE32+ x86-64，ImageBase 0x140000000，Entry RVA 0x1125，11 个 section；导入 KERNEL32.dll、msvcrt.dll。
- 未运行该 EXE。分析只读取附件字节、PE 元数据、字符串和静态反汇编。

## main 的控制流

main 位于 VA 0x1400018b9。它引用比较串 z8nO0NTOntKdop6dloqh1Q==，打印“请输入 flag: ”，调用 fgets(..., 0x12, stdin)，以 strcspn 去除 CR/LF，然后要求 strlen 为 0x11，即 17 字节。之后复制 17 字节，调用 VM 和 base64_encode（长度也是 17），将结果与常量 strcmp。成功只输出“你太强了！！”，失败输出“错误：输入的flag无效。”；成功路径没有额外打印 flag。

## VM 逐字节变换

_Z10vm_executePc 位于 VA 0x140001823，循环下标 0..16（含末尾）逐字节原位执行：

    b = input[i] XOR 0xAA
    b = (b + 5) & 0xFF
    b = (b - 2) & 0xFF

合并为 b = ((input[i] XOR 0xAA) + 3) mod 256。证据是反汇编中的 xor edx,0xffffffaa、lea ecx,[rax+5]、lea ecx,[rax-2] 和 byte 写回。

## Base64 填充缺陷

_Z13base64_encodePKhy 位于 VA 0x1400015e0，使用标准 Base64 字符表。17 字节输出长度为 24，填充代码计算：

    pad = (encoded_length - (input_length mod 3)) & 3
    pad = (24 - 2) & 3 = 2

它把最后两个字符都覆盖为等号，但 17 字节的标准 Base64 应只有一个等号。第二个被覆盖的字符本来携带输入末字节的低四位，因此目标常量无法唯一确定最后一个字节。

## 逆推与可复核候选

目标 Base64 解码为 16 字节：

    cfc9ced0d4ce9ed29da29e9d968aa1d5

对每个字节应用逆变换 input = ((y - 3) mod 256) XOR 0xAA，得到前缀：

    flag{a1e05109-4x

穷举末字节可打印 ASCII，并按程序的错误 padding 前向重编码，且仅以下三个匹配硬编码串：

| 程序输入候选 | 变换后末字节 | 正向结果 |
|---|---:|---|
| flag{a1e05109-4xT | 0x01 | z8nO0NTOntKdop6dloqh1Q== |
| flag{a1e05109-4xU | 0x02 | z8nO0NTOntKdop6dloqh1Q== |
| flag{a1e05109-4xW | 0x00 | z8nO0NTOntKdop6dloqh1Q== |

三者都不含闭合花括号，附件无法区分。按同一逻辑验证完整候选 flag{a1e05109-4x}，其输出为 z8nO0NTOntKd6dloqh1d==，不等于附件目标。

## 结论

校验器存在可证明的 Base64 padding 缺陷，信息不足以确定唯一、完整的平台 flag。成功分支也不输出隐藏 flag。因此本题标记为“附件逻辑矛盾，未提交”，不计入已解。
