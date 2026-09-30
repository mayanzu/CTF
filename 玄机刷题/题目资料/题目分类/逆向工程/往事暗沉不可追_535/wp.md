# 玄机 CTF #535《往事暗沉不可追》静态分析 WP

## 1. 题目与安全边界

题面提示：“解密后的数据就是 flag，用逗号隔开。”附件为来日之路光明灿烂.zip。本地分析只对压缩包和其中 PE 文件作静态分析：未运行 EXE、DLL、PYD 或其它陌生二进制，也未联网搜索。候选随后由 root 通过前台 UI 提交并验证（见第 8 节）；本地分析 agent 未直接向平台提交。

## 2. 归档核验

先记录原始归档及成员信息，避免分析过程混淆对象：

- ZIP SHA-256：3D83F586009E705F48172F59148A536F919F17994959ED863782AA629D079365
- ZIP 长度：5,290,473 bytes
- 唯一成员：来日之路光明灿烂.exe
- 成员未压缩长度：5,465,233 bytes；压缩长度：5,290,319 bytes
- 静态分析副本 SHA-256：70E0194F1914D6872F2D991475A2967905AD92D3A8DD2EE0810330A153E43B19

命令 transcript 记录每一步本地命令和输出，位于 analysis/command_transcript_20260929.txt。

## 3. 识别并静态解包 PyInstaller

PE 头显示文件为 x64 PE32+，入口 RVA 为 0xC380，没有 Authenticode 签名。最后一个节之后有 5,131,921 bytes overlay，ASCII 字符串和 CArchive cookie 显示它是 PyInstaller one-file 包，而不是只需研究 PE 原生代码的普通程序。

CArchive cookie 给出 Python 版本字段 310 和 python310.dll。静态解包器依据 cookie 与 TOC 的偏移、压缩长度和解压长度，解压了全部 21 项，没有执行任何成员。主脚本成员为 0007_来日之路光明灿烂，解压后 1,771 bytes，SHA-256：

BDAEF0C93E7B31436CACFEF6BDA996372D3F48A70889BFFD88C7D39675C8A334

完整 TOC、每项哈希和状态见 analysis/pyi_extracted/pyinstaller_toc.txt。包中其余重要成员包括 python310.dll、PYZ-00.pyz、base_library.zip 和运行时组件；均只保留为数据。

## 4. 解析 Python 3.10 冻结代码

本机 Python 为 3.12；直接将 Python 3.10 marshal 数据交给本机 marshal.loads 得到 “bad marshal data (unknown type code)”。这是代码对象布局版本不一致，并非附件损坏。analysis/marshal310.py 按 Python 3.10 marshal 格式读取嵌套代码对象、常量、名称及字节码；它不导入或执行冻结脚本。

主模块常量中恢复出：

- VM 类：SimpleVM
- 字节码：LOAD, 0, 16, XOR, 0, 85, STORE, 0, 32, LOAD, 1, 32, XOR, 1, 170, STORE, 1, 48
- 密文数据：153, 147, 158, 152, 132, 200, 202, 203, 198, 154, 156, 156, 158, 210, 153, 130
- 数据长度：16

类方法和操作语义如下：

- 初始化 memory 为 256 个 0，registers 为 16 个 0。
- LOAD(reg, addr)：registers[reg] = memory[addr]。
- STORE(reg, addr)：memory[addr] = registers[reg]。
- XOR(reg, value)：registers[reg] = registers[reg] XOR value。
- execute 按每 3 个值解释一条指令，直到字节码结束。

主脚本先把密文写到 memory[16:32]，再调用 VM。

## 5. 推导 XOR 解密数据

嵌入指令中的两个 XOR 立即数是十进制 85 和 170，即 0x55 与 0xAA。二者合成：

0x55 XOR 0xAA = 0xFF

因此将这条两阶段 XOR 链逐字节用于 16 个密文字节：

明文[i] = 密文[i] XOR 0x55 XOR 0xAA = 密文[i] XOR 0xFF

密文（十进制）：

153,147,158,152,132,200,202,203,198,154,156,156,158,210,153,130

逐字节结果（十进制）：

102,108,97,103,123,55,53,52,57,101,99,99,97,45,102,125

按 ASCII 解码得到：

flag{7549ecca-f}

两种表达都保留为候选。按题面“用逗号隔开”的格式，待平台核验的候选是：

102,108,97,103,123,55,53,52,57,101,99,99,97,45,102,125

ASCII 展示 flag{7549ecca-f} 是相同字节的另一种表示。每字节与 0xFF 再异或可还原原密文，完成逆变换核对。

## 6. 本地复现

运行以下静态分析脚本可从冻结脚本 marshal 对象中自动读回字节码与数据，模拟实际 VM，并检查 XOR 链、逆变换和 ASCII 结果：

    python analysis/decrypt_verify.py analysis/pyi_extracted/0007_来日之路光明灿烂

成功输出中包括解密字节列表、ASCII 文本和逗号十进制候选。完整 stdout/stderr 已记入 transcript。脚本源码与 PE/CArchive 提取物都留在 analysis/。

## 7. 实现边界与结论

必须区分推导出的全数组候选与 EXE 的字面执行结果。VM 真实字节码只有 6 条指令：

1. LOAD 0, 16：读取密文首字节 153。
2. XOR 0, 85：寄存器 0 变成 204（0xCC）。
3. STORE 0, 32：将 204 写入 memory[32]。
4. LOAD 1, 32：把 204 读入寄存器 1。
5. XOR 1, 170：寄存器 1 变成 102（0x66，即 ASCII f）。
6. STORE 1, 48：将 102 写入 memory[48]。

它没有循环遍历 16 字节；执行后原密文所在 memory[16:32] 不变，只产生 memory[32]=204、memory[48]=102。随后主模块仅保存 get_memory() 的返回值，没有输出或继续解密。因此严格解释程序时，附件本身没有实际生成完整明文。全数组候选依据同一组明确 XOR 常数作用于嵌入的 16 字节密文，并由完整的 flag{...} ASCII 形式和逆变换支持。root 后续通过前台 UI 提交 flag{7549ecca-f}，平台接受，题页显示 1/1 已完成、首血。该结果确认本题被接受的提交形式是 ASCII flag 文本；逗号十进制序列是相同明文字节的逐字节展开表示，并非本次提交值。
## 8. 平台提交核验

由 root 通过玄机前台 UI 提交 ASCII 候选 flag{7549ecca-f}，平台接受并显示 1/1 已完成、首血。该前台结果确认提交值。题面中的逗号提示在本 WP 中对应解密字节的十进制展开；提交时使用了这些字节组成的 ASCII flag 文本。VM bytecode 只处理首字节的事实不受平台验证结果改变，完整候选仍由逐字节应用嵌入 XOR 链得到。