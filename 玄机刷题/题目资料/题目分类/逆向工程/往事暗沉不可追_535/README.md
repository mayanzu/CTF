# 玄机 CTF #535：往事暗沉不可追

## 状态

- 状态：已求解并由题目平台前台核验通过；1/1 已完成，首血。
- 题页状态（处理前）：免费、中等、未完成、一步 0/1。
- flag 由 root 通过前台 UI 提交并验证；本地静态分析未联网搜索或查找公开 writeup，也未运行附件中的 EXE、DLL 或 PYD。
- 候选与实现缺陷同时记录在 wp.md。题目页面提示“解密后的数据就是 flag，用逗号隔开”，因此保留十进制逗号序列和 ASCII 展示两种形式供前台核验。

## 候选

- 解密字节的十进制逗号形式：102,108,97,103,123,55,53,52,57,101,99,99,97,45,102,125
- 对应 ASCII：flag{7549ecca-f}
- 验证状态：root 通过前台 UI 提交 ASCII flag 文本后获平台接受。逗号十进制序列是相同明文字节的展开形式，本次被接受的提交为 flag{7549ecca-f}。

## 原始附件与哈希

附件归档位于 originals/来日之路光明灿烂.zip。

| 文件 | 长度 | SHA-256 |
|---|---:|---|
| originals/来日之路光明灿烂.zip | 5,290,473 bytes | 3D83F586009E705F48172F59148A536F919F17994959ED863782AA629D079365 |
| analysis/extracted/来日之路光明灿烂.exe（仅供静态分析） | 5,465,233 bytes | 70E0194F1914D6872F2D991475A2967905AD92D3A8DD2EE0810330A153E43B19 |

归档仅包含一个成员：来日之路光明灿烂.exe，解压长度 5,465,233 bytes，ZIP 压缩长度 5,290,319 bytes。PyInstaller CArchive 主脚本成员为 0007_来日之路光明灿烂，解压长度 1,771 bytes，SHA-256 为 BDAEF0C93E7B31436CACFEF6BDA996372D3F48A70889BFFD88C7D39675C8A334。

## 文件索引

| 路径 | 用途 |
|---|---|
| originals/来日之路光明灿烂.zip | 前台下载归档，保留原件 |
| analysis/extracted/来日之路光明灿烂.exe | ZIP 成员副本，仅作静态分析 |
| analysis/command_transcript_20260929.txt | 每条本地命令及其 stdout/stderr 记录 |
| analysis\static_triage.py | PE 头、节、导入表、熵和字符串静态提取 |
| analysis/pyi_extract.py | PyInstaller CArchive 静态解包器；只解压数据，不执行内容 |
| analysis\pyi_extracted\pyinstaller_toc.txt | 21 个 CArchive 成员的类型、长度、状态、SHA-256 |
| analysis/pyi_extracted/ | 由 CArchive 解压出的静态分析成员；其中 DLL/PYD 仅存档未执行 |
| analysis/pyi_extracted/0007_来日之路光明灿烂 | CPython 3.10 冻结主脚本的 marshal 数据 |
| analysis/pe_imports.txt | PE 导入符号 |
| analysis/strings_ascii.txt | 全量 ASCII 可打印字符串 |
| analysis\strings_utf16le.txt | 全量 UTF-16LE 可打印字符串 |
| analysis/marshal310_inspect.py | 初次检查 Python 3.10 marshal 对象并显示常量/字节码 |
| analysis/marshal310.py | 可复用的 Python 3.10 marshal 静态解析器 |
| analysis/decrypt_verify.py | 解析嵌入常量，模拟实际 VM 单次执行并复核逐字节 XOR 候选 |

## 静态识别

EXE 是未签名的 x64 PE32+。其 overlay 为 5,131,921 bytes，包含 PyInstaller one-file CArchive。CArchive 标记的 Python 版本字段为 310，运行时字段为 python310.dll。整个 ZIP 只含一个 EXE。完整 PE 和 CArchive 清单在 analysis 中。

本机可用 Python 3.12 无法直接 marshal.loads 该 Python 3.10 代码对象，故采用只解析 marshal 数据结构的静态解析器。没有加载或执行题目附带的任何二进制。

## 重要限制

冻结主脚本中的 VM 程序只有 6 条三元组指令。严格按该程序执行时，它读取 encrypted_data[0]，经过 0x55 和 0xAA 两次 XOR，并把中间/最终值写入两个内存地址；它没有循环处理 16 个密文字节，也没有打印结果。候选全串是将脚本明确给出的两步 XOR 链逐字节应用于 16 字节 encrypted_data 得到的结果。全串呈现完整 flag{...} ASCII 形态，且逆变换通过。root 已通过题目平台前台 UI 验证该 ASCII flag 提交成功（1/1，首血）。原程序未实现全数组循环的局限仍需保留说明。
## 平台提交记录

由 root 通过玄机前台 UI 提交：flag{7549ecca-f}。平台接受，题页显示 1/1 已完成、首血。十进制逗号字节串用于描述解密数据；本次成功提交的 flag 形式是 ASCII 文本。