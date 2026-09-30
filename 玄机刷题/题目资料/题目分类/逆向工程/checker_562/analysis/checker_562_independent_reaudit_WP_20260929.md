# 玄机 #562「第一届启航杯 checker」独立重审 WP

> 重审日期：2026-09-29。范围：项目中留存的题目 ZIP 与 checker.exe。本 WP 独立从原始 PE 字节重新定位比较串并反推输入，不把先前候选当作前提。没有向玄机平台提交任何 flag。

## 结论与状态

对附件中的 checker.exe，独立恢复出的输入是：

    flag{enp17I4p8TZmAriao2lq5tAArZ2P1wxBUwXU2}

恢复过程从 PE32 头部解析节表，定位机器码中的 XOR key 与 .data 中的比较目标，逐字节解密并做往返验证。再把结果输入与 ZIP 内附件 SHA-256 完全相同的 checker，程序输出 Correct! You have the flag. 因此，这是当前保存附件的本地正确输入。

父任务记录该候选此前在平台被拒绝；本次没有再次提交。项目中没有保存平台拒绝提示的原始截图/回执、用户实际粘贴内容的证据、平台当前下载附件哈希或服务器端校验值。因此能确认的是“候选通过本地附件”，不能确定“为何平台拒绝”。最需要核对的是平台页面 ID/题目状态、平台当时下载的附件 SHA-256、提交框实际内容以及服务端响应。仅凭本地 PE，不能证明平台端使用的是同一答案数据；不要把尚未验证的推测写成平台完成。

## 题目材料与完整性

项目目录：

    C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\checker_562\
    ├── checker_platform_20260929.zip
    ├── checker.exe
    ├── 附件_20260929\checker.exe
    └── analysis/
        ├── agent_checker562_independent_rederive.py
        ├── agent_checker562_independent_WP_transcript_20260929.txt
        ├── checker_562_independent_reaudit_WP_20260929.md
        ├── checker_disassembly.txt
        └── checker_strings_ascii.txt

ZIP 中仅有一个非目录成员 checker.exe，大小 42,857 字节。哈希如下：

| 对象 | SHA-256 |
|---|---|
| 平台附件 ZIP | 598E457DCDFFCB89F4A1B5CF56133E1D8A194E737B8C25C6C0EA722854426D36 |
| ZIP 内 checker.exe | 449D9F4569A0ED70FCB9BC8B96737719B62CFD8AE7C1E99D2864A3999887FDF5 |
| 附件_20260929\checker.exe | 449D9F4569A0ED70FCB9BC8B96737719B62CFD8AE7C1E99D2864A3999887FDF5 |
| 根目录 checker.exe | 449D9F4569A0ED70FCB9BC8B96737719B62CFD8AE7C1E99D2864A3999887FDF5 |

独立 Python verifier 直接通过 zipfile 读取 ZIP 成员并与解压文件逐字节比较，输出 ZIP member equals extracted bytes: True。这排除了“本地分析误用了不同内容的同名 EXE”。但它不能证明平台服务器当前所关联的附件与本地 ZIP 一致。

## 1. 文件格式与地址换算

PE 头解析结果：

- DOS MZ 与 PE 签名有效；
- machine 0x014C（i386），可选头 magic 0x010B（PE32）；
- ImageBase 0x00400000；
- .text VA 0x00401000、原始文件偏移 0x400；
- .data VA 0x00404000、原始文件偏移 0x3200。

对于映射到文件中的地址，按节表计算：

    RVA = VA - ImageBase
    file_offset = section.PointerToRawData + (RVA - section.VirtualAddress)

例如：

    目标数据 VA       = 0x404020
    RVA               = 0x404020 - 0x400000 = 0x4020
    .data RVA         = 0x4000
    .data raw offset  = 0x3200
    文件偏移          = 0x3200 + (0x4020 - 0x4000) = 0x3220

关键指令 VA 0x401496 同理映射到 .text 的文件偏移 0x896。独立脚本检查原始 7 字节为：

    C7 45 F0 23 00 00 00

已有反汇编将这条指令解为 mov DWORD PTR [ebp-0x10],0x23，它为 _encrypt_flag 设置固定 XOR key 0x23。脚本又直接从原始立即数的小端 4 字节读取 key，结果仍为 0x23；它没有从旧 WP 复制 flag 字符串。

## 2. 确认输入变换与比较流程

反汇编关键部分（地址均为程序映像 VA）：

    00401490 <_encrypt_flag>:
      401496: c7 45 f0 23 00 00 00    mov DWORD PTR [ebp-0x10],0x23
      40149d: c7 45 f4 00 00 00 00    mov DWORD PTR [ebp-0xc],0x0
      ...
      4014b6: 0f b6 0a                movzx ecx,BYTE PTR [edx]   ; input[i]
      4014b9: 8b 55 f0                mov edx,DWORD PTR [ebp-0x10] ; key
      4014bc: 31 ca                   xor edx,ecx                ; key ^ input[i]
      4014be: 88 10                   mov BYTE PTR [eax],dl      ; output[i]
      ...
      4014ca: call _strlen
      4014d4: cmp edx,eax
      4014d6: ja 4014a6                 ; continue while i < strlen(input)
      ...
      4014ea: mov BYTE PTR [eax],0       ; output terminator

    004014f0 <_check_flag>:
      4014f6: call _fake_check
      ...
      401508: call _encrypt_flag
      40150d: mov DWORD PTR [esp+0x4],0x404020
      40151b: call _strcmp

因此变换逐字节为：

    cipher[i] = input[i] XOR 0x23

_check_flag 把加密后的输入与 0x404020 处的 NUL 结尾目标串传给 strcmp，只有完全一致才返回成功。由于 XOR 自反，逆变换也是 plain[i] = cipher[i] XOR 0x23。_fake_check 仅在主判定前运行延时/提示流程，不改变比较目标。

## 3. 定位比较目标并独立恢复字符串

0x404020 位于 .data，对应文件偏移 0x3220。从这个位置读到 NUL 为止，共 43 字节；随后 00 是 C 字符串终止符，不是密文内容：

    45 4F 42 44 58 46 4D 53 12 14 6A 17 53 1B 77 79
    4E 62 51 4A 42 4C 11 4F 52 16 57 62 62 51 79 11
    73 12 54 5B 61 76 54 7B 76 11 5E

逐字节执行 cipher[i] XOR 0x23 得到 43 个明文字节：

    66 6C 61 67 7B 65 6E 70 31 37 49 34 70 38 54 5A
    6D 41 72 69 61 6F 32 6C 71 35 74 41 41 72 5A 32
    50 31 77 78 42 55 77 58 55 32 7D

ASCII 为：

    flag{enp17I4p8TZmAriao2lq5tAArZ2P1wxBUwXU2}

独立 verifier 做三个检查：

1. 明文字节可按 ASCII 解码；
2. 满足附件中观察到的 flag{字母数字下划线} 字节格式；
3. 再次 XOR 0x23 后逐字节等于原始 43 字节比较目标。

输出为：

    cipher length: 43
    XOR key immediate: 0x23
    XOR round-trip exact: True
    expected flag syntax: True
    independently derived candidate: flag{enp17I4p8TZmAriao2lq5tAArZ2P1wxBUwXU2}

## 4. 输入读取与长度检查

_main（0x40152a）调用 fgets，第二个参数是 0x32（十进制 50），即最多读入 49 个非 NUL 字符并补终止符；然后通过 strcspn(input, "\n") 将首个换行改为 NUL。恢复出的字符串为 43 个 ASCII 字符，能完整放入输入区。_check_flag 的输出缓冲区也可容纳该长度和终止符。

因此，在本地 checker 的逻辑下，不存在需要再移除 flag{}、转换大小写或做字符编码的证据；这些改动反而会破坏 strcmp 的逐字节精确匹配。此结论只描述本地附件，不假定平台前端/后端有相同的输入规则。

## 5. 本地原程序验证

MSYS objdump 直接读取含中文目录名的路径时报告找不到文件；为查看机器码与运行程序，将同一附件复制到仅含 ASCII 的临时路径：

    C:\Users\mzj\Desktop\CTF\checker562_audit_temp.exe

临时副本 SHA-256 同样是 449D9F4569A0ED70FCB9BC8B96737719B62CFD8AE7C1E99D2864A3999887FDF5。静态导入表只显示 KERNEL32.dll 与 msvcrt.dll。本地验证命令与原样输出：

    $candidate = 'flag{enp17I4p8TZmAriao2lq5tAArZ2P1wxBUwXU2}'
    $candidate | & 'C:\Users\mzj\Desktop\CTF\checker562_audit_temp.exe'

    Enter the flag: Performing initial checks...
    Checks completed.
    Correct! You have the flag.

这一步证明候选对 SHA-256 相同的本地程序有效；不等同于平台已接受。

## 6. 关于此前平台拒绝

平台拒绝这一事实由父任务上下文提供；现有本地记录仅描述附件逆向和本地运行，没有附上平台响应原文或提交时截图。基于现有证据：

- 可排除的本地原因：旧候选字节与附件比较目标精确匹配；长度未超出读取上限；ASCII 内容无编码歧义；同哈希原程序打印成功。
- 不能从本地文件单独确定的原因：提交时页面是否确为 #562；平台当时附件是否与本地 ZIP 同哈希；输入框是否完整接收了 43 个字符；平台后端的答案记录是否与附件一致；或平台是否存在状态/判分异常。
- 当前判断：附件内答案高度确定；平台拒绝的具体根因仍未证实。若平台之前确实对完全相同的 43 字符返回错误，首要排查应是页面/附件/服务端校验数据不一致，而不是对候选做猜测式改写。

本次按任务要求没有访问公开 Writeup，也没有向平台提交或重试 flag。

## 7. 可复现命令

以下命令按 PowerShell 使用。文件路径假定和本机项目一致：

    $root = 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\checker_562'
    python (Join-Path $root 'analysis\agent_checker562_independent_rederive.py')
    Get-FileHash -Algorithm SHA256 (Join-Path $root 'checker_platform_20260929.zip'), (Join-Path $root 'checker.exe'), (Join-Path $root '附件_20260929\checker.exe')

若要重新运行 PE 工具，可先复制到 ASCII 路径以避免 MSYS 对中文路径的编码问题：

    Copy-Item -LiteralPath (Join-Path $root '附件_20260929\checker.exe') -Destination 'C:\Users\mzj\Desktop\CTF\checker562_audit_temp.exe' -Force
    & 'C:\msys64\mingw64\bin\objdump.exe' -d -Mintel --start-address=0x401490 --stop-address=0x40152a 'C:\Users\mzj\Desktop\CTF\checker562_audit_temp.exe'
    $candidate = 'flag{enp17I4p8TZmAriao2lq5tAArZ2P1wxBUwXU2}'
    $candidate | & 'C:\Users\mzj\Desktop\CTF\checker562_audit_temp.exe'

完整命令行与原始输出记录在：

    analysis\agent_checker562_independent_WP_transcript_20260929.txt

独立 PE 解码器（Python 标准库，无额外依赖）在：

    analysis\agent_checker562_independent_rederive.py

## 本题状态

- 本地附件：已独立分析并验证。
- 本地候选：flag{enp17I4p8TZmAriao2lq5tAArZ2P1wxBUwXU2}。
- 玄机平台：未提交、未验证；此前拒绝的具体原因待查。
