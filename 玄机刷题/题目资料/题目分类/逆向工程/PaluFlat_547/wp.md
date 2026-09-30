# 第547题：第二届 Parloo 杯 RE — PaluFlat

## 题目信息与结论

- 玄机 ID：547
- 类型：REVERSE
- 页面状态：免费、中等；提交前 0/1，提交后平台接受、已完成 1/1
- 原始附件：originals/PaluFlat_flag.zip
- 解压后外层成员：analysis/extracted/PaluFlat_flag.com
- 内层 7z 成员：analysis/extracted/PaluFlat.exe
- 静态变换恢复出的 flag 候选：flag{bdm23Ne6ljz5O}
- 本地验证：按 PE 内实际控制流得到的 19 字节输入，经正向变换后逐字节等于程序内的 19 字节目标常量。
- 提交状态：2026-09-29 由协调者在登录后的玄机题目页前台提交 `flag{bdm23Ne6ljz5O}`，页面返回“FLAG 正确~, 恭喜你完成此挑战~”，并显示“已完成”、步骤 1/1。平台接受为本题最终完成依据。

本题的 .com 附件不是可直接执行的 DOS 程序，而是一个 7z 归档；归档中又包含一个 1 GiB 的 x64 PE。PE 文件在 0x4800 之后有 1 GiB 左右的全零 overlay。有效的 PE 节区都位于文件开头，实际变换函数使用被控制流平坦化混淆的 switch 状态机。静态化简后，每个输入字节按顺序执行 XOR、半字节交换、减 0x55、按位取反。

## 附件与归档完整性

分析只读取归档与二进制数据，没有运行 .com 或 .exe。

### 外层 ZIP

- originals/PaluFlat_flag.zip 大小：9,644 字节
- SHA-256：5CA642495D769B3A02FCB73B3F2F20281A4AE4001938B0F282736332C72409D7
- ZIP 内唯一成员：PaluFlat_flag.com
- 解压大小：164,561 字节
- CRC32：2ACE2719
- Python zipfile.testzip() 结果：None，未发现 CRC 错误

### 内层文件

PaluFlat_flag.com 的开头为 7z 魔数 37 7A BC AF 27 1C。使用系统 tar 只列出目录、确认成员名后，发现归档仅含平面成员 PaluFlat.exe；未发现路径穿越成员。随后才把该成员解到 analysis/extracted。

- PaluFlat_flag.com SHA-256：678801F5EBBAF73B346D5B090A2A44191CB1629C1C12CD57D34FD6A69603D185
- PaluFlat.exe 长度：1,073,741,824 字节（1 GiB）
- PaluFlat.exe SHA-256：EC9F3D4B137085E6D45530744CDD3D3CC49573B35176062855C5E2732A81006D

PE 节区原始数据到文件偏移 0x4800 结束。overlay 从 0x4800 到 EOF，共 1,073,723,392 字节。analysis/check_overlay.py 使用每块 16 MiB 的分块读取扫描，结果为 0 个非零字节，首尾非零偏移均不存在。没有一次把整个 1 GiB 文件读入内存。原始 ZIP、内层 .com、1 GiB PE 均保留在题目目录中。

## PE 结构与静态分析材料

PaluFlat.exe 是 PE32+ / AMD64：

- Machine：0x8664
- Optional Header magic：0x20b
- ImageBase：0x400000
- 入口点 RVA：0x14e0，VA：0x4014e0
- 节区数：9
- .text：RVA 0x1000，raw offset 0x400，长度 0x2a00
- .data：RVA 0x4000，raw offset 0x2e00
- .rdata：RVA 0x5000，raw offset 0x3000
- 最后一个有文件内容的节区结束于 raw offset 0x4800

为了让静态反汇编工具避开 1 GiB 的零填充，也规避 Windows 工具链对中文路径的编码问题，把原 PE 的前 0x5000 字节复制到 analysis/PaluFlat_head_0x5000.bin。该副本覆盖 PE 头、所有节区头和全部节区原始数据；与原 PE 前缀逐字节比较一致，大小 20,480 字节，SHA-256 为 9FB745DAB1C76F9A0118A871753E50FF5DD251DF81DE9B502508ED65B11EEC03。objdump 读取的是这个数据副本，未执行文件。

静态产物：

- analysis/commands_output.log：PowerShell transcript，记录附件检查、命令和脚本输出。
- analysis/objdump_headers.txt：节区与 PE 头。
- analysis/objdump_imports.txt：导入表。
- analysis/objdump_symbols.txt：符号表检查；文件已剥离题目函数符号。
- analysis/objdump_data.txt：.data 与 .rdata hexdump。
- analysis/objdump_text.txt：.text 完整反汇编。
- analysis/decode_vm.py、analysis/vm_cases.txt：跳转表解析和状态块清单。
- analysis/solve_static.py：从 PE 指令立即数提取目标串并逆变换。
- analysis/verify_forward.py：独立正向变换校验。
- analysis/check_overlay.py：分块检查大文件 overlay 是否全零。
- analysis/inspect_zip_547.py、analysis/inspect_zip_547_output.txt：外层 ZIP 成员及哈希检查。

导入表中与题目逻辑有关的函数包括 fgets、printf、puts、strcspn、strlen 和 strncmp。可打印字符串有 input flag:、success、error。字符串 input flag: 位于 VA 0x4050b8，反汇编在 0x40210a 处引用，因此可以从该处向前后查看输入主逻辑。

## 解题过程

### 1. 从入口提示定位校验逻辑

在 0x40209f 找到使用 input flag: 的函数。关键步骤如下：

1. 0x4020b4 至 0x4020fc 初始化 19 个目标字节。
2. 0x402100 将比较长度常量 0x13（十进制 19）写入局部变量。
3. 0x40210a 调用 printf 显示 input flag:。
4. 0x40211b 从标准输入读取数据；0x402136 调用 fgets，长度参数是 0x64（100）。
5. 0x402149 用 strcspn 查找换行，0x40214e 写入字符串终止 NUL。
6. 0x40215e 调用 0x401550，把用户输入作为第一个参数、输出缓冲区作为第二个参数。
7. 0x40216a 调用 strlen 检查变换输出长度是否为 19。
8. 0x402193 至 0x4021d6 按 19 字节逐项比较输出和内置目标。
9. 0x4021df 输出 success；失败分支在 0x4021ed 或 0x4021fb 输出 error。

这段代码说明目标是先对输入逐字节变换，再要求长度和目标缓冲区都匹配。目标字节并非放在 .data，而是通过一串机器指令直接写到栈上的局部缓冲区。

### 2. 提取 19 字节比较目标

0x4020b4 开始连续出现 19 条指令，形式为：

~~~text
mov byte ptr [rbp + disp8], imm8
~~~

位移从 0xa0 连续递增到 0xb2，立即数依序组成：

~~~text
f3 54 84 23 a4 74 d4 c3 30 5f 32 43 f0 54 f4 74 00 22 43
~~~

总长度由 0x402100 的立即数 0x13 确认，为 19 字节。analysis/solve_static.py 动态读取 PE 头和 .text 节区映射，以 VA 0x4020b4 定位指令，再验证每条指令前缀和位移递增规律，提取每条指令中的 imm8。它没有从 ASCII strings 猜常量。

### 3. 识别被平坦化的变换函数

函数从 VA 0x401550 开始：

- 入口将 Windows x64 参数 RCX、RDX 保存在局部变量中。结合调用点 0x40215e，可知 RCX 指向输入，RDX 指向变换输出。
- 0x401560 将字符串 palu 写入栈内，0x40156b 将 flat 写入栈内。
- 0x40157d、0x40158c、0x401598 调用 strlen，记录 palu、flat、输入的长度；两个常量串的长度都是 4。
- 0x4015a0 将 VM 状态设为 0；0x4015a7 将字符索引设为 0；0x4015ae 将调度常量设为 0x3039。
- 0x4015b5 检查状态范围 0 到 0x2d。0x4015ca 从 RVA 0x5000 对应的数据表取相对偏移，0x4015e0 跳到对应 case。这是控制流平坦化形成的 jump table。
- 大量 case 对 0x3039 的不同位做条件判断，状态值在 0 到 45 之间跳转。key 常量没有在函数中被修改。

静态跟踪常量 0x3039 的有关分支后，针对每个字节得到固定路径：

~~~text
状态 0 -> 状态 10 -> 状态 12 -> 状态 2 -> 状态 3 -> 状态 4 -> 状态 0
~~~

路径证据如下：

- 状态 0 在 0x4015fe 检查 bit 0；bit 0 为 1 后到 0x401654。bit 2 为 0，继续到 0x401661。这里依字符索引奇偶选择 palu 或 flat：偶数索引选 palu，奇数索引选 flat，随后令状态为 10。
- 状态 10 在 0x401a52 检查 bit 13；bit 13 为 1 后检查 bit 14。bit 14 为 0，于 0x401a78 令状态为 12。该路径也按奇偶重新设置 key 指针。
- 状态 12 从 input[i] 和 key[i % 4] 取字节，在 0x401acd 做 XOR。bit 14 为 0，随后状态设为 2。
- 状态 2 在 0x401785 至 0x401797 对当前字节做半字节交换：高低 4 bit 互换。bit 6、7、8 都是 0，路径在 0x4017c1 把状态设为 3。
- 状态 3 在 0x401855 至 0x40185c 执行 byte 值减 0x55。bit 9、10、11 都是 0，路径在 0x401886 把状态设为 4。
- 状态 4 在 0x40191a 对 byte 执行 NOT，0x40192d 写入 output[i]，0x40192f 将索引加一，之后回到状态 0。

0x3039 的相关位为：bit0=1、bit2=0、bit13=1、bit14=0、bit6=bit7=bit8=bit9=bit10=bit11=0。每个字符都经过相同四种变换；每次迭代的 key 字节由索引奇偶和 i%4 决定。

实际 key 序列为：

~~~text
i 偶数：从 palu 取 palu[i % 4]
i 奇数：从 flat 取 flat[i % 4]
循环字节：70 6c 6c 74，即 p l l t
~~~

因两个 key 长度同为 4，整串使用 p、l、l、t 循环。

### 4. 写出变换和逆变换

按指令执行顺序，单字节变换为：

~~~text
x = input_byte XOR key_byte
x = ROL4(x)                   # 交换高低半字节
x = (x - 0x55) mod 256
output_byte = NOT(x) mod 256
~~~

反向恢复时倒序执行：

~~~text
x = NOT(cipher_byte) mod 256
x = (x + 0x55) mod 256
x = ROL4(x)                   # nibble swap 自身是逆运算
input_byte = x XOR key_byte
~~~

这里 NOT 和加减都按 8 bit 字节处理，运算后截断到 0..255。

### 5. 逐字节恢复

对每个目标字节应用逆变换：

| i | 目标字节 | key | 恢复字节 | 字符 |
|---:|---:|---:|---:|:---|
| 0 | f3 | 70 | 66 | f |
| 1 | 54 | 6c | 6c | l |
| 2 | 84 | 6c | 61 | a |
| 3 | 23 | 74 | 67 | g |
| 4 | a4 | 70 | 7b | { |
| 5 | 74 | 6c | 62 | b |
| 6 | d4 | 6c | 64 | d |
| 7 | c3 | 74 | 6d | m |
| 8 | 30 | 70 | 32 | 2 |
| 9 | 5f | 6c | 33 | 3 |
| 10 | 32 | 6c | 4e | N |
| 11 | 43 | 74 | 65 | e |
| 12 | f0 | 70 | 36 | 6 |
| 13 | 54 | 6c | 6c | l |
| 14 | f4 | 6c | 6a | j |
| 15 | 74 | 74 | 7a | z |
| 16 | 00 | 70 | 35 | 5 |
| 17 | 22 | 6c | 4f | O |
| 18 | 43 | 6c | 7d | } |

比如首字节：cipher f3 先取反为 0c，加 55 得 61，交换半字节得到 16，再与 p（70）XOR 得 66，即字符 f。对全部 19 字节同样计算，得到：

~~~text
flag{bdm23Ne6ljz5O}
~~~

### 6. 正向复算

analysis/solve_static.py 从指令立即数自动提取目标字节、key 字符串、长度和 0x3039，然后逆变换恢复候选并按原顺序重做正向变换。

analysis/verify_forward.py 则独立使用固定候选和固定目标字节，不调用逆变换，逐字节计算正向公式。完整输出为：

~~~text
candidate: flag{bdm23Ne6ljz5O}
candidate length: 19
key pattern: 706c6c74
expected bytes: f3548423a474d4c3305f3243f054f474002243
forward bytes: f3548423a474d4c3305f3243f054f474002243
complete 19-byte match: True
target NUL byte indices: [16]
~~~

该校验比较了全部 19 个字节，未使用前缀、长度猜测或只比较部分密文。

## 附件自身的长度检查矛盾

平台已接受候选，但离线附件代码本身有一个可复现的矛盾，不能把本地成功路径写成已验证：

静态恢复过程中发现一个确定的运行时逻辑问题，需要在 WP 中保留：

1. main 把目标长度设为 19。
2. 目标数组第 16 号字节为 0x00，紧随其后仍有 0x22、0x43。
3. main 在逐字节比较之前先对变换输出调用 strlen，并要求结果等于 19。
4. C 的 strlen 会在第一个 NUL 停止。如果变换输出的第 16 号字节为 0，则 strlen 至多为 16；如果该字节不是 0，后续逐字节比较又不可能等于目标的 0x00。

所以按静态反汇编，附件中 main 的 success 分支不可达：长度检查与后续目标字节要求互相矛盾。flag 候选仍由逐字节可逆变换和 19 字节全量回算唯一确定，但不应声称本地运行验证成功。本任务按要求没有执行这个 1 GiB 的陌生 PE，也没有提交平台；如批次协调者在玄机平台提交候选，应单独记录平台回执，不能把平台结果与本地可达性混为一谈。

## 复现命令

在 PowerShell 中进入题目目录后，可复现静态校验：

~~~powershell
Set-Location 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluFlat_547'
python .\analysis\solve_static.py
python .\analysis\verify_forward.py
python .\analysis\check_overlay.py
~~~

重新查看附件和 PE 信息的命令：

~~~powershell
tar -tf .\analysis\extracted\PaluFlat_flag.com
& 'C:\msys64\mingw64\bin\objdump.exe' -h .\analysis\PaluFlat_head_0x5000.bin
& 'C:\msys64\mingw64\bin\objdump.exe' -p .\analysis\PaluFlat_head_0x5000.bin
& 'C:\msys64\mingw64\bin\objdump.exe' -s -j .data -j .rdata .\analysis\PaluFlat_head_0x5000.bin
& 'C:\msys64\mingw64\bin\objdump.exe' -d -M intel -j .text .\analysis\PaluFlat_head_0x5000.bin
~~~

全部实际检查命令和输出保存在 analysis/commands_output.log；完整反汇编、数据和跳转状态清单分别保存在 analysis/objdump_text.txt、analysis/objdump_data.txt 和 analysis/vm_cases.txt。

## 结论

依据 x64 PE 的完整静态控制流，逐字节变换是：

~~~text
output[i] = NOT((ROL4(input[i] XOR key[i % 4]) - 0x55) mod 256)
~~~

其中 key 字节流为循环的 p l l t。嵌入目标的 19 字节常量完整逆变换为：

~~~text
flag{bdm23Ne6ljz5O}
~~~

正向变换的 19 字节结果与附件中内置常量完全相等，置信度高。附件自身的 strlen 长度检查有矛盾；本次未运行样本、未联网、未打开公开 Writeup、未操作平台或提交 flag。

## 独立静态审计补充（2026-09-29）

本节是在既有分析后追加的独立复核记录，没有覆盖原推理。复现脚本为 `analysis/audit_independent_547.py`，完整输入命令与输出保存在 `analysis/audit_independent_547_transcript.txt`，独立标准输出另存于 `analysis/audit_independent_547_output.txt`。

### 归档与 PE 文件复核

- 外层 ZIP 为 9,644 字节，SHA-256 为 `5CA642495D769B3A02FCB73B3F2F20281A4AE4001938B0F282736332C72409D7`。Python `zipfile.testzip()` 返回 `None`；唯一成员为 `PaluFlat_flag.com`，大小 164,561 字节，CRC32 `2ACE2719`。从 ZIP 成员分块读取后，与保存的 `.com` 逐块相同，SHA-256 为 `678801F5EBBAF73B346D5B090A2A44191CB1629C1C12CD57D34FD6A69603D185`。
- 对 `.com` 只执行 `tar -tvf` 清单读取，确认内层 7z 只有单个平面成员 `PaluFlat.exe`，声明大小 1,073,741,824 字节；没有路径穿越成员。
- 为验证已保存 PE 与归档内容一致，`tar -xOf ... PaluFlat.exe` 的输出通过 4 MiB 缓冲逐块与 `analysis/extracted/PaluFlat.exe` 比较并计算 SHA-256，没有落地第二份 1 GiB 文件，也没有把整文件装入内存。逐块结果完全一致，SHA-256 为 `EC9F3D4B137085E6D45530744CDD3D3CC49573B35176062855C5E2732A81006D`。
- PE 头是 AMD64 / PE32+，ImageBase `0x400000`、入口点 `0x4014e0`、9 个节区。所有带原始数据的节区范围均不重叠且完整落在仅读取的 `0x5000` 前缀内；最后有效 raw offset 为 `0x4800`。状态表、目标常量和代码检查均只读此前缀。

### 状态机与算术右移细节

由头部内的 46 项相对跳表和 `0x3039` 固定 seed 逐分支核对，逐字节路径为：

`state 0 → 10 → 12 → 2 → 3 → 4 → 0`

相关位为 bit0=1、bit2=0、bit13=1、bit14=0、bit6..11 全为 0。state 0 因 bit0=1 走到 `0x401654`，再由 bit2=0 选择偶数索引 `palu`、奇数索引 `flat` 并进入 state 10；state 10 由 bit13/14 进入 state 12；state 12 对输入字节和 key 字节异或；state 2 执行 `SHL EAX,4`、`MOVZX EAX,BYTE [...]`、`SAR AL,4`、`OR EAX,EDX`；state 3 减 `0x55`；state 4 对字节取反、写出并回到 state 0。key 字节流为 `70 6c 6c 74` 循环，即 `pllt`。

需要限定一个易被过度简化的地方：机器码的 `SAR AL,4` 是算术右移。若 XOR 中间字节最高位为 1，右移后的低半字节会被符号位填成 `F`，此时运算不等于普遍的高低半字节交换。本候选的 19 个 XOR 中间值全部小于 `0x80`，因此本题候选路径上该操作确实等价于交换半字节；审计脚本对每个字节按实际 SAR 语义复算。这样不会把候选的正确性错误推广到任意二进制输入。

### 候选闭环和本地验证限制

目标常量从 `0x4020b4` 的 19 条 `mov byte [rbp+disp8], imm8` 提取为：

`f3548423a474d4c3305f3243f054f474002243`

目标长度立即数为 19。对每字节按 NOT、加 `0x55`、反推 state 2 的结果、再 XOR 对应 key 逆算，得到唯一满足此目标的候选 `flag{bdm23Ne6ljz5O}`。审计脚本随后重新按机器码中的 SAR/SHL/OR、减法、NOT 顺序正向计算，输出完整 19 字节与目标完全一致；逐字节中间值见 transcript。

但这不能证明附件自身会输出成功。主函数 `0x40216a` 调用的 thunk `0x4036f0` 经导入表解析为 `msvcrt.dll!strlen`。主函数先要求 `strlen(output)==19`，再逐项比较 19 字节；正向输出在 offset 16 为 NUL，所以 `strlen` 返回 16。若该字节不为 NUL，后面的 19 字节比较又不会匹配目标。因此这个附件内的 success 分支不可达。此候选是静态反推并完整正向回算的结果；本审计没有操作平台，平台接受状态仍待验证，不能记为已完成。

另发现原 `analysis/solve_static.py` 的一条说明注释把 seed bit9 写成 1；`0x3039` 的 bit9 实际为 0。该脚本的断言、状态分支结论和本次审计计算均采用 bit9=0，因此这是注释笔误，不影响候选结果。

### 复现记录

从 `C:\Users\mzj\Desktop\CTF` 运行：

~~~powershell
python .\玄机刷题\题目资料\PaluFlat_547\analysis\audit_independent_547.py
~~~

脚本仅对外层 ZIP 和内层 7z 做清单/流式字节校验，并从 PE 读取有限前缀解析节表、跳表、状态、目标和导入符号。准确的脚本启动行、内部 `tar` argv、每一步输出及退出码均保存于 `analysis/audit_independent_547_transcript.txt`。本次没有运行 `.com` 或 `.exe`、没有浏览公开 Writeup、没有联网，也没有向平台提交 flag。

