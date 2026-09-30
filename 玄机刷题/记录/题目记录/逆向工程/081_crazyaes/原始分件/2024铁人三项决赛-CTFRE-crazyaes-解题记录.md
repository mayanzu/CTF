# 2024铁人三项决赛 CTFRE-crazyaes（ID 81）解题记录

## 1. 题目信息与最终状态
- 平台：玄机，题目 ID 81
- 分类 / 难度 / 费用：REVERSE / 极难 / 免费
- 附件：crazyaes.exe；原始文件 SHA-256：924E14635E4ECA8823EDC8FC7F857A58F1EA1FEEDBE8210B3585E381C968280C
- 本地验证：候选输入送入修复后静态解包的程序，得到 WOW!!!
- 平台验证：提交后页面提示“FLAG 正确，恭喜你完成此挑战”，标题显示“已完成”，步骤进度 1/1
- Flag：flag{Re_1ts_f0n}

本题使用本地附件做离线静态逆向。没有把原始附件直接运行；所有头部修复与解包都在工作副本上进行。没有用联网搜索。早期错误候选只在本地测试，没有向平台提交。

## 2. 先建立证据边界
题目提供 Windows PE 文件。初始字符串看起来像自定义 AES 检查器：程序读取 flag，将 16 字节输入块做变换后与编译进程序的目标常量比较。文件头有损坏迹象，因此先核对原件哈希，再只制作副本供分析。分析过程中将“程序格式修复”“UPX 解包”“算法反推”“本地运行验证”分成独立步骤，避免把解包器误报或错误候选当成答案。

附件原件：
~~~text
路径：D:\Downloads\crazyaes-20240524094418-p72tac5.zip
ZIP 大小：155,757 bytes
解压程序：crazyaes.exe，158,720 bytes
SHA-256：924E14635E4ECA8823EDC8FC7F857A58F1EA1FEEDBE8210B3585E381C968280C
~~~

## 3. 格式识别、PE 头修复与 UPX 解包
初始 PE signature 的首字节在文件偏移 0x108 处异常。我们没有覆盖原始文件，而是复制后恢复分析副本的 PE 签名，再准备 UPX 输入副本。早期尝试用自写 NRV 解压器解析时遇到输出边界错误；它只是说明自写解码器假设不完整，不构成附件损坏的结论。随后对照官方 UPX 5.2.0 静态解包成功，得到 527,872 字节的 unpacked PE。

关键工作副本：
~~~text
crazyaes-headerpatched.exe   158,720 bytes
crazyaes-upxready.exe        158,720 bytes
crazyaes-upx-unpacked.exe    527,872 bytes
~~~

之后用 PE section header 的 raw offset 与 RVA 对照数据。曾把 .data 的虚拟地址差错地当作文件偏移，读到一片零值；重新读取 section table 并按 PointerToRawData 修正映射后，才在正确位置读到 AES key。这个修正是关键排错点：PE 内存地址不能直接当文件偏移。

静态反汇编定位到入口逻辑约 0x43b3c0。程序逐字节读入直到换行，只把前 16 bytes 放入状态块，执行自定义 AES 后与目标 16 bytes 比较。目标状态为：
~~~text
B4 38 36 30 1E 68 48 57 51 01 B7 03 9B 98 E3 7E
~~~
不相等打印 wrong!!!，相等打印 WOW!!!。这意味着可以离线还原恰好 16 bytes 的输入，不必猜更长的数据。

## 4. 先从调用链确认输入、目标值和比较规则
静态检查主函数的调用关系，逐项记录：
1. 提示串为 flag:，输入按字符读到换行。
2. 程序最多把前 16 个输入字节复制到状态块；末尾的换行不是 flag 内容。
3. 加密结果与 16 字节常量比较。
4. 比较相同进入正确分支，输出 WOW!!!；否则输出 wrong!!!。
5. 全局数据附近可见 key 和 AES 参数：key-size 0x80、Nr=10、Nk=4、Nb=4，符合 AES-128 的轮数/字数设置。
6. S-box 在 VA 0x4a1ea0；key 全局在 VA 0x4ae000；解包后 .data 的 raw offset 是 0x7b200。初次用错误文件偏移取值读到零，修正 section 映射后读到 ASCII key。

静态 key bytes 是：
~~~text
ga!43jJKgfjGMeAR
~~~

## 5. 排除反调试导致的 key 分支差异
初始化函数约 0x439cb0 调用 GetCurrentProcess 和 CheckRemoteDebuggerPresent。若没有检测到远程调试器，它会把 key 第 3 个索引（零起算）的字符写成 h；若检测到调试器，则保留原始 !。因此：
- 正常、无调试器运行的 key：gah43jJKgfjGMeAR
- 调试器存在时的 key：ga!43jJKgfjGMeAR

这不是装饰性逻辑：两条运行路径会产生不同输入。为了对照，我们把两种 key 都代入完整实现；两者都能正向映射到程序中的目标 16 字节，但只有正常执行路径解出符合 flag 格式的 ASCII 文本。这个双向对照同时验证了 key 分支分析和 AES 实现。

## 6. 从 AES 结构逐轮还原自定义变换
程序主体借用了 AES-128 的结构，但不能直接调用标准 AES 解密，因为每轮又添加了自定义操作。逐个辅助函数确认：

### 6.1 密钥扩展
- RotWord 执行字节循环旋转。
- SubWord 直接使用标准 AES S-box，不带下面状态 SubBytes 的额外变换。
- Rcon 通过字节序调整后异或到轮密钥。
- Nk=4、Nr=10，生成 11 组轮密钥。
- AddRoundKey 对 16-byte state 与对应轮密钥逐字节 XOR。

### 6.2 状态变换
- ShiftRows 是标准 AES 行循环左移，行号即偏移量。
- MixColumns 使用标准 AES 矩阵和 GF(2^8) 多项式，xtime 约在 0x43ad70；约简常数为 0x1B。
- 关键自定义点一：状态 SubBytes 在标准 S-box 查表后，再将每个结果字节 XOR 0xA1。注意 key schedule 的 SubWord 不做这一层 XOR。
- 关键自定义点二：MixColumns 的每个输出字节另 XOR 0x54。
- 关键自定义点三：每次 AddRoundKey 后都 XOR 固定 16-byte round mask：
~~~text
00 01 02 03 01 00 03 02 02 03 00 01 03 02 01 00
~~~

### 6.3 轮数顺序
程序循环从 round 0 开始：
- round 0 只执行 AddRoundKey(0)，跳过 SubBytes、ShiftRows、MixColumns。
- rounds 1–9 执行 SubBytes → ShiftRows → MixColumns → AddRoundKey，然后 XOR round mask。
- round 10 执行 SubBytes → ShiftRows → AddRoundKey，然后 XOR round mask；与标准 AES 一样省略最后一轮 MixColumns。

因此解密时必须反向撤销每一步，并且必须在逆 MixColumns 前去掉对应的 0x54；round mask 也要在每一轮正确撤销。最初漏掉 round mask、0x54 或 SubBytes 的 0xA1 中任意一项，都会给出完全不同的明文。我们保留了这些错误分支，最终只接受同时满足完整正向复算、程序输出与平台判题的结果。

## 7. 逆向解密、候选与独立复算
实现脚本文件：crazyaes_custom_aes.py。它分别对无调试器与有调试器 key 做完整的自定义 AES 逆运算，然后再将结果正向加密回目标密文。记录输出：
~~~text
no_debugger_h_mutation:
  key_hex=67616834336A4A4B67666A474D654152
  plaintext_hex=666C61677B52655F3174735F66306E7D
  plaintext_bytes=b'flag{Re_1ts_f0n}'
  custom_roundtrip=B43836301E6848575101B7039B98E37E
  matches_target=True

debugger_present_original:
  key_hex=67612134336A4A4B67666A474D654152
  plaintext_hex=8C7B7A19E30731554EE414D4F9F5D9A3
  custom_roundtrip=B43836301E6848575101B7039B98E37E
  matches_target=True
~~~

正常路径解出的字节共 16 个，包含可打印 ASCII，结构为：
~~~text
flag{Re_1ts_f0n}
~~~
大小写、数字 1 与 0 都按原样保留。先前未正确实现所有自定义轮变换时，本地候选的程序回显为 wrong!!!；这一步作为反证保留在 transcript 中，后续没有将那些猜测提交平台。

## 8. 用题目程序作本地验证
为让控制台不受非 ASCII 字节编码影响，把精确 ASCII 候选写为 16 bytes，再附换行构成 17-byte stdin 文件，然后将 stdin 重定向给静态解包的工作副本。关键命令：
~~~powershell
[byte[]]$candidateInput = [System.Text.Encoding]::ASCII.GetBytes('flag{Re_1ts_f0n}')
[Array]::Resize([ref]$candidateInput, 17)
$candidateInput[16] = 0x0A
[System.IO.File]::WriteAllBytes((Join-Path (Get-Location).Path 'crazyaes-flag-input.bin'), $candidateInput)
& cmd.exe /c '.\crazyaes-upx-unpacked.exe < .\crazyaes-flag-input.bin'
~~~

真实本地输出末尾：
~~~text
flag:WOW!!!Press any key to continue . . .
~~~
乱码提示来自 Windows 控制台代码页，只影响前面的非 ASCII banner；ASCII 判定串 WOW!!! 清楚可见。错误候选在相同程序中输出 wrong!!!，所以这个输出是本地独立验证。

## 9. 平台提交与证据
在玄机 ID 81 的题目页点“提交FLAG”，输入 flag{Re_1ts_f0n} 并提交。平台截图当场显示绿色提示“FLAG 正确，恭喜你完成此挑战”，题目标题上方标记“已完成”，步骤卡片为 1/1。该页面状态和 accessibility tree 在本轮 Computer Use 中现场核对。浏览器工具能把截图呈现在对话里，但本轮没有可保存的截图文件；手册如实保留页面文字结果，不伪造本地图片。
平台验证为最终依据：本题已完成。

## 10. 常见误区与复现资料
- 不要直接执行有损坏 PE 头的原附件；对分析副本修复，并先记录原件哈希。
- UPX 自写解包器失败不代表样本损坏；用 section/RVA 映射和可靠解包工具分离问题。
- PE RVA、VA 与 raw file offset 是不同坐标；读取 key 前先映射 section。
- 不能把“使用 AES”理解为“标准 AES”：SubBytes 的 0xA1、MixColumns 后的 0x54、每轮掩码都会改变逆运算。
- 反调试分支会修改 key；必须以实际运行路径判定用哪个 key。
- 不能只依赖自写解密器输出；至少再做正向轮函数复算，并用程序输出与平台结果双重验证。
- 本题所有命令、输入、输出、错误候选和排错过程均保留于同目录 玄机刷题-终端完整记录.txt；本条记录把关键输出按步骤整理，便于阅读。