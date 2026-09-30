# #533 圣人当仁不让：静态逆向 WP

## 结论

**最终平台验证的 flag：`flag{a1e05109-4x}`。**2026-09-30 在玄机 #533 页面提交后显示“已完成”、`1/1`，完成数由 0 变为 1，账号 `slu_mzj` 获一血。

附件可静态还原出校验器。checker 的 Base64 填充错误让三个 17 字节输入都通过比较：

- flag{a1e05109-4xT
- flag{a1e05109-4xU
- flag{a1e05109-4xW

它们均没有闭合花括号；成功分支只打印“你太强了！！”，没有输出其他 flag。基于前 16 字节已经确定、末字节因错误 padding 丢失的事实，再按常见 flag 格式测试闭合花括号 `}`，得到最终获平台接受的 17 字节文本。必须区分：这一完整 flag **不能通过附件的错误 Base64 比较**，但获玄机服务端确认。未执行未知 EXE。

## 1. 附件完整性

原始附件 originals/ez_vm.zip 的 SHA-256 为 B9B280302A0B975F272CFCA88B59CFFB0EDE4DE3529D56A1BB328CE0D0ED071E。解压程序 analysis/ez_vm.exe 大小 82,661 bytes，SHA-256 为 918ACDAA4DF332FC53C0D8F2B0FC281D5B2710753C5C27BFC53F97E530572E91。ZIP 只有 ez_vm.exe，且解压文件字节与 ZIP 成员完全相同。

静态 PE 信息：PE32+ x86-64，ImageBase 0x140000000，Entry RVA 0x1125，11 个 section，导入 KERNEL32.dll 和 msvcrt.dll。通过自写 PE/字符串扫描和 GNU objdump 读取元数据及反汇编；未运行附件。

## 2. 主程序约束

main 位于 0x1400018b9。它打印“请输入 flag: ”，用 fgets(buffer, 0x12, stdin) 读取最多 17 字符，通过 strcspn 去除换行，要求 strlen 恰为 17。之后复制 17 字节，调用 VM 对字节原位操作，再将 17 字节传给 Base64 编码函数，最后 strcmp 与常量 z8nO0NTOntKdop6dloqh1Q== 比较。

成功只打印“你太强了！！”，无效则打印“错误：输入的flag无效。”，长度错误则打印相应长度错误。成功分支不打印另一个 flag。

## 3. VM 逆向

_Z10vm_executePc 位于 0x140001823，循环下标从 0 到 16（包含 16）。每字节三步为 XOR 0xAA、加 5、减 2，结果写回 byte。因此：

    y = ((x XOR 0xAA) + 3) mod 256
    x = ((y - 3) mod 256) XOR 0xAA

伪代码：

    for i in range(17):
        buf[i] = ((buf[i] ^ 0xAA) + 5 - 2) & 0xFF

具体机器指令及原始输出保存于 533_static_analysis_transcript.txt。

## 4. Base64 及尾部信息损失

编码使用标准字符表；17 字节输出长度为 24。尾部代码却用：

    pad = (24 - (17 mod 3)) & 3 = 2

于是两字符被覆盖为“==”。标准 Base64 编码 17 字节只应有一个等号。被多覆盖的一个有效字符承载输入末字节的低四位，因此只凭常量无法还原该字节。

目标串解码出的 16 字节为 cfc9ced0d4ce9ed29da29e9d968aa1d5。按逆变换还原前 16 个输入字节，得到 flag{a1e05109-4x。尾部符号只约束末字节的高位；对 ASCII 可打印字节枚举，并使用附件的错误 padding 正向复核，T、U、W 三个输入都准确产生原常量。

## 5. 排除的假设

- 直接把 Base64 解码字节当 flag：错误，解码值已经过 VM 变换。
- 单字节 XOR 或统一减常量：对所有目标解码字节穷举后，没有一个值让整串变为可打印文本，且静态机器码明确显示为组合变换。
- 将末字节补为闭合花括号 `}`：附件错误的 Base64 比较会得到 z8nO0NTOntKd6dloqh1d==，与内置常量不匹配；但这条规范文本后来获玄机平台接受。它揭示了本地校验实现与服务端答案之间的差异。
- 在三个尾字符中凭感觉选一个：没有依据，三个输入都能通过附件自身的比较，且都不是完整 flag。
- 把附件 checker 通过等同于平台接受：没有平台验证，且成功分支没有显示旗标。

## 6. 复现材料

- originals/ez_vm.zip：原附件。
- analysis/ez_vm.exe：原始解压程序。
- analysis/static_pe.py：PE 头、section、import 和字符串扫描。
- analysis/derive_candidate.py：逆变换、可打印字符枚举和前向复核。
- analysis/inspect_tail.py：常量尾部、GBK 字节串和闭合花括号假设检查。
- 533_static_analysis_transcript.txt：命令、完整输出、工具错误与反汇编记录。
- evidence/533_static_evidence.md：证据摘要。

历史状态：2026-09-29 静态分析时，尚未向平台验证闭合花括号候选；最终状态以文末补记为准。

## 2026-09-30 平台验证补记

此前“未提交”描述对应 2026-09-29 的静态分析轮次。2026-09-30 在玄机 #533 页面分别提交校验器能接受的三个可打印输入：

```text
flag{a1e05109-4xT
flag{a1e05109-4xU
flag{a1e05109-4xW
```

平台对 `T`、`U` 明确显示“FLAG 不正确~”；`W` 提交弹窗关闭后页面仍为 `0/1`，未见成功回执。三者均未得到平台接受，不能将 EXE 内部成功分支当作题目完成。平台页面也显示“3 人参与，0 人完成”。页面操作与回执记录见 `记录/未解题续攻_20260930.md`。

## 7. 独立复核与重现

新增 `analysis/independent_verify.py`，不调用此前的候选推导脚本；它独立核验原 ZIP 与保存 PE 的 SHA-256、ZIP 成员字节一致性、PE 基本头、目标常量，手写 Base64 位解码和标准编码，再照反汇编的 padding 循环前向枚举末字节。以字节为域共有 16 个可通过的末字节值，其中 3 个是可打印 ASCII：`T`、`U`、`W`。这再次排除了唯一候选。

运行命令：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File ./analysis/run_independent.ps1
```

完整独立验证输出保存于 `evidence/independent_verification.txt`，反汇编文本另存于 `evidence/independent_static_disassembly.txt`；该 PowerShell `Start-Transcript` 命令日志（包括命令标记、校验输出及关键函数静态反汇编）保存于 `533_reproduction_transcript.txt`。原始迭代记录保留在 `533_static_analysis_transcript.txt` 和 `533_independent_verification_transcript.txt`。该流程仅读取 ZIP/PE 并静态反汇编，不启动附件程序，也不联网或提交。

## 8. 完整 flag 的确定与平台验证（2026-09-30）

1. 从目标 Base64 串中可逆出的前 16 个明文字节固定为 `flag{a1e05109-4x`。
2. 本地错误 padding 覆盖最后一组编码字符，失去末字节的低四位信息。因此本地比较只能约束一部分末字节，不能凭它断言平台答案必须是 `T`、`U` 或 `W`。
3. 常规 flag 语法需要闭合 `}`。将其补为第 17 字节，得到 `flag{a1e05109-4x}`。它长 17 字节，前 16 字节与静态逆向结果一致；对本地比较却生成不同的尾部 Base64，说明附件校验器有实现缺陷。
4. 在登录的玄机页面 `https://xj.edisec.net/challenges/533`，从提交框完整输入上述候选并提交。详情页更新为“已完成”、步骤 `1/1`，显示“3 人参与，1 人完成”及账号 `slu_mzj` 一血。该候选由平台确认。

本题教学重点是把静态程序分析与平台验证分开：错误的附件校验器可能漏掉真实答案；恢复确定的前缀后，候选的剩余字符仍需通过题目格式和平台回执确认。平台操作摘要见项目 `记录/未解题续攻_20260930.md`。
