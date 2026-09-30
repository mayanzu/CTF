# #541 — 轩辕杯云盾砺剑 CTF ezBase

## 当前结论

状态：未解决。题目详情由任务发起方确认仍为免费、未完成、1 个 flag 步骤。平台曾明确拒绝此前提交的 `flag{Y0u_@R3_Upx_4nd_b45364_m4st3r!}`。我没有访问或操作平台。

我从原始 RAR 重新核对并静态重建 PE，得到的本地校验输入仍是同一个候选；独立正向模拟逐字节匹配附件内目标串。因为它已被平台拒绝，这只能证明它满足**当前附件**中的比较逻辑，不能证明它是平台答案。没有从当前附件证据中得到新的候选，因此题目保持未解决。

## 原始附件与核验

- 原始附件：`附件_平台原件/ezBase_platform_20260929.rar`
- 附件 SHA-256：`0A7420F1D2D832474AD09EA55825900AF75EBA30DEA46DFB63F9A1AD17F0AF18`
- RAR 成员：`ezBase/ezre.exe` 和目录项 `ezBase`
- RAR 重提取副本：`附件_平台原件\解压复核_20260929\ezBase\ezre.exe`
- 提取 EXE SHA-256：`607BD3E8E5D7E715F7A9B819C8D5CC235C8DCC22F06A4AE77D0383E46BBDDACE`
- 重提取 EXE 与 `ezBase/ezre.exe` 哈希相同。批次目录内针对 `ezBase` / `dq14shk` 的只读检索只发现本附件，没有发现另一个命名变体。

整个过程仅读取原始 EXE 字节，没有执行目标程序，也没有访问网站。

## 静态重建与程序逻辑

`analysis\rederive_541.py` 从原始 EXE 解析 PE32+ 节表和入口。UPX stub 的指令 `lea rsi,[rip - 0x194e]` 位于 VA `0x14000d964`，将压缩流定位到 RVA `0xc01d`、文件偏移 `0x21d`；stub 的输出起点为 RVA `0x1000`。脚本独立实现 NRV2B 位流解码和静态 UPX 相对分支修正，没有加载或执行 PE。

- 压缩流在原始文件偏移 `0x1b60` 遇到结束标记；解码得到 `0xb6a5`（46,757）字节。
- 解码结果 SHA-256：`C06D1A34ACC1D6BD25E384E9CFACB4E07D0D6E97D7CD5545829026A953E9B2CB`。
- UPX E8/E9 和近条件跳转过滤共修正 174 个操作数；修正后 SHA-256：`1D307EDE66CEA05A2B4C6D34CF6FC71EA035884104CC133AD09DD1891C4332E3`。

重建映像的静态指令表明：

1. 主路径在 VA `0x140001089` 要求输入长度为 `0x24`（36）字节。
2. 编码器按 3 字节分组，查输出偏移 `0x3040` 的 64 字节自定义 Base64 字母表：
   `AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789+/`
3. 编码后逐字符处理：字符为 `=` 时跳过，否则 XOR `0x04`。
4. 结果与输出偏移 `0x3000` 的 48 字节常量比较：
   `iP}ui7siC`otMgA~h5o]Tg<4jPmtIvM5C~I4h644K7M~KVg=`

长度 36 是 3 的倍数，因此编码结果包含 12 个完整分组，没有 Base64 padding。把目标串逐字节 XOR `0x04` 后得到 48 个合法字母表字符；用自定义字母表逆解得到唯一的 36 字节输入：

```text
flag{Y0u_@R3_Upx_4nd_b45364_m4st3r!}
```

末尾目标字节 `=` 的另一种解释是原始 padding，但该解释只解出 35 字节，无法通过 36 字节长度门。新脚本再次正向编码候选，结果 48 字节与目标常量完全相同。

## 可复现文件与命令

从此项目目录的 PowerShell 运行：

```powershell
& .\analysis\run_rederive_541.ps1
& .\analysis\run_verify_541.ps1
```

第一条命令记录附件哈希、RAR 成员、PE/NRV2B 重建过程及逆解；第二条命令把 RAR 重提取到 `analysis\rar_reextract\`，再运行独立的正向验证器。

- PowerShell `Start-Transcript` 完整记录：`analysis/rederive_541_transcript.txt`（保留验证脚本偏移修正前的失败尝试及成功复跑）。
- 独立正向验证器：`analysis\verify_candidate_541.py`。
- 独立验证器输出：`analysis\independent_verification_541.txt`。
- 静态核心反汇编：`analysis\rederived_assembly.txt`。
- 新的原始附件重建脚本：`analysis\rederive_541.py`。

### 状态判断

当前附件唯一导出的候选与此前已被平台拒绝的输入相同。附件和解码哈希可复现，输入经过新解码结果的正向逐字节复核也通过；这些结果仍无法解释平台拒绝。未发现支持另一个答案的附件证据。保持 #541 未解决，不把本地匹配记为平台完成。

