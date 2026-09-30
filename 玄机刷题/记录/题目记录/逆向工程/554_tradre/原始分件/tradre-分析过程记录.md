# 第九届“强网杯”tradre 分析记录

- 玄机题目 ID：554；分类 REVERSE；难度中等；详情页标注免费。
- 历史状态（初稿时）：未解出、未提交 flag；后续已提交并由平台验证正确（1/1），详见指南末尾 2026-09-27 更新。
- 附件：`D:\Downloads\tradre.zip`
  - SHA256：\hexwrap{71BE666F73FF9214BEF7211C8F413FED628B9AB42ABD10EE1E2F8AB9D1995FB0}
- 解压文件：`tradre-附件\tradre`
  - SHA256：\hexwrap{2BBB2EB4E309B4D09EC793C7E20B922FCDB114AA40F3630935572020FA488CF3}

## 题面与初步检查

题目步骤写“尝试读取文件/flag获得本题flag”，但附件提供的是 64 位 ELF 可执行文件。静态字符串包含 `Input your flag:`、`This is a fake flag!`、`Correct flag! Validation passed.`，也包含 ptrace/fork 相关符号。`.rodata` 可见类似 AES Rcon 的字节表和一段 32 字节常量，推测校验可能含 AES 变换与反调试逻辑。

## 已做尝试

1. 下载附件并计算哈希，解压后确认 ELF64 x86-64，文件大小 29160 字节。
2. 初次 `Format-Hex -Count 64` 报参数错误：当前 PowerShell 的 `Format-Hex` 不支持该参数；此失败已在 transcript 中记录。
3. 用 GNU objdump 对含中文的绝对路径操作时，MSYS 路径转换把路径变成问号，导致失败；切到父目录后用相对路径成功读取文件头、符号和 `.rodata`。
4. 用 strings / objdump 检查字符串、导入符号、入口点和常量；试过将可见 32 字节常量与候选栈常量按 AES-256 ECB 正反方向解密，输出不成明文。
5. 可见 WSL 启动程序并输入空行，程序打印 ASCII art 与 `This is a fake flag!` 后退出。该信息是程序拒绝输入时的提示，不是 flag，也不表示验证成功。
6. 检查到 WSL 环境没有可用的 gdb；尚未追完反调试/控制流，因此暂停本题并换题。

## 九、攻关续记：tradre（ID 554）解出并通过平台验证（2026-09-27）

### 9.1 页面与附件复核

玄机题目页标题为“第九届‘强网杯’全国网络安全挑战赛tradre”，分类 REVERSE，难度中等，免费，积分 300。页面唯一步骤提示“尝试读取文件/flag获得本题flag”，要求将正确内容放入 `flag{}` 后提交。附件 ZIP 仅含一个 29,160 字节 ELF64 x86-64 文件 `tradre`，没有独立 flag 或远程地址。

### 9.2 观察程序结构

1. `strings` 找到 `Input your flag:`、`This is a fake flag!`、`Correct flag! Validation passed.` 等字符串，说明错误路径会打印假 flag，不能把该字面量当成答案。
2. `readelf` 显示入口地址 `0x400910`。入口将 `0x4047cb` 交给 `__libc_start_main`，该函数设置 60 秒 alarm 后 fork。
3. 子进程先调用 `ptrace(PTRACE_TRACEME)`，随后进入 `0x4009f7`；父进程持续 wait/ptrace 观察子进程的断点。主体代码散布大量 `int3`，父进程会在每次陷阱后改写子进程寄存器/栈，再继续执行。
4. 因此不能把所有 `int3` 当普通无操作指令直接跳过。我曾建立仅用于本地实验的 SIGTRAP 处理器，并让其把 RIP 加 1；运行立即触发“非法指令”，证实这种绕过会破坏题目设计的控制流。该失败没有改变原附件。
5. 随后建立 `tradre_ptrace_logger.c`：以 `LD_PRELOAD` 包装 ptrace，但把每次调用继续转交真实 libc ptrace；输出保存到 `题目资料/tradre/分析脚本/tradre_ptrace_trace.log`。输入测试串 `flag{test}` 后程序仍输出 `This is a fake flag!`。日志共 19,813 行，确认正常父子监控路径确实运行；完整原始日志保留为本地分析证据。

### 9.3 平台公开 Writeup 给出的解密规则

我打开题目页的 Writeup。平台提示“未完成挑战时查看将无法获得积分”；用户明确允许继续并接受可能失去本题积分后，我才确认进入。Writeup（作者：潍院小手手，标题“菜鸡之笔”，2026-08-17）给出以下规则：

```python
key = bytes.fromhex("f470bbc031caee5e58b272ea02f3ffe6")
target = bytes.fromhex(
    "027532640ce1c1b999349f08b1c457df"
    "202a5e01b4655cdde3dce131a2e83440"
    "8b"
)
mask = bytes.fromhex(
    "1acf9382d81f8ef9c605ca4d598fd365"
    "d9ae3f4cb57c3140fda22c7889497769"
)
used_target = target[:16] + target[17:33]
cipher = bytes(a ^ b for a, b in zip(used_target, mask))
flag_body = AES.new(key, AES.MODE_ECB).decrypt(cipher)
```

这一步有两个容易遗漏的细节：`target` 一共 33 字节，不是 32 字节；切片先取前 16 字节，再从下标 17 取至 32，故有意跳过下标 16 的单字节 `0x20`，总长重新变为 32 字节。随后逐字节与 32 字节 `mask` XOR，再用 16 字节密钥执行 AES-128-ECB 解密；输出不需要填充。

### 9.4 本地独立复算

为避免直接照抄 Writeup 作为验证，我把同样运算写入 PowerShell/.NET 脚本 `题目资料/tradre/分析脚本/tradre_decrypt_flag.ps1`，逐步打印关键中间值：

- `key`：`f470bbc031caee5e58b272ea02f3ffe6`
- `target`（33 字节）：`027532640ce1c1b999349f08b1c457df202a5e01b4655cdde3dce131a2e834408b`
- 重排后的 `used_target`（32 字节）：`027532640ce1c1b999349f08b1c457df2a5e01b4655cdde3dce131a2e834408b`
- `mask`：`1acf9382d81f8ef9c605ca4d598fd365d9ae3f4cb57c3140fda22c7889497769`
- XOR 结果 `cipher`：`18baa1e6d4fe4f405f315545e84b84baf3f03ef8d020eca321431dda617d37e2`
- AES 解密结果十六进制：`3135373639323933306365353538356666336633613637343535613033343433`
- ASCII 正文：`157692930ce5585ff3f3a67455a03443`

正文长度为 32，字符均属于小写十六进制字符集，与题目要求 `flag{}` 的形式相符。

### 9.5 平台提交验证

1. 在玄机 ID 554 题目页打开“提交FLAG”。
2. 在前台浏览器输入 `flag{157692930ce5585ff3f3a67455a03443}` 并提交。
3. 页面返回绿色提示“FLAG 正确，恭喜你完成此挑战”；题目状态变成“已完成”，步骤 #1 从 `0/1` 变成 `1/1`。刷新后的视觉截图和无障碍树在本轮 Computer Use 会话中现场可见；截图没有独立保存到本地文件，因此手册只记录可复核的页面状态，不伪称存在截图文件。

### 9.6 原始命令记录与复现文件

本轮 PowerShell 输入与可见输出追加到 `记录/四题攻关终端记录.txt`。复现脚本、ptrace 日志层和原始跟踪日志保存在 `题目资料/tradre/分析脚本/`。平台 Writeup 是本题发现 key/mask 与切片规则的直接线索；独立复算和平台正确提示则分别验证了运算与最终答案。

**结论：** tradre 已通过玄机平台验证，flag 为 `flag{157692930ce5585ff3f3a67455a03443}`。



