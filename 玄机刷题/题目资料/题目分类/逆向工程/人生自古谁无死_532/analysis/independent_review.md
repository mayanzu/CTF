# #532「人生自古谁无死」独立静态复核

**状态：静态推导完成，尚未提交玄机平台。** 本复核只读取附件并对 PE 做静态分析；没有运行或加载挑战 EXE，没有联网查公开 WP，也没有提交任何候选。

## 1. 样本与证据

附件目录：`extracted/`。独立核对的 SHA-256：

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `人生自古谁无死.exe` | 136,097 | `1743BDDFE96BB079FEDF7BAC17557A5065810B4BDB8130C794C5D85D4FDF44F5` |
| `1.enc` | 30 | `AABF22FFE2D55E23FC65AFE8EC70AE6E7C0C57225B0F1540D6E070E3FB6B7E54` |
| `2.enc` | 25 | `811A4C75495ADDDAD792921F525A0557AC31FE1EDC3B1A6013D6AB17249D0FB9` |

用 `objdump -s -j .data -j .rdata analysis/target.exe` 对与附件 SHA 相同的 ASCII 路径副本做只读 section dump。原始 dump 明确显示：

- `.data+0x20`：ASCII `expand 32-byte k`。
- `.data+0x40`：原始字节顺序 `DE AD BE EF`。这里按 objdump 十六进制 dump 的字节序逐字节读取，不能把显示文本 `deadbeef` 当成一个小端整数后再倒序。
- `.rdata+0x50`：嵌入的混淆字符串（30 字节），与磁盘 `1.enc` 是两份不同数据。
- `.rdata+0x70`：25 字节 `target_str`：`d0 a1 14 b7 58 fa 85 91 41 53 1b 60 38 ab a5 02 29 cb dd 28 4e 67 e6 32 d9`。

完整 section 证据保存在 [independent_sections.txt](independent_sections.txt)，PowerShell transcript 记录在 [independent_commands.log](independent_commands.log)。

## 2. `1.enc`：反转后 XOR `0x55`

1. 附件原始 30 字节：

   ```text
   28 6c 66 63 33 64 36 6c 6c 63 63 63 61 60 6d 61 67 30 66 61 6d 6c 60 65 6d 2e 32 34 39 33
   ```

2. 全部 30 字节反转：

   ```text
   33 39 34 32 2e 6d 65 60 6c 6d 61 66 30 67 61 6d 60 61 63 63 63 6c 6c 36 64 33 63 66 6c 28
   ```

3. 每字节 XOR `0x55`：

   ```text
   66 6c 61 67 7b 38 30 35 39 38 34 33 65 32 34 38 35 34 36 36 36 39 39 63 31 66 36 33 39 7d
   ```

   ASCII 为 **`flag{8059843e2485466699c1f639}`**。中间 24 位十六进制值是 `8059843e2485466699c1f639`。反转与逐字节 XOR 固定常数可交换顺序，结果一致。

## 3. EXE 中另外一条显式假线索

`handle_strings`（`0x401ade`）从 `.rdata+0x50` 复制 30 字节，但对这份嵌入字符串只传长度 29：先 `obf_transform` 将索引 `0..28` 各 XOR `0x55`，再 `flip_bytes` 反转索引 `0..28`。最后一个 `0x06` 未处理。结果为：

```text
QCTF{fake_flag_do_not_submit}\x06
```

因此这条字符串明确是诱饵，不能与磁盘上的 `1.enc` 混为一谈。变换函数依据：`obf_transform` 位于 `0x401530`，`flip_bytes` 位于 `0x40157c`；相应循环和调用参数见 `analysis/challenge_disassembly.txt` 中 `0x401ade` 附近。

## 4. 从静态反汇编恢复流密码状态

`handle_strings` 构造 64 字节初态并传给 `secure_encrypt`（`0x401600`）；`secure_encrypt` 调用 `process_block`（`0x40166e`）生成 64 字节 keystream，再将输入字节与 keystream XOR。XOR 对称，因此相同操作可解密。

初态逐段恢复如下：

1. `state[0:16] = b"expand 32-byte k"`，直接来自 `.data+0x20`。
2. 反汇编的循环对 `i=0..31` 写入 `((i + 0x11) XOR g_obf2[i mod 4]) & 0xff`。`g_obf2` 原始内存字节是 `DE AD BE EF`，所以 `state[16:48]` 为：

   ```text
   cf bf ad fb cb bb a9 f7 c7 b7 a5 f3 c3 b3 a1 cf
   ff 8f 9d cb fb 8b 99 c7 f7 87 95 c3 f3 83 91 df
   ```

3. 指令 `mov DWORD PTR [rbp+0x30],0` 明确设置 `state[48:52] = 00 00 00 00`。
4. 后续循环 `state[52+i] = (i<<4)+i`，`i=0..11`，所以为 `00 11 22 33 44 55 66 77 88 99 aa bb`。

以 little-endian 32 位 word 表示的初态是：

```text
61707865 3320646e 79622d32 6b206574
fbadbfcf f7a9bbcb f3a5b7c7 cfa1b3c3
cb9d8fff c7998bfb c39587f7 df9183f3
00000000 33221100 77665544 bbaa9988
```

`process_block` 复制 16 个 word，在循环计数 `0..9` 中执行 10 个 ChaCha 双轮；每双轮先按列再按对角线做 8 个 quarter-round，旋转量是 `16,12,8,7`。最后逐 word 加回初始状态（32 位模加）并按 little-endian 输出。这里使用的是附件代码构造的定制 64 字节状态；不能擅自换成 RFC 常见 key/nonce/counter 布局。

独立脚本得到的 64 字节块输出（即本题使用的 keystream）：

```text
83 f0 57 e3 1e 81 f7 f4 20 3f 44 03 50 ca c6 6a
48 f9 ed 77 28 0b 87 55 a4 2a 88 e3 f7 95 0c 8d
84 4b 5f a7 72 0c f7 76 b0 0a ed 44 07 86 9d 98
4f 22 f5 7e 9c ae 77 18 ac e4 d1 5f 59 b1 c5 c3
```

## 5. `2.enc` 与交叉核验

用上述 keystream 的前 25 字节与 `2.enc` XOR，得到：

```text
flag{8059843e-2485-4666-}
```

它只包含 `8059843e24854666` 这 16 位十六进制前缀，并在下一组之前停住。与 `1.enc` 解出的 24 位内容比较：

```text
1.enc 完整值：8059843e 2485 4666 99c1f639
2.enc 可见值：8059843e-2485-4666-
```

也就是说，两个附件在相同解码链上相互印证；`2.enc` 单独没有给出末尾 `99c1f639`，但完整 `1.enc` 给出了它。仅凭现有 25 字节不能判断 `2.enc` 是有意截短的提示还是作者留的片段，因此记录为数据限制，不从 `2.enc` 单独臆造后缀。

**当前最受附件交叉证据支持的提交候选：`flag{8059843e2485466699c1f639}`。** 这是静态推导，不等于平台已验证。

## 6. 嵌入 `target_str` 的歧义候选

同一 keystream XOR `.rdata+0x70` 的 25 字节也会得到完整文本 **`SQCTF{real_chacha20_flag}`**。它是另一个旗标形字符串，不能在没有平台反馈前声称它无效；不过磁盘 `1.enc` 的完整 GUID 形内容与 `2.enc` 的 GUID 前缀相互吻合，故本复核把附件一致支持的 `flag{8059843e2485466699c1f639}` 排在首位，并将 `SQCTF{real_chacha20_flag}` 作为未验证的嵌入候选单独保留。玄机页面验证仍是最终判据。

## 7. 复现文件

- [independent_review.py](independent_review.py)：只读文件字节并复现反转/XOR 与 ChaCha 核心；没有加载或执行 EXE。
- [independent_verified_output.txt](independent_verified_output.txt)：修正内存字节序后的独立输出。
- [independent_sections.txt](independent_sections.txt)：从与附件 SHA 一致的 ASCII 路径样本导出的 PE `.data` / `.rdata` 原始 dump。
- [independent_commands.log](independent_commands.log)：本次 PowerShell Start-Transcript，保留命令、输出、失败的中文路径探测以及修正后的结果。
