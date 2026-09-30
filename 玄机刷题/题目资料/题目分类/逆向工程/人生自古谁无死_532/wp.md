# 玄机题 #532：人生自古谁无死（静态分析）

## 结论与验证状态

对附件中的 `1.enc` 执行“整串反转，再逐字节 XOR `0x55`”，得到完整候选：

```text
flag{8059843e2485466699c1f639}
```

`2.enc` 使用程序静态还原出的 ChaCha20 密钥流解开后，得到 `flag{8059843e-2485-4666-}`。去掉连字符后，其内容恰好是上面完整候选中 24 位十六进制主体的前 16 位，因此它为 `1.enc` 结果提供了独立的前缀交叉核验。**平台状态：未完成。** 附件支持的首选候选已被玄机平台拒绝；另一条 EXE 分支候选提交后仍为 0/1，没有成功回执。

EXE 中另有两段隐藏文本：诱饵函数输出 `QCTF{fake_flag_do_not_submit}\x06`（末尾 `0x06` 是未处理字节），而另一条 ChaCha20 数据流得到 `SQCTF{real_chacha20_flag}`。这两段都不是附件互相印证的 `flag{...}` 候选。它们说明二进制里确有专门设计的诱饵/演示字符串，不能只因字符串看起来像 flag 就提交；本题首选候选来自两个 `.enc` 文件的一致数据。

## 1. 题目与附件

玄机题 #532，题名“商丘师范学院第四届网络安全及信息对抗大赛 人生自古谁无死”，类别 REVERSE，难度中等，页面显示免费、一个步骤 `0/1`。题面提示：“小李学了个新算法，但是可恶的阿尼亚把秘密删了，只剩下谜语。你能把给他找到答案吗？”页面可下载附件，附件 ZIP 内含 `1.enc`、`2.enc` 和 Windows PE 程序 `人生自古谁无死.exe`。

项目文件如下：

- `originals/人生自古谁无死.zip`：原始附件
- `extracted/1.enc`、`extracted/2.enc`：两个加密文件
- `extracted/人生自古谁无死.exe`：随包程序
- `analysis/solve_532.py` 与 `analysis/solve_532_output.txt`：可复现静态解题脚本和输出
- `analysis/independent_review.py`、`analysis/independent_review_output.txt`：子代理独立复核材料
- `analysis/commands_output.log`、`analysis/independent_commands.log`：完整 PowerShell 命令与输出记录
- `analysis/challenge_disassembly.txt`、`analysis/obfuscation_disassembly.txt`、`analysis/rdata_dump.txt`、`analysis/data_dump.txt`：关键反汇编和静态数据转储

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `originals/人生自古谁无死.zip` | 43,696 字节 | `C27CFAEE48A03D4512461E558795B09C2A3E715B808A5BA697A33D774C9655E5` |
| `extracted/1.enc` | 30 字节 | `AABF22FFE2D55E23FC65AFE8EC70AE6E7C0C57225B0F1540D6E070E3FB6B7E54` |
| `extracted/2.enc` | 25 字节 | `811A4C75495ADDDAD792921F525A0557AC31FE1EDC3B1A6013D6AB17249D0FB9` |
| `extracted/人生自古谁无死.exe` | 136,097 字节 | `1743BDDFE96BB079FEDF7BAC17557A5065810B4BDB8130C794C5D85D4FDF44F5` |

检查 ZIP 成员、提取文件与 SHA-256 后，所有数据均与项目记录相符。整个分析使用文件读取、十六进制检查和 `objdump` 静态反汇编；没有运行或加载题目 EXE，没有查看公开 Writeup。

## 2. 先检查两个 `.enc` 文件

### 2.1 `1.enc` 是可逆的字节变换

`1.enc` 的 30 字节原始内容为：

```text
286c66633364366c6c63636361606d61673066616d6c60656d2e32343933
```

把字节顺序反转，再让每个字节与 `0x55` 异或：

```text
P[i] = C[29 - i] XOR 0x55,  i = 0..29
```

逐字节 XOR 是自身的逆运算，因此无需密钥搜索；倒序也可逆。脚本输出 30 字节 ASCII：

```text
flag{8059843e2485466699c1f639}
```

长度、前缀 `flag{` 和闭合花括号均匹配。脚本的完整字节输入、结果和正向复现见 `analysis/solve_532_output.txt`。

### 2.2 `2.enc` 与上述主体前缀一致

`2.enc` 是 25 字节二进制，原始 hex：

```text
e59c368465b9c7c11907703035e7f45e70ccc0431e3db178d9
```

附件本身没有附带可直接说明密钥的文本。通过静态分析 EXE 的 `secure_encrypt` / `process_block` 得到 64 字节状态和 ChaCha20 密钥流，`2.enc XOR keystream` 得：

```text
flag{8059843e-2485-4666-}
```

这一短串以结束花括号结束，但主体停在连字符后，单独看像被截断的 flag。移除分组用连字符并去掉外层闭括号后，它对应 `8059843e24854666`，刚好与 `1.enc` 完整候选的 24 位十六进制主体开头 16 位一致：

```text
1.enc: 8059843e 2485 4666 99c1f639
2.enc: 8059843e 2485 4666
```

因此把 `2.enc` 记录为对主体开头的交叉校验，而不是用这条不完整文本替代完整候选。

## 3. 静态分析 EXE 与诱饵辨识

PE 文件为 x86-64 Windows 程序，保留了 COFF 符号。`objdump -t` 可见以下题目函数：

- `_Z14secure_encryptPjPhS0_i`：对输入字节与状态生成的密钥流逐字节 XOR；
- `_Z13process_blockPjPh`：复制 64 字节状态，执行 ChaCha quarter-round，再加回初始状态；
- `_Z14handle_stringsv`：处理一个诱饵串，并把另一段嵌入数据送入 `secure_encrypt`；
- `main`：检查调试器，调用 `handle_strings`，最后打印文件名提示。

程序在 `.rdata` 中打印：

```text
flag1 -> 1.enc
  flag2 -> 2.enc
```

这将注意力指向附件文件。COFF 符号还标出 `.rdata` 中的 `decoy_str` 与 `target_str`。对隐藏文本应结合生成长度和输入来源解读，不能依赖 `strings` 搜出的可读字样。

### 3.1 诱饵字符串的长度边界

`handle_strings` 把 `.rdata` 地址 `0x405050` 起的 30 字节复制到栈上。随后调用 `obf_transform` 时传入长度 `0x1d`（29），只将前 29 字节 XOR `0x55`；再调用 `flip_bytes` 时也传 29，只反转前 29 字节。最后的第 30 字节没有参加任何变换，仍为 `0x06`：

```text
QCTF{fake_flag_do_not_submit}\x06
```

其中明文已经写有 `fake_flag_do_not_submit`，是明确诱饵。注意若误把长度按 30 处理，会额外异或末字节并把它挪到开头，得到一个看似更整齐的 `SQCTF{...}`；这不是程序实际调用参数，不能据此描述真实执行结果。

### 3.2 重建 ChaCha20 状态

`handle_strings` 构造状态的内存布局为：

```text
16-byte constant || 32-byte key || 4-byte counter || 12-byte nonce
```

静态 `.data` 显示常量 `g_obf1` 内容为 ASCII `expand 32-byte k`；`g_obf2` 的内存字节顺序为 `DE AD BE EF`。循环逐字节设置密钥：

```text
key[i] = (i + 0x11) XOR g_obf2[i mod 4],  i = 0..31
```

例如：

```text
i=0: 0x11 XOR 0xDE = 0xCF
i=1: 0x12 XOR 0xAD = 0xBF
i=2: 0x13 XOR 0xBE = 0xAD
i=3: 0x14 XOR 0xEF = 0xFB
```

得到 key：

```text
cfbfadfbcbbba9f7c7b7a5f3c3b3a1cfff8f9dcbfb8b99c7f78795c3f38391df
```

counter 为 `00000000`。nonce 循环按 `nonce[i] = i * 0x11` 赋值，因此为：

```text
00112233445566778899aabb
```

`process_block` 的四元组运算是 ChaCha quarter-round：加法按 32 位回绕，接着 XOR 和循环左移 `16, 12, 8, 7` 位。外层循环运行 10 次，每次先做 4 个列向 quarter-round，再做 4 个对角 quarter-round，即 20 轮 ChaCha；最后每个工作状态字加上对应初始状态字。反汇编中的循环上界比较、各状态偏移、移位常量和最终的 16-word 加回共同支持该复现。

生成的密钥流开头为：

```text
83f057e31e81f7f4203f440350cac66a48f9ed77280b8755a4
```

用它与 25 字节 `2.enc` XOR 得到前述残片。相同密钥流与 PE `.rdata` 的 25 字节 `target_str` XOR，则得到另一字符串：

```text
SQCTF{real_chacha20_flag}
```

这条嵌入串虽然经过可复现的 ChaCha20 解密，但附件 `1.enc` 与 `2.enc` 的 24 位主体交叉验证共同指向另一个完整的 `flag{...}` 候选。此处保留所有证据与歧义，平台验证前不把嵌入演示串写成已接受答案。

## 4. 求解步骤复现

在题目文件夹 `人生自古谁无死_532` 下运行：

```powershell
python .\analysis\solve_532.py
```

脚本只读取 `extracted/1.enc`、`extracted/2.enc`，在 Python 中复现从反汇编恢复的 ChaCha20 状态，输出两个附件的字节解码、候选前缀比较，并展示真实 decoy 长度的结果。脚本不启动或加载 EXE，也不访问网络。Python 控制台首次直接打印二进制时遇到 GBK 对替换字符的编码错误；随后改成 ASCII 反斜线转义，重跑成功。失败和修正过程均保存在 `analysis/commands_output.log`。

## 5. 结论、平台步骤和限制

由两个附件互相支持的本地首选候选（平台已拒绝）：

```text
flag{8059843e2485466699c1f639}
```

2026-09-29 提交附件候选后，平台明确返回“FLAG 不正确”；随后提交 target_str 解密所得 SQCTF 候选，详情仍显示步骤 0/1，未出现完成回执。本题保持未完成。不得将本地解密结果等同于平台通过。

所有已执行的 PowerShell 命令、输出与错误都记在 `analysis/commands_output.log`；子代理独立复核结论与其命令输出分别记录在 `analysis/independent_review_output.txt` 和 `analysis/independent_commands.log`。源 ZIP、提取文件、静态脚本、输出和反汇编均保留在本题目录。


## 6. 玄机平台提交记录（2026-09-29）

2026-09-30 补充：平台标准前缀变体 `flag{real_chacha20_flag}` 也已在登录账号的题页提交。对话框关闭后仍为 `0/1`，未见成功回执；因此 EXE 内嵌演示串改换外层格式也未解决题目。本轮浏览器操作见项目 `记录/未解题续攻_20260930.md`。

同日再按 `2.enc` 明确给出的 `8059843e-2485-4666-` 和 `1.enc` 的尾部 8 位十六进制，把后段写成 `99c1-f639`，提交 `flag{8059843e-2485-4666-99c1-f639}`。平台仍为 `0/1`，未见成功回执。此前无分隔符与 `8-4-4-8` 分组均未通过，此次 `8-4-4-4-4` 分组也被排除。

- 页面：https://xj.edisec.net/challenges/532，题目为“人生自古谁无死”，提交前步骤为 0/1。
- 第一次提交：flag{8059843e2485466699c1f639}。平台明确提示“FLAG 不正确”，步骤仍为 0/1。
- 第二次提交：SQCTF{real_chacha20_flag}。该值来自 EXE 中 target_str 的 ChaCha20 解密分支；提交后页面没有出现成功提示，重新查看详情仍为 0/1。本次不把它记录成平台接受，后续需要新证据判断是否值得继续。
- 两次提交通过 Chrome 前台 computer-use 点击表单完成。截图在会话中展示，未保存 PNG 到项目。

## 7. 2026-09-30 续攻：按第二份附件插入分组符

`2.enc` 解密文本为 `flag{8059843e-2485-4666-}`，给出了前三组的连字符位置；`1.enc` 给出完整主体 `8059843e2485466699c1f639`。将剩余八位接在最后一个连字符后，得到由两份附件共同支持的格式候选 `flag{8059843e-2485-4666-99c1f639}`。在玄机 #532 页面提交后明确收到“FLAG 不正确~”，步骤保持 0/1。此结果排除了仅因漏写三个连字符导致旧候选失败的解释，题目继续未完成。记录见 `记录/未解题续攻_20260930.md`。
