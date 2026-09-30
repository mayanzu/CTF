# 玄机 ID 542「轩辕杯”云盾砺剑CTF挑战赛 REVERSE hookme」完整 WP

## 0. 状态与边界

本批附件的静态分析已形成候选 `flag{ee9fb062624c1e527fab36d3a27484d1}`。离线脚本按推定算法重新加密，得到的 38 字节与资源表中 `correct_ciphertext` 一致；这只是本地模型内部的闭环，不能证明平台接受。

**平台核验未通过：**2026-09-29，主线程通过 Chrome Computer Use 在 [玄机 ID 542 题页](https://xj.edisec.net/challenges/542)提交该候选，页面明确显示“FLAG 不正确~”，进度仍为 0/1。因此候选不能作为已验证 flag，本题仍未解决；应继续检查算法、种子、输入处理或题目提交预期，不得据本地闭环标记完成。提交过程记录见[批次提交核验记录](../../../../记录/批次记录/第10批/原始分件/提交核验_20260929_第十批.md)。本子代理不再提交平台。

本 WP 只依据本批新下载的 `..\..\..\原始下载附件\hookme.rar`，没有使用旧题目资料或旧 WP。RAR 内只发现一个 APK。没有安装、启动或运行 APK，也没有执行 APK 内的任何 `.so`；分析脚本只读取二进制数据并静态解析 DEX、资源表和 ELF。

## 1. 原始附件核验与解包

原始文件：`..\..\..\原始下载附件\hookme.rar`

- 大小：5,125,397 bytes
- SHA-256：`1DC981B273CB80A32863B9A89A09CFA82B731F6D4BC8E37D72C445DEB29E993F`
- `tar.exe -tf` 清单：`hookme/HookMe.apk`，以及目录项 `hookme`
- RAR 清单中 APK 长度：7,329,635 bytes

使用系统 `tar.exe` 仅提取该成员到 `附件解包\hookme\HookMe.apk`。解出的 APK SHA-256：

`61BB5BA33C8EBD3BD01BA9ECF6EDC69A18D664D91F3309447B95132B27E14E9B`

APK 是 ZIP 格式，共 891 个成员。关键成员：

| 成员 | 大小 | SHA-256 |
|---|---:|---|
| `AndroidManifest.xml` | 5,328 | `1585F1535F814F2B9BA93A750357F8BFF24DA68A0DAD2BCA71284FCB91019059` |
| `classes.dex` | 9,916,936 | `488746FFA37A656EB3CBCD28D78F0179D2DEA53C1F73DC23926D21ABC86EE019` |
| `classes2.dex` | 512,592 | `6CBBB5CA6B4D734C017973D9782BCB79C4BBF995F93DD6F66B3E4EFB8BFECE4E` |
| `classes3.dex` | 2,464 | `59E97C3D35CE2D9AD7148B65630048E4C7E193D1BCBE60CF4844AB0ADEB58DD8` |
| `classes4.dex` | 5,112 | `C3CB9DB6ECF2DBBFA9B1C49476B9EE1EDC3085AA6808B5CFF98190EE3FABF0CA` |
| `resources.arsc` | 1,013,392 | `EA931FC8C84136C30E96356FA3B906D4B160A36B9C1C85F68787E48280B4021E` |
| `lib\arm64-v8a\libhookme.so` | 442,072 | `7E34475E2B6B29C3CF9AC7F256544FCE17264F992E418B2DB6667CEA35D91B85` |
| `lib\armeabi-v7a\libhookme.so` | 265,360 | `3F0F0FE9814293CF1826D7C663128BFA9505883C554E4295C15523800891A9DB` |
| `lib\x86\libhookme.so` | 413,936 | `1F337C1D15A8F212EE1CC8BBF05D6820AC5CF9EF802ABF3FC517D63F7A17E763` |
| `lib\x86_64\libhookme.so` | 418,600 | `C222F80B8C1565594F821648EA6FC36625501E213E61C48E22FFF83A3768F6C1` |

完整 ZIP 成员、压缩前后大小、CRC32 与逐成员 SHA-256 保存在 `records\apk_inventory_20260929.txt`；对应离线脚本为 `analysis\apk_inventory.py`。

## 2. 先从 DEX 找验证入口

系统没有 `jadx`、`apktool`、`aapt` 或 Androguard。保留了这项工具盘点：`records\tool_inventory_20260929.txt`。因此从 DEX 头部和表项写了只读解析器，并用 Capstone 反汇编 ELF 函数，没有安装或运行 APK。

应用入口在 `classes4.dex` 的 `Lcom/example/hookme/MainActivity;`。静态字符串包括：

- `rc4Encrypt`
- `encryptedData`
- `correctCiphertext`、`correctCiphertextHex`、`correct_ciphertext`
- `setPackageNameToNative`
- `hookme`
- `inputField`、`submitButton`、`resultTextView`
- `success`、`wrong`、`请输入flag！`

完整的 app 自有方法表和反汇编在 `analysis\dex\classes4.dex.corrected_report.txt` 与 `analysis\dex\classes4.dex.disasm.txt`。关键控制流如下：

1. 静态初始化调用 `System.loadLibrary("hookme")`。
2. `onCreate()` 调用 `getPackageName()`，把返回的包名传给 native `setPackageNameToNative(String)`。
3. 提交按钮回调读取文本框内容。输入为空时显示“请输入flag！”。
4. 非空输入调用 native `rc4Encrypt(String)` 得到字节数组。
5. 从 `R.string.correct_ciphertext` 读取十六进制字符串，经 `hexStringToByteArray` 解码后用 `Arrays.equals` 与 native 结果逐字节比较。
6. 相等显示 `success`，否则显示 `wrong`。

### 一处解析器误报

第一版自写 DEX 清单脚本漏报了两个 native 方法，输出了 `native_methods=0`。我保留了错误版的脚本/报告，并以另一份按 `class_data_item` 逐字段重新解析的 `analysis\dex_static_corrected.py` 核对。正确报告列出：

- `MainActivity.rc4Encrypt(Ljava/lang/String;)[B`，`access_flags=0x111`，`code_off=0`（native）
- `MainActivity.setPackageNameToNative(Ljava/lang/String;)V`，`access_flags=0x111`，`code_off=0`（native）

正确的解析结果与 Java/Kotlin 静态反汇编、ELF 导出 JNI 函数互相吻合。失败输出和修正版 transcript 分别在 `records\dex_static_rerun_20260929.txt`、`records\dex_debug_20260929.txt`、`records\dex_static_corrected_20260929.txt`。

## 3. 从资源表取出目标密文

`correct_ciphertext` 不是 DEX 常量，而是 APK 编译资源。`analysis\arsc_parse.py` 只读解析 `resources.arsc` 的全局字符串池、包字符串池、类型块和资源项。

解析结果：

```text
RESOURCE 0x7f0f002f string/correct_ciphertext =
f235b888b3f4e08bff17e7e29bc3bf67d0f9a1b7b6581bb4a1eb299684e99923a8d193caf91d
```

密文长度为 76 个 hex 字符，即 38 字节。完整解析文件为 `analysis\resources\arsc_parse.txt`，命令输出记录于 `records\arsc_parse_20260929_retry.txt`。

## 4. 确认 RC4 key：包名

二进制 XML/资源包标识给出 `com.example.hookme`，并且应用类路径也是 `Lcom/example/hookme/MainActivity;`。更关键的是 DEX 的真实调用顺序：`getPackageName()` 的返回值直接传给 `setPackageNameToNative(String)`。

四个 ABI 的 `libhookme.so` 都导出：

- `Java_com_example_hookme_MainActivity_setPackageNameToNative`
- `Java_com_example_hookme_MainActivity_rc4Encrypt`
- `_Z10rc4Encrypt...`
- `_Z14initializeSBox...`
- `_Z3ksa...`
- `_Z4prga...`

AArch64 `.rela.plt` 修正后的符号对应表进一步确认 native 函数调用链：

| PLT 地址 | 符号 |
|---:|---|
| `0x65fc0` | `initializeSBox` |
| `0x66020` | `ksa` |
| `0x66030` | `prga` |
| `0x66050` | `rc4Encrypt` |

`Java_*_setPackageNameToNative` 把 JNI 字符串转成 `std::string`，在 mutex 保护下保存为全局 key。`Java_*_rc4Encrypt` 取输入字符串并读取同一个全局 key，调用 `_Z10rc4Encrypt(key,input)`，最后将结果复制回 Java `byte[]`。四个 ABI 的静态符号清单、函数反汇编及 SHA-256 分别在 `analysis\native\*_libhookme.so.txt` 与 `analysis\native\*_libhookme.so.disasm.txt`。

## 5. 反编译自定义 S-box 初始化

函数 `_Z14initializeSBox` 接收输出缓冲区和 `std::string key`。

### 5.1 从 key 的前两字节构造 PRNG seed

AArch64 的相关指令顺序（地址以 `lib\arm64-v8a\libhookme.so` 为准）：

1. 读取 `key[0]`，保存到临时值。
2. 读取 `key[1]`。
3. 执行 `orr w8, w8, w9, lsl #8`，所以 seed 是 `key[1] | (key[0] << 8)`。

包名开头两个 UTF-8 字节为 `0x63 0x6f`，因此：

```text
seed = 0x6f | (0x63 << 8) = 0x636f = 25455
```

这一步有一个容易踩的端序坑：把它写成 `key[0] | (key[1] << 8)` 会得到 0x6f63，解密结果不可读。错误尝试被保存在 `analysis\failed_seed_little_endian.py` 和 `records/final_solver_replay_20260929.txt` 的 ATTEMPT 1；根据实际 `orr` 指令改正后才得到合法 flag。

### 5.2 生成 256 字节初始状态

初始化过程使用标准参数的 `std::mt19937`（32 位 Mersenne Twister）：

```text
state[0] = seed
state[k] = (1812433253 * (state[k-1] xor (state[k-1] >> 30)) + k) mod 2^32
```

机器码明确包含状态长度 624、偏移 `0x1380 = 624 * 8`、跳跃量 397、常数 `0x9908b0df`、掩码 `0x7fffffff`/`0x80000000`。输出 tempering 对应：

```text
x ^= x >> 11
x ^= (x << 7)  & 0x9d2c5680
x ^= (x << 15) & 0xefc60000
x ^= x >> 18
```

每次随机输出只取最低 8 位，依序填入 `S[0..255]`。这不是标准 RC4 的 `S[i]=i` 初始化；如果忽略 PRNG 这一步，后续 RC4 即使写对也会失败。

正确 seed 下，脚本列出的前 8 个 PRNG 输出为：

```text
1f6217df, b54945be, c0032c26, aa67d988,
f954e755, 3807be10, 926687e6, 96b6f54d
```

初始 S-box 前 32 字节为：

```text
dfbe26885510e64d9aea6a0707d86813eaea9e8bda6115bb9cff4c68c836eef2
```

MT 初始化和逐槽 twist/temper 实现记录在 `analysis\solve_static.py`。脚本还与独立的批量 twist 参考实现比较前 256 个输出，结果 `MT_IMPL_MATCH=True`。

## 6. KSA 与 PRGA

初始化 S-box 后，`ksa(S,key)` 遍历 256 项。反汇编可见 `key` 长度、`i % key.length`、两字节求和取模 256、交换 `S[i]` 与 `S[j]`。对应：

```text
j = 0
for i = 0..255:
    j = (j + S[i] + key[i % len(key)]) mod 256
    swap(S[i], S[j])
```

这里 `key` 是完整 UTF-8 包名 `com.example.hookme`，十六进制为：

```text
636f6d2e6578616d706c652e686f6f6b6d65
```

`prga(S,input)` 由反汇编确认使用两个 8 位滚动索引、交换状态项、从 `S[(S[i]+S[j]) mod 256]` 取字节并与输入 XOR：

```text
i = 0; j = 0
for each input byte p:
    i = (i + 1) mod 256
    j = (j + S[i]) mod 256
    swap(S[i], S[j])
    k = S[(S[i] + S[j]) mod 256]
    output = p xor k
```

因此变换是 XOR 流，解密与加密相同：把目标密文作为 PRGA 输入即可恢复明文。

## 7. 离线求解与闭环

运行命令：

```powershell
& 'C:\Users\mzj\AppData\Local\Programs\Python\Python312\python.exe' 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542\analysis\solve_static.py'
```

脚本读取 `analysis\resources\arsc_parse.txt` 中的资源值，不执行 APK。求解步骤：

1. 取 key `com.example.hookme`。
2. 依照 native 指令合成 seed `0x636f`。
3. 用 MT19937 产生 256 个低字节作为自定义初始 S-box。
4. 用完整 key 执行 KSA。
5. 将资源密文交给 PRGA，得到明文。
6. 用新 S-box 从头正向加密明文，与原密文比较。

输出要点：

```text
CIPHERTEXT_LEN=38
PLAINTEXT_HEX=666c61677b65653966623036323632346331653532376661623336643361323734383464317d
PLAINTEXT_UTF8=flag{ee9fb062624c1e527fab36d3a27484d1}
FORWARD_CLOSURE=True
REPRODUCED_HEX=f235b888b3f4e08bff17e7e29bc3bf67d0f9a1b7b6581bb4a1eb299684e99923a8d193caf91d
```

复现日志：`records/final_solver_replay_20260929.txt`。注意 ATTEMPT 1 是有意保留的端序错误结果；只有 ATTEMPT 2 与 native 指令一致。

## 8. 平台验证结果（未通过）

- 时间：2026-09-29。
- 操作：主线程通过 Chrome Computer Use，在 [玄机 ID 542 题页](https://xj.edisec.net/challenges/542)提交精确候选 `flag{ee9fb062624c1e527fab36d3a27484d1}`。
- 页面反馈：`FLAG 不正确~`；题目进度仍为 `0/1`。
- 结论：提交未通过，题目保持未解决状态。`FORWARD_CLOSURE=True` 只说明当前离线脚本按当前模型可以重现附件密文；这项自洽检查不能推翻平台拒绝结果。候选或对附件逻辑的解释仍需修正。
- 完整提交核验记录：[提交核验_20260929_第十批.md](../../../../记录/批次记录/第10批/原始分件/提交核验_20260929_第十批.md)（由主线程整理）。本子代理不会再次提交。

## 9. 本次踩坑与修正记录

失败尝试全部保留，便于复查，不作为解题依据：

1. Windows 默认 GBK 控制台无法显示部分 DEX 字符串，第一次筛选抛 `UnicodeEncodeError`。修正：详细结果写 UTF-8 文件，并设 `PYTHONIOENCODING=utf-8`；记录 `records\dex_string_extract_20260929.txt`。
2. 第一次解析 `resources.arsc` 把 package chunk 的 `typeStrings` 与相邻字段错位，触发 “not string pool” 异常。修正：按结构分别读 `typeStrings` (+268)、`keyStrings` (+276)、`typeIdOffset` (+284)；记录 `records\arsc_parse_20260929.txt`（失败）和 `records\arsc_parse_20260929_retry.txt`（成功）。
3. seed 初始按小端理解，虽然对错误模型做的自洽加密能回到密文，但明文是非 UTF-8/不可读字节。修正：回到 `orr` 操作数顺序，seed=`(key[0]<<8)|key[1]`。同时保存两份脚本和双结果日志。
4. 第一次 `.plt` 映射把 AArch64 PLT0 当作 0x10 字节，符号映射偏移 0x10。修正后使用 `.plt + 0x20 + 0x10*relocation_index`，并通过 JNI 的 `NewByteArray` / `SetByteArrayRegion` 调用参数交叉确认。错误与修正记录在 `records\plt_map_20260929.txt`、`records\plt_map_corrected_20260929.txt`。
5. 第一次反汇编输出文件路径拼错，脚本停止于 `FileNotFoundError`；只影响报告写入，未影响附件。修正脚本根目录并重新生成四架构报告。记录 `records\elf_disasm_20260929.txt`（失败）和 `records\elf_disasm_all_20260929.txt`（成功）。
6. 初版 DEX 清单漏报 native access flag，导致 `native_methods=0`。再次逐项解析 class data 后确认是两条 native 方法；旧报告保留为 `classes4.dex.report.initial_parser_bug.txt`，修正报告为 `classes4.dex.corrected_report.txt`，命令证据在 `records\dex_static_corrected_20260929.txt`。

## 10. 文件与记录索引

- 原附件：`..\..\..\原始下载附件\hookme.rar`
- 解出的 APK：`附件解包\hookme\HookMe.apk`
- APK ZIP 成员及 hashes：`analysis\apk_inventory.py`、`records\apk_inventory_20260929.txt`
- DEX 字符串、类方法和反汇编：`analysis\dex\`、`analysis\dex_disasm.py`、`analysis\dex_static_corrected.py`
- 编译资源解析：`analysis\arsc_parse.py`、`analysis\resources\arsc_parse.txt`
- ELF 符号/ASCII 字符串/反汇编：`analysis\elf_static.py`、`analysis\elf_disasm.py`、`analysis\native\`
- AArch64 PLT 符号映射：`analysis\plt_map_corrected.py`、`analysis\native\plt_map_corrected.txt`
- 求解：`analysis\solve_static.py`；错误端序复现：`analysis\failed_seed_little_endian.py`
- PowerShell transcripts：`records\`
