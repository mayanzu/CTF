# 第一届 OpenHarmony secret（玄机 #561）完整解题记录

## 最终结论（2026-09-30 平台已验证）

最终获玄机接受的 flag 为：

```text
flag{871f72716d85a6374f438ea70c2fd62c}
```

该文本不是由题内给出的 MD5 公式正确计算得到的结果，而是解密后的 233 字节资源提示最后一行**直接写出的示例 flag**。2026-09-30 在 #561 页面提交后，平台返回“FLAG 正确~，恭喜你完成此挑战~”，步骤从 0/1 变为 1/1，显示“已完成”和 `slu_mzj` 一血。下文保留此前逆向和错误公式审计的全过程；其中各处“未完成”“示例不能作为有效候选”是提交前的历史判断，已由本次平台验证更正。教学时必须明确：`MD5("012345678Harmony5337")` 实际为 `a8f2f50ac7bcf159d3e017721542768b`，与平台接受的示例值不同，不能声称两者在数学上相等。

> **历史分析状态（2026-09-29，现已由平台验证更新）：**当时按实际 pattern 推导的候选提交后仍为 `0/1`，所以没有将本题记为完成。后来直接提交解密提示末行的示例 flag，平台确认正确。示例 digest 与提示中的计算公式仍不相符，这一处是题目材料本身的矛盾。

## 1. 题目信息与材料

- 平台：玄机，`https://xj.edisec.net/challenges/561`
- 题目：第一届 OpenHarmony secret
- 类型 / 难度：REVERSE / 中等；免费
- 页面提示：`The smart box hiding a secret, can you find it ?`
- 附件包：`secret_platform_20260929.zip`，SHA-256：`77177B600FEA6DA73C41935763ED555047F15CB7F17B7A707550BBD9E633080F`
- HAP：`secret.hap`，SHA-256：`743EB75674EB2BBF8696D5414FD9E122236022E49FB2C30D19A1D24D76D07720`
- 解包目录：`hap_contents/`
- 原附件、副本、分析脚本、反汇编和命令输出均留在本题目录内；批次级 PowerShell 记录位于项目 `..\..\..\..\记录\批次记录\综合协调\原始分件\批次_20260929_选题与本地资料核对.txt`，资源解密探索日志位于 `analysis/agent_secret561_assets_20260929.txt`。

## 2. 先理解应用的文件与提示流程

HAP 中最有用的部分是 `ets/modules.abc`、`resources.index`、`resources/rawfile/enc` 和 `libs/x86_64/libsecret.so`。`sourceMaps.map` 有模块名和映射，但不含可直接还原的 `sourcesContent`，所以主线是读 Panda 字节码和 native ELF。

从已保存的 `analysis/disassemble_app_output.txt` 可以还原出这些调用关系：

1. `pages/face` 通过文件选择器读入照片字节，转为 Base64 后写入应用私有目录的 `bb.txt`。
2. 页面读回 `bb.txt`，调用 `secret.ValidateCiphertext(bbText, enc)` 做照片校验；成功后才路由到下一页和 pattern lock。
3. final 页再次读 `bb.txt`，调用 `CryptoJS.MD5(fileText).toString(CryptoJS.enc.Hex)`，以这串摘要解密 `resources.index` 中的 AES 密文，再显示解出的提示文本。
4. 因此，final 页里的 MD5/AES 过程是**取出题目提示**的流程；它本身不把 pattern 传给 final，也不在应用代码里自动生成最后的 flag。

`resources/rawfile/enc` 是 ASCII Base64 文本，解码后为 45,264 字节密文。`decrypt_enc_custom_sm4.py` 使用附件中 `libsecret.so` 的自定义 SM4 实现、S-box、轮常量和硬编码轮密钥解密。结果为带 PKCS#7 padding 的 Base64 文本；逐块重加密可回到原密文，padding 为 12 个有效字节。去 padding 后得到 45,252 字节 Base64，解码为 33,939 字节 JPEG，SHA-256 为：

```text
71E5D289A949A642D8D139C4193894133110B327EE3379CCFE0AF619360C772F
```

图片是 OpenHarmony 标志。它主要用于理解 face 页的验证和生成 `bb.txt` 的流程，不包含明文 flag。

## 3. 解出资源索引里的加密提示

`resources.index` 的 ASCII 数据中，`Salted__` Base64 数据从十进制偏移 `1060`（`0x424`）开始，长度 `344`（`0x158`），覆盖 `[0x424, 0x57c)`。Base64 解码为 256 字节：8 字节 `Salted__`、8 字节 salt `5efd2afd3fa774c7`、240 字节 AES-CBC 密文。

把恢复的 JPEG 原始 33,939 字节重新 Base64 编码，得到 45,252 字节；对此 Base64 文本做 MD5 得小写十六进制口令：

```text
4ba9b421e88b4a70cff1b4300af97b74
```

该口令用于 OpenSSL AES-256-CBC（`Salted__` 格式、MD5 KDF）解密，成功输出 233 字节明文。逐字内容如下：

```text
The flag is MD5 of: (lock's password + "Harmony5337").
For example: If the lock's password is 012345678
Then the flag is flag{md5("012345678" + "Harmony5337")} (Note! There is no ',')
Which is flag{871f72716d85a6374f438ea70c2fd62c}
```

这里的关键是最后一行示例与前两行公式不相符。标准 MD5(`012345678Harmony5337`) 为 `a8f2f50ac7bcf159d3e017721542768b`，不是提示所写的 `871f72716d85a6374f438ea70c2fd62c`。对 0–8 无重复的长度 4–9 序列，以逗号或无逗号形式加后缀枚举，也没有匹配到提示中的 `871f...`。故不能把该示例 digest 当成可信的最终 flag；需由平台验证裁决。

## 4. 逆向 pattern lock

### 4.1 找校验入口

`libsecret.so` 的 NAPI 导出注册了 `verifyPattern`、`readFileUsingPickerFd`、`ValidateCiphertext` 等函数。native `verifyPattern`：

1. 要求传入数组长度恰好为 9；
2. 取出 9 个整数；
3. 对该数组执行 `init_proc`；
4. 将结果逐项与全局数组 `is` 比较。

关键地址和反汇编分别保存在：

- `analysis/libsecret_callbacks_disassembly.txt`
- `analysis/libsecret_init_proc_disassembly.txt`

`init_proc` 是标准 XXTEA 加密循环，delta 为 `0x9e3779b9`，轮数为 `6 + 52/n`。固定 4-word key `what` 和 9-word 目标数组 `is` 位于 ELF `.data`：文件偏移分别是 `0xe730` 与 `0xe740`。key 和目标值由 `analysis\recover_pattern_561.py` 从 x86_64 ELF 中按小端序读取。

### 4.2 逆向 XXTEA

脚本对目标 `is` 做 XXTEA 解密，再将解出的 9 个整数重新加密。关键输出：

```text
key words       = ['0xb', '0x2d', '0xe', '0x1bf52']
target words    = ['0xe52bcc34', '0x344e3b05', '0xded45d41', '0x5f1ed75a', '0x97439820', '0x1f1b5b18', '0xf108fe7f', '0x93962769', '0xc4b198ca']
decrypted words = [1, 3, 7, 5, 2, 4, 8, 6, 0]
re-encrypt      = ['0xe52bcc34', '0x344e3b05', '0xded45d41', '0x5f1ed75a', '0x97439820', '0x1f1b5b18', '0xf108fe7f', '0x93962769', '0xc4b198ca']
round-trip      = True
```

闭环吻合证明了解出的整数序列确实是 native 校验器期望的输入，而不是只依靠函数名猜测。pattern 节点值范围为 0–8，每个点一次，序列是：

```text
[1, 3, 7, 5, 2, 4, 8, 6, 0]
```

反汇编还确认 `onPatternComplete` 中 `input.toString()` 仅用于 `console.log`；native 收到的是原始数组。成功分支只路由到 final，没有把路径作为参数传给 final。结合提示的 `There is no ','`，计算公式时将数字直接连起来：

```text
lock password = 137524860
MD5 输入      = 137524860Harmony5337
MD5           = 8b4ec604943712483bfca67cacf85f1a
候选          = flag{8b4ec604943712483bfca67cacf85f1a}
```

## 5. 本地复现

主 solver：`analysis\recover_pattern_561.py`。在项目根目录的 PowerShell 中传入解包后的 x86_64 ELF：

```powershell
py -3 "C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\OpenHarmony_secret_561\analysis\recover_pattern_561.py" "C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\OpenHarmony_secret_561\hap_contents\libs\x86_64\libsecret.so"
```

输出原文保存在 `analysis\recover_pattern_561_output.txt`；完整批次命令及 stdout/stderr 保存在 `..\..\..\..\记录\批次记录\综合协调\原始分件\批次_20260929_选题与本地资料核对.txt`。辅助复算在 `analysis/check_formula_variants.py`，SM4 解密及闭环在 `analysis/decrypt_enc_custom_sm4.py` 与 `analysis/verify_roundtrip_and_decode_jpeg.py`，字节码主输出为 `analysis/disassemble_app_output.txt`。

## 6. 玄机平台验证记录

玄机 #561 页面（登录账号 `slu_mzj`）上已通过可见的“提交 FLAG”表单进行过以下两次测试：

| 测试 | 提交内容 | 页面回执 |
|---|---|---|
| A | `flag{8b4ec604943712483bfca67cacf85f1a}` | 提交后刷新页面，步骤仍为 `0 / 1`，未显示“已完成”；记为未通过/未确认 |
| B | `flag{429ebe492a801046d1a43c328db88e7f}`（把 path 按 JavaScript 数组逗号形式参与 MD5） | 提交后刷新仍为 `0 / 1`；记为未通过/未确认 |

因此当前正确状态应记录为：**native pattern 已闭环，本地公式候选存在，但 #561 尚未通过玄机平台验证。** 不能把题内示例值、候选值或本地 XXTEA 闭环混写成平台接受回执。两次表单交互由 CUA 前台浏览器完成；具体交互状态可在本轮工具记录中查阅。后续再次提交网页表单需按 computer-use 技能在提交时另行确认。

## 7. 资料索引与后续事项

- 原始题包：`secret_platform_20260929.zip`
- HAP 原件：`secret.hap`、`附件_20260929/secret.hap`
- 解包资料：`hap_contents/`
- 图片路径：`analysis\enc.base64-decoded.bin`、`enc.custom-sm4-decrypted.bin`、`enc.recovered.jpg`
- 关键 native 证据：`analysis/libsecret_callbacks_disassembly.txt`、`libsecret_init_proc_disassembly.txt`
- Panda 分析：`analysis/disassemble_app_output.txt`、`disassemble_indexed_output.txt`
- XXTEA solver 与输出：`analysis\recover_pattern_561.py`、`recover_pattern_561_output.txt`
- 资源密文和公式分析：`analysis/resource_index_salted_ciphertext.b64`、`secret561_resource_flow_findings_20260929.md`
- 终端日志：`analysis/agent_secret561_assets_20260929.txt`、`..\..\..\..\记录\批次记录\综合协调\原始分件\批次_20260929_选题与本地资料核对.txt`

后续状态：当前没有由现存附件唯一支持、且尚未测试的 flag 候选。示例值与明文自己的公式不一致，不纳入候选；只有出现新的独立技术证据时才继续推导。

## 8. 独立审计补记（2026-09-29）

本轮独立复查没有再向平台提交任何内容。完整 PowerShell 命令和输出保存在 `analysis/agent_secret561_independent_audit_20260929.txt`。

### 8.1 附件与逆向结果复核

- 重新计算的题包 SHA-256 为 `77177B600FEA6DA73C41935763ED555047F15CB7F17B7A707550BBD9E633080F`；HAP 为 `743EB75674EB2BBF8696D5414FD9E122236022E49FB2C30D19A1D24D76D07720`；所用 `libs/x86_64/libsecret.so` 为 `388EC90B343F5C74E70F2ECB5F83098F9C3A09F23B6222F59F33F2587967627A`。
- 再次执行 `recover_pattern_561.py`，恢复数组 `[1,3,7,5,2,4,8,6,0]`，XXTEA 重新加密后的 9 个 word 与 native `.data` 中目标 `is` 全部相同，`round-trip = True`。
- `verifyPattern` 的反汇编逐项证实 N-API 取 9 个数组元素并转换为 int32，调用 `init_proc_`，然后比较变换结果与目标数组。因此反演所得数组是此附件 native 校验器所期望的输入。

### 8.2 ArkTS 数据流再核对

- `pages/lock::Index` 将字符串 `0,1,2,3,4,5,6,7,8` 设为 PatternLock 的 `defaultPassword` 属性；这是组件配置值，不是成功回调的哈希输入。
- PatternLock 的 `onPatternComplete` 回调先执行 `input.toString()` 并将文本传入 `console.log('enter password :', ...)`；接下来直接将原数组传给 `secret.verifyPattern(input)`。由此日志形式虽为 `1,3,7,5,2,4,8,6,0`，但校验器接收的是数组，逗号文本没有传给验证器。
- native 验证成功后，回调只路由到 final 页面。final 页独立从运行时私有目录读取 `bb.txt`（照片 Base64），其 MD5 用来解开应用资源中的 AES 提示；final 未读取 PatternLock 数组，也没有把它作为最终 MD5 的调用参数。
- 因而“实际 pattern 的节点编号串接后加 Harmony5337”是依据资源提示推导的外部 flag 计算，而不是应用运行时执行的哈希逻辑。原数组的逗号表示只用于日志；提示写明无逗号时，紧凑候选是 `flag{8b4ec604943712483bfca67cacf85f1a}`。

### 8.3 示例 MD5 矛盾及候选边界

独立复算得到：

```text
MD5("012345678Harmony5337")         = a8f2f50ac7bcf159d3e017721542768b
题目明文声称该示例的摘要为            = 871f72716d85a6374f438ea70c2fd62c
MD5("137524860Harmony5337")          = 8b4ec604943712483bfca67cacf85f1a
MD5("1,3,7,5,2,4,8,6,0Harmony5337")   = 429ebe492a801046d1a43c328db88e7f
```

差异不是大小写或是否含逗号造成的：`check_formula_variants.py` 核对了常见表示；`brute_pattern_example_hash.py` 穷举了节点 `0`–`8` 不重复、长度 4–9 的所有序列，分别以紧凑串和逗号串拼接后缀，共测试 985,824 个输入，目标 `871f...` 的命中数为 0。故 `flag{871f72716d85a6374f438ea70c2fd62c}` 仅是与公式冲突的字面示例，不应当作推导结果或“备用候选”。

### 8.4 当前结论


## 9. 本批独立复核（2026-09-29）

本批接手时，题目 ZIP、HAP、`hap_contents`、反汇编、资源解密脚本和旧 WP 均已在项目中，因附件齐全而没有重新打开平台或再次下载。为避免直接沿用旧结论，新增 `analysis\independent_rederive_secret561.py`，直接从 `libs/x86_64/libsecret.so` 的文件偏移 `0xe730` 读 4-word key、从 `0xe740` 读 9-word 比较目标，独立实现 XXTEA 解密与加密闭环。

本批重新核对的 SHA-256：

```text
secret_platform_20260929.zip  77177B600FEA6DA73C41935763ED555047F15CB7F17B7A707550BBD9E633080F
secret.hap                    743EB75674EB2BBF8696D5414FD9E122236022E49FB2C30D19A1D24D76D07720
modules.abc                   114534191129BB84CF11E3B1021D8E4F3A85E34C72DE34464D48A1BA8237FE83
x86_64\libsecret.so           388EC90B343F5C74E70F2ECB5F83098F9C3A09F23B6222F59F33F2587967627A
```

独立结果与原脚本一致：native 目标解密为 `[1,3,7,5,2,4,8,6,0]`，再用同一 key 加密后，9 个 32-bit word 全部逐项相等。针对“lock password”可能表示的几种字符串，本批另行计算：

| 解释 | 实际 MD5 输入 | MD5 |
|---|---|---|
| 0-based path，依照提示去掉逗号 | `137524860Harmony5337` | `8b4ec604943712483bfca67cacf85f1a` |
| JavaScript 数组默认字符串形式 | `1,3,7,5,2,4,8,6,0Harmony5337` | `429ebe492a801046d1a43c328db88e7f` |
| 将 0-based 节点全部加一 | `248635971Harmony5337` | `f6f4a6c7c16f27a4fd8b34e9b6b9b9e3` |
| 题内示例密码 | `012345678Harmony5337` | `a8f2f50ac7bcf159d3e017721542768b` |

题面明文把最后一行示例写成 `871f72716d85a6374f438ea70c2fd62c`，但本批用 Python 标准库重新计算仍得到 `a8f2...`。这使题内示例不能作为公式正确性的证明；同时，native 数组闭环只证明了锁接受的 0-based 顺序，不会自行证明最终字符串怎样编码。现有最强本地推导仍是题面“无逗号”所指向的紧凑候选 `flag{8b4ec604943712483bfca67cacf85f1a}`，但历史页面记录没有成功回执。本批没有提交任何 flag。

新增可复现命令：

```powershell
Set-Location 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\OpenHarmony_secret_561'
Get-FileHash '.\secret_platform_20260929.zip','.\secret.hap','.\hap_contents\ets\modules.abc','.\hap_contents\libs\x86_64\libsecret.so' -Algorithm SHA256
python .\analysis\independent_rederive_secret561.py
python .\analysis\recover_pattern_561.py .\hap_contents\libs\x86_64\libsecret.so
```

本批完整 PowerShell 命令和输出（包括上述哈希、独立反演、已有反汇编交叉检查）保存在 `arkt561_analysis_transcript_20260929.txt`。本地 native pattern 求解已闭环；最终 flag 仍未得到平台回执。后续待办是取得题目维护方对错误示例的更正，或其他独立说明以确认最终口令的编码；在此之前保留候选和平台未验证状态，不把题目标示为完成。

另外，本批第一次重跑图片资源 round-trip 时，旧脚本因为把项目根目录写死为 WSL 路径 `/mnt/c/...` 而在 Windows 下报 `FileNotFoundError`。已将 `analysis/decrypt_enc_custom_sm4.py` 的根目录改为相对脚本位置解析，再运行 `analysis/verify_roundtrip_and_decode_jpeg.py`：2829 个分组全部重加密匹配；PKCS#7 padding 12 字节通过逐字节检查；去 padding 后 Base64 长 45252 字节，解出 JPEG 33939 字节，SHA-256 为 `71E5D289A949A642D8D139C4193894133110B327EE3379CCFE0AF619360C772F`。随后 `analysis/probe_resource_index_secret.py` 成功解出 233 字节资源提示。以上输出也在本题主 transcript 中。

作为题内示例矛盾的补充核验，本批重跑 `analysis/brute_pattern_example_hash.py`：枚举 `0`–`8` 不重复、长度 4–9 的节点串，分别测试紧凑和逗号形式，共 `985824` 个输入，对应 `871f72716d85a6374f438ea70c2fd62c` 的命中数为 0。该结果排除了这些常见 path 字符串形式，但不能替代题目维护方澄清错误示例。

## 10. 本轮附件与求解链复核（2026-09-29）

本轮不访问题目平台、不查公开 Writeup，也没有运行 HAP、ELF 或其他附件程序。只将 `libsecret.so` 当作字节文件解析，并用 Python 标准库独立实现 XXTEA 解密和加密，用于核对已有 pattern 候选。

### 10.1 附件完整性

- `secret_platform_20260929.zip` 中只有一项 `secret.hap`（3,252,706 字节）；本轮只读取 ZIP 目录，没有再次解压或改写原件。
- 根目录 `secret.hap` 与 `附件_20260929/secret.hap` 的 SHA-256 完全相同，均为 `743EB75674EB2BBF8696D5414FD9E122236022E49FB2C30D19A1D24D76D07720`。
- 当前解包树、题包和两份 HAP 的逐文件清单在 `analysis\sha256_manifest_20260929.csv`，由 `analysis\hash_materials_561.py` 生成；共核对 23 个文件。
- 本轮所需主要输入摘要：

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `secret_platform_20260929.zip` | 1,170,497 | `77177B600FEA6DA73C41935763ED555047F15CB7F17B7A707550BBD9E633080F` |
| `secret.hap`（两份相同） | 3,252,706 | `743EB75674EB2BBF8696D5414FD9E122236022E49FB2C30D19A1D24D76D07720` |
| `hap_contents/ets/modules.abc` | 334,752 | `114534191129BB84CF11E3B1021D8E4F3A85E34C72DE34464D48A1BA8237FE83` |
| `hap_contents/resources.index` | 4,336 | `C86F71012FCA59DE7C733BD5720B6FB45DEDA36CD05F03A2023254658CFEB7C5` |
| `hap_contents/resources/rawfile/enc` | 60,352 | `2BA36E4DEECE0D74EF13765352AF25F9063BE11BDEC3C582206FBAD6556BDFCC` |
| `hap_contents/libs/x86_64/libsecret.so` | 61,384 | `388EC90B343F5C74E70F2ECB5F83098F9C3A09F23B6222F59F33F2587967627A` |
| `hap_contents\libs\arm64-v8a\libsecret.so` | 60,088 | `41F4EEDA3FDB86E16683BDC6DDD954EBA2202B4E65065065CDC82968841C710E` |

### 10.2 不依赖硬编码文件偏移的 pattern 复算

新增 `analysis/revalidate_native_pattern.py`。与此前脚本不同，它先从 ELF64 little-endian section table 查找 `.data`，再从该 section 的相对偏移读取 native 常量；不会调用 `libsecret.so`。本附件的 ELF 机器编号为 62（x86-64），`.data` 文件偏移为 `0xe720`、长度 `0x140`：

1. `.data + 0x10` 起的四个小端 `uint32` 为 XXTEA key：`[0x0b, 0x2d, 0x0e, 0x1bf52]`。
2. `.data + 0x20` 起的九个小端 `uint32` 为 native verifier 的目标数组：`[0xe52bcc34, 0x344e3b05, 0xded45d41, 0x5f1ed75a, 0x97439820, 0x1f1b5b18, 0xf108fe7f, 0x93962769, 0xc4b198ca]`。
3. `n=9`，标准 XXTEA 轮数为 `6 + floor(52/9) = 11`。从 `sum = rounds × 0x9e3779b9` 开始，按 `p=8..0` 倒序执行带 32-bit 回绕的减法，解出 `[1,3,7,5,2,4,8,6,0]`。
4. 再从该数组按正向 XXTEA 加密。输出九个 word 与 ELF 中目标数组逐项相同，`XXTEA_ROUNDTRIP=True`。这将路径闭环到附件常量，并与既有 `verifyPattern` 反汇编相互印证。
5. 将路径数字紧凑拼接得 `137524860`；按提示的“no comma”计算 `MD5("137524860Harmony5337")`，得到理论候选 `flag{8b4ec604943712483bfca67cacf85f1a}`。若按 JavaScript `Array.toString()` 则摘要为 `429ebe492a801046d1a43c328db88e7f`；若改为 1-based 标签，摘要为 `f6f4a6c7c16f27a4fd8b34e9b6b9b9e3`。

本轮独立程序再次得到 `MD5("012345678Harmony5337") = a8f2f50ac7bcf159d3e017721542768b`，与资源提示写出的 `871f72716d85a6374f438ea70c2fd62c` 不符。提示内部矛盾仍未解决；本轮没有新的最终 flag 证据，也没有向平台提交。因此紧凑摘要只保留为本地理论候选，**#561 仍未通过平台验证，不能标为已完成**。此前 WP 所述两种提交尝试均无完成回执，应继续按未完成处理。

### 10.3 复现命令与记录

在 PowerShell 中进入本题目录后运行：

```powershell
Set-Location 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\OpenHarmony_secret_561'
py -3 .\analysis\hash_materials_561.py
py -3 .\analysis\revalidate_native_pattern.py
```

SHA-256 清单写入 `analysis\sha256_manifest_20260929.csv`。本轮命令、ZIP 目录清单、哈希结果和完整求解器 stdout 保存在 `analysis\revalidate_561_transcript_20260929.txt`。程序只读原始 ELF；不运行附件，也不生成或覆盖解包目录中的原始内容。
