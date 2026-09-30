# #561 OpenHarmony_secret：资源与应用流程独立分析

日期：2026-09-29。此笔记记录本地附件静态分析；没有浏览公开 Writeup。平台提交结果见本笔记末尾。

## 核查材料

- HAP：`secret.hap`，SHA-256 `743EB75674EB2BBF8696D5414FD9E122236022E49FB2C30D19A1D24D76D07720`
- `hap_contents\ets\modules.abc`：334,752 字节。
- `hap_contents\ets\sourceMaps.map`：59,374 字节，是按模块名索引的 Source Map JSON；页面有 `sources` 与 `mappings`，无 `sourcesContent`，因此没有可直接还原的源码文本。
- 普通解包树中没有 `bb.txt`。它是在应用私有 `filesDir` 内运行时生成的文件。

## 文件与资源链

1. `resources/rawfile/enc` 是 60,352 字节的 ASCII Base64 文本。解码后 45,264 字节；既有 `decrypt_enc_custom_sm4.py` 用 HAP 内 `libsecret.so` 的自定义 SM4 轮函数、S-box、轮常量以及硬编码轮密钥解密。
2. 解密结果是带 PKCS#7 padding 的 Base64 文本，不是 JPEG 原始字节。已有校验脚本确认每个 16 字节块可重新加密回原密文，padding 为 12 字节且逐字节合法。移除 padding 得到 45,252 字节 Base64，解码成 33,939 字节 JPEG，SHA-256 为 `71E5D289A949A642D8D139C4193894133110B327EE3379CCFE0AF619360C772F`。图像内容是 OpenHarmony 标志。
3. `pages/face` 路径从照片选择器取图，将字节编码为 Base64，并保存到 `context.filesDir + '/' + fileName`；此流程把文件名设为 `bb.txt`。同页从该文件读回字符串，并调用 native `secret.ValidateCiphertext(bbText, enc)` 验证，然后进入 `pages/final`。
4. `pages/final` 再读 `bb.txt`，调用 `getMd5(fileText)`；`getMd5` 是 `CryptoJS.MD5(fileText).toString(CryptoJS.enc.Hex)`。接着通过 `context.resourceManager.getStringSync(...)` 取资源字符串，把它与 MD5 字符串交给 `CryptoJS.AES.decrypt(ciphertext, key)`，再由 `TextDecoder` 读出明文。

上述调用证据可在 `analysis/disassemble_app_output.txt` 找到：`readStringFromFile` 定义约 1981 行、face 保存 Base64 调用约 1715 行、`bb.txt` 与 `ValidateCiphertext` 调用约 2602–2619 行、`getMd5` 约 3132–3164 行、final AES 解密约 3641–3718 行。行号依据当前已保存的反汇编输出。

## resources.index 密文提取与解密

`hap_contents/resources.index` 的 ASCII 数据中，Salted Base64 字符串从偏移十进制 `1060`（`0x424`）开始，长度 `344`（`0x158`）；字节区间为 `[0x424, 0x57c)`。其后 1404–1406 是 NUL 分隔，`53cr37` 从十进制偏移 1407 开始。

提取出的 Base64 保存为 `analysis/resource_index_salted_ciphertext.b64`。解码后共 256 字节：

- 前 8 字节是 OpenSSL 标记 `Salted__`。
- 接下来 8 字节 salt：`5efd2afd3fa774c7`。
- 剩下 240 字节为 AES-CBC 密文（15 个 16 字节块）。

用已恢复 JPEG 的原始 33,939 字节重新 Base64 编码，得到 45,252 字节 ASCII；对此字符串做 MD5 得小写十六进制口令 `4ba9b421e88b4a70cff1b4300af97b74`。该口令交给 OpenSSL 的 AES-256-CBC 解密后，Exit Code 为 0，PKCS#7 解码成功，输出 233 字节。可复现脚本：`analysis/probe_resource_index_secret.py`。完整命令与输出收录在 `analysis/agent_secret561_assets_20260929.txt`。

解密明文逐字内容（`\n` 表示换行）：

```text
The flag is MD5 of: (lock's password + "Harmony5337"). \nFor example: If the lock's password is 012345678 \nThen the flag is flag{md5("012345678" + "Harmony5337")} (Note! There is no ',')\nWhich is flag{871f72716d85a6374f438ea70c2fd62c}
```

## 锁密码证据与矛盾

- 锁页 `pages/lock::Index` 构造处（反汇编输出约第 4136–4137 行）将 `defaultPassword` 设为字符串 `0,1,2,3,4,5,6,7,8`。
- `onPatternComplete` 的 `method_id=0x178` 在模块的 method-index 表中映射到方法实体 `0x2bbe`，即 `pages/lock::#7109887286077709236#`（code offset `0x1fd02`）。回调对原输入数组调用 `toString()` 仅用于 `console.log('enter password :', ...)`；随后将未转换的数组直接传给 `secret.verifyPattern(input)`。native 校验要求数组长度为 9，并逐项校验节点值。
- 校验成功后，回调只执行 `router.replaceUrl(...)` 跳转，不把数组或 `toString()` 结果作为参数传给 final。final 页独立读取 `bb.txt` 中照片的 Base64 字符串，并对它求 MD5 来解密资源提示。因而不能把日志中的逗号序列当作 flag 哈希输入。
- `defaultPassword` 在 `Index` 初始化时被赋值为字符串 `0,1,2,3,4,5,6,7,8`，这是页面/组件属性；静态回调路径显示真正的图案校验走 native `verifyPattern`。已通过 native XXTEA 逆向恢复精确路径 `[1,3,7,5,2,4,8,6,0]`，并以重新加密命中 native 目标数组确认。
- 资源明文自身的公式示例不一致：标准 MD5(`012345678Harmony5337`) 计算结果为 `a8f2f50ac7bcf159d3e017721542768b`，不是明文声称的 `871f72716d85a6374f438ea70c2fd62c`。此外枚举 0–8 不重复的长度 4–9 序列（无逗号与逗号连接两种形式，共 985,824 个序列）也没有任何一个在拼接 `Harmony5337` 后得到该目标摘要。复现验证：`analysis/check_formula_variants.py`、`analysis/brute_pattern_example_hash.py`。

因此，明文末尾的 `flag{871f72716d85a6374f438ea70c2fd62c}` 与其示例密码和公式不能相互验证，不应直接当作答案。依据 native 验证通过的 pattern 路径，按明文给出的无逗号公式计算，当前本地候选为 `flag{8b4ec604943712483bfca67cacf85f1a}`；由于平台未提交验证，仍不能标成已解决。本分析没有进行平台提交。

## 本次新增分析资料

- `analysis/agent_secret561_assets_20260929.txt`：PowerShell transcript，记录命令与输出，包括探索中出现的错误。
- `analysis/resource_index_salted_ciphertext.b64`：从 `resources.index` 直接提取的密文。
- `analysis/probe_resource_index_secret.py`：尝试几种口令、解密并校验示例哈希的脚本。
- `analysis/check_formula_variants.py`：核对示例中常见字符串格式的 MD5。
- `analysis/brute_pattern_example_hash.py`：枚举 0–8 pattern 输入格式的本地校验。

## 按恢复出的 pattern 序列计算公式（补充）

静态分析恢复出的锁路径为 `[1,3,7,5,2,4,8,6,0]`。`pages/lock::#7109887286077709236#` 把原数组交给 `secret.verifyPattern(input)`；`input.toString()` 只用于日志，既不传给 final，也不作为 hash 输入。按资源明文“没有逗号”的说明，把节点编号串接成 `137524860`，再拼接 `Harmony5337`：

```text
输入 = 137524860Harmony5337
MD5  = 8b4ec604943712483bfca67cacf85f1a
候选 = flag{8b4ec604943712483bfca67cacf85f1a}
```

`analysis/check_formula_variants.py` 可复算逗号与无逗号两种表示。final 页没有接收锁密码的状态字段：它从 `bb.txt` 读取照片 Base64，并用其 MD5 作为 AES 口令解出上述提示；应用本身不执行“pattern + Harmony5337”的最终 flag 哈希。资源明文给出的示例 hash `871f...` 仍与标准 MD5(`012345678Harmony5337`) 不符，故不能用该示例 hash 替代基于实际 pattern 的计算。

### 平台验证补记

在玄机 #561 可见的“提交 FLAG”表单中测试过两个候选：无逗号候选 `flag{8b4ec604943712483bfca67cacf85f1a}` 和逗号候选 `flag{429ebe492a801046d1a43c328db88e7f}`。刷新后页面仍显示 `0/1`，没有“已完成”回执；因此题目当前仍未通过平台验证。过程详见同目录 `../WP.md`，批次 PowerShell 输入/输出详见项目 `..\..\..\..\..\记录\批次记录\综合协调\原始分件\批次_20260929_选题与本地资料核对.txt`。后续提交其他候选须按 computer-use 技能在操作当时确认。
