# 第一届 OpenHarmony secret（玄机 #561）完整 WP

> **当前结论：未得到平台接受的 flag。** 本文区分了本批次新下载和复核步骤、早期目录留下的分析结论。新下载附件与早期资料附件 SHA-256 完全相同。本批次独立重跑了附件校验、native XXTEA 反解/正向重加密、照片资源解密/逐块重加密、提示提取，以及 MD5 示例矛盾复核。公式能导出理论候选，但历史平台记录显示它及逗号形式候选均未通过；不要把理论候选写成已解题 flag。

## 1. 题目信息与资料边界

- 题目：第一届 OpenHarmony secret
- 平台 ID：561；类型 REVERSE，中等；页面标示免费。
- 页面描述：`The smart box hiding a secret, can you find it?`
- 本批次从下载目录取得 `D:\Downloads\secret (2).zip`，下载时间为 2026-09-29 15:38。原始副本保存在 `secret_platform_20260929.zip`。
- 新 ZIP 的 SHA-256：`77177B600FEA6DA73C41935763ED555047F15CB7F17B7A707550BBD9E633080F`；只含 `secret.hap`。
- 新 HAP 的 SHA-256：`743EB75674EB2BBF8696D5414FD9E122236022E49FB2C30D19A1D24D76D07720`。
- `D:\Downloads\secret.zip`、`secret (1).zip`、本批次新下载的 `secret (2).zip`，以及早期项目副本 `secret_platform_20260929.zip` 的 SHA-256 全部相同；因此本批次没有拿到内容更新的附件。旧目录中 `secret.hap` 与本次 HAP 也同 hash。
- 本目录 `analysis/WP_preexisting_20260929.md` 和 `analysis/secret561_resource_flow_findings_20260929.md` 是已有工作副本，**不是本批次新产生的分析步骤**。本批次新增的命令、输出以及复核文件均列在 `README.md`。

所有操作只针对静态附件，没有运行 HAP、没有启动靶场、没有访问公开 WP，也没有在本批次提交 flag。命令及完整 stdout/stderr 按顺序保存在 `../../../../记录/批次记录/第14批/原始分件/批次14_561_调查记录.txt`（项目总记录副本在 `../../../../记录/批次记录/第14批/原始分件/批次14_561_调查记录.txt`）。

## 2. 从 HAP 建立附件结构

对新 ZIP 解压得到单个 `secret.hap`，再按 ZIP/HAP 容器解出应用文件。主要文件：

- `hap_contents/ets/modules.abc`：OpenHarmony Panda 字节码。
- `hap_contents/ets/sourceMaps.map`：source map，但没有可直接还原的源码内容。
- `hap_contents/resources.index`：包含加密后的提示字符串。
- `hap_contents/resources/rawfile/enc`：照片数据的 Base64 密文。
- `hap_contents/libs/x86_64/libsecret.so`：x86_64 native 库，含 pattern verifier、SM4-like 资源解密常量。

本目录中的 `analysis/disassemble_app_output.txt`、`analysis/libsecret_callbacks_disassembly.txt`、`analysis/libsecret_init_proc_disassembly.txt` 是旧工作树中保存的反汇编证据副本。已有调用链分析表明：应用将照片存入私有 `bb.txt`，native `ValidateCiphertext` 校验照片；锁页把 9 个节点编号数组传给 native `verifyPattern`；最终页面读取的是照片 Base64 并对其 MD5 后解密资源提示。页面没有把 pattern 数组传给最终页面或直接替用户生成 flag。

## 3. 静态反解 pattern lock

### 3.1 目标数组和密钥

`analysis/revalidate_native_pattern.py` 读取附件中 x86_64 ELF 的 `.data` 节。脚本会先确认 ELF64、小端、`e_machine=62`，再按已保存反汇编确认的相对偏移读取常量：

- XXTEA 四字密钥位于 `.data + 0x10`：`[0x0000000b, 0x0000002d, 0x0000000e, 0x0001bf52]`。
- native 校验目标位于 `.data + 0x20` 的 9 个 uint32：`[0xe52bcc34, 0x344e3b05, 0xded45d41, 0x5f1ed75a, 0x97439820, 0x1f1b5b18, 0xf108fe7f, 0x93962769, 0xc4b198ca]`。
- native 逻辑要求数组长度是 9；把输入经 `init_proc` 变换后逐项与该目标数组比较。

### 3.2 XXTEA 逆运算与闭环

对 9 个 word，标准 XXTEA 轮数为 `6 + floor(52/9) = 11`。按 XXTEA 逆序从 `sum = 11 × 0x9e3779b9` 开始，每轮以 32-bit 回绕倒序减去 `MX` 项，得到：

```text
[1, 3, 7, 5, 2, 4, 8, 6, 0]
```

再把这 9 个 word 用同一 key 正向加密，得到的九个 uint32 与 ELF 内目标逐项完全相同，`XXTEA_ROUNDTRIP=True`。本批次重新运行的完整值见 `analysis/batch14_revalidate_native_stdout.txt`。这个闭环确认了 native 数组逆解与附件常量相符。

把节点按提示所说“没有逗号”紧凑拼接得到 `137524860`；`analysis/revalidate_native_pattern.py` 对理论输入 `137524860Harmony5337` 求标准 MD5，结果为：

```text
8b4ec604943712483bfca67cacf85f1a
```

因此这只是依据提示推导的理论候选 `flag{8b4ec604943712483bfca67cacf85f1a}`。JavaScript 数组的逗号表示 `1,3,7,5,2,4,8,6,0` 则算出另一候选 `flag{429ebe492a801046d1a43c328db88e7f}`。历史 WP 记录了这两种形式的平台尝试后题目仍为 `0/1`；本批次没有再次提交。

## 4. 还原隐藏照片和提示

### 4.1 `enc` 的自定义 SM4-like 解密

`analysis/decrypt_enc_custom_sm4.py` 只读取附件 ELF 与 `resources/rawfile/enc`，不执行 HAP。它从 native 库 `.rodata` 的 `0x44e0` 读取 S-box、`0x45e0` 读取 32 个 CK，并使用脚本中恢复出的轮 key `[e52bcc34, 1f1b5b18, 5f1ed75a, f108fe7f]`。本批次重跑确认：

1. `enc` 是 60,352 字节 ASCII Base64；解码成 45,264 字节，长度是 16 的倍数。
2. 自定义分组算法处理 2,829 个 16 字节块。`analysis/verify_roundtrip_and_decode_jpeg.py` 把每个解密块重新加密，与输入密文逐块比较，2,829 块全部一致。
3. 解密数据尾部有 12 个 `0x0c`，严格符合 PKCS#7 padding；去 padding 后 45,252 字节为 Base64。
4. Base64 解码成 33,939 字节 JPEG，SHA-256：`71e5d289a949a642d8d139c4193894133110b327ee3379ccfe0af619360c772f`。JPEG magic 为 `ffd8ffe0...`，图片是 OpenHarmony logo。它用来通过应用照片校验/派生照片口令，不是直接含有 flag 的文本。

本批次实际输出分别保存在 `analysis/batch14_custom_sm4_stdout.txt`、`analysis/batch14_roundtrip_stdout.txt`，生成的静态文件有 `analysis/enc.custom-sm4-decrypted.bin` 和 `analysis/enc.recovered.jpg`。

### 4.2 从 `resources.index` 解密文字提示

`analysis/recover_hint_batch14.py` 在附件 `resources.index` 中查找可解码为 `Salted__` 的 Base64 段，而不是对原始索引假定它直接含有 `Salted__` 字节：

- `resources.index` 为 4,336 字节。
- Base64 字符串位于偏移 1,060，长度 344；解码后 256 字节。
- 解码数据以 `Salted__` 开头；salt 为 `5efd2afd3fa774c7`，后续 AES-CBC 密文 240 字节。
- 将 JPEG 原始字节重新 Base64 编码得 45,252 字节，对这段 Base64 求 MD5，得到 OpenSSL 口令 `4ba9b421e88b4a70cff1b4300af97b74`。
- 按附件应用的 OpenSSL 兼容格式执行 `openssl enc -d -aes-256-cbc -md md5 -a -A -pass pass:<口令>`，退出码 0，得到 233 字节 UTF-8 提示。完整输入命令、stdout、stderr、明文 hex 与 repr 保存在 `analysis/batch14_recover_hint_stdout.txt`。

解出的提示原文：

```text
The flag is MD5 of: (lock's password + "Harmony5337").
For example: If the lock's password is 012345678
Then the flag is flag{md5("012345678" + "Harmony5337")} (Note! There is no ',')
Which is flag{871f72716d85a6374f438ea70c2fd62c}
```

## 5. 题目提示存在可验证的内部矛盾

按标准 MD5 计算提示自己的示例输入：

```text
MD5("012345678Harmony5337") = a8f2f50ac7bcf159d3e017721542768b
```

这不等于提示写出的 `871f72716d85a6374f438ea70c2fd62c`。本批次重新枚举所有由 `0` 到 `8` 组成、长度 4 到 9、节点不重复的序列；对每个序列都分别测紧凑连接和逗号连接两种输入格式，总共检查 985,824 个序列（两种格式各测一次），没有任何 digest 等于提示中的 `871f...`。复现脚本为 `analysis/brute_pattern_example_hash.py`，本批输出在 `analysis/batch14_bruteforce_stdout.txt`。

所以提示中例子的 digest 错误不能用简单的逗号解释；题目可能存在错误提示，或最终 flag 公式/输入与题面说明不完整。尽管 native pattern 路径和资源提示都能独立复现，题面示例的自检却失败，而且历史上从实际路径推导的 compact/逗号两种 flag 形式均未获平台接受。当前证据不足以断言哪一个字符串是正确答案，不能将任一理论候选标记成“已解”。

## 6. 复现命令、文件和最终状态

在 PowerShell 执行这些命令会将命令与完整输出追加记录到本目录 `../../../../记录/批次记录/第14批/原始分件/批次14_561_调查记录.txt`。本批的实际完整 transcript 是判断每步先后和输出的主证据。

```powershell
Set-Location 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\OpenHarmony_secret_561'
py -3 .\analysis\revalidate_native_pattern.py
py -3 .\analysis\decrypt_enc_custom_sm4.py
py -3 .\analysis\verify_roundtrip_and_decode_jpeg.py
py -3 .\analysis\recover_hint_batch14.py
py -3 .\analysis\brute_pattern_example_hash.py
```

`README.md` 是文件索引。`analysis/WP_preexisting_20260929.md` 保留早期资料的完整 WP 副本，以便核对历史分析/平台提交记录；`analysis/secret561_resource_flow_findings_20260929.md` 是早期资源链分析副本。两者没有被当成本批次新步骤。本批无靶场启动、无付费行为、无 flag 提交。

**最终状态：#561 未解决 / 无已验证 flag。** 证据证明了 native pattern 路径、资源解密流程和两种常见 MD5 格式的值；同时证明题面示例 hash 与其公式冲突且 pattern 枚举没有复现该 hash。历史平台尝试不接受路径推导出的候选。本题只有理论候选，没有本批次平台接受回执。
