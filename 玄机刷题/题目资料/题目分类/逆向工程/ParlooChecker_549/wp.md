# 第二届 Parloo 杯 ParlooChecker（玄机 ID 549）

## 结论与验证范围

本题已通过 APK 与 native library 的静态分析恢复出候选输入：

```text
flag{vhl8XriruyiB2zeTLNc8pik29HJy7S2w0}
```

候选通过了源码外的独立 Python 复核：PKCS#7 填充合法；对候选重新执行 CBC 加密后，40 字节结果与 APK 内的比较常量逐字节相同；候选满足 `flag{...}` 包装格式。**玄机平台已验证：2026-09-29 在登录后的前台页面提交，页面提示“FLAG 正确，恭喜你完成此挑战”，详情截图显示已完成、步骤 1/1。**分析期间没有联网，没有加载或运行 APK、DEX 或陌生 `.so`。

完整命令和输出保存在 `analysis\commands_output.log`；JNI 与轮函数重点汇编保存在 `analysis\native_disassembly_x86_64.txt`、`analysis\native_helpers_28c00.txt`、`analysis\native_helpers_29a40.txt`、`analysis\xtea_round_function_disassembly.txt`、`analysis\target_range_disassembly.txt`。复现脚本为 `analysis\solve_offline.py`，独立复核脚本为 `analysis\independent_verify.py`。

## 1. 附件检查与安全提取

题目附件原件在：

```text
originals\ParlooChecker_flag.zip
```

先计算原件 SHA-256 并列出 ZIP 中央目录，不直接解压全部成员。记录的原件 SHA-256 为：

```text
2E9A94CAF25E2EA5B63753C1BD0B5FE53E3AF9F275D7F3B60D61E877F3CA86D6
```

检查结果只有一个 APK 成员 `ParlooChecker_flag.apk`，长度 7,154,151 字节；成员名是普通文件名，没有绝对路径或 `..` 路径穿越项。通过 `analysis\inspect_zip.ps1` 查看目录后，由 `analysis\extract_apk.ps1` 按固定成员名提取。提取 APK 的 SHA-256：

```text
BF0EB5D18F35B7CDF8BD556F20CA8F40E4D45DCD7F00A76AC706727E29ED504C
```

检查 APK 自身 ZIP 目录后，只提取固定清单中的 manifest、DEX 和四种 ABI 的 `libparloo.so`。脚本 `analysis\extract_code.ps1` 拒绝路径分隔符、绝对路径及不在允许列表中的成员；没有提取或执行其它 APK 内容。

复现时从项目根目录运行：

```powershell
.\题目资料\ParlooChecker_549\analysis\inspect_zip.ps1
.\题目资料\ParlooChecker_549\analysis\extract_apk.ps1
python .\题目资料\ParlooChecker_549\analysis\inspect_apk.py
.\题目资料\ParlooChecker_549\analysis\extract_code.ps1
```

APK ZIP 共 911 个条目；包含 `classes.dex`、`classes2.dex`、`classes3.dex` 及 `x86_64`、`x86`、`arm64-v8a`、`armeabi-v7a` 四种 ABI 的 native library。

## 2. DEX 入口与输入流程

应用逻辑主要落在体积很小的 `classes3.dex`。静态 DEX 转储确认：

1. `MainActivity.onCreate` 建立输入框和按钮，并给按钮注册监听器。
2. 点击后，监听器从 `EditText` 读取字符串，调用 `MainActivity.onCreat3(String)` native 方法。
3. JNI 导出符号为 `Java_com_linkhash_parloochecker_MainActivity_onCreat3`。
4. Java 层随后按 native 返回文本走混淆后的分支并显示 Toast；因此核心检查在 JNI native 代码中。

DEX 中可见字符串使用 18 个阿拉伯字符构造映射，若干流程又被稀疏 `switch` 和字符串哈希混淆。第一次使用旧 DEX 解析器时，`packed-switch` / `sparse-switch` 与 array-data payload 的宽度处理不正确，导致反汇编错位；修正 payload 长度处理后，入口、按钮监听器、JNI 方法名和调用参数能连贯对应。相关脚本和结果：

```text
analysis\dump_dex_app.py
analysis\dump_dex_app_fixed.py
analysis\extract_dex_strings.py
analysis\analyze_app_strings.py
analysis\decode_dex_switches.py
analysis\dex_disassembly_fixed.txt
analysis\dex_switch_maps.txt
analysis\app_string_analysis.txt
```

这些处理均为 DEX 文件静态读取，没有启动 Android 应用。

## 3. JNI native 校验链

分析 `analysis\code\lib\x86_64\libparloo.so` 的导出函数及调用关系后，整理出的输入检查流程如下：

1. JNI 从 `jstring` 读取 UTF 字节并构造 native 字符串。
2. `0x28c00` 附近的填充函数按 8 字节分组添加 PKCS#7：`n = 8 - (输入长度 mod 8)`，在末尾追加 `n` 个值为 `n` 的字节；若输入正好是 8 的倍数，仍追加 8 个 `0x08`。
3. `0x28d30` 执行分组变换。它要求输入长度是 8 的倍数，使用静态密钥与 IV 做 CBC。
4. 结果字符串与静态目标字符串比较，相同才走成功返回分支。

目标字符串由初始化代码传入 `[0x10130, 0x10158)` 两端指针；helper 计算两指针差并复制相应字节。因此目标长度是 `0x28`，即 40 字节。目标十六进制为：

```text
af9008e79057a3edb1052dba56c04fd3fcaab795eee49f1ae92c21fc292ece52c48cf041e9890d79
```

`analysis\target_range_disassembly.txt` 留存了从 `0x10130` 起、加 `0x28` 后构造目标字符串的汇编证据。

## 4. RC4 静态密钥派生

native 初始化函数对同一密钥执行两次 RC4：一次解出 16 字节分组密钥，一次解出 8 字节 IV。

静态内容如下：

| 项目 | 位置 | 字节 |
|---|---:|---|
| RC4 密码 | `0x10158`, 11 字节 | ASCII `DoNotHackMe` |
| 加密后的分组密钥 | `0x10170`, 16 字节 | `99dd56ff6dd95554424d791a34b7812f` |
| 加密后的 IV | `0x10180`, 8 字节 | `87c156c04cf4634f` |

静态 helper `0x2c740` 做标准 RC4 KSA：初始化 `S[i]=i`，使用 `j=(j+S[i]+key[i mod keylen]) mod 256` 交换；`0x293e0` 的 PRGA 每次从新状态开始生成流并 XOR 输入。用独立实现解得：

```text
TEA_KEY_RAW = 52756e74696d65537472696e67457874
             ASCII: RuntimeStringExt
IV          = 4c696e4b48405348
             ASCII: LinKH@SH
```

16 字节密钥按 little-endian 拆成四个 32 位字：

```text
0x746e7552, 0x53656d69, 0x6e697274, 0x74784567
```

## 5. 分组算法：带密钥扰动累计值的 XTEA 变体

识别算法时不能只按常见 XTEA 模板抄写。`0x28b20` 的汇编确实使用 XTEA 结构：每个 8 字节块读成两个 little-endian 32 位字，做 32 轮，混合项是 `((v << 4) XOR (v >> 5)) + v`，轮常数基值为 `0x9e3779b9`。但它的累计值不是普通 XTEA 的固定 `sum += delta`。

令 `i` 为从 0 到 31 的轮号、`k[0..3]` 为密钥字、`sum_0=0`。每一轮精确顺序为：

```text
T_i = (0x9e3779b9 + (k[i & 3] XOR i)) mod 2^32
v0  = v0 + (mix(v1) XOR (sum_i + k[sum_i & 3])) mod 2^32
sum_(i+1) = sum_i + T_i mod 2^32
v1  = v1 + (mix(v0) XOR (sum_(i+1) + k[(sum_(i+1) >> 11) & 3])) mod 2^32
```

所有加减法按 32 位回绕。注意 `v0` 使用本轮更新前的 `sum_i`，`v1` 使用加过扰动量后的 `sum_(i+1)`。汇编证据保存在 `analysis\xtea_round_function_disassembly.txt`：

```text
0x28b5b..0x28b69：读取 key[round & 3]，与 round XOR，再加 0x9e3779b9
0x28b71..0x28b99：计算 v1 的 mix，并用旧 sum 与 key[sum & 3] 更新 v0
0x28b9c..0x28ba2：将上一步的扰动量累加进 sum
0x28ba5..0x28bd0：计算 v0 的 mix，并用新 sum 的高位选择密钥字更新 v1
```

在 CBC 解密时逐块执行：

```text
P_i = XTEA_variant_decrypt(C_i, key) XOR C_(i-1)
P_0 = XTEA_variant_decrypt(C_0, key) XOR IV
```

## 6. 错误尝试与修正

第一次实现把轮常量按标准 XTEA 处理为固定 `sum += 0x9e3779b9`。程序本身的加解密互逆自测通过，正向 CBC 也能回算目标，但逆向明文末 8 字节是：

```text
238f8210bf7d11b1
```

这不是合法 PKCS#7 填充，不能据此提交候选。主求解器报错：

```text
ValueError: invalid PKCS#7 bytes: 238f8210bf7d11b1
```

这说明“自写加解密互逆”只说明两段代码互相吻合，不足以证明它们与二进制实现一致。回到 `0x28b20` 逐条看汇编后，发现每轮在加 delta 前先将 `key[round & 3] XOR round` 加入该轮增量。将真实增量写成 `delta + (key[round & 3] XOR round)` 并按 32 位回绕后，PKCS#7、`flag{...}` 格式和完整 CBC 回算同时通过。

另一次早期 DEX 转储也曾因 payload 解析宽度错误失败，修正版 `dump_dex_app_fixed.py` 已替代旧版。过程中未把失败候选提交平台。

## 7. 解密与独立复核

主脚本：

```powershell
python .\玄机刷题\题目资料\题目分类\逆向工程\ParlooChecker_549\analysis\solve_offline.py
```

关键输出：

```text
TARGET_CIPHERTEXT_LEN=40
TEA_KEY_RAW=52756e74696d65537472696e67457874
IV=4c696e4b48405348
BLOCK_CIPHER_SELFTEST_MATCH=True
DECRYPTED_PADDED_HEX=666c61677b76686c385872697275796942327a65544c4e633870696b3239484a7937533277307d01
PKCS7_PADDING_LEN=1
CANDIDATE_LEN=39
CANDIDATE_BYTES=b'flag{vhl8XriruyiB2zeTLNc8pik29HJy7S2w0}'
ROUNDTRIP_TARGET_MATCH=True
ROUNDTRIP_CIPHERTEXT=af9008e79057a3edb1052dba56c04fd3fcaab795eee49f1ae92c21fc292ece52c48cf041e9890d79
FLAG_WRAPPER_CHECK=True
```

随后运行 `analysis\independent_verify.py`。这个脚本不导入主求解器，而是独立实现 RC4、带扰动的 XTEA 变体和 CBC，并重新检查所有条件：

```powershell
python .\玄机刷题\题目资料\题目分类\逆向工程\ParlooChecker_549\analysis\independent_verify.py
```

复核结果：

```text
REF_PAD_BYTE=01; REF_PAD_VALID=True
REF_CANDIDATE=flag{vhl8XriruyiB2zeTLNc8pik29HJy7S2w0}
REF_CBC_REENCRYPT_MATCH=True
REF_BLOCK_SELFTEST=True
```

四个 ABI 库中都能找到相同的目标、RC4 密钥、加密分组密钥和加密 IV 常量，减少了只读错单一 ABI 常量的可能：

```text
x86_64      ALL_CONSTANTS_PRESENT=True
x86         ALL_CONSTANTS_PRESENT=True
arm64-v8a   ALL_CONSTANTS_PRESENT=True
armeabi-v7a ALL_CONSTANTS_PRESENT=True
```

## 8. 文件清单与复现记录

```text
originals\ParlooChecker_flag.zip             原始附件
analysis\extracted\ParlooChecker_flag.apk   安全提取的 APK
analysis\code\                              固定清单提取的 manifest、DEX、四 ABI so
analysis\solve_offline.py                    主离线求解器
analysis\independent_verify.py                独立实现的复核器
analysis\commands_output.log                  命令及 stdout/stderr 记录
analysis\native_disassembly_x86_64.txt         JNI 主函数汇编
analysis\native_helpers_28c00.txt              padding/CBC 相关函数汇编
analysis\native_helpers_29a40.txt              native 比较及辅助函数汇编
analysis\xtea_round_function_disassembly.txt   关键轮函数汇编
analysis\target_range_disassembly.txt           目标字符串边界汇编
analysis\dex_disassembly_fixed.txt              修正 payload 后的 DEX 转储
analysis\dex_switch_maps.txt                    混淆 switch 映射
```

命令输出文件保留了解压前检查、静态提取、DEX/ELF 分析、首次 padding 失败、算法修正与两次复核的过程。出现输出过长的汇编时，完整内容同时保存在对应 `analysis` 文本文件中；主日志记录生成命令。
