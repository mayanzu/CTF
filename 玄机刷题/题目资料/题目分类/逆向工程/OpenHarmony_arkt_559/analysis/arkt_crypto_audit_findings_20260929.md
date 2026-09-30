# OpenHarmony arkt (#559) 加解密链独立审计

审计日期：2026-09-29

## 结论

本地静态分析得到的候选 flag 是：

```text
flag{b80ebf0f0e210ad73664bdd19c16387e}
```

候选通过本地逐层正向复现：38 个目标 Base64 字符串、RSA 公钥变换及 RC4 变体输出全部与 ABC 中的 `targetCipher` 一致。**尚未向玄机平台提交，因此平台验证状态未确认。**

## 还原过程

### 1. 找到实际目标数组

在 `modules.abc` 头部 literal-array 索引表中，`Index` 构造函数所用目标数组是索引 17，文件偏移 `0x265a`。数组头的 `num_literals=76`；项目随附的 `literal_data_accessor-inl.h` 显示枚举按两个 literal slot 处理一个值，因此数组含 38 个字符串，不是 76 个，也不是旧脚本里的 36 个。

旧的 36 项硬编码表漏掉了目标索引 8 的 `nte3ndK=` 和索引 35 的 `nJaXma==`。审计重新从 ABC 逐项读取全部 38 项。

### 2. 自定义 Base64 与 RSA

`customBase64` 先用 `Base64Helper.encodeToStringSync` 编码，再把标准字符表
`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
按索引替换为
`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/`。
因此反向时用后一字符表转换回标准 Base64，再解出 ASCII 十进制整数。

`rsaEncrypt` 对每个字节逐项调用 `modPow(value, 7, 75067)`。模数分解为 `271 × 277`，所以 `phi=74520`，`d=42583` 且 `7 × 42583 ≡ 1 (mod 74520)`。对 38 个十进制密文逐项计算 `pow(c, d, 75067)` 得到 RC4 层数据：

```text
138c5ff4280f930c8c0f3c15e8bb72bcb6f8e11c70ecaf0f724fe48a4e082359d4294e15eae4
```

38 个字节都在 0–255 范围内，且逐项执行 `pow(m, 7, 75067)` 可还原原十进制密文。

### 3. 页面生命周期中的有效密钥

构造函数先把 `secretKey` 初始化为 `OHCTF2025`，但这不是首次提交时的有效值。`onPageShow` 在 `isInitialized` 为假时执行：

```text
this.secretKey = "OHCTF2026"
this.isInitialized = true
```

因此在正常页面首次显示后，校验使用的密钥是 `OHCTF2026`。只按构造函数常量 `OHCTF2025` 逆向会得到乱码，这是之前解密冲突的原因。

### 4. RC4 变体

`rc4Encrypt` 的 KSA 与标准 RC4 有差异。逐条读取的字节码表明每轮按旧状态 `j` 更新：

```text
j = (j + S[j] + key.charCodeAt(j % key.length)) % 256
swap(S[i], S[j])
```

PRGA 将 `i`、`j` 清零后运行：

```text
i = (i + 1) % 256
j = (j + S[i]) % 256
swap(S[i], S[j])
stream = S[(S[i] + S[j]) % 256]
```

每个输出字节不是标准 RC4 的 XOR，而是：

```text
cipherByte = (input.charCodeAt(position) + stream) % 256
```

所以逆变换是 `inputByte = (cipherByte - stream) % 256`。用有效密钥 `OHCTF2026` 解得上述 flag。

### 5. 正向复现

候选重新经过 KSA/PRGA 加法、RSA 指数 7、十进制字符串、UTF-8、自定义 Base64 后，与 ABC 中 38 个 `targetCipher` 字符串逐项完全相同。独立复现脚本报告：

- RSA 公钥逐项往返：PASS
- 38 个自定义 Base64 token 逐项匹配：PASS
- `flag{...}` 格式：PASS
- 候选长度与目标项数同为 38：PASS

这证明候选与本地程序常量一致，但平台是否接受仍需通过平台提交结果确认。

## 本地证据与可复现记录

- 原始附件：`附件\arkt_platform_20260929.zip`
- HAP 字节码：`附件解包\HAP内容\ets\modules.abc`
- 本审计逐方法反汇编：`analysis\arkt_crypto_audit_methods_20260929.txt`
- 逐层命令与输出 transcript：`analysis\arkt_crypto_audit_transcript_20260929.txt`
- 独立正向复现：`analysis\agent_arkt559_independent_reproduce.py`
- ISA / ABC 格式参考：`..\OpenHarmony_easyre_560\analysis\reference\isa.yaml`、`file_format.md` 及同目录 OpenHarmony 源码

独立复现命令：

```powershell
python -B -u "C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\OpenHarmony_arkt_559\analysis\agent_arkt559_independent_reproduce.py"
```

全程使用项目已有本地附件、解析器、ISA 与 reference；没有使用公开 Writeup，没有下载或运行新工具，也没有提交平台。
