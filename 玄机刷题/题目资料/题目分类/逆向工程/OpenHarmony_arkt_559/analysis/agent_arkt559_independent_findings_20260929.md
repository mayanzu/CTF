# #559 第一届 OpenHarmony arkt：独立逆向记录

## 结论

本地附件可复现候选 flag：

```text
flag{b80ebf0f0e210ad73664bdd19c16387e}
```

解题路径已通过逐项正向重加密核对：38 个目标密文分块全部匹配附件中的 `targetCipher`。本记录没有向玄机平台提交该候选，因此平台状态仍需由主流程提交后确认。

可复现脚本：[agent_arkt559_independent_reproduce.py](agent_arkt559_independent_reproduce.py)
完整 PowerShell 命令和原始输出：[agent_arkt559_independent_transcript_20260929.txt](agent_arkt559_independent_transcript_20260929.txt)

## 附件与环境

- 平台附件副本：`附件\arkt_platform_20260929.zip`
- 平台下载 ZIP SHA-256：`81D7F3225DC36345A968A2F498E00AAD570C08B8DCAD89E13405BD3195A4263B`。
- HAP：`附件解包\task_5.hap`
- Ark 字节码：`附件解包\HAP内容\ets\modules.abc`
- `modules.abc` SHA-256：`aa0579a16af1d76438040f1470c46a007b5c7ae386aff775c09eb82c0be6f03f`
- 使用项目内已保存的 `OpenHarmony_easyre_560\analysis\disassemble_target_methods.py`、`isa.yaml` 和 Panda 格式说明解析字节码。未下载或运行新工具。
- 复现脚本只依赖 Python 标准库，直接读取本题 `modules.abc`。

## 题目校验逻辑

`Index` 类的 `handleCheck` 取输入框文本并调用 `enc`，再把加密结果逐项同 `targetCipher` 比较；比较长度也必须为 38。`enc` 的处理顺序是：

1. 用组件字段 `secretKey` 调用 `rc4Encrypt`。
2. 对每个 RC4 输出字节调用 `rsaEncrypt`，RSA 参数为公钥 `n=75067, e=7`。
3. 把 RSA 整数转成十进制文本，以 UTF-8 编码后使用标准 Base64，再按自定义字母表换字母。
4. 将得到的 38 个字符串与 `targetCipher` 逐项比较。

`customBase64` 中的标准字母表是 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`，自定义字母表是 `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/`。解码时须先把自定义字母映射回标准字母表，再执行 Base64 解码；解出的内容是 RSA 密文整数的十进制文本。

## 逐步还原过程

### 1. 定位关键方法和常量

从 `modules.abc` 的 class index 解析出 `entry/src/main/ets/pages/Index` 类。用项目内已有 ISA 表解出 `handleCheck`、`enc`、`rc4Encrypt`、`rsaEncrypt`、`modPow`、`customBase64`、`stringToUint8Array` 和页面初始化代码。解析输出及指令证据均在独立 transcript 中。

`rsaEncrypt` 的指令常量给出 `n=75067`、`e=7`。分解模数：

```text
75067 = 271 × 277
φ(n) = (271−1)(277−1) = 74520
d = 7⁻¹ mod 74520 = 42583
```

### 2. 还原运行时 RC4 密钥

`Index` 构造函数先将 `secretKey` 置为 `OHCTF2025`，同时把 `isInitialized` 置为 `false`。页面的 `onPageShow` 检查该字段；首次显示时会把 `secretKey` 改为 `OHCTF2026`，并将 `isInitialized` 设为 `true`。提交按钮在页面显示后使用运行时值，因此本次逆向使用 `OHCTF2026`。

### 3. 从 LiteralArray 取完整目标

用 ABC 头部的 `num_literalarrays` 和 `literalarray_idx_off` 遍历数组索引表；第 17 项位于文件偏移 `0x265a`。该 LiteralArray 的 `num_literals=76`，按两个字段（tag、value）一组解析后得到 38 个字符串。所有项目的 tag 都是 `STRING (0x05)`。

这一步也避免了只按可打印字符串提取造成的漏项：数组中的重复项必须保留。完整顺序由复现脚本直接读取，不手工重排。

### 4. 解自定义 Base64

对每个目标字符串先按自定义字母表反向换表，再 Base64 解码并将结果作为十进制整数解析。前几个结果为：

```text
ndG5nZa= → 48970
nte3ndK= → 51749
nJy2nJi= → 66662
mtK0mJG= → 19428
nde5mZK= → 41939
```

38 项完整整数数组由脚本打印并在正向验证中逐项使用。

### 5. 解 RSA 层

逐项计算：

```python
m = pow(cipher_integer, 42583, 75067)
```

解出的 38 字节为：

```text
138c5ff4280f930c8c0f3c15e8bb72bcb6f8e11c70ecaf0f724fe48a4e082359d4294e15eae4
```

RSA 逆向结果仍是 RC4 的输出字节，还需要按字节码恢复 RC4 变体。

### 6. 按字节码逆向 `rc4Encrypt`

该函数保留了 RC4 的状态表初始化、KSA/PRGA 结构，但两个细节与标准 RC4 不同：

- KSA 每轮以当前 `j` 索引状态表和密钥字符：

  ```text
  j = (j + S[j] + key.charCodeAt(j % key.length)) mod 256
  swap(S[i], S[j])
  ```

- PRGA 得到流字节 `K` 后，输出是加法而非 XOR：

  ```text
  C = (P + K) mod 256
  P = (C - K) mod 256
  ```

因此用标准 RC4（`S[i]`/`key[i % len]` 作为 KSA 索引或 `P XOR K`）都会得到错误结果。复现脚本严格按本题字节码执行上述变体，并用 `OHCTF2026` 逆向，得到候选 flag。

### 7. 正向验证

把候选 flag 重新送入相同变换：

1. 按 `OHCTF2026` 执行 KSA/PRGA，计算 `(P+K) mod 256`。
2. 对每个字节计算 `pow(value, 7, 75067)`。
3. 将 RSA 数值转十进制 UTF-8 文本，执行 Base64 编码并换成小写字母优先的自定义字母表。
4. 将生成的 38 个 token 和从 LiteralArray 直接读取的原目标逐项比较。

脚本结果：RSA 公钥回算通过、自定义 Base64 逐项匹配通过、长度检查通过、`flag{...}` 语法检查通过。该端到端匹配为本地候选的强证据；最终平台接受结果尚未记录。

## 复现命令

在 PowerShell 中执行：

```powershell
Set-Location 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\OpenHarmony_arkt_559'
python .\analysis\agent_arkt559_independent_reproduce.py
```

脚本会输出附件 SHA-256、LiteralArray 偏移和项数、RSA 参数、38 个目标整数、RSA 中间字节、候选 flag、正向生成的 token，并对四项检查逐一打印 `PASS`。

## 排错记录

- 初次只从连续可打印字符串手工抄取目标，漏掉了 LiteralArray 中的重复条目；按索引表读取后确认正确目标长度是 38。
- 以标准 RC4 的 XOR 和常规 KSA 索引试解时无法得到可读文本。逐条查看 `rc4Encrypt` 指令后，确认题目使用模 256 加法，且 KSA 以 `j` 取索引；按此变体恢复后才能匹配全部目标。
- 构造函数中的 `OHCTF2025` 是首次显示前的默认值；`onPageShow` 会覆盖成 `OHCTF2026`。忽略页面生命周期会选错密钥。
- 当前状态：本地候选和完整端到端复算均已完成；平台尚未提交验证。

