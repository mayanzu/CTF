# 玄机 #559：第一届 OpenHarmony arkt

## 结论与验证状态

本地逆向恢复出的候选 flag 为：

```text
flag{b80ebf0f0e210ad73664bdd19c16387e}
```

附件中的 38 项密文经过逆向后得到该字符串；再按字节码恢复的完整加密流程正向计算，38 项逐一与附件目标相同。2026-09-29 已在玄机平台前台提交并取得“FLAG 正确”回执；详情页显示“已完成”，步骤 1/1。

## 附件与工具

| 项目 | 路径 | SHA-256 |
|---|---|---|
| 平台下载 ZIP | `附件\arkt_platform_20260929.zip` | `81D7F3225DC36345A968A2F498E00AAD570C08B8DCAD89E13405BD3195A4263B` |
| HAP | `附件解包\task_5.hap` | `AFF302A750AF02C649ECCC1FB504F348B74F76366B708389CE38971A0B58F3DA` |
| Ark ABC | `附件解包\HAP内容\ets\modules.abc` | `AA0579A16AF1D76438040F1470C46A007B5C7AE386AFF775C09EB82C0BE6F03F` |

分析只使用本机 Python 标准库、项目中已有的 `isa.yaml`、ABC 手工解析/反汇编脚本和随题附件；没有为此安装反编译器。格式依据此前一次性查阅并保存到本地的 OpenHarmony 官方资料，查阅日期为 2026-09-29：[`file_format.md`](https://github.com/openharmony/arkcompiler_runtime_core/blob/master/docs/file_format.md) 用于核实 ABC 文件及 LiteralArray 布局；[`isa.yaml`](https://raw.githubusercontent.com/openharmony/arkcompiler_runtime_core/master/isa/isa.yaml) 用于解释指令编码；[官方源码仓库](https://github.com/openharmony/arkcompiler_runtime_core) 中随项目保存的 `literal_data_accessor-inl.h` 用于核实 LiteralArray 计数规则。它们只作格式和指令参考，没有查看题目公开 Writeup。

关键复现文件：

- `solve_arkt_target.py`：本题目录内的逆向和正向复算脚本；显式比较构造函数默认 key 与页面运行时 key。
- `analysis\agent_arkt559_independent_reproduce.py`：独立实现的 ABC 索引、LiteralArray 解析及端到端复算脚本。
- `arkt559_analysis_transcript_20260929.txt`：本目录主 PowerShell transcript，保存命令和原始输出，包括早期错误假设、纠错过程、字节码输出、最终复算和哈希。
- `analysis\agent_arkt559_independent_findings_20260929.md` 及 `analysis\agent_arkt559_independent_transcript_20260929.txt`：并行复核记录和独立 transcript。

## 题目检查逻辑

从 `entry/src/main/ets/pages/Index` 的 Ark 字节码确认：`handleCheck` 读取输入框文本并调用 `enc`，随后把 `enc` 产生的字符串数组与 `targetCipher` 按位置比较。数组长度及每一项都必须匹配。

`enc` 的数据路径是：

```text
输入文本
  -> rc4Encrypt(secretKey, input)
  -> 对每个 RC4 字节执行 modPow(byte, 7, 75067)
  -> RSA 数字转十进制字符串
  -> UTF-8 字节
  -> 标准 Base64
  -> 自定义 Base64 字母表
  -> targetCipher 逐项比较
```

`customBase64` 中标准字母表为 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`，自定义字母表为 `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/`。其实现把标准 Base64 字符按相同下标替换为自定义表字符，所以解码时要把自定义表换回标准表，再 Base64 解码。解码后的字节是 RSA 密文整数的十进制文本。

## 逐步还原

### 1. 定位 ABC 与关键方法

HAP 中的 Ark 字节码位于 `ets/modules.abc`。使用项目中保存的 OpenHarmony ISA 表解析类索引、方法记录和指令。对 `handleCheck`、`enc`、`rc4Encrypt`、`rsaEncrypt`、`modPow`、`customBase64`、`stringToUint8Array`、构造函数及 `onPageShow` 进行交叉核对。方法指令和解析输出在 transcript 中。

### 2. 确定实际密钥

构造函数将 `secretKey` 初始设为 `OHCTF2025`，并将 `isInitialized` 设为 `false`。首次显示页面时，`onPageShow` 检查该字段；尚未初始化时把 key 覆写为 `OHCTF2026`，再把标志置为 `true`。用户在页面输入并触发检查时，`enc` 从当前组件对象读取 `secretKey`，所以运行时有效密钥为 `OHCTF2026`。

忽略生命周期、只使用构造函数中的默认值会得到不可读的字节。复算脚本也试了默认值：它能按数学定义回算目标密文，但明文不符合 flag 格式；生命周期确定的 `OHCTF2026` 得到可读候选。

### 3. 解析 38 个目标字符串

构造函数的 `createarraywithbuffer` 指令引用 LiteralArray 偏移 `0x265a`。ABC LiteralArray 头部的计数是 `76`。本地官方实现 `LiteralDataAccessor::EnumerateLiteralVals` 每轮按 `i += 2` 消费一个 tag/value 对，因此 `76` 对应 38 个数组值，而不是 76 个 flag 字符或 76 个独立字符串。38 个 tag 均为 `STRING (0x05)`；顺序及重复值必须原样保留。

按顺序解析并解码出的 RSA 密文整数为：

```text
48970, 51749, 66662, 19428, 41939, 6883, 25852, 24849,
51749, 6883, 20438, 6010, 10970, 10850, 30648, 26553,
32227, 26954, 8412, 10597, 66344, 70294, 44489, 6883,
30648, 6031, 19460, 46945, 2330, 70343, 46778, 61810,
40341, 73746, 2330, 6010, 66221, 19460
```

完整自定义 Base64 token 顺序由脚本和 transcript 打印；例如开头 `ndG5nZa=` 解回 ASCII `48970`，紧接的 `nte3ndK=` 解回 `51749`。重复项（如 `nte3ndK=`、`nJG4mW==`）是目标数组内容的一部分，不能去重。

### 4. 逆向 RSA

`rsaEncrypt` 的字节码给出公钥参数 `n=75067`、`e=7`。分解：

```text
75067 = 271 × 277
φ(n) = (271−1)(277−1) = 74520
d = 7⁻¹ mod 74520 = 42583
```

逐项计算 `m = pow(cipher, 42583, 75067)`，得到 38 个 RC4 输出字节：

```text
138c5ff4280f930c8c0f3c15e8bb72bcb6f8e11c70ecaf0f724fe48a4e082359d4294e15eae4
```

独立验证每项 `pow(m, 7, 75067) == cipher` 均成立。

### 5. 按题目字节码逆向 RC4 变体

此函数使用 RC4 风格的 S 盒和 PRGA，但 KSA 的索引与最终逐字节运算都不是标准 RC4。手工追踪 `rc4Encrypt` 的寄存器：

1. 初始化 `S` 为 `0..255`。
2. KSA 每轮更新 `j` 时，从字节码确认它读取 `S[j]`，并以 `j` 取密钥字符：

   ```text
   j = (j + S[j] + key.charCodeAt(j % key.length)) mod 256
   swap(S[i], S[j])
   ```

3. PRGA 使用通常的状态更新：`i=(i+1) mod 256`，`j=(j+S[i]) mod 256`，交换 `S[i]` 和 `S[j]`，再取 `K=S[(S[i]+S[j]) mod 256]`。
4. 输出字节是加法：`C=(P+K) mod 256`。逆向要执行 `P=(C-K) mod 256`，不是 XOR。

使用运行时 key `OHCTF2026` 对 RSA 中间字节逐项相减，恢复：

```text
flag{b80ebf0f0e210ad73664bdd19c16387e}
```

### 6. 端到端正向验证

复现脚本把候选按原链路正向计算：自定义 KSA/PRGA 与模 256 加法、RSA `pow(byte,7,75067)`、十进制 UTF-8、Base64、自定义字母替换。输出的 38 个 token 与 LiteralArray 顺序逐项一致。两份解析路径不同的脚本都得到同一候选：主脚本直接从 `0x265a` 解析 tag/value；独立脚本先从 ABC 头部索引表读取第 17 项，再依据官方 accessor 的计数规则解析。

独立复算脚本最终报告：

```text
CHECK RSA public-key roundtrip: PASS
CHECK custom Base64 token-by-token roundtrip: PASS
CHECK flag syntax: PASS
CHECK flag length: PASS
```

这证明附件内目标与候选在本地端到端匹配；玄机平台于 2026-09-29 前台提交接受，详情页显示步骤 1/1。

## 复现命令

在 PowerShell 中运行独立复核脚本：

```powershell
Set-Location 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\OpenHarmony_arkt_559'
python .\analysis\agent_arkt559_independent_reproduce.py
```

或运行当前目录内会同时比较构造函数默认 key 与页面运行时 key 的脚本：

```powershell
python .\solve_arkt_target.py
```

完整的逐条终端输入、工具输出和前期纠错过程请查看 `arkt559_analysis_transcript_20260929.txt`。复核版还可查看 `analysis\agent_arkt559_independent_transcript_20260929.txt`。

## 常见误区

- 只按文件中的可打印字符串扫描会漏掉重复项或打乱顺序；应按 LiteralArray 索引和 tag/value 解析。
- 把头部计数 `76` 当作 76 个独立数组元素会多读后续数据；本格式中一个值由 tag/value 两槽组成，实际是 38 项。
- 只取构造函数里的 `OHCTF2025` 会忽略 `onPageShow` 的覆写。
- 使用标准 RC4 KSA（`S[i]`、`key[i % len]`）或 XOR 都与此题字节码不一致。
- 自定义 Base64 解码前必须先把自定义字母映回标准表。
- 正向验证必须保留所有 38 项的原始顺序和重复项；只检查 flag 语法不足以验证候选。

## 当前题目状态

- 本地求解：完成，候选经完整正向复算匹配附件。
- 玄机平台：2026-09-29 前台提交后显示“FLAG 正确”，详情页已完成，步骤 1/1。
- 日志与 WP：本目录 `arkt559_analysis_transcript_20260929.txt`、`WP.md`；独立材料位于 `analysis` 子目录。

## 2026-09-29 静态复核补充

本轮重新从原始压缩包核对附件溯源，并运行两个纯 Python 标准库复现脚本。没有启动 HAP/应用，也没有执行题目目录中的任何 EXE；没有访问平台、网络或公开 Writeup。

### 附件来源与完整性

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `附件\arkt_platform_20260929.zip` | 109,627 bytes | `81D7F3225DC36345A968A2F498E00AAD570C08B8DCAD89E13405BD3195A4263B` |
| `附件解包\task_5.hap` | 135,682 bytes | `AFF302A750AF02C649ECCC1FB504F348B74F76366B708389CE38971A0B58F3DA` |
| `附件解包\HAP内容\ets\modules.abc` | 22,072 bytes | `AA0579A16AF1D76438040F1470C46A007B5C7AE386AFF775C09EB82C0BE6F03F` |

复现脚本使用 Python `zipfile` 只读检查容器：原 ZIP 中唯一的 `task_5.hap` 与保存的 HAP 字节完全相同；HAP 中唯一的 `ets/modules.abc` 与解包目录里的 ABC 字节完全相同。这样可确认分析所用字节码确实来自随题 ZIP，而不是后来替换的文件。

### 逐层复算证据

1. ABC literal-array 头部给出 21 个数组和索引表偏移 `0x6c`。索引 17 对应数组偏移 `0x265a`，与构造函数 `createarraywithbuffer` 对 `targetCipher` 的引用一致。数组声明 76 个 literal slots；每个字符串由 STRING tag 与 offset 两个槽组成，因此是 38 个字符串。脚本逐条检查 tag，保留顺序和重复项。
2. 将自定义 Base64 逆映射为标准 Base64 后，解码值是十进制 ASCII。比如 `ndG5nZa=` 解为 `48970`，`nte3ndK=` 解为 `51749`。38 项完整序列由脚本从 ABC 动态读取，没有写死在求解程序中。
3. 字节码中的 RSA 公钥为 `(n,e)=(75067,7)`。`n=271×277`，`φ(n)=74520`，`d=7^{-1} mod 74520=42583`。每项通过 `m=pow(c,d,n)` 还原为 0–255 的一个字节；脚本同时逐项核对 `pow(m,e,n)==c`。
4. 结合页面生命周期静态反汇编，构造函数的 `OHCTF2025` 是初始值；首次 `onPageShow` 在 `isInitialized == false` 时改为 `OHCTF2026` 并设为已初始化。因此页面检查实际使用 `OHCTF2026`。
5. KSA 根据字节码实现为 `j=(j+S[j]+key[j mod len]) mod 256`，随后交换 `S[i]` 与 `S[j]`。PRGA 产生的流字节与输入相加（模 256），故逆向是相减（模 256）。RSA 解出的中间字节经此逆变换得到候选 `flag{b80ebf0f0e210ad73664bdd19c16387e}`。
6. 正向重算完整执行变体 RC4、RSA 指数 7、十进制编码、自定义 Base64；生成的 38 个 token 与 ABC 目标逐项相等，`ALL_38_MATCH=True`。这还检查了数组中索引 8、9、23、35 等重复项没有被漏掉或去重。

### 可复现命令与记录

从题目目录运行新的相对路径复现脚本：

```powershell
Set-Location 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\OpenHarmony_arkt_559'
python -B -u .\analysis\reproduce_arkt559.py
```

独立交叉复核：

```powershell
python -B -u .\analysis\agent_arkt559_independent_reproduce.py
```

两条命令都退出码为 0。完整输入命令和逐条输出（含 38 个目标值与 38 行正向比较）记录在 `analysis\reproduce_arkt559_transcript_20260929.txt`；第二个解析器的输出也追加在该记录末尾。程序源代码分别为 `analysis\reproduce_arkt559.py` 和 `analysis\agent_arkt559_independent_reproduce.py`。目录级 SHA-256 文件清单由 `analysis\hash_inventory.py` 生成，见 `analysis\SHA256_INVENTORY_20260929.txt`；生成命令、条数和清单自身哈希记录在 `analysis\SHA256_INVENTORY_RUN_20260929.txt`。清单将其自身和生成日志排除，以避免递归哈希。

本地附件一致性和 38 项重加密匹配均通过；玄机平台已接受此候选，详情页显示步骤 1/1。


## 玄机平台提交与验收记录（2026-09-29）

- 题目页：https://xj.edisec.net/challenges/559
- 候选：flag{b80ebf0f0e210ad73664bdd19c16387e}
- 操作：Chrome 前台打开题目页，点击“提交FLAG”，键入候选并点击“提交”。
- 平台反馈：“FLAG 正确，恭喜你完成此挑战”；详情页标记“已完成”，步骤 1/1。
- 截图在 computer-use 会话中捕获并展示，未保存成项目内 PNG 文件。