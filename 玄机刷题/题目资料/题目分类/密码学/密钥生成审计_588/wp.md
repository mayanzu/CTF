# 2026安网杯—密钥生成审计（玄机 #588）

## 题目与本地范围

- 题目：2026安网杯-密钥生成审计，ID #588。
- 题目页初始状态：免费、困难、0/1；2026-09-29 前台提交候选后平台接受，页面显示已完成、步骤 1/1。
- 附件：`originals/密钥生成审计附件.zip`，内有 `challenge.py` 和 `output.txt`。原始 ZIP 未修改。
- 本解法只把 `challenge.py` 当作源码文本读取；没有运行题目脚本或附件中的可执行文件，也没有访问公开 Writeup 或联网。

## 附件结构与程序语义

`challenge.py` 给出完整的生成流程（`FLAG` 字面量被替换成 `???`）：

1. 创建 `random.Random()`，以 `os.urandom(16)` 转成的 128 位整数作为种子。
2. 连续公开 624 次 `getrandbits(32)` 的十进制结果。
3. 紧接着再取 4 个 32 位结果，每个按大端序转成 4 字节并拼成 AES-128 密钥。
4. 用该密钥通过 AES-ECB 加密 `pad(FLAG, 16)`，密文以十六进制放在 `output.txt` 的最后一行。

安全问题在于 Python `random.Random` 使用 MT19937 伪随机数发生器，不适合生成密钥。把连续 624 个完整 32 位输出全部公开，足以逆转每次输出上的可逆 temper 变换并恢复当前 624 个状态字。种子原本有 128 位熵也无法补救：攻击者不需要恢复种子，只需预测紧接着的输出。

附件核对结果：`output.txt` 恰好 625 个非空行。前 624 行均为 0 至 `2^32-1` 的十进制整数；末行是 96 个十六进制字符，即 48 字节、3 个 AES 分组的密文。

## 逐步求解

### 1. 读取并校验公开数据

运行 `analysis/solve_588.py`。脚本检查行数、整数范围、密文十六进制格式和 AES 分组长度，拒绝格式不符的输入。首个公开数是 `611087032`，第 624 个公开数是 `3945758924`。

### 2. 逆转 MT19937 temper

MT19937 对内部状态字 `x` 执行如下可逆变换得到公开值 `y`：

```text
y = x ^ (x >> 11)
y = y ^ ((y << 7)  & 0x9D2C5680)
y = y ^ ((y << 15) & 0xEFC60000)
y = y ^ (y >> 18)
```

逆变换按相反次序处理移位，并通过重复代入消除被异或的高位或低位：右移 18、带掩码左移 15、带掩码左移 7、右移 11。脚本对 624 个输入全部执行 `temper(untemper(y)) == y`，结果为 `PASS (624/624)`。

### 3. 重建状态并预测后续四个输出

Python 状态 API 的状态格式为 `(version, 624 个状态字 + index, gauss_cache)`。将逆 temper 得到的 624 个状态字装入 `random.Random.setstate((3, tuple(words + [624]), None))`。索引 624 表示这一整块输出已经消耗；下一次抽取会执行 MT19937 的 twist，随后得到原生成器的第 625 个输出。

为避免状态边界的 off-by-one，脚本用独立的固定种子测试流生成 628 个输出，只把前 624 个交给克隆器，然后确认克隆器预测的第 625–628 个值与参考流完全一致。测试通过。对附件数据得到：

```text
2372119022, 1272119227, 2846020694, 1107164319
```

程序按大端序拼接这四个 32 位值：

```text
2372119022 = 0x8D63A9EE
1272119227 = 0x4BD2FFBB
2846020694 = 0xA9A2D456
1107164319 = 0x41FDFC9F
AES-128 key = 8d63a9ee4bd2ffbba9a2d45641fdfc9f
```

以上过程由纯 Python 标准库实现，不需要安装 PyCryptodome。系统上的 Python 是 3.12.10；本机未安装 `Crypto` 模块，因此 AES 解密采用 Windows PowerShell/.NET 的系统密码学库。

### 4. AES 解密与明文校验

`analysis/decrypt_588.ps1` 读取上一步写出的 `derived_material.json`，使用 AES-128、ECB、无自动填充解密 48 字节密文，再手工验证并移除 PKCS#7 填充。末尾字节为 `0x0A`，连续 10 个字节均为 `0x0A`，故移除 10 字节后剩 38 个 ASCII 字节。结果符合 `flag{...}` 格式：

```text
flag{2db163a20ecc0e6a27ce588669211a2e}
```

最后将解密得到的 48 字节（含填充）重新 AES-ECB 加密，结果与附件密文逐字节相等，`REENCRYPTION_ROUNDTRIP=PASS`。这验证密钥、模式、字节序及解填充长度相互一致。

## 结论

**静态候选：`flag{2db163a20ecc0e6a27ce588669211a2e}`**

完整数据链为：624 个连续 MT19937 输出 → 逆 temper 恢复状态 → 预测后续四个 32 位值 → 大端拼成 AES 密钥 → AES-ECB 解密 → 验证 PKCS#7 并得到标准 flag。候选已由玄机平台接受，页面显示已完成、步骤 1/1。

## 复现命令

在 Windows PowerShell 中，从题目目录运行：

```powershell
$D = 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\密钥生成审计_588'
python (Join-Path $D 'analysis\solve_588.py')
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $D 'analysis\decrypt_588.ps1')
```

完整逐步输入/输出、环境检查和调试记录见 `analysis/session_transcript.txt`；最终脚本输出分别保存在 `analysis/solve_588_output.txt` 与 `analysis/decrypt_588_output.txt`。首轮自检和本机 .NET API 兼容性调试失败也保留在总 transcript 中，最终修正版两步退出码均为 0。

## 玄机平台提交与验收记录（2026-09-29）

- 题目页：https://xj.edisec.net/challenges/588
- 候选：flag{2db163a20ecc0e6a27ce588669211a2e}
- 操作：Chrome 前台打开题目页，点击“提交FLAG”，键入候选并点击“提交”。
- 平台详情页显示“已完成”，步骤 1/1；页面总体进度随之更新。此为平台接受回执。
- 截图在 computer-use 会话中捕获并展示，未保存成项目内 PNG 文件。