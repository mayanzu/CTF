# PositionalXOR（玄机 ID 550）解题记录

## 题目信息与附件核验

- 题目：第二届 Parloo 杯 PositionalXOR
- 题目 ID：550
- 类型/难度：REVERSE / 中等（以平台题目页为准）
- 本地分析方式：离线分析用户已下载的 ZIP；没有访问公开题解；平台提交由主线程通过 Computer Use 完成。
- 下载包：`D:\Downloads\encrypted_flag.zip`
- ZIP 大小：198 字节
- ZIP SHA-256：`0C563421AE63279233377EEEDFAA34DD85DEFA23A663C46CF1F9DC18FFB0F834`
- ZIP 内唯一文件：`encrypted_flag.bin`，26 字节
- 解压文件 SHA-256：`4D587E8E9916DB9AB5A43F186F606250209B4B7EA8DDB1970B6D2FACFCFE5496`

页面提供的题目附件名在先前观察中记为 `encrypted.bin`，ZIP 内实际文件名为 `encrypted_flag.bin`。因此附件命名有差异；但下载包是在打开本题后取得，文件内容通过题型所述的位置 XOR 解出格式完整的 `flag{...}`，并且复算可无损还原全部 26 字节密文。题目与附件对应关系有较强内容证据。主线程已提交并通过平台验证，详情见本 WP 末节。

## 解题思路

题目名提示 XOR 与字符位置有关。XOR 的性质是同一个值异或两次会抵消：

\[
(x \oplus k) \oplus k = x.
\]

因此若密文第 \(i\) 个字节由明文与位置值异或得到，则解密仍是用同一个位置值异或。这里将数组下标记为从 0 开始的 \(i\)，实际位置值为 \(i+1\)：

\[
P_i = C_i \oplus (i+1), \quad 0 \le i < 26.
\]

第一个字节验证了偏移：密文字节 `0x67` 与位置值 `0x01` 异或得到 `0x66`（`f`）；随后四个字节分别得到 `l`、`a`、`g`、`{`。最后一个字节 `0x67` 与位置值 `0x1A`（十进制 26）异或得到 `0x7D`（`}`）。这同时确定位置计数从 1 开始。

## 逐步操作

以下命令在 Windows PowerShell 5.1 中执行。完整逐条输入与输出（包括早期因 PowerShell/.NET 版本和引号展开导致的失败尝试）见同目录的 `PositionalXOR_550-终端记录.txt`。

### 1. 检查下载包

检查文件路径、大小和下载时间，确认当前分析的是本批下载的压缩包：

```powershell
Get-Item -LiteralPath 'D:\Downloads\encrypted_flag.zip' | Format-List FullName,Length,LastWriteTime
```

输出显示路径 `D:\Downloads\encrypted_flag.zip`、大小 `198` 字节、时间 `2026/9/28 20:15:57`。

对原始压缩包计算 SHA-256，作为输入证据：

```powershell
Get-FileHash -LiteralPath 'D:\Downloads\encrypted_flag.zip' -Algorithm SHA256 | Format-List Algorithm,Hash,Path
```

输出的哈希为 `0C563421AE63279233377EEEDFAA34DD85DEFA23A663C46CF1F9DC18FFB0F834`。

列出压缩包目录，不先假定附件内部文件名：

```powershell
Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::OpenRead('D:\Downloads\encrypted_flag.zip').Entries | Select-Object FullName,Length,CompressedLength | Format-Table -AutoSize
```

输出只有一项：`encrypted_flag.bin`，原始长度 26 字节，压缩长度 28 字节。

### 2. 解压并记录输入摘要

将附件解压到题目专属资料目录，保留下载包和提取文件：

```powershell
Expand-Archive -LiteralPath 'D:\Downloads\encrypted_flag.zip' -DestinationPath 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\附件' -Force
Get-ChildItem -LiteralPath 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\附件' -File | Select-Object FullName,Length,LastWriteTime | Format-Table -AutoSize
Get-FileHash -LiteralPath 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\附件\encrypted_flag.bin' -Algorithm SHA256 | Format-List Algorithm,Hash,Path
```

解压结果是 26 字节的 `encrypted_flag.bin`，SHA-256 为 `4D587E8E9916DB9AB5A43F186F606250209B4B7EA8DDB1970B6D2FACFCFE5496`。

读取原始字节并显示 ASCII：

```powershell
$b=[System.IO.File]::ReadAllBytes("C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\附件\encrypted_flag.bin"); "Length: $($b.Length)"; "ASCII: $([Text.Encoding]::ASCII.GetString($b))"
```

长度为 26，密文 ASCII 展示为：

```text
gnbc~`Tk\kNU`kNWBJEsOr"hOg
```

### 3. 先验证零起始下标假设

数组下标通常从 0 开始，因此先测试直接使用下标 \(i\)：

```powershell
$b=[System.IO.File]::ReadAllBytes("C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\附件\encrypted_flag.bin"); $p=for($i=0;$i -lt $b.Length;$i++){[byte]($b[$i] -bxor ($i -band 255))}; "XOR-index ASCII: $([Text.Encoding]::ASCII.GetString([byte[]]$p))"
```

输出：

```text
go``zeRlTbD^lf@XR[W`[g4W~
```

这串结果不以 `flag{` 开头，也没有 `}` 结尾，说明加密使用的位置值可能是从 1 起算，而不是数组下标本身。

### 4. 使用 1 起始位置值解密

将每个密文字节与 `i+1` 异或，并输出明文十六进制和 ASCII：

```powershell
$b=[System.IO.File]::ReadAllBytes("C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\附件\encrypted_flag.bin"); $p=for($i=0;$i -lt $b.Length;$i++){[byte]($b[$i] -bxor (($i+1) -band 255))}; "XOR (position starts at 1) hex: $(($p | ForEach-Object { $_.ToString("X2") }) -join " ")"; "XOR (position starts at 1) ASCII: $([Text.Encoding]::ASCII.GetString([byte[]]$p))"
```

输出：

```text
XOR (position starts at 1) hex: 66 6C 61 67 7B 66 53 63 55 61 45 59 6D 65 41 47 53 58 56 67 5A 64 35 70 56 7D
XOR (position starts at 1) ASCII: flag{fScUaEYmeAGSXVgZd5pV}
```

结果满足题目常见 flag 外壳，且所有字节均为可打印 ASCII。为逐字节确认位置和运算，输出完整映射表：

```powershell
$b=[System.IO.File]::ReadAllBytes("C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\附件\encrypted_flag.bin"); $p=for($i=0;$i -lt $b.Length;$i++){[byte]($b[$i] -bxor (($i+1) -band 255))}; $rows=for($i=0;$i -lt $b.Length;$i++){[pscustomobject]@{Index=$i;Position=$i+1;CipherHex=$b[$i].ToString("X2");CipherChar=[char]$b[$i];XorKey=$i+1;PlainHex=$p[$i].ToString("X2");PlainChar=[char]$p[$i]}}; $rows | Format-Table -AutoSize
```

映射表完整保存在终端记录中。首尾字节的结果为：

| 下标 | 位置值 | 密文 | XOR | 明文 |
|---:|---:|---:|---:|:---|
| 0 | 1 (`0x01`) | `0x67` (`g`) | `0x67 ^ 0x01` | `0x66` (`f`) |
| 1 | 2 (`0x02`) | `0x6E` (`n`) | `0x6E ^ 0x02` | `0x6C` (`l`) |
| 2 | 3 (`0x03`) | `0x62` (`b`) | `0x62 ^ 0x03` | `0x61` (`a`) |
| 3 | 4 (`0x04`) | `0x63` (`c`) | `0x63 ^ 0x04` | `0x67` (`g`) |
| 4 | 5 (`0x05`) | `0x7E` (`~`) | `0x7E ^ 0x05` | `0x7B` (`{`) |
| 25 | 26 (`0x1A`) | `0x67` (`g`) | `0x67 ^ 0x1A` | `0x7D` (`}`) |

### 5. 逆向复算验证

再将恢复的明文按相同位置值 XOR 一遍，与输入密文逐字节比较；同时检查 flag 外壳和可打印范围：

```powershell
$b=[System.IO.File]::ReadAllBytes("C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\附件\encrypted_flag.bin"); $p=for($i=0;$i -lt $b.Length;$i++){[byte]($b[$i] -bxor (($i+1) -band 255))}; $enc=for($i=0;$i -lt $p.Length;$i++){[byte]($p[$i] -bxor (($i+1) -band 255))}; $match=$true; for($i=0;$i -lt $b.Length;$i++){if($enc[$i] -ne $b[$i]){$match=$false}}; "Round-trip equals original: $match"; "Recovered flag format check: starts_with_flag_brace=$([Text.Encoding]::ASCII.GetString([byte[]]$p).StartsWith("flag{")), ends_with_closing_brace=$([Text.Encoding]::ASCII.GetString([byte[]]$p).EndsWith("}")), printable_ascii_only=$((($p | Where-Object { $_ -lt 32 -or $_ -gt 126 }).Count) -eq 0)"
```

输出：

```text
Round-trip equals original: True
Recovered flag format check: starts_with_flag_brace=True, ends_with_closing_brace=True, printable_ascii_only=True
```

将候选明文以原始字节保存，避免追加文本换行，再读取并计算摘要：

```powershell
$b=[System.IO.File]::ReadAllBytes("C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\附件\encrypted_flag.bin"); $p=for($i=0;$i -lt $b.Length;$i++){[byte]($b[$i] -bxor (($i+1) -band 255))}; [System.IO.File]::WriteAllBytes("C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\analysis\recovered_flag.txt",[byte[]]$p); Get-Content -LiteralPath "C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\analysis\recovered_flag.txt" -Raw; Get-FileHash -LiteralPath "C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\analysis\recovered_flag.txt" -Algorithm SHA256 | Format-List Algorithm,Hash,Path
```

输出明文为 `flag{fScUaEYmeAGSXVgZd5pV}`，文件 SHA-256 为 `7231C0724F04C01F3FA35798D76DC6FC8866C59304D8965BD364795941400FF7`。

## 结论

附件采用简单的位置 XOR。对 0 基数组下标 \(i\)，密钥字节为 `i+1`；解密公式为 `明文[i] = 密文[i] XOR (i+1)`。本地强验证的候选 flag 是：

```text
flag{fScUaEYmeAGSXVgZd5pV}
```

候选符合 `flag{...}` 格式，全部字符可打印，且重新加密后与附件逐字节相同。主线程已将候选提交到 ID 550 题目页并获得平台正确反馈，详情见本 WP 末节。

## 文件位置

- 附件：`C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\附件\encrypted_flag.bin`
- 恢复结果：`C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PositionalXOR_550\analysis\recovered_flag.txt`
- 完整 PowerShell 命令和输出：`C:\Users\mzj\Desktop\CTF\玄机刷题\记录\PositionalXOR_550-终端记录.txt`

## 玄机平台验证记录

- 题目：ID 550，第二届Parloo杯PositionalXOR。
- 操作方式：使用 Computer Use 前台浏览器在 `https://xj.edisec.net/challenges/550` 打开“提交 FLAG”，输入本地逆向复核得到的 `flag{fScUaEYmeAGSXVgZd5pV}`，并点击对话框中的“提交”。
- 平台返回：`FLAG 正确~, 恭喜你完成此挑战~`。
- 页面核验：题目显示“已完成”，步骤为 `1/1`；完成度环从 20% 变为 40%。
- 结果：平台验证通过。页面截图已在本轮 Computer Use 操作中展示；终端与平台动作记录见 `新批次-主线程终端记录.txt`。
