# #544 第二届 Parloo 杯：Asymmetric

## 结论

候选 flag：

```text
flag{7IvWgcex}
```

这是从附件中静态还原并通过 RSA 正向运算复核的候选值。**没有运行题目 EXE，也没有向玄机平台提交；平台是否接受尚未验证。** 本题附件为 Windows x64 Go 程序，静态分析足以复现输入校验路径。

## 附件与取证记录

题目目录：`题目资料/Asymmetric_544/`

- 原始附件：`originals/Asymmetric_flag.zip`
- 已解压文件：`extracted/Asymmetric_flag.exe`
- ZIP 内只有 `Asymmetric_flag.exe`，未压缩大小 1,546,240 字节；归档内数据与已解压文件逐字节相同。
- EXE SHA-256：`2AB8292A83FA8C9DBA9579C66F1AFE28BE6B3889CA94FCAA6265D18B1466C3DD`
- ZIP SHA-256：`7F405F5B5E2D2F47D6F75B03402863B8F7200E1D14B27DC0DDD6CA8BA1265038`
- Go build 信息：Go 1.22.5，构建参数包含 `-ldflags="-s -w"`。虽移除了常规符号，Go 的 pclntab 仍保留函数名信息。

本分析只将 EXE 当作字节数据读取。没有启动、加载或调用附件，也没有使用网上题解。PowerShell 命令及输出追加保存在 `analysis/commands_output.log`。

## 1. 确认文件类型并定位 Go 函数表

先检查 ZIP 成员、EXE 哈希和 PE 头。EXE 是 PE32+、AMD64（`Machine=0x8664`），ImageBase 为 `0x400000`。PE 中 Go build info 标明版本为 1.22.5；静态扫描还找到源码路径 `F:/ParlooDevelop/Asymmetric/Asymmetric.go`。这些信息表明这是 Go 编译的 x64 程序，而非加壳脚本或.NET 程序。

Go 1.22 pclntab 位于文件偏移 `0xED940`。按该版本的 `pcHeader` 布局解析得到：

- `nfunc = 1807`
- `textStart = 0x401000`
- `funcnameOffset = 0x60`
- `pclnOffset = 0x4EC60`

遍历函数表及其 `_func.nameOff` 后，定位到 `main.main`：VA `0x4A45A0`、RVA `0xA45A0`，其末端函数表项对应 VA `0x4A4A98`。反汇编使用 Python Capstone 直接处理 `.text` 字节，不需要执行程序。

重现文件：

- `analysis/inspect_pe.py`：PE 头、节表、Go build info 及静态字符串扫描
- `analysis/parse_go_pclntab.py`：解析 pclntab 并定位 `main.main`
- `analysis/disasm_main.py`：由 PE 文件字节反汇编 `main.main`
- `analysis/main_disasm.txt`：完整 `main.main` 指令输出
- `analysis/resolve_refs.py`、`analysis/resolved_references.txt`：映射关键调用和静态数据

## 2. 还原输入校验逻辑

`main.main` 的调用及数据流给出以下校验过程：

1. 通过 `fmt.Fprint` 输出输入提示。提示的 Go 字符串头在 VA `0x4EB610`，指向长度 13 的字节串 `Input Secret:`。
2. 创建 `bufio.Reader` 并调用 `bufio.(*Reader).ReadString`（VA `0x470340`），分隔符是换行 `0x0A`；再调用 `strings.TrimSpace`（VA `0x46FAE0`）。因此输入末尾的换行和空白会被剔除。
3. 使用 `math/big.(*Int).SetString`（VA `0x495400`）按十进制从程序内置字符串读取模数 `n`。该字符串地址由 `main.main` 中的 RIP 相对 `LEA` 得到：`0x4A47DE + 0x26EC0 = 0x4CB69E`，长度由 `mov ecx, 0x24` 给出，即 36 字节。
4. 把用户输入的字符串字节交给 `math/big.nat.setBytes`（VA `0x49EDC0`）。这相当于将输入的原始字节按**大端序**解释为整数 `m`；并非将用户文本当十进制数字解析。
5. 构造指数 `e = 0x10001 = 65537`，调用 `math/big.(*Int).exp`（VA `0x495580`）计算 `m^e mod n`。
6. 将结果转换为十进制字符串后，与程序内置的 35 字节目标串比较。目标串的静态地址是 `0x4CB405`，长度由 `cmp rbx, 0x23`（`0x23 = 35`）限定。相等时走 `[+] Passed.` 输出分支，否则走失败分支。

所以通过条件是：

\[
\operatorname{OS2IP}(\text{输入字节})^{65537} \bmod n = y.
\]

从静态 PE 数据中精确读出的常量为：

```text
n = 100000000000000106100000000000003093
y = 55236603000047821981538836465742452
e = 65537
```

其中 `n` 的原始文本长度是 36 字节，`y` 的原始文本长度是 35 字节。`y < n`，符合模幂结果的范围。

关键位置和调用信息也分别保存在 `analysis/rsa_constants.txt`、`analysis/go_functions.txt` 与 `analysis/main_disasm.txt`。

## 3. 分解模数并恢复输入

对 `n` 作整数分解：

\[
n=3\times47\times2287\times3101092514893\times100000000000000003.
\]

这五个因子互不相同且均为素数，乘积与原始 `n` 完全相等。因此：

\[
\begin{aligned}
\varphi(n)
&=(3-1)(47-1)(2287-1)(3101092514893-1)\\
&\quad\cdot(100000000000000003-1)\\
&=65219696899196631704393937983932608.
\end{aligned}
\]

`gcd(65537, φ(n)) = 1`，所以可以求出私有指数：

\[
d=65537^{-1}\bmod\varphi(n)
=4679234856951379560768120243533441.
\]

对目标值作 RSA 反运算，并转换为最短的大端字节串：

\[
m=y^d\bmod n
=2077392566271193964312727644371069.
\]

```text
hex:   666c61677b37497657676365787d
bytes: b'flag{7IvWgcex}'
```

字节串可读为 `flag{7IvWgcex}`。复核时把它按题目相同的方式转成整数，计算：

\[
2077392566271193964312727644371069^{65537}\bmod
100000000000000106100000000000003093
=55236603000047821981538836465742452.
\]

该结果与程序内置的 `y` 逐位相同，且输入字节以 `flag{` 开始、以 `}` 结束。这里是独立的正向数学校验，没有通过运行附件来验证。

## 4. 复现方法

从项目根目录运行静态分析脚本：

```powershell
python ".\题目资料\Asymmetric_544\analysis\inspect_pe.py" ".\题目资料\Asymmetric_544\extracted\Asymmetric_flag.exe"
python ".\题目资料\Asymmetric_544\analysis\parse_go_pclntab.py" ".\题目资料\Asymmetric_544\extracted\Asymmetric_flag.exe"
python ".\题目资料\Asymmetric_544\analysis\disasm_main.py" ".\题目资料\Asymmetric_544\extracted\Asymmetric_flag.exe"
python ".\题目资料\Asymmetric_544\analysis\extract_constants.py" ".\题目资料\Asymmetric_544\extracted\Asymmetric_flag.exe"
python ".\题目资料\Asymmetric_544\analysis\solve_rsa_544.py" ".\题目资料\Asymmetric_544\extracted\Asymmetric_flag.exe"
```

RSA 脚本只读取 EXE 的 PE 节数据来提取上述两个静态字符串；之后使用 SymPy 的 `factorint` 和 `isprime` 检查因子，再用 Python 大整数运算求逆和验证。脚本会断言因子乘积、素性、指数可逆性、正向模幂结果以及 flag 字符串格式。执行脚本不会加载题目 EXE。

详细命令与脚本输出记录在 `analysis/commands_output.log`；便于直接查阅的输出另存为：

- `analysis/inspect_pe_output.txt`
- `analysis/go_functions.txt`
- `analysis/main_disasm.txt`
- `analysis/resolved_references.txt`
- `analysis/rsa_constants.txt`
- `analysis/solve_rsa_output.txt`
- `analysis/verify_archive_output.txt`

## 状态与限制

- 静态算法恢复完成；`flag{7IvWgcex}` 经 RSA 正向计算精确匹配附件中的目标常量。
- 没有执行 EXE，没有使用公开 Writeup，没有向平台提交 flag。
- 因此当前记录的是高置信度候选与本地静态校验结果，**不是玄机平台的提交成功记录**。
