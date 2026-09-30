# PaluArray（玄机 ID 546）静态逆向 WP

## 结论

2026-09-30 补充：将同一 MD5 摘要改成 `flag{1b501325fc96d5a845cbdd2ba4f01cd7}` 在玄机页面提交，平台也明确显示“FLAG 不正确~”，仍为 0/1。因此不能用统一前缀替换解释旧候选被拒；本题继续未完成。提交细节见 `记录/未解题续攻_20260930.md`。

公开的原参赛者 [Parloo杯 2025（PaluArray 节）](https://seandictionary.top/articles/parloo-bei-2025/) 记录了与本地相同的输入 `aa_9a_a?a?!aP`；其成功弹窗截图中的输出也逐字为 `palu{1b501325fc96d5a845cbdd2ba4f01cd7}`。这是对原比赛附件解法的独立旁证，仍不能证明玄机导入后的服务端答案一致。玄机目前显示 0/1、7 人参与且 0 人完成，本题按平台状态保留为未解决。

> **两次候选均未获平台接受。** 旧候选 `palu{c5302025cc6eab4bb4c17c67fe39e44d}` 来自把 RVA `0x5e66` 处前一条 ASCII 错误消息的 UTF-16LE 读法误当字符表起点，因而多读入一个 `g`；新候选按真实字符表 RVA `0x5e68` 静态逆算并计算 MD5。2026-09-29 在玄机 ID 546 页面前台提交新候选后，平台明确返回“FLAG 不正确”。因此新候选只记录为被拒绝的本地推导，不计为已解；应继续检查平台 flag 格式、附件与平台配置是否一致，不要重复盲交。

从附件静态恢复出的输入字符串为：

```text
aa_9a_a?a?!aP
```

逐字节按程序实际使用的字符表 `Palu_996!?` 查找首个匹配索引后，得到题目内置目标串 `1145141919810`。程序在输入通过后，会对这段 ASCII 输入计算标准 MD5，并将 32 位小写十六进制摘要包装成 `palu{...}`。据此得到待验证候选 flag：

```text
palu{1b501325fc96d5a845cbdd2ba4f01cd7}
```

本 WP 更正了此前错误的字符表起点和摘要；但新的静态候选也已在平台被拒绝。平台结果优先于静态推测，本题目前状态为未解决。前台提交过程与回执记录在 `../../../../记录/批次记录/第09批/原始分件/提交核验_20260929_第九批.md`。当前题目页仍显示 0/1。

## 附件与分析边界

原压缩包为 `originals\PaluArray_flag.zip`，其中只有 `PaluArray_flag.exe`（89,088 字节）。解压后的文件与压缩包内文件逐字节相同，SHA-256 为：

```text
CD8E2BE79AAA454F295132B7ECE6AE30D0CC05FF24DA7541639F05F76D482A4D
```

附件是 PE32+ x64 文件，带有经改名的 UPX 标记。为静态拆包，先在副本的三个 4 字节位置恢复 UPX 标记，再使用项目里的 UPX 5.2.0 解包。原 ZIP 与原 EXE 均保留不动：

| 阶段 | 文件 | SHA-256 |
|---|---|---|
| 原始附件 | `extracted\PaluArray_flag.exe` | `CD8E2BE79AAA454F295132B7ECE6AE30D0CC05FF24DA7541639F05F76D482A4D` |
| 恢复标记的副本 | `PaluArray_flag_upx_names.exe` | `CDDE48AC7862A5753C11A52D5BAAF3CF677576DBC5108542F9094CB98E8282FA` |
| UPX 解包副本 | `analysis\PaluArray_flag_unpacked_repro.exe` | `8B1263DE36EDA3E5E3F1183C2D08C520ECAE09649B1A04891F597033FDF842A5` |

标记恢复仅改动副本：文件偏移 `0x208` 的 `PALU` → `UPX0`，`0x230` 的 `PALU` → `UPX1`，`0x3E0` 的 `PALU` → `UPX!`。重新解包所得副本与项目中已有的 `PaluArray_flag_unpacked.exe` 哈希完全相同。这一过程只让 UPX 工具读取并重建 PE 文件数据，没有启动、加载或执行附件程序。

## 1. 确认程序内置常量

拆包后按 PE 头解析节表。镜像基址为 `0x140000000`，入口 RVA 为 `0x37d0`；`.rdata` 节从 RVA `0x5000` 开始，对应文件偏移 `0x4200`。按 `file_offset = raw_ptr + (RVA - section_RVA)` 换算，关键 UTF-16LE 字符串位于：

| RVA | 文件偏移 | 字符串 | 用途 |
|---|---:|---|---|
| `0x5e68` | `0x5068` | `Palu_996!?` | 字符索引表（初始化代码传入的起点） |
| `0x5e80` | `0x5080` | `flag` | 成功时弹窗标题 |
| `0x5e8c` | `0x508c` | `}` | flag 后缀 |
| `0x5e90` | `0x5090` | `palu{` | flag 前缀 |
| `0x5ea0` | `0x50a0` | `1145141919810` | 正确索引序列 |
| `0x5ec0` | `0x50c0` | `Success` | 成功分支提示 |
| `0x5ed0` | `0x50d0` | `Failed` | 失败分支提示 |

另有界面字符串 `Input Flag:`。字符表和目标都存成 UTF-16LE；静态字符串扫描与反汇编交叉引用显示，验证逻辑会读取字符表和目标串。字符表前一个区域是 ASCII 错误消息 `string too long\0`：RVA `0x5e66` 是其末尾字节 `g`，RVA `0x5e67` 是 NUL。若从 `0x5e66` 按 UTF-16LE 解码，会把 `67 00` 错当成字符 `g`，再接上从 `0x5e68` 开始的真实表，从而误得 `gPalu_996!?`。静态初始化代码（RVA `0x1040`）计算并传入的表指针是 RVA `0x5e68`，验证器使用该初始化后的全局对象。因此表不包含 `g`。`analysis\string_xrefs.txt` 保存了相关交叉引用，`analysis\validator_disassembly.txt` 保存了验证函数反汇编；`analysis\independent_audit.md` 记录了这次独立复核。

## 2. 还原字符索引校验

验证函数在 RVA `0x1994`。其循环逐个读取输入字符，使用内置字符表查找当前字符的位置，并把找到的索引转为十进制文本追加到结果串；如果字符未找到（返回 `-1`），该分支不追加索引。循环结束后，主流程（RVA `0x1e4e` 附近）把生成的索引串与内置目标 `1145141919810` 比较，再选择 `Success` 或 `Failed` 分支。

程序实际传入字符表对象的 UTF-16LE 数据从 RVA `0x5e68` 开始。按下标展开如下：

| 下标 | 字符 | 下标 | 字符 |
|---:|:---:|---:|:---:|
| 0 | `P` | 5 | `9` |
| 1 | `a` | 6 | `9` |
| 2 | `l` | 7 | `6` |
| 3 | `u` | 8 | `!` |
| 4 | `_` | 9 | `?` |

这里有一个会影响反解的细节：`9` 在下标 5 和 6 重复出现，而代码用的是首个匹配语义的 `find`。因此输入字符 `9` 只会编码为 `5`；下标 6 对应的第二个 `9` 无法被单独表示。目标串中没有数字 `6`，所以仍可逐位反解。字符表之前的 `g` 不属于表；从 `0x5e66` 解码产生的旧字符表会使所有索引错位。

把目标串每一位 `d` 反查为 `alphabet[d]`，并同时验证反向查找确实回到 `d`：

| 位次（从 0 起） | 目标数字 | 字符表下标 | 输入字符 | `find` 首次返回 |
|---:|---:|---:|:---:|---:|
| 0 | 1 | 1 | `a` | 1 |
| 1 | 1 | 1 | `a` | 1 |
| 2 | 4 | 4 | `_` | 4 |
| 3 | 5 | 5 | `9` | 5 |
| 4 | 1 | 1 | `a` | 1 |
| 5 | 4 | 4 | `_` | 4 |
| 6 | 1 | 1 | `a` | 1 |
| 7 | 9 | 9 | `?` | 9 |
| 8 | 1 | 1 | `a` | 1 |
| 9 | 9 | 9 | `?` | 9 |
| 10 | 8 | 8 | `!` | 8 |
| 11 | 1 | 1 | `a` | 1 |
| 12 | 0 | 0 | `P` | 0 |

拼接得到：

```text
目标索引串：1145141919810
候选输入：  aa_9a_a?a?!aP
```

## 3. 正向校验候选输入

对候选输入再次按字符表执行首个匹配查找：

```text
a  a  _  9  a  _  a  ?  a  ?  !  a  P
1  1  4  5  1  4  1  9  1  9  8  1  0
```

连接索引得 `1145141919810`，与 `.rdata` 中逐字节解码出的目标文本相同。候选输入的 ASCII 十六进制字节为：

```text
61 61 5f 39 61 5f 61 3f 61 3f 21 61 50
```

这一步同时覆盖了重复字符陷阱：字符 `9` 的首次下标为 5；候选中的两个 `9` 都因此贡献索引 5。候选所有字符都满足 `alphabet.find(ch) == 对应目标下标`。

## 4. 还原 MD5 与 flag 包装

成功比较之后，代码调用 RVA `0x1a48` 的摘要路径。静态指令显示 MD5 的四个标准初始状态常量：`67452301`、`efcdab89`、`98badcfe`、`10325476`；随后对输入串的字节指针和长度进行更新、补位和最终压缩。十六进制输出使用字符表 `0123456789abcdef`。成功路径还引用 UTF-16LE 前缀 `palu{` 和后缀 `}`，并把完成的文本以 `flag` 为标题显示。因此应计算的是**候选输入原始 ASCII 字节**的 MD5，再包装成小写 `palu{...}`，无需把目标数字串拿去哈希，也不要把外层 `palu{}` 一起作为 MD5 输入。

以标准库独立计算：

```text
MD5(ASCII("aa_9a_a?a?!aP")) = 1b501325fc96d5a845cbdd2ba4f01cd7
结果格式 = palu{<32 位小写 MD5>}
候选 flag = palu{1b501325fc96d5a845cbdd2ba4f01cd7}
```

旧候选 `palu{c5302025cc6eab4bb4c17c67fe39e44d}` 的 MD5 对应的是错误输入 `PPu_PuP!P!6Pg`，且该输入包含真实字符表中不存在的 `g`，无法通过程序的字符查找校验；平台也已拒绝该旧候选。当前新候选的 MD5 由主静态求解脚本根据 ASCII 输入计算，并与独立复核结果比对。该候选已提交平台但被拒绝，不能据此标记为已解决。命令和输出追加保存在 `analysis\commands_output.log`。


`analysis\solve_paluarray_546_static.py` 会直接读取 ZIP、检查抽取文件与附件相同、核对三个 UPX 标记改动、解析 PE RVA、从初始化实际传入的 RVA `0x5e68` 提取字符表、提取目标、执行带重复字符首索引断言的逆算、正向重算目标串并计算 MD5。脚本只读文件字节，不调用或加载 EXE。每次运行的完整标准输出追加到 `analysis\commands_output.log`。

## 5. 可复现命令

在 PowerShell 中从题目目录执行以下命令。拆包器读取的是恢复标记后的副本，Python 脚本只解析数据：

```powershell
$Root = 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluArray_546'
$UPX = 'C:\Users\mzj\Desktop\CTF\玄机刷题\tools\upx-5.2.0\upx-5.2.0-win64\upx.exe'
py -3.12 "$Root\patch_palu_markers.py"
& $UPX -d "$Root\PaluArray_flag_upx_names.exe" -o "$Root\analysis\PaluArray_flag_unpacked_repro.exe"
py -3.12 "$Root\analysis\solve_paluarray_546_static.py"
```

本轮 PowerShell 命令、错误、标准输出与哈希核对均追加记录在 `analysis\commands_output.log`。此前的阶段分析记录也保存在项目 `..\..\..\..\记录\题目记录\逆向工程\546_PaluArray\原始分件\代理-PaluArray-终端记录.txt` 和 `..\..\..\..\记录\题目记录\逆向工程\546_PaluArray\原始分件\代理-PaluArray-MD5复核终端记录.txt` 中。

## 6. 题目文件索引与验证边界

- 附件原件：`originals\PaluArray_flag.zip`
- 解压原件：`extracted\PaluArray_flag.exe`
- 静态分析的解包副本：`analysis\PaluArray_flag_unpacked_repro.exe`
- 可重复验证脚本：`analysis\solve_paluarray_546_static.py`
- 逆算与摘要输出：`analysis\solve_static_output.txt`、`analysis\corrected_alphabet_output.txt`、`analysis\legacy_solver_output.txt`
- 标记恢复记录：`analysis\patch_upx_markers_output.txt`
- 字符串引用和反汇编：`analysis\string_xrefs.txt`、`analysis\validator_disassembly.txt`、`analysis\transform_helper_disassembly.txt`、`analysis\success_pipeline_disassembly.txt`、`analysis\md5_flow_disassembly.txt`
- PowerShell 命令/输出记录：`analysis\commands_output.log`

结论是从 PE 静态初始化参数、验证逻辑、正向索引重算和 MD5 计算互相印证出来的。附件程序没有被执行。更正后的候选已在平台提交但被拒绝；现有静态链条与平台结果矛盾，本题保持未解决，不猜测其他 flag 格式，也不重复盲提。



