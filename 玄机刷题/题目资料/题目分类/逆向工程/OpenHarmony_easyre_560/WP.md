# 第一届 OpenHarmony easyre（玄机 #560）完整解题记录

> **状态：已在玄机平台验证完成。** 页面曾显示题目已完成。候选 flag 的构造可以从附件字节码静态复现；没有通过脚本模拟一百万次 UI 点击。

## 1. 题目信息与附件

- 平台题目：第一届 OpenHarmony easyre
- URL：`https://xj.edisec.net/challenges/560`
- 类型：REVERSE；免费
- 附件 ZIP：`题目资料/OpenHarmony_easyre_560/easyre_platform_20260929.zip`
- SHA-256：`7401DF22E0BEEA48C439938B622931414F3EC89D383B5AA4CD72E138C42805EA`
- 解包和分析资料均保存在 `题目资料/OpenHarmony_easyre_560/`。批次 PowerShell 命令和输出在 `../../../../记录/批次记录/综合协调/原始分件/批次_20260929_选题与本地资料核对.txt`；早期静态分析输出以 `analysis/*_output.txt` 保存。

## 2. 分析思路：从 ArkUI 交互追到 flag 页面

附件是 OpenHarmony/HarmonyOS 应用包。主代码位于 Panda 字节码文件 `ets/modules.abc`，因此先检查 HAP 目录、模块名、资源和字节码，再使用已保存的 Panda 解析/反汇编结果搜索页面交互函数、路由参数、编码器和 flag 拼接逻辑。

静态分析中发现一个源字符串和多个变换步骤。页面逻辑需要重复交互达到很大的计数门槛，字节码中可见 `1,000,000` 阈值。由于变换是确定性的，直接从字节码计算路由参数即可得到同一结果；不需要、也没有执行一百万次点击。

关键反汇编结果见：

- `analysis/disassemble_indexed_output.txt`
- `analysis/disassemble_target_methods_output.txt`
- Panda 文件结构/ISA参考：`analysis/reference/file_format.md`、`analysis/reference/isa.yaml`
- 官方参考来源（用于解释 Panda 格式和指令）：OpenHarmony ArkCompiler Runtime Core 的 `docs/file_format.md`、`isa/isa.yaml` 和 `disassembler/disassembler.cpp`。

## 3. 逐步还原字符变换

### 第一步：记录源字符串

字节码中的 `hint1` 字面值为：

```text
`d^ba_^YZZZVWXRRT
```

字符串长度是 17。将其保留原样；后续两个循环都在这个输入的派生值上执行。

### 第二步：第一轮逐字符加偏移并逆序

第一段逻辑对每个字符执行 `String.fromCharCode(charCodeAt(i) + hint1.length)`，即每个字符码加 17，再把整串逆序：

```text
加17、逆序前：quosrpojkkkghicce
逆序后：    eccihgkkkjoprsouq
```

`String.fromCharCode` 保留 UTF-16 code unit 的低 16 位；本题字符均落在 ASCII 范围，不发生高位截断。

### 第三步：第二轮按索引减值并逆序

对上一轮字符串执行 `charCodeAt(i) - i`，再逆序：

```text
逐位减索引、逆序前：ebafdbedcaeeffafa
路由参数 hint1：    afaffeeacdebdfabe
```

注意第二轮的 `i` 从 0 开始；减数不是固定常量，而是当前字符下标。

### 第四步：解码另一段 Base64 字面值

字节码中的 `encodedMagic` 为不带填充的 Base64：

```text
NzAyZDBlODgxZDNjNzNjOWIzOTBkZjIwNTRiZGQxNWNjY2I
```

按标准 Base64 解码（补齐所需 `=`）得到：

```text
702d0e881d3c73c9b390df2054bdd15cccb
```

### 第五步：拼接并形成 flag

页面把 `hint1` 路由参数与解码后的 magic 字符串直接拼接，中间没有额外分隔符：

```text
hint1   = afaffeeacdebdfabe
magic   = 702d0e881d3c73c9b390df2054bdd15cccb
flag body = afaffeeacdebdfabe702d0e881d3c73c9b390df2054bdd15cccb
```

候选 flag：

```text
flag{afaffeeacdebdfabe702d0e881d3c73c9b390df2054bdd15cccb}
```

## 4. 可复现脚本和输出

核心脚本：`analysis/derive_easyre_flag.py`。在项目根目录运行：

```powershell
py -3 "C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\OpenHarmony_easyre_560\analysis\derive_easyre_flag.py"
```

完整输出：

```text
hint1 source = '`d^ba_^YZZZVWXRRT' (length 17)
loop 1 before reverse = 'quosrpojkkkghicce'
loop 1 after reverse  = 'eccihgkkkjoprsouq'
loop 2 before reverse = 'ebafdbedcaeeffafa'
route param hint1     = 'afaffeeacdebdfabe'
magic base64 decoded  = '702d0e881d3c73c9b390df2054bdd15cccb'
flag body             = 'afaffeeacdebdfabe702d0e881d3c73c9b390df2054bdd15cccb'
candidate flag        = flag{afaffeeacdebdfabe702d0e881d3c73c9b390df2054bdd15cccb}
```

重跑输出另存于 `analysis/derive_easyre_flag_output.txt`；SHA-256 与脚本执行命令/输出追加到了批次 transcript。

## 5. 玄机平台验证

通过玄机题页的可见提交表单提交上述候选后，平台将 #560 标记为已完成。平台界面成功状态在当时的浏览器交互记录中可见；本题的成功结论基于平台状态，不只依赖本地脚本输出。

## 6. 常见误区

1. 只对源字符串做 Base64 解码会遗漏两轮按字符码变换。
2. 第二轮减的是当前字符的索引 `i`，容易误当作再减字符串长度。
3. 每轮逆序位置重要；先后顺序交换会得到不同字符串。
4. Base64 字符串没有 `=` 填充，解码前按模 4 补齐即可。
5. UI 门槛很大不代表需要暴力点击；状态转移可由字节码直接还原。

## 7. 项目资料索引

- 附件 ZIP：`easyre_platform_20260929.zip`
- 解包 HAP 与资源：`题目资料/OpenHarmony_easyre_560/`
- Panda 反汇编：`analysis/disassemble_indexed_output.txt`、`disassemble_target_methods_output.txt`
- 解析脚本：`analysis/parse_panda_methods.py`、`disassemble_target_methods.py`、`dump_index_records.py`
- 最终计算：`analysis/derive_easyre_flag.py`、`derive_easyre_flag_output.txt`
- 相关命令/输出：项目 `../../../../记录/批次记录/综合协调/原始分件/批次_20260929_选题与本地资料核对.txt`
