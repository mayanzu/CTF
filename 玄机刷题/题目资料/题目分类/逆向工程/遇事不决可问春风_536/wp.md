# WP：遇事不决，可问春风

> 已接受 flag：`flag{f8f06f2b-60ee-43ca-8e3a-1048042edddd}`。root 在玄机 #536 前台提交修正版后，页面显示“FLAG 正确~，恭喜你完成此挑战~”，题目状态 1/1；一血栏显示 35分14秒。此前第一版被拒绝，原因是本地 DEX opcode 名称表错误，详见第 5 节。

## 1. 记录输入并检查归档

输入附件为 `originals/app-debug.zip`。先计算原 ZIP 的 SHA256 并列出归档条目：

```text
SHA256(app-debug.zip) = A366F7C8B031940BC96016811BBD441A17B3473F8B9D288511E02CC63E6A1D59
ZIP contents          = app-debug.apk (4,609,869 bytes uncompressed; 4,418,898 compressed)
```

解出的 APK 为 4,609,869 bytes，SHA256 为 `BA82DA14824377E2CCCB085B7A6871FAAB9C3B0CCB3E02EB555DBC8B92C1EFD7`。没有安装或运行 APK。ZIP 与 APK 的检查结果及 APK 内全部条目见 `analysis/command_transcript_20260929.txt` 和 `analysis/apk_contents_index.txt`。

## 2. 从 manifest 找到应用入口

`analysis/parse_axml.py` 静态解析 APK 中的 binary XML。manifest 显示：

- package：`com.example.wakurev`
- `minSdkVersion=21`、`targetSdkVersion=35`
- launcher activity：`com.example.wakurev.MainActivity`

APK 有 `classes.dex`、`classes2.dex`、`classes3.dex` 三份 DEX。第三份只有 3,556 bytes，定义了 `com.example.wakurev.MainActivity` 和回调包装类，是题目代码所在处；较大的 DEX 主要包含依赖库。`classes3.dex` SHA256 为 `29DCC3110E4B13F6AB3C9B009EAD33362C1D324351CF6AD4BD0EE5BB87E24553`。

## 3. 静态还原校验流程

设备上没有可用的 jadx、apktool、aapt 或 Java，所以用 `analysis/analyze_dex.py` 读取 DEX 的 string/type/proto/method/class 表、`class_data_item` 与 `code_item`，只反汇编应用自有类所需的指令。没有执行 DEX 或 APK。

先看 `MainActivity.<clinit>()`：它把一个字符串放进 `ENCRYPTED_PARTS`：

```text
$z$rt$p otr''ovq!#oz'q#osrvzrvp'&&&&
```

`getText()` 循环拼接 `ENCRYPTED_PARTS`。这里数组只有一个元素，因此拼接结果就是上述密文。

然后看 `decryptPassword()`。关键指令顺序为：

```text
String.toCharArray()
array-length
循环读取 char
xor-int/lit8 v6, v5, #66
int-to-char v6, v6
StringBuilder.append(C)
```

DEX Dalvik opcode 映射中，`0xde` 才是 `or-int/lit8`，`0xdf` 是 `xor-int/lit8`。反汇编的 code unit 为 `06df 4205`：首单元低 8 位 `0xdf`，下一单元高 8 位 `0x42` 是立即数 66。因此实际变换是每个 UTF-16 字符与 `0x42` 按位 XOR：

```python
password = ''.join(chr(ord(ch) ^ 0x42) for ch in ciphertext)
```

静态字段值表显示 `XOR_KEY=66`、`FLAG_PREFIX="REFLAG"`、`FLAG_SUFFIX="}"`。校验方法中的 `0xdf` 与 key 66 相符；`buildFlag()` 的字节码直接使用硬编码的 `flag{` 与 `}`，并未通过 `FLAG_PREFIX` 取前缀。

## 4. 复现密码和 flag

`analysis/recover_candidate.py` 从 `classes3.dex` 读取密文和 `decryptPassword()` 里的 XOR 立即数，检查 `checkPassword()` 调用解密后以输入字符串执行 `equals`，再从 `buildFlag()` 读取前后缀。逐字符 XOR 计算得到 36 字符、UUID 形态的密码：

```text
f8f06f2b-60ee-43ca-8e3a-1048042edddd
```

`checkPassword()` 的比较关系为 `userInput.equals(decryptPassword())`。成功分支调用 `buildFlag(userInput)`，其实现拼接 `flag{` + 输入 + `}`，所以候选为：

```text
flag{f8f06f2b-60ee-43ca-8e3a-1048042edddd}
```

从题目目录运行复现脚本：

```powershell
python analysis/recover_candidate.py analysis/dex_static/classes3.dex
```

脚本会打印密文、实际 opcode 立即数、密码、完整 flag 和每个字符的 Unicode 码点对应关系；输出保存在 `analysis/recovery_report.txt`。核心校验是 DEX 中确实存在 `xor-int/lit8` 立即数 66、后续 `int-to-char`，且输入字符串在校验分支中作为 `equals` 的接收者。

## 5. 验证状态和限制

- 已通过本地静态证据重建校验与 flag 生成链，并由修正后的复现脚本验证 XOR 字符变换和字符串拼接。第一版曾误将 `0xdf` 解作 OR；这是解析器 opcode 表错误，已修复。
- root 第一次提交 `flag{fzfrvfrbovrggovsccozgscosrvzrvrgffff}`，页面返回“FLAG 不正确~”。复核 `0xdf` 的定义为 `xor-int/lit8` 后，从同一附件重算为 `flag{f8f06f2b-60ee-43ca-8e3a-1048042edddd}`。最终完整 UI 流程：进入 [https://xj.edisec.net/challenges/536](https://xj.edisec.net/challenges/536) → 点击“提交FLAG” → 在“提交 FLAG”弹窗输入修正候选 → 点击“提 交”。页面即时返回“FLAG 正确~，恭喜你完成此挑战~”；详情页显示“已完成”、步骤 1/1；一血栏显示 35分14秒。
- 对 APK 863 项做过目标标记扫描：无 `assets/`、`lib/`、`res/raw/` payload；校验常量集中在 `classes3.dex`。目前没有发现支持其他包装或不同输入的本地证据。
- 未安装或运行 APK；没有 Android runtime 行为验证。
- 未联网搜索或参考公开 writeup；没有将候选提交到平台。
- 平台已接受修正版。分析脚本只覆盖本题所需的 DEX 和 manifest 结构，不是通用 APK 反编译器；静态分析没有安装或运行 APK。
