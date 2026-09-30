$ErrorActionPreference = 'Stop'
$root = 'C:\Users\mzj\Desktop\CTF\玄机刷题'
$guidePath = Join-Path $root '指南\玄机刷题指南_合并源.md'
$readmePath = Join-Path $root 'README.md'
$reportPath = Join-Path $root '记录\提交核验_20260929_第十二批.md'
$selectionPath = Join-Path $root '记录\批次_20260929_第十二批题目确认.md'
$logPath = Join-Path $root '记录\批次12_提交核验与指南更新_20260929.txt'
Start-Transcript -LiteralPath $logPath -Append
Write-Output '=== 写入第十二批最终平台回执 ==='
$report = @'
# 第十二批提交核验（2026-09-29）

本批三题均由对应子代理静态研究；所有 FLAG 均由 root 在玄机题页通过前台 Computer Use 输入与点击提交。只把平台接受的题目计入完成数。

## #534 天下谁人不识君

- 题目页：https://xj.edisec.net/challenges/534
- 前置状态：免费、中等、REVERSE；提交前步骤 1 为 0/1，题页无“已完成”徽标。
- 候选来源：静态反解附件注释密文得 `SQCTF{libai_jianxian}`；使用同一变换正向计算得到原注释密文，逐字符一致。源码顶部硬编码 flag 与注释密文长度不一致，候选存在来源冲突。
- 前台步骤：打开题页 → 点击“提交FLAG” → 输入 `SQCTF{libai_jianxian}` → 点击“提交”。
- 回执：页面返回“FLAG 不正确~”；步骤保持 0/1。题目未解决，不计入平台完成数；没有盲试其它包装。
- 截图：提交后页面截图曾在 Computer Use 交互输出展示，未另存为项目 PNG。
- 静态唯一性审计和各命令/输出：`题目资料/批次12_20260929/534_天下谁人不识君/`。

## #535 往事暗沉不可追

- 题目页：https://xj.edisec.net/challenges/535
- 前置状态：免费、中等、REVERSE；提交前步骤 1 为 0/1，题页无“已完成”徽标。题面：“解密后的数据就是 flag，用逗号隔开。”
- 本地候选：静态读取 PyInstaller Python 3.10 冻结脚本中的 16 个密文字节和两条 XOR 常数（0x55、0xAA）；逐字节结果为十进制 `102,108,97,103,123,55,53,52,57,101,99,99,97,45,102,125`，ASCII 文本为 `flag{7549ecca-f}`。每字节再次 XOR 0xFF 可恢复原密文。
- 前台步骤：打开题页 → 点击“提交FLAG” → 输入 `flag{7549ecca-f}` → 点击“提交”。
- 回执：页面显示“FLAG 正确~，恭喜你完成此挑战~”、题目“已完成”、步骤 1/1、进度 100%；动态记为 `slu_mzj` 完成挑战，并标记一血（21分29秒）。
- VM 六条真实指令只读取密文首字节、写入两个内存位置，没有遍历 16 字节，也没有输出完整明文。完整候选是把附件数据按嵌入 XOR 链逐字节运算所得；不能声称 VM 本地实际执行输出了 flag。
- 完整 WP、附件、CArchive/字节码提取物、复现脚本和命令输出：`题目资料/批次12_20260929/535_往事暗沉不可追/`。

## #536 遇事不决，可问春风

- 题目页：https://xj.edisec.net/challenges/536
- 前置状态：免费、中等、REVERSE；提交前步骤 1 为 0/1，题页无“已完成”徽标。
- DEX 独立复核：`classes3.dex` SHA-256 为 `29DCC3110E4B13F6AB3C9B009EAD33362C1D324351CF6AD4BD0EE5BB87E24553`；APK SHA-256 为 `BA82DA14824377E2CCCB085B7A6871FAAB9C3B0CCB3E02EB555DBC8B92C1EFD7`。原码单元 `06df 4205` 的首字节 `0xdf` 是 `xor-int/lit8`，不是 `or-int/lit8`；指令对每个字符 XOR `0x42`。
- 分析错误与纠正：初版 DEX 操作码表映射偏移一项，把 XOR 错读成 OR，得出并提交错误候选 `flag{fzfrvfrbovrggovsccozgscosrvzrvrgffff}`，平台返回“FLAG 不正确~”、步骤 0/1。复查 Dalvik opcode 表及原始 code unit 后纠正为 XOR，并修复解析脚本、输出和 WP；没有继续试包装猜测。
- 修正后的 36 字符密码为 `f8f06f2b-60ee-43ca-8e3a-1048042edddd`。`checkPassword()` 比较用户输入与该解密结果；`buildFlag()` 硬编码前缀 `flag{` 和后缀 `}`，所以候选为 `flag{f8f06f2b-60ee-43ca-8e3a-1048042edddd}`。
- 前台步骤：进入题页 → 点击“提交FLAG” → 在“提交 FLAG”弹窗输入修正候选 → 点击“提 交”。
- 回执：页面即时显示“FLAG 正确~，恭喜你完成此挑战~”，题页标记“已完成”、步骤 1/1；一血栏显示 `slu_mzj`、35分14秒。
- 未安装或运行 APK。完整 manifest/DEX 静态分析、opcode 错误发现与修正、复现脚本和每条命令/输出：`题目资料/批次12_20260929/536_遇事不决可问春风/`。

## 本批统计

- 本批新增通过平台验证 2 题：#535、#536；两题均取得一血。平台已完成总数从 44 更新为 46。
- #534 仍未解决，不纳入完成题列表或总数；失败输入和平台拒绝均保存在本记录及题目目录。
- 子代理的完整命令、标准输出/错误见三题各自 `analysis/command_transcript_20260929.txt`；主指南、README 与本核验文件的更新日志见 `记录/批次12_提交核验与指南更新_20260929.txt`。
- 截图在 Computer Use 交互中展示，没有保存为本地 PNG；本记录不声称存在截图文件。
'@
[IO.File]::WriteAllText($reportPath, $report, [Text.UTF8Encoding]::new($false))
Write-Output "已更新平台回执：$reportPath"
Write-Output '=== 更新题目确认记录的纠错与最终状态 ==='
$selection = Get-Content -LiteralPath $selectionPath -Raw
if (-not $selection.Contains('#536 二次核验与最终状态')) {
  $selection += @'

## #536 二次核验与最终状态（2026-09-29）

- 初次提交候选 `flag{fzfrvfrbovrggovsccozgscosrvzrvrgffff}` 被拒绝。代理复查发现 DEX opcode 表偏移一项：原码 `0xdf` 为 `xor-int/lit8`，不是 OR。
- 按 raw code unit `06df 4205` 重新解析，逐字符 XOR `0x42`，并核对 `classes3.dex`、APK 哈希、校验比较和 `buildFlag` 字面量，得到 `flag{f8f06f2b-60ee-43ca-8e3a-1048042edddd}`。
- 修正候选前台提交后，平台接受，题页为已完成、1/1，并显示一血（35分14秒）。

本批最终平台验收见 `记录/提交核验_20260929_第十二批.md`。
'@
  [IO.File]::WriteAllText($selectionPath, $selection, [Text.UTF8Encoding]::new($false))
}
Write-Output "已更新题目确认记录：$selectionPath"
Write-Output '=== 更新主指南的完成数和 #536 题解 ==='
$guidePath = Join-Path $root '指南\玄机刷题指南_合并源.md'
$guide = Get-Content -LiteralPath $guidePath -Raw
$guide = $guide.Replace('## 平台已完成（45 道）', '## 平台已完成（46 道）')
$row535 = '| 535 | 商丘师范学院第四届网络安全及信息对抗大赛 往事暗沉不可追 | REVERSE / 中等 | 平台已接受；PyInstaller/Python 3.10 字节码静态解析、逐字节 XOR 复核及平台一血 |'
$row536 = '| 536 | 商丘师范学院第四届网络安全及信息对抗大赛 遇事不决，可问春风 | REVERSE / 中等 | 平台已接受；DEX XOR 逆向、opcode 独立复核及平台一血 |'
if (-not $guide.Contains($row536)) {
  if (-not $guide.Contains($row535)) { throw '找不到 #535 表格行，停止修改。' }
  $guide = $guide.Replace($row535, $row535 + [Environment]::NewLine + $row536)
}
$chapterTitle = '## 第十二批：商丘师范学院第四届网络安全及信息对抗大赛 REVERSE'
$introOld = '本批从平台“全部”题目列表中选取三道免费、中等 REVERSE 题。主指南只收录已取得平台接受回执的解题；本批仅 #535 通过，#534 与 #536 仍未解决，留在各自题目资料和第十二批核验记录中，不计入完成数。'
$introNew = '本批从平台“全部”题目列表中选取三道免费、中等 REVERSE 题。主指南只收录已取得平台接受回执的解题；#535、#536 已通过平台验证，#534 仍未解决，留在独立资料与核验记录中，不计入完成数。'
$guide = $guide.Replace($introOld, $introNew)
$terminalHeading = '# 终端记录与复现文件'
$title536 = '### #536 遇事不决，可问春风（平台已接受）'
if (-not $guide.Contains($title536)) {
  $chapter536 = @'
### #536 遇事不决，可问春风（平台已接受）

- 平台 ID：536；REVERSE；免费、中等。修正候选 `flag{f8f06f2b-60ee-43ca-8e3a-1048042edddd}` 前台提交后被接受，详情页标记“已完成”、步骤 1/1，并显示一血。
- APK 静态解析定位应用自有类 `com.example.wakurev.MainActivity` 于 `classes3.dex`。原始指令 code unit `06df 4205` 中 opcode `0xdf` 对应 Dalvik `xor-int/lit8`，不是初版解析器误标的 OR。第三个 code unit 提供立即数 `0x42`；`decryptPassword()` 对密文逐字符 XOR 0x42。
- 密文为 `$z$rt$p otr''ovq!#oz'q#osrvzrvp'&&&&`。逐字符执行 `ord(ch) XOR 0x42` 得到 `f8f06f2b-60ee-43ca-8e3a-1048042edddd`。校验方法将输入字符串与 `decryptPassword()` 结果比较；成功分支 `buildFlag()` 明确拼接 `flag{`、用户输入和 `}`，因此得到上面的完整 flag。
- 首次静态解读把 `0xdf` 错读成 OR，形成的候选被平台拒绝。复查 opcode 表和原始 DEX code unit 后修正译码、脚本及 WP；修正候选得到平台接受。把这次错误与更正保留在逐题材料中，避免将错误推导写成正确流程。
- APK 未安装、未运行。附件哈希、DEX 结构、反汇编、逐字符结果、错误分支、前台提交回执和完整命令输出：`题目资料/批次12_20260929/536_遇事不决可问春风/`；三题确认和平台验收：`记录/批次_20260929_第十二批题目确认.md`、`记录/提交核验_20260929_第十二批.md`。

'@
  if (-not $guide.Contains($terminalHeading)) { throw '找不到指南末尾插入锚点。' }
  $guide = $guide.Replace($terminalHeading, $chapter536 + $terminalHeading)
}
[IO.File]::WriteAllText($guidePath, $guide, [Text.UTF8Encoding]::new($false))
Write-Output "已写入主指南：$guidePath"
Write-Output '=== 更新 README 汇总 ==='
$readmePath = Join-Path $root 'README.md'
$readme = Get-Content -LiteralPath $readmePath -Raw
$readme = $readme.Replace('手册已同步列出 45 道平台接受题；平台当前已接受总数为 45 道；旧版 README 的 10 题统计已废止。', '手册已同步列出 46 道平台接受题；平台当前已接受总数为 46 道；旧版 README 的 10 题统计已废止。')
$oldBatch = '第十二批从“全部”列表选出三道免费、中等 REVERSE 题：#535「往事暗沉不可追」已通过前台 FLAG 验证、步骤 1/1 并取得一血，平台已完成数升至 45；#534「天下谁人不识君」和 #536「遇事不决，可问春风」的候选未获接受，仍未解决，不计入已完成数。完整题目附件、逐题 WP、分析产物和命令输出保存在 题目资料/批次12_20260929/；选择与平台回执见 记录/批次_20260929_第十二批题目确认.md、记录/提交核验_20260929_第十二批.md。'
$newBatch = '第十二批从“全部”列表选出三道免费、中等 REVERSE 题：#535「往事暗沉不可追」和 #536「遇事不决，可问春风」均通过前台 FLAG 验证，步骤 1/1 并取得一血；平台已完成总数更新为 46。#534「天下谁人不识君」的候选未获接受，仍未解决，不计入已完成数。三题附件、逐题 WP、分析产物和命令输出保存在 题目资料/批次12_20260929/；选择与平台回执见 记录/批次_20260929_第十二批题目确认.md、记录/提交核验_20260929_第十二批.md。'
$readme = $readme.Replace($oldBatch, $newBatch)
[IO.File]::WriteAllText($readmePath, $readme, [Text.UTF8Encoding]::new($false))
Write-Output "已更新 README：$readmePath"
Write-Output '=== 更新后复核 ==='
Select-String -LiteralPath $guidePath -Pattern '^## 平台已完成','\| 535 \|','\| 536 \|','^## 第十二批','### #535','### #536' | ForEach-Object { $_.Line }
Select-String -LiteralPath $readmePath -Pattern '46 道','第十二批从' | ForEach-Object { $_.Line }
Get-FileHash -LiteralPath $guidePath,$readmePath,$reportPath,$selectionPath -Algorithm SHA256 | Select-Object Path,Hash
Stop-Transcript
