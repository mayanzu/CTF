$ErrorActionPreference = 'Stop'
$root = 'C:\Users\mzj\Desktop\CTF\玄机刷题'
$guidePath = Join-Path $root '指南\玄机刷题指南_合并源.md'
$readmePath = Join-Path $root 'README.md'
$logPath = Join-Path $root '记录\批次12_提交核验与指南更新_20260929.txt'
Start-Transcript -LiteralPath $logPath -Append
Write-Output '=== 更新主指南中已被平台接受的 #535 ==='
$guide = Get-Content -LiteralPath $guidePath -Raw
$guide = $guide.Replace('## 平台已完成（44 道）', '## 平台已完成（45 道）')
$row539 = '| 539 | 湘岚杯cryptor | REVERSE / 中等 | 平台已接受；Cython 扩展静态分析、AES-CBC 双实现复核及完整命令记录齐全 |'
$row535 = '| 535 | 商丘师范学院第四届网络安全及信息对抗大赛 往事暗沉不可追 | REVERSE / 中等 | 平台已接受；PyInstaller/Python 3.10 字节码静态解析、逐字节 XOR 复核及平台一血 |'
if (-not $guide.Contains($row535)) {
  if (-not $guide.Contains($row539)) { throw '找不到 #539 表格行，停止修改。' }
  $guide = $guide.Replace($row539, $row539 + [Environment]::NewLine + $row535)
}
$chapterTitle = '## 第十二批：商丘师范学院第四届网络安全及信息对抗大赛 REVERSE'
$terminalHeading = '# 终端记录与复现文件'
if (-not $guide.Contains($chapterTitle)) {
  $chapter = @'
## 第十二批：商丘师范学院第四届网络安全及信息对抗大赛 REVERSE

本批从平台“全部”题目列表中选取三道免费、中等 REVERSE 题。主指南只收录已取得平台接受回执的解题；本批仅 #535 通过，#534 与 #536 仍未解决，留在各自题目资料和第十二批核验记录中，不计入完成数。

### #535 往事暗沉不可追（平台已接受）

- 平台 ID：535；REVERSE；免费、中等。题面说明“解密后的数据就是 flag，用逗号隔开”。平台实际接受的文本为 `flag{7549ecca-f}`，步骤 1/1，页面记录一血。
- 附件是 PyInstaller one-file x64 PE。静态解析 CArchive，恢复 Python 3.10 冻结主模块；未运行陌生 EXE、DLL、PYD 或其中代码。由于本机 marshal 版本为 Python 3.12，使用仅解析结构的 Python 3.10 marshal 读取器恢复代码对象和常量。
- 密文数组为 `153,147,158,152,132,200,202,203,198,154,156,156,158,210,153,130`；两条嵌入 XOR 常数分别为 0x55、0xAA，异或合成 0xFF。逐字节计算 `cipher[i] XOR 0x55 XOR 0xAA` 得到 `102,108,97,103,123,55,53,52,57,101,99,99,97,45,102,125`，ASCII 解释为上面的 flag 文本。再次 XOR 0xFF 能逐字节还原原密文。
- 需如实保留实现缺陷：VM 的六条真实指令只读取密文第一个字节，写入两个内存位置，没有遍历 16 字节，也没有打印完整明文。完整 flag 是基于题面数据和嵌入 XOR 链逐字节推导出来；平台接受回执确认候选正确，但不能称 VM 本地实际执行产出了完整 flag。
- 前台 Computer Use 提交后，玄机显示“FLAG 正确~，恭喜你完成此挑战~”、步骤 1/1、进度 100% 和一血。
- 中文逐步 WP、附件、CArchive/字节码提取物、求解器与完整命令/输出记录：`题目资料/批次12_20260929/535_往事暗沉不可追/`；本批三题选择和平台核验记录：`记录/批次_20260929_第十二批题目确认.md`、`记录/提交核验_20260929_第十二批.md`。

'@
  if (-not $guide.Contains($terminalHeading)) { throw '找不到指南末尾插入锚点。' }
  $guide = $guide.Replace($terminalHeading, $chapter + $terminalHeading)
}
[IO.File]::WriteAllText($guidePath, $guide, [Text.UTF8Encoding]::new($false))
Write-Output "已写入主指南：$guidePath"
Write-Output '=== 更新 README 完成数和第十二批状态 ==='
$readme = Get-Content -LiteralPath $readmePath -Raw
$readme = $readme.Replace('手册已同步列出 44 道平台接受题；平台当前已接受总数为 44 道；旧版 README 的 10 题统计已废止。', '手册已同步列出 45 道平台接受题；平台当前已接受总数为 45 道；旧版 README 的 10 题统计已废止。')
$oldBatch = '第十二批处理中：通过“全部”列表和中等难度题卡核验，选定免费、未完成的 #536「遇事不决，可问春风」、#535「往事暗沉不可追」、#534「天下谁人不识君」。前台题页与下载记录见 记录/批次_20260929_第十二批题目确认.md、记录/批次12_附件归档_20260929.txt；三份原始附件副本和独立 WP 分别保存在 题目资料/批次12_20260929/。三名子代理并行静态分析中；完成和平台验证状态待更新，尚不计入已完成数。'
$newBatch = '第十二批从“全部”列表选出三道免费、中等 REVERSE 题：#535「往事暗沉不可追」已通过前台 FLAG 验证、步骤 1/1 并取得一血，平台已完成数升至 45；#534「天下谁人不识君」和 #536「遇事不决，可问春风」的候选未获接受，仍未解决，不计入已完成数。完整题目附件、逐题 WP、分析产物和命令输出保存在 题目资料/批次12_20260929/；选择与平台回执见 记录/批次_20260929_第十二批题目确认.md、记录/提交核验_20260929_第十二批.md。'
if ($readme.Contains($oldBatch)) { $readme = $readme.Replace($oldBatch, $newBatch) }
[IO.File]::WriteAllText($readmePath, $readme, [Text.UTF8Encoding]::new($false))
Write-Output "已更新 README：$readmePath"
Write-Output '=== 校验 ==='
Select-String -LiteralPath $guidePath -Pattern '^## 平台已完成','\| 535 \|','^## 第十二批','### #535' | ForEach-Object { $_.Line }
Select-String -LiteralPath $readmePath -Pattern '45 道','第十二批从' | ForEach-Object { $_.Line }
Get-FileHash -LiteralPath $guidePath,$readmePath -Algorithm SHA256 | Select-Object Path,Hash
Stop-Transcript
