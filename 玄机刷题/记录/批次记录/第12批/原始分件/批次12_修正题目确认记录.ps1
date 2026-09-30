$ErrorActionPreference = 'Stop'
$root = 'C:\Users\mzj\Desktop\CTF\玄机刷题'
$batch = Join-Path $root '题目资料\批次12_20260929'
$selectionPath = Join-Path $root '记录\批次_20260929_第十二批题目确认.md'
$logPath = Join-Path $root '记录\批次12_指南更新命令记录_20260929.txt'
Start-Transcript -LiteralPath $logPath -Append
Write-Output 'COMMAND> Regenerate batch 12 selection record with one Markdown field per line; list archive entries and hashes.'
$lines = New-Object 'System.Collections.Generic.List[string]'
[void]$lines.Add('# 第十二批题目确认（2026-09-29）')
[void]$lines.Add('')
[void]$lines.Add('## 选择方法与筛选状态')
[void]$lines.Add('')
[void]$lines.Add('- 前台打开玄机题目列表 https://xj.edisec.net/challenges，确认状态筛选选中“全部”，没有用“已完成/未完成”作为唯一来源。列表按中等难度和 REVERSE 分类浏览，另以平台搜索定位第三题。')
[void]$lines.Add('- 每个详情页均在前台核对题名、ID、类别、难度、费用与进度；三题都是免费 / 中等 / REVERSE / 未完成（详情页 0/1）。#541、#542、#543 此前已经尝试，本批排除。')
[void]$lines.Add('- 每题交由一个子代理分析。候选只由主线程在前台提交验证；平台未接受的候选不算完成，也不进入已完成手册章节。')
[void]$lines.Add('')
[void]$lines.Add('## 已选题目')
[void]$lines.Add('')
$items = @(
  @{Id='534'; Name='天下谁人不识君'; File='天下谁人不识君.zip'; Folder='534_天下谁人不识君'; Download='D:\Downloads\天下谁人不识君.zip'; Unfinished='前台详情 0/1'}
  @{Id='535'; Name='往事暗沉不可追'; File='来日之路光明灿烂.zip'; Folder='535_往事暗沉不可追'; Download='D:\Downloads\来日之路光明灿烂.zip'; Unfinished='前台详情 0/1'}
  @{Id='536'; Name='遇事不决，可问春风'; File='app-debug.zip'; Folder='536_遇事不决可问春风'; Download='D:\Downloads\app-debug.zip'; Unfinished='前台详情 0/1'}
)
foreach ($item in $items) {
  $archive = Join-Path (Join-Path $batch $item.Folder) ('originals\' + $item.File)
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash
  $size = (Get-Item -LiteralPath $archive).Length
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
  $entries = @($zip.Entries | ForEach-Object { $_.FullName + ' (' + $_.Length + ' bytes)' })
  $zip.Dispose()
  [void]$lines.Add('### #' + $item.Id + ' ' + $item.Name)
  [void]$lines.Add('')
  [void]$lines.Add('- 详情页：https://xj.edisec.net/challenges/' + $item.Id)
  [void]$lines.Add('- 类别 / 难度 / 费用 / 状态：REVERSE / 中等 / 免费 / ' + $item.Unfinished)
  [void]$lines.Add('- 下载来源：前台点击玄机“下载附件”；Downloads 原始文件：' + $item.Download)
  [void]$lines.Add('- 项目原件：题目资料/批次12_20260929/' + $item.Folder + '/originals/' + $item.File)
  [void]$lines.Add('- 大小：' + $size + ' bytes；SHA-256：' + $hash)
  [void]$lines.Add('- ZIP 成员：')
  foreach ($entry in $entries) { [void]$lines.Add('  - ' + $entry) }
  [void]$lines.Add('')
  Write-Output ('ARCHIVE #' + $item.Id + ': size=' + $size + '; SHA256=' + $hash)
  foreach ($entry in $entries) { Write-Output ('ZIP ENTRY: ' + $entry) }
}
[void]$lines.Add('## 当前状态')
[void]$lines.Add('')
[void]$lines.Add('#534 本地候选 SQCTF{libai_jianxian} 经正向复算与注释密文一致，但 2026-09-29 玄机前台提交后提示“FLAG 不正确~”，详情页仍为 0/1；不得计为已解决。代理已复核可打印 ASCII 解唯一，附件内源码字面量与注释密文矛盾；没有题面格式证据，不做包装猜测。#535、#536 正在分析，最终候选与回执待补。')
[void]$lines.Add('')
[void]$lines.Add('## 归档目录')
[void]$lines.Add('')
[void]$lines.Add('- 题目资料/批次12_20260929/534_天下谁人不识君/')
[void]$lines.Add('- 题目资料/批次12_20260929/535_往事暗沉不可追/')
[void]$lines.Add('- 题目资料/批次12_20260929/536_遇事不决可问春风/')
[void]$lines.Add('')
[System.IO.File]::WriteAllLines($selectionPath, $lines, [System.Text.UTF8Encoding]::new($false))
Write-Output ('SELECTION WRITTEN: ' + $selectionPath)
Write-Output ('LINE COUNT: ' + ([System.IO.File]::ReadAllLines($selectionPath).Count))
Select-String -LiteralPath $selectionPath -Pattern '^### #','^- 详情页','^- 类别 /','^- 大小','^  - '
Stop-Transcript

