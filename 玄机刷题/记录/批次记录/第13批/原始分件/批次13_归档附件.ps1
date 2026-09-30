$ErrorActionPreference = 'Stop'
$root = 'C:\Users\mzj\Desktop\CTF\玄机刷题'
$batchRoot = Join-Path $root '题目资料\批次13_20260929'
$recordPath = Join-Path $root '记录\批次_20260929_第十三批题目确认.md'
$logPath = Join-Path $root '记录\批次13_附件归档_20260929.txt'
Start-Transcript -LiteralPath $logPath
$items = @(
  [pscustomobject]@{ Id = 533; Title = '圣人当仁不让'; Source = 'D:\Downloads\ez_vm.zip'; Folder = '533_圣人当仁不让' },
  [pscustomobject]@{ Id = 537; Title = '湘岚杯ezbase'; Source = 'D:\Downloads\ezbase.zip'; Folder = '537_湘岚杯ezbase' },
  [pscustomobject]@{ Id = 538; Title = '湘岚杯1997'; Source = 'D:\Downloads\1997.zip'; Folder = '538_湘岚杯1997' }
)
$assets = @()
foreach ($item in $items) {
  $destination = Join-Path (Join-Path $batchRoot $item.Folder) 'originals'
  $analysis = Join-Path (Join-Path $batchRoot $item.Folder) 'analysis'
  New-Item -ItemType Directory -Force -Path $destination,$analysis | Out-Null
  $copy = Join-Path $destination (Split-Path -Leaf $item.Source)
  Copy-Item -LiteralPath $item.Source -Destination $copy -Force
  $sourceHash = (Get-FileHash -LiteralPath $item.Source -Algorithm SHA256).Hash
  $copyHash = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash
  if ($sourceHash -ne $copyHash) { throw "Hash mismatch for challenge $($item.Id)" }
  $archive = [IO.Compression.ZipFile]::OpenRead($copy)
  try {
    $entries = @($archive.Entries | ForEach-Object { [pscustomobject]@{ Name = $_.FullName; Length = $_.Length } })
  } finally { $archive.Dispose() }
  Expand-Archive -LiteralPath $copy -DestinationPath $analysis -Force
  Write-Output "=== #$($item.Id) $($item.Title) ==="
  Write-Output "Source: $($item.Source)"
  Write-Output "Copy: $copy"
  Write-Output "ZIP bytes: $((Get-Item -LiteralPath $copy).Length)"
  Write-Output "SHA256 source: $sourceHash"
  Write-Output "SHA256 copy:   $copyHash"
  Write-Output 'Archive entries:'
  $entries | Format-Table -AutoSize
  Write-Output 'Extracted files:'
  Get-ChildItem -LiteralPath $analysis -Recurse -File | Select-Object FullName,Length
  $assets += [pscustomobject]@{ Id = $item.Id; Title = $item.Title; Zip = (Split-Path -Leaf $copy); SHA256 = $copyHash; Entries = (($entries | ForEach-Object { "$($_.Name) ($($_.Length) bytes)" }) -join '; ') }
}
$lines = @(
  '# 第十三批题目确认（2026-09-29）',
  '',
  '## 选择方式',
  '',
  '- 在玄机 `/challenges` 页面选择“全部”题目，保留状态单选“全部”，点击难度“中等”；未依赖“未完成”筛选，因为用户指出该筛选不完整。',
  '- 在中等难度分页中逐题核对详情页，确认免费、中等、REVERSE、步骤 0/1 且无“已完成”徽标。选取三道新题；排除已完成题、此前尝试过的 #532、#534、#541、#542、#546、#561、#562 等题。',
  '',
  '## 本批题目',
  ''
)
foreach ($asset in $assets) {
  $lines += @(
    "### #$($asset.Id) $($asset.Title)",
    '',
    "- 详情页：https://xj.edisec.net/challenges/$($asset.Id)",
    '- 核验：免费；难度中等；类型 REVERSE；挑战步骤 0/1；提交前没有“已完成”徽标。',
    "- 附件：`$($asset.Zip)`；SHA-256 `$($asset.SHA256)`。ZIP 成员：$($asset.Entries)。",
    "- 归档目录：`题目资料/批次13_20260929/$($asset.Id)_$($asset.Title)/`。",
    ''
  )
}
$lines += @(
  '## 状态',
  '',
  '- 三题附件已由玄机详情页通过前台下载并复制入项目；D:\Downloads 原始文件保留。',
  '- 各题由独立子代理静态分析。平台提交只由 root 根据本地复核过的候选在前台进行。',
  '- 页面选择及详情核对在 Computer Use 交互中可见；没有将交互截图另存为项目 PNG。',
  ''
)
[IO.File]::WriteAllLines($recordPath, $lines, [Text.UTF8Encoding]::new($false))
Write-Output "Selection record: $recordPath"
Get-FileHash -LiteralPath $recordPath -Algorithm SHA256 | Select-Object Path,Hash
Stop-Transcript
