$ErrorActionPreference = 'Stop'
$root = 'C:\Users\mzj\Desktop\CTF\玄机刷题'
$guidePath = Join-Path $root '指南\玄机刷题指南_合并源.md'
$readmePath = Join-Path $root 'README.md'
$selectionPath = Join-Path $root '记录\批次_20260929_第十二批题目确认.md'
$submissionPath = Join-Path $root '记录\提交核验_20260929_第十二批.md'
$logPath = Join-Path $root '记录\批次12_指南更新命令记录_20260929.txt'
Start-Transcript -LiteralPath $logPath -Append
Write-Output 'COMMAND> Update verified batch 11 guide entries and counts; update README; write batch 12 selection and platform submission records.'
$guideText = [System.IO.File]::ReadAllText($guidePath, [System.Text.Encoding]::UTF8)
$oldIntro = '此后 #367、#450、#451、#520、#551、#530、#531、#559、#588、#549、#558、#547、#548、#552 共 14 道新题均取得平台接受回执，手册现收录 42 道已完成题。'
$newIntro = '此后 #367、#450、#451、#520、#551、#530、#531、#559、#588、#549、#558、#547、#548、#552、#539、#540 共 16 道新题均取得平台接受回执，手册现收录 44 道已完成题。'
if (-not $guideText.Contains($oldIntro)) { throw 'Expected guide intro missing; no changes were written.' }
$guideText = $guideText.Replace($oldIntro, $newIntro)
$guideText = $guideText.Replace('## 平台已完成（42 道）', '## 平台已完成（44 道）')
$tableMarker = '| 531 | 商丘师范学院第四届网络安全及信息对抗大赛 你若安好便是晴 |'
if (-not $guideText.Contains($tableMarker)) { throw 'Expected table insertion marker missing.' }
if ($guideText.Contains('| 540 | 湘岚杯maybesignin |') -or $guideText.Contains('| 539 | 湘岚杯cryptor |')) { throw 'Batch 11 rows already exist.' }
$tableRows = '| 540 | 湘岚杯maybesignin | REVERSE / 中等 | 平台已接受；SM4 静态逆向、Python 与 OpenSSL 独立解密及复加密验证齐全 |' + [Environment]::NewLine + '| 539 | 湘岚杯cryptor | REVERSE / 中等 | 平台已接受；Cython 扩展静态分析、AES-CBC 双实现复核及完整命令记录齐全 |' + [Environment]::NewLine
$guideText = $guideText.Replace($tableMarker, $tableRows + $tableMarker)
$newStats = '**统计：本指南原收录 28 道，后续新增的 #367、#450、#451、#520、#551、#530、#531、#559、#588、#549、#558、#547、#548、#552、#539、#540 均有逐题平台接受回执，当前共 44 道。现有证据可给出 42 道题的 flag 候选或公开 Writeup 结果；Ancient-Recall 与 pwn-ezpwn 的最终 flag 输出仍缺失。#541 ezBase 与 #546 PaluArray 的新候选均被平台拒绝，不计入已完成总数。旧题若只有平台完成徽标或离线候选，仍与具体 flag 的提交回执分开标注。**'
$guideText = [System.Text.RegularExpressions.Regex]::Replace($guideText, '(?m)^\*\*统计：.*\*\*$', $newStats)
$newPending = '#532《人生自古谁无死》的两个已提交候选均无平台完成回执，需新的独立证据后再决定；#546《PaluArray》的静态候选被平台明确拒绝，需解释二进制推导与平台 flag 不一致的原因；#561《第一届OpenHarmony secret》的 pattern 闭环已复核，但题内 MD5 示例与明文公式不符，现有候选也未获平台确认；#562 checker 的 ZIP 与 checker.exe 副本哈希一致，静态复核仍得到已被拒绝的同一候选；#541《ezBase》本批静态逆向候选被前台平台拒绝，且附件比较常量存在填充分支歧义，暂不盲目重交。这五题都不计入已完成总数。'
$guideText = [System.Text.RegularExpressions.Regex]::Replace($guideText, '(?m)^#532《人生自古谁无死》.*这四题都不计入已完成总数。$', [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $newPending })
$batch11 = @(
'## 第十一批：湘岚杯静态逆向题',
'',
'本批在玄机平台“全部”题目列表中核对免费、中等 REVERSE 项。#539「湘岚杯cryptor」和 #540「湘岚杯maybesignin」取得前台正确回执；#541「ezBase」的候选被拒绝，因此未放入已完成表。',
'',
'### #539 湘岚杯 cryptor（平台已接受）',
'',
'- 平台 ID：539；REVERSE；免费、中等。候选 flag{AtYpXBh38fNvc1ymsQ7vL} 在玄机前台提交后显示正确、步骤 1/1 和一血。',
'- main.py 只接收输入并调用 cryptor.check；判定逻辑位于 CPython 3.10 x64 的 Cython .pyd。静态字符串与数据区提供 AES 模式、零填充提示、Base64 密文、16 字节 key EzCrypt0ofPython 和 16 字节 IV 1145140A01919810。IV 按 16 个 ASCII 字符处理。',
'- Base64 解码得到 32 字节密文。按 AES-128-CBC、关闭标准填充解密，明文为 flag 后接 5 个 NUL 字节；去掉 NUL 后得到候选。Python cryptography 与 OpenSSL 两套独立实现的明文十六进制相同；扩展未加载或运行。',
'- 首轮尝试 ECB / PKCS#7 未得到有效明文；缺少 PyCryptodome、PowerShell/.NET API 差异和中文路径工具调用问题均保留在命令记录中。完整常量定位、错误分支、命令输出和复现代码见 题目资料/批次11_20260929/539_cryptor/wp.md 及其 analysis 子目录。',
'',
'### #540 湘岚杯 maybesignin（平台已接受）',
'',
'- 平台 ID：540；REVERSE；免费、中等。候选 flag{wlascJDAFS} 前台提交后显示正确、步骤 1/1。',
'- 附件是 12,800 字节 PE32+ x86-64。静态识别比较目标块 1C84BE5145CE1AF31FA3F75E3A38D0BE，并从 S-box、FK、CK 和轮函数常量确认校验算法为标准 SM4 单块变换。',
'- 关键字节序检查：四个 mov dword 立即数按小端存储组成 16 字节 key 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16（十六进制字节）。逆序轮密钥解密得到 flag{wlascJDAFS}；本地 Python 正向加密回目标块，且 OpenSSL SM4-ECB 独立解密得到相同明文。附件 EXE 未运行。',
'- 首次将 key 误读成更长的十六进制序列，虽然自洽重加密仍不对；回到小端立即数还原后才得到正确 16 字节 key。详细反汇编、常量表、错误假设、复算命令和输出见 题目资料/批次11_20260929/540_maybesignin/wp.md 与 analysis。',
'',
'### 第十一批其他记录',
'',
'#541 ezBase 的本地候选仅是分析分支，平台明确拒绝；不把它作为答案。候选输入、拒绝回执、解包修正、分支检查和逐命令记录见 题目资料/批次11_20260929/541_ezBase/ 与 记录/提交核验_20260929_第十一批.md。',
''
) -join [Environment]::NewLine
$terminalMarker = '# 终端记录与复现文件'
if (-not $guideText.Contains($terminalMarker)) { throw 'Terminal record marker missing.' }
if ($guideText.Contains('## 第十一批：湘岚杯静态逆向题')) { throw 'Batch 11 section already exists.' }
$guideText = $guideText.Replace($terminalMarker, $batch11 + [Environment]::NewLine + $terminalMarker)
$terminalBullet = '- 第十一批 #539/#540 平台接受、#541 被拒绝的前台核验及附件确认：记录/批次_20260929_第十一批题目确认.md、记录/提交核验_20260929_第十一批.md；附件哈希、逐题 WP、静态分析产物与终端记录见 题目资料/批次11_20260929/。'
$guideIndexMarker = '- 各题逐题记录：'
if (-not $guideText.Contains($guideIndexMarker)) { throw 'File index marker missing.' }
$guideText = $guideText.Replace($guideIndexMarker, $terminalBullet + [Environment]::NewLine + $guideIndexMarker)
[System.IO.File]::WriteAllText($guidePath, $guideText, [System.Text.UTF8Encoding]::new($false))
Write-Output ('GUIDE UPDATED: ' + $guidePath)
Write-Output ('GUIDE SHA256: ' + (Get-FileHash -Algorithm SHA256 -LiteralPath $guidePath).Hash)
Select-String -LiteralPath $guidePath -Pattern '^本指南原记录','^## 平台已完成','^\*\*统计','^\| 540 \|','^\| 539 \|','^## 第十一批','^### #539','^### #540','^# 终端记录' | ForEach-Object { Write-Output ($_.LineNumber.ToString() + ': ' + $_.Line) }
$readmeText = [System.IO.File]::ReadAllText($readmePath, [System.Text.Encoding]::UTF8)
$readmeText = $readmeText.Replace('第十一批手册整合待本批结束后更新。平台当前已接受 44 道题（此前主手册列出 42 道）', '手册已同步列出 44 道平台接受题；平台当前已接受总数为 44 道')
$readmeText = $readmeText.Replace('第十一批处理中：', '第十一批已归档：')
if (-not $readmeText.Contains('第十二批处理中：')) {
  $readmeText += [Environment]::NewLine + '第十二批处理中：通过“全部”列表和中等难度题卡核验，选定免费、未完成的 #536「遇事不决，可问春风」、#535「往事暗沉不可追」、#534「天下谁人不识君」。前台题页与下载记录见 记录/批次_20260929_第十二批题目确认.md、记录/批次12_附件归档_20260929.txt；三份原始附件副本和独立 WP 分别保存在 题目资料/批次12_20260929/。三名子代理并行静态分析中；完成和平台验证状态待更新，尚不计入已完成数。' + [Environment]::NewLine
}
[System.IO.File]::WriteAllText($readmePath, $readmeText, [System.Text.UTF8Encoding]::new($false))
Write-Output ('README UPDATED: ' + $readmePath)
Write-Output ('README SHA256: ' + (Get-FileHash -Algorithm SHA256 -LiteralPath $readmePath).Hash)
$batch = Join-Path $root '题目资料\批次12_20260929'
$items = @(
  @{Id='534'; Name='天下谁人不识君'; File='天下谁人不识君.zip'; Folder='534_天下谁人不识君'; Download='D:\Downloads\天下谁人不识君.zip'; Difficulty='中等'; Price='免费'; Unfinished='前台详情 0/1'}
  @{Id='535'; Name='往事暗沉不可追'; File='来日之路光明灿烂.zip'; Folder='535_往事暗沉不可追'; Download='D:\Downloads\来日之路光明灿烂.zip'; Difficulty='中等'; Price='免费'; Unfinished='前台详情 0/1'}
  @{Id='536'; Name='遇事不决，可问春风'; File='app-debug.zip'; Folder='536_遇事不决可问春风'; Download='D:\Downloads\app-debug.zip'; Difficulty='中等'; Price='免费'; Unfinished='前台详情 0/1'}
)
$selectionLines = @(
'# 第十二批题目确认（2026-09-29）',
'',
'## 选择方法与筛选状态',
'',
'- 前台打开玄机题目列表 https://xj.edisec.net/challenges，确认状态筛选选中“全部”，没有用“已完成/未完成”作为唯一来源。列表按中等难度和 REVERSE 分类浏览，另以平台搜索定位第三题。',
'- 每个详情页均在前台核对题名、ID、类别、难度、费用与进度；三题都是免费 / 中等 / REVERSE / 未完成（详情页 0/1）。#541、#542、#543 此前已经尝试，本批排除。',
'- 每题交由一个子代理分析。候选只由主线程在前台提交验证；平台未接受的候选不算完成，也不进入已完成手册章节。',
'',
'## 已选题目',
''
)
foreach ($item in $items) {
  $archive = Join-Path (Join-Path $batch $item.Folder) ('originals\' + $item.File)
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash
  $size = (Get-Item -LiteralPath $archive).Length
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
  $entryLines = @($zip.Entries | ForEach-Object { '- ' + $_.FullName + ' (' + $_.Length + ' bytes)' })
  $zip.Dispose()
  $selectionLines += @(
    '### #' + $item.Id + ' ' + $item.Name,
    '',
    '- 详情页：https://xj.edisec.net/challenges/' + $item.Id,
    '- 类别 / 难度 / 费用 / 状态：REVERSE / ' + $item.Difficulty + ' / ' + $item.Price + ' / ' + $item.Unfinished,
    '- 下载来源：前台点击玄机“下载附件”；Downloads 原始文件：' + $item.Download,
    '- 项目原件：题目资料/批次12_20260929/' + $item.Folder + '/originals/' + $item.File,
    '- 大小：' + $size + ' bytes；SHA-256：' + $hash,
    '- ZIP 成员：',
    ($entryLines -join [Environment]::NewLine),
    ''
  )
  Write-Output ('ARCHIVE #' + $item.Id + ': size=' + $size + '; SHA256=' + $hash)
  foreach ($entry in $entryLines) { Write-Output $entry }
}
$selectionLines += @(
'',
'## 当前状态',
'',
'#534 本地候选 SQCTF{libai_jianxian} 经正向复算与注释密文一致，但 2026-09-29 玄机前台提交后提示“FLAG 不正确~”，详情页仍为 0/1；不得计为已解决。代理继续审计源码中注释密文与硬编码 flag 的冲突。#535、#536 正在分析，最终候选与回执待补。',
'',
'## 归档目录',
'',
'- 题目资料/批次12_20260929/534_天下谁人不识君/',
'- 题目资料/批次12_20260929/535_往事暗沉不可追/',
'- 题目资料/批次12_20260929/536_遇事不决可问春风/',
''
)
[System.IO.File]::WriteAllText($selectionPath, ($selectionLines -join [Environment]::NewLine), [System.Text.UTF8Encoding]::new($false))
Write-Output ('SELECTION RECORD: ' + $selectionPath)
Write-Output ('SELECTION SHA256: ' + (Get-FileHash -Algorithm SHA256 -LiteralPath $selectionPath).Hash)
$submission = @(
'# 第十二批提交核验（2026-09-29）',
'',
'## #534 天下谁人不识君',
'',
'- 题目页：https://xj.edisec.net/challenges/534',
'- 前置状态：免费、中等、REVERSE；提交前步骤 1 为 0/1，题页无“已完成”徽标。',
'- 候选来源：静态反解附件注释密文得 SQCTF{libai_jianxian}；使用同一变换正向计算得到原注释密文，逐字符一致。源码顶部硬编码 flag 与注释密文长度不一致，候选存在来源冲突。',
'- 前台步骤：Computer Use 打开该题页 → 点击“提交FLAG” → 输入框准确输入 SQCTF{libai_jianxian} → 点击“提交”。',
'- 回执：玄机可访问文本返回“FLAG 不正确~”；截图显示完成情况 0%、1 人参与 / 0 人完成，步骤为 0/1。该候选已拒绝，题目未解决，不计入平台完成统计；未盲试其它包装。',
'- Computer Use 会话输出含提交后页面截图；该图未另存为项目中的 PNG，故不在此声称存在本地截图文件。',
'',
'## #535、#536',
'',
'尚未提交；待两题完成静态分析、独立复算并给出唯一候选后再在前台提交。'
)
[System.IO.File]::WriteAllText($submissionPath, ($submission -join [Environment]::NewLine), [System.Text.UTF8Encoding]::new($false))
Write-Output ('SUBMISSION RECORD: ' + $submissionPath)
Write-Output ('SUBMISSION SHA256: ' + (Get-FileHash -Algorithm SHA256 -LiteralPath $submissionPath).Hash)
Stop-Transcript

