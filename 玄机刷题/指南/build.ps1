# 玄机平台 CTF 刷题指南 构建脚本
#   1) pandoc: 玄机刷题指南_合并源.md -> 玄机刷题指南_正文.tex
#   2) 后处理: 修正 pandoc 表格的 \LTcaptype，给长行内代码加可断行包装
#   3) xelatex: 玄机刷题指南.tex -> 玄机刷题指南.pdf（两遍，生成目录）
param(
    [switch]$SkipPandoc   # 跳过 pandoc，直接用现有正文重新编译
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$bodyMd  = '玄机刷题指南_合并源.md'
$bodyTex = '玄机刷题指南_正文.tex'
$mainTex = '玄机刷题指南.tex'
$pdf     = '玄机刷题指南.pdf'
$ctfRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$buildDir = Join-Path $ctfRoot 'tmp\guide-build'
New-Item -ItemType Directory -Path $buildDir -Force | Out-Null

# ---------- 1. pandoc ----------
if (-not $SkipPandoc) {
    Write-Host '[1/3] pandoc 转换正文...'
    pandoc $bodyMd `
        -f markdown+lists_without_preceding_blankline `
        -t latex --syntax-highlighting=none `
        --top-level-division=chapter --wrap=none `
        -o $bodyTex
    if ($LASTEXITCODE -ne 0) { throw "pandoc 失败，退出码 $LASTEXITCODE" }
}

# ---------- 2. 正文后处理 ----------
Write-Host '[2/3] 正文后处理...'
$enc   = New-Object System.Text.UTF8Encoding($false)
$text  = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $bodyTex), [Text.Encoding]::UTF8)

# (a) pandoc 给表格包了 {\def\LTcaptype{none} ...}，新版 longtable 会执行
#     \refstepcounter{none}，报 "No counter 'none' defined"。
#     置空即 longtable 认定"无题注、不计数"，与 pandoc 的本意一致。
$ltCount = ([regex]::Matches($text, [regex]::Escape('\def\LTcaptype{none}'))).Count
$text = $text.Replace('\def\LTcaptype{none}', '\def\LTcaptype{}')

# (a2) lmroman10-regular 没有 U+2264（≤）字形，xelatex 会打 "Missing character"
#      并印出空位。正文（非 verbatim）里改用数学模式的 \le。全文仅此 1 处。
$leqCount = ([regex]::Matches($text, '≤')).Count
$text = $text.Replace('≤', '$\le$')

# (b) 长行内代码（64 位哈希、十六进制串、路径）无法断行会溢出页边界。
#     对 \texttt{} 内容套 \seqsplit 让其逐字符断行。已验证 seqsplit 可安全处理
#     \_、\{、\}、\%、\&、\#、\$、\textbackslash{}、\textbar{}、\textless{} 等
#     转义，唯一例外是重音命令 \^{}（会报 "Missing number"），先改写成等价的
#     \textasciicircum{} 再套 seqsplit。
function Get-TextttSpans([string]$s) {
    $spans = @()
    $i = 0
    while (($i = $s.IndexOf('\texttt{', $i, [StringComparison]::Ordinal)) -ge 0) {
        $depth = 1
        $j = $i + 8
        while ($j -lt $s.Length -and $depth -gt 0) {
            $c = $s[$j]
            if ($c -eq '\') { $j += 2; continue }   # 跳过 \{ \} 等转义
            if ($c -eq '{') { $depth++ }
            elseif ($c -eq '}') { $depth-- }
            $j++
        }
        if ($depth -ne 0) { break }                 # 括号不配对，停止以免误改
        $spans += ,@($i, $j)                        # [起始, 结束(不含)]
        $i = $j
    }
    return $spans
}

$spans = Get-TextttSpans $text
$sb = New-Object System.Text.StringBuilder
$pos = 0
$ttCount = 0
foreach ($sp in $spans) {
    $s0 = $sp[0]; $s1 = $sp[1]
    [void]$sb.Append($text.Substring($pos, $s0 - $pos))
    $inner = $text.Substring($s0 + 8, ($s1 - 1) - ($s0 + 8))
    if ($inner.Length -ge 16 -and $inner -notmatch '\\seqsplit\{') {
        $inner = $inner.Replace('\^{}', '\textasciicircum{}')
        [void]$sb.Append('\texttt{\seqsplit{' + $inner + '}}')
        $ttCount++
    }
    else {
        [void]$sb.Append($text.Substring($s0, $s1 - $s0))
    }
    $pos = $s1
}
[void]$sb.Append($text.Substring($pos))
$text = $sb.ToString()

# (c) 正文中裸露的 32 位以上十六进制串 / 40 位以上 Base32 串（不在行内代码里）
#     同样无法断行，套 \seqsplit。verbatm 环境、\texttt{}、\href{} 与行内公式
#     内的内容保持原样。
$protect = @()
foreach ($m in [regex]::Matches($text, '\\begin\{verbatim\}.*?\\end\{verbatim\}', 'Singleline')) {
    $end = $m.Index + $m.Length
    $protect += ,@($m.Index, $end)
}
foreach ($sp in (Get-TextttSpans $text)) { $protect += ,$sp }
foreach ($m in [regex]::Matches($text, '\\href\{[^{}]*\}')) {
    $end = $m.Index + $m.Length
    $protect += ,@($m.Index, $end)
}
# \hexwrap 内部已含 \seqsplit（见样式文件），嵌套会让 seqsplit 吃爆内存
foreach ($m in [regex]::Matches($text, '\\hexwrap\{[^{}]*\}')) {
    $end = $m.Index + $m.Length
    $protect += ,@($m.Index, $end)
}
foreach ($m in [regex]::Matches($text, '\$[^$\r\n]+\$')) {
    $end = $m.Index + $m.Length
    $protect += ,@($m.Index, $end)
}

function Test-InSpan([int]$idx, [array]$spans) {
    foreach ($r in $spans) { if ($idx -ge $r[0] -and $idx -lt $r[1]) { return $true } }
    return $false
}

$hexPattern = '(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{32,}|[A-Z2-7]{40,})(?![A-Za-z0-9])'
$hexMatches = [regex]::Matches($text, $hexPattern)
$sb2 = New-Object System.Text.StringBuilder
$pos = 0
$hexCount = 0
foreach ($m in $hexMatches) {
    if (Test-InSpan $m.Index $protect) { continue }
    [void]$sb2.Append($text.Substring($pos, $m.Index - $pos))
    [void]$sb2.Append('\seqsplit{' + $m.Value + '}')
    $pos = $m.Index + $m.Length
    $hexCount++
}
[void]$sb2.Append($text.Substring($pos))
$text = $sb2.ToString()

[IO.File]::WriteAllText((Join-Path $PSScriptRoot $bodyTex), $text, $enc)
Write-Host ("      LTcaptype 修正 {0} 处；可断行行内代码 {1} 处；可断行裸哈希 {2} 处" -f $ltCount, $ttCount, $hexCount)

# ---------- 3. xelatex ----------
function Invoke-XeLaTeX {
    param([int]$Pass)
    Write-Host ("      xelatex 第 {0} 遍..." -f $Pass)
    $out = (& xelatex -interaction=nonstopmode "-output-directory=$buildDir" $mainTex 2>&1 | Out-String)
    $errs = @(($out -split "`r?`n") | Where-Object { $_ -match '^!' })
    if ($errs.Count -gt 0) {
        Write-Host ($errs | Select-Object -First 8)
        Write-Host ((($out -split "`r?`n") | Select-String -Pattern '^l\.\d+' | Select-Object -First 5) -join "`n")
        throw "xelatex 第 $Pass 遍失败"
    }
}

Write-Host '[3/3] xelatex 编译...'
Invoke-XeLaTeX -Pass 1
Invoke-XeLaTeX -Pass 2

Copy-Item -LiteralPath (Join-Path $buildDir $pdf) -Destination (Join-Path $PSScriptRoot $pdf) -Force
$item = Get-Item (Join-Path $PSScriptRoot $pdf)
Write-Host ("完成：{0}  {1:N0} 字节" -f $item.FullName, $item.Length)
