param(
    [ValidateSet('all','web','crypto','reverse','pwn','misc')]
    [string]$Book = 'all'
)

$ErrorActionPreference = 'Stop'
$courseDir = $PSScriptRoot
$ctfRoot = Split-Path -Parent $courseDir
$buildDir = Join-Path $ctfRoot 'tmp\handout-build'
New-Item -ItemType Directory -Path $buildDir -Force | Out-Null

$books = if ($Book -eq 'all') { @('web','crypto','reverse','pwn','misc') } else { @($Book) }
Push-Location $courseDir
try {
    foreach ($item in $books) {
        $stem = "handout-$item"
        foreach ($pass in 1..2) {
            $output = (& xelatex -interaction=nonstopmode -halt-on-error "-output-directory=$buildDir" "$stem.tex" 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0) {
                Write-Host (($output -split "`r?`n" | Select-Object -Last 18) -join "`n")
                throw "$stem 第 $pass 遍编译失败。日志位于 $buildDir"
            }
        }
        $builtPdf = Join-Path $buildDir "$stem.pdf"
        Copy-Item -LiteralPath $builtPdf -Destination (Join-Path $courseDir "$stem.pdf") -Force
        Write-Host "完成：$(Join-Path $courseDir "$stem.pdf")"
    }
}
finally {
    Pop-Location
}
