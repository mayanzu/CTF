param()
$ErrorActionPreference = 'Continue'
$LogPath = Join-Path $PSScriptRoot 'rederive_541_transcript.txt'
$null = chcp.com 65001
$env:PYTHONUTF8 = '1'
$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Start-Transcript -LiteralPath $LogPath -Append | Out-Null
Write-Output '=== Fresh offline #541 re-derivation ==='
Write-Output ('Started: ' + (Get-Date -Format o))
Write-Output 'Safety: no web/platform access, no challenge executable execution, no file deletion.'
function Invoke-Logged([string]$InputText, [scriptblock]$Action) {
    Write-Output "`nCOMMAND> $InputText"
    & $Action 2>&1 | ForEach-Object { Write-Output $_ }
    Write-Output ('NATIVE_EXIT=' + $LASTEXITCODE)
}
Invoke-Logged "Get-FileHash -LiteralPath (Join-Path `$PSScriptRoot '..\附件_平台原件\ezBase_platform_20260929.rar') -Algorithm SHA256; Get-FileHash -LiteralPath (Join-Path `$PSScriptRoot '..\ezBase\ezre.exe') -Algorithm SHA256" {
    Get-FileHash -LiteralPath (Join-Path $PSScriptRoot '..\附件_平台原件\ezBase_platform_20260929.rar') -Algorithm SHA256 | Format-List Path,Hash
    Get-FileHash -LiteralPath (Join-Path $PSScriptRoot '..\ezBase\ezre.exe') -Algorithm SHA256 | Format-List Path,Hash
}
Invoke-Logged "Get-ChildItem -LiteralPath 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\ezBase_541' -Recurse -File | Where-Object { `$_.Name -match 'ezBase|dq14shk' } | Select-Object FullName,Length | Format-List" {
    Get-ChildItem -LiteralPath 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\ezBase_541' -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'ezBase|dq14shk' } | Select-Object FullName,Length
}
Invoke-Logged "Test-Path known 7-Zip/WinRAR paths; Get-Command tar; tar -tf (Join-Path `$PSScriptRoot '..\附件_平台原件\ezBase_platform_20260929.rar')" {
    $candidates = @('C:/Program Files\7-Zip\7z.exe','C:/Program Files (x86)\7-Zip\7z.exe','C:/Program Files\WinRAR\UnRAR.exe','C:/Program Files\WinRAR\WinRAR.exe')
    foreach ($candidate in $candidates) { '{0} exists={1}' -f $candidate,(Test-Path -LiteralPath $candidate) }
    Get-Command tar -ErrorAction SilentlyContinue | Select-Object Name,Source
    $rar = Join-Path $PSScriptRoot '..\附件_平台原件\ezBase_platform_20260929.rar'
    tar -tf $rar 2>&1
}
Invoke-Logged "python -X utf8 (Join-Path `$PSScriptRoot 'rederive_541.py')" {
    python -X utf8 (Join-Path $PSScriptRoot 'rederive_541.py')
}
Write-Output "`nTRANSCRIPT_END: $((Get-Date).ToString('o'))"
Stop-Transcript | Out-Null
