param()
$ErrorActionPreference = 'Continue'
$LogPath = Join-Path $PSScriptRoot 'rederive_541_transcript.txt'
$null = chcp.com 65001
$env:PYTHONUTF8 = '1'
$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Start-Transcript -LiteralPath $LogPath -Append | Out-Null
Write-Output '=== Attachment extraction and independent forward verification ==='
Write-Output ('Started: ' + (Get-Date -Format o))
function Invoke-Logged([string]$InputText, [scriptblock]$Action) {
    Write-Output "`nCOMMAND> $InputText"
    & $Action 2>&1 | ForEach-Object { Write-Output $_ }
    Write-Output ('NATIVE_EXIT=' + $LASTEXITCODE)
}
Invoke-Logged "tar -xf (Join-Path `$PSScriptRoot '..\附件_平台原件\ezBase_platform_20260929.rar') -C (Join-Path `$PSScriptRoot 'rar_reextract'); Get-FileHash re-extracted EXE" {
    $rar = Join-Path $PSScriptRoot '..\附件_平台原件\ezBase_platform_20260929.rar'
    $dst = Join-Path $PSScriptRoot 'rar_reextract'
    if (-not (Test-Path -LiteralPath $dst)) { New-Item -ItemType Directory -Path $dst | Out-Null }
    tar -xf $rar -C $dst
    $reextracted = Join-Path $dst 'ezBase\ezre.exe'
    if (Test-Path -LiteralPath $reextracted) { Get-FileHash -LiteralPath $reextracted -Algorithm SHA256 | Format-List Path,Hash }
    else { Write-Output 'RAR extractor did not produce ezBase\ezre.exe' }
}
Invoke-Logged "python -X utf8 (Join-Path `$PSScriptRoot 'verify_candidate_541.py') 'flag{Y0u_@R3_Upx_4nd_b45364_m4st3r!}' | Tee-Object -FilePath (Join-Path `$PSScriptRoot 'independent_verification_541.txt')" {
    python -X utf8 (Join-Path $PSScriptRoot 'verify_candidate_541.py') 'flag{Y0u_@R3_Upx_4nd_b45364_m4st3r!}' | Tee-Object -FilePath (Join-Path $PSScriptRoot 'independent_verification_541.txt')
}
Write-Output "`nTRANSCRIPT_END: $((Get-Date).ToString('o'))"
Stop-Transcript | Out-Null
