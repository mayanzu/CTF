param([Parameter(Mandatory=$true)][string]$CommandText)
$transcript = Join-Path $PSScriptRoot 'command_transcript_20260929.txt'
$global:LASTEXITCODE = $null
$output = (& { Invoke-Expression $CommandText 2>&1 } | Out-String -Width 4096).TrimEnd()
$success = $?
$nativeExit = $global:LASTEXITCODE
if ($null -eq $nativeExit) { $nativeExit = if ($success) { 0 } else { 1 } }
$entry = @("`nCOMMAND> $CommandText", 'OUTPUT>', $output, "EXIT> $nativeExit") -join "`n"
Add-Content -LiteralPath $transcript -Value $entry -Encoding UTF8
if ($output.Length -gt 0) { Write-Output $output }
Write-Output "[logged exit=$nativeExit]"
