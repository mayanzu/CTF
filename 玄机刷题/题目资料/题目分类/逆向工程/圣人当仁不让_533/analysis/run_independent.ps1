$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$transcript = Join-Path $root '533_reproduction_transcript.txt'
$output = Join-Path $root 'evidence\independent_verification.txt'
$disassembly = Join-Path $root 'evidence/independent_static_disassembly.txt'
$exePath = Join-Path $root 'analysis\ez_vm.exe'
$exeRelative = '.\analysis\ez_vm.exe'
$verify = Join-Path $root 'analysis\independent_verify.py'
$binutils = 'C:\msys64\mingw64\bin\objdump.exe'
Start-Transcript -LiteralPath $transcript -Force
try {
    Write-Output 'INPUT> Get-FileHash -LiteralPath originals\ez_vm.zip, analysis\ez_vm.exe -Algorithm SHA256'
    Get-FileHash -LiteralPath (Join-Path $root 'originals\ez_vm.zip'), $exePath -Algorithm SHA256 | Format-Table -AutoSize

    Write-Output 'INPUT> python -I analysis\independent_verify.py'
    & python -I $verify | Tee-Object -FilePath $output
    if ($LASTEXITCODE -ne 0) { throw "independent_verify.py failed with exit code $LASTEXITCODE" }

    Write-Output 'INPUT> objdump -d -M intel --start-address=0x1400015e0 --stop-address=0x140001823 analysis\ez_vm.exe'
    Push-Location $root
    $captured = & $binutils -d -M intel --start-address=0x1400015e0 --stop-address=0x140001823 $exeRelative 2>&1 | Out-String -Width 240
    if ($LASTEXITCODE -ne 0) { throw "objdump encoder disassembly failed with exit code $LASTEXITCODE" }
    Write-Output $captured
    Add-Content -LiteralPath $disassembly -Value $captured -Encoding UTF8

    Write-Output 'INPUT> objdump -d -M intel --start-address=0x140001823 --stop-address=0x1400018b9 analysis\ez_vm.exe'
    $captured = & $binutils -d -M intel --start-address=0x140001823 --stop-address=0x1400018b9 $exeRelative 2>&1 | Out-String -Width 240
    if ($LASTEXITCODE -ne 0) { throw "objdump VM disassembly failed with exit code $LASTEXITCODE" }
    Write-Output $captured
    Add-Content -LiteralPath $disassembly -Value $captured -Encoding UTF8

    Write-Output 'INPUT> objdump -d -M intel --start-address=0x1400018b9 --stop-address=0x1400019ce analysis\ez_vm.exe'
    $captured = & $binutils -d -M intel --start-address=0x1400018b9 --stop-address=0x1400019ce $exeRelative 2>&1 | Out-String -Width 240
    if ($LASTEXITCODE -ne 0) { throw "objdump main disassembly failed with exit code $LASTEXITCODE" }
    Write-Output $captured
    Add-Content -LiteralPath $disassembly -Value $captured -Encoding UTF8
    Pop-Location

    Write-Output 'INPUT> Get-Content evidence\independent_verification.txt'
    Get-Content -LiteralPath $output
} finally {
    Stop-Transcript
}
