$ErrorActionPreference = 'Stop'
$analysis = $PSScriptRoot
$root = Split-Path -Parent $analysis
$transcript = Join-Path $analysis '538_static_transcript_20260929.txt'
Start-Transcript -LiteralPath $transcript -Append | Out-Null
try {
    Write-Output 'COMMAND> Get-ChildItem -Force -Recurse -LiteralPath $root | Select-Object FullName,Length,Mode | Format-Table'
    Get-ChildItem -Force -Recurse -LiteralPath $root | Select-Object FullName,Length,Mode | Format-Table -AutoSize

    Write-Output 'COMMAND> Get-FileHash -Algorithm SHA256 on original ZIP and extracted EXE'
    foreach ($path in @((Join-Path $root 'originals\1997.zip'), (Join-Path $analysis '123.exe'))) {
        if (Test-Path -LiteralPath $path) { Get-FileHash -LiteralPath $path -Algorithm SHA256 | Format-List } else { Write-Output "MISSING: $path" }
    }

    Write-Output 'COMMAND> Read ZIP central directory metadata with System.IO.Compression.ZipFile; no extraction or execution'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $root 'originals\1997.zip'))
    try { $zip.Entries | Select-Object FullName,Length,CompressedLength,LastWriteTime | Format-Table -AutoSize } finally { $zip.Dispose() }

    Write-Output 'COMMAND> Read EXE DOS/PE headers and section table as bytes'
    $bytes = [System.IO.File]::ReadAllBytes((Join-Path $analysis '123.exe'))
    Write-Output ("FILE_SIZE={0}" -f $bytes.Length)
    Write-Output ("DOS_MAGIC={0:X2}{1:X2}" -f $bytes[0], $bytes[1])
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    Write-Output ("PE_OFFSET=0x{0:X}" -f $peOffset)
    Write-Output ("PE_SIGNATURE={0:X2}{1:X2}{2:X2}{3:X2}" -f $bytes[$peOffset],$bytes[$peOffset+1],$bytes[$peOffset+2],$bytes[$peOffset+3])
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    $numSections = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
    $optionalSize = [BitConverter]::ToUInt16($bytes, $peOffset + 20)
    Write-Output ("MACHINE=0x{0:X4} NUM_SECTIONS={1} OPTIONAL_HEADER_SIZE={2}" -f $machine,$numSections,$optionalSize)
    $optional = $peOffset + 24
    $magic = [BitConverter]::ToUInt16($bytes, $optional)
    Write-Output ("OPTIONAL_MAGIC=0x{0:X4}" -f $magic)
    if ($magic -eq 0x20b) { $imageBase = [BitConverter]::ToUInt64($bytes, $optional + 24) } else { $imageBase = [BitConverter]::ToUInt32($bytes, $optional + 28) }
    Write-Output ("IMAGE_BASE=0x{0:X}" -f $imageBase)
    $sectionTable = $optional + $optionalSize
    for ($i=0; $i -lt $numSections; $i++) {
        $o = $sectionTable + 40*$i
        $name = [Text.Encoding]::ASCII.GetString($bytes, $o, 8).Trim([char]0)
        $virtualSize = [BitConverter]::ToUInt32($bytes, $o+8)
        $virtualAddress = [BitConverter]::ToUInt32($bytes, $o+12)
        $rawSize = [BitConverter]::ToUInt32($bytes, $o+16)
        $rawPointer = [BitConverter]::ToUInt32($bytes, $o+20)
        Write-Output ("SECTION {0}: VA=0x{1:X8} VSZ=0x{2:X8} RAW=0x{3:X8} PTR=0x{4:X8}" -f $name,$virtualAddress,$virtualSize,$rawSize,$rawPointer)
    }

    Write-Output 'COMMAND> Extract printable ASCII strings with [ -~]{4,} from binary bytes; no execution'
    $ascii = [Text.Encoding]::ASCII.GetString($bytes)
    [regex]::Matches($ascii, '[ -~]{4,}') | ForEach-Object { $_.Value } | Select-Object -Unique

    Write-Output 'COMMAND> Extract printable UTF-16LE strings with [ -~]{4,} from binary bytes; no execution'
    $wide = [Text.Encoding]::Unicode.GetString($bytes)
    [regex]::Matches($wide, '[ -~]{4,}') | ForEach-Object { $_.Value } | Select-Object -Unique
}
finally { Stop-Transcript | Out-Null }
