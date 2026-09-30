$ErrorActionPreference = 'Stop'
function Convert-HexToBytes {
    param([Parameter(Mandatory=$true)][string]$Hex)
    if (($Hex.Length % 2) -ne 0) { throw 'Odd-length hex string' }
    [byte[]]$Bytes = New-Object byte[] ([int]($Hex.Length / 2))
    for ($i = 0; $i -lt $Bytes.Length; $i++) { $Bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }
    return ,$Bytes
}
function Convert-BytesToHex {
    param([Parameter(Mandatory=$true)][byte[]]$Bytes)
    return [System.BitConverter]::ToString($Bytes).Replace('-', '').ToLowerInvariant()
}
$AnalysisDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Base = Split-Path -Parent $AnalysisDir
$MaterialPath = Join-Path $AnalysisDir 'derived_material.json'
$Material = Get-Content -LiteralPath $MaterialPath -Raw | ConvertFrom-Json
[byte[]]$Key = Convert-HexToBytes -Hex ([string]$Material.aes_key_hex)
[byte[]]$Ciphertext = Convert-HexToBytes -Hex ([string]$Material.ciphertext_hex)
if ($Key.Length -ne 16) { throw "Expected AES-128 key, got $($Key.Length) bytes" }
if ($Ciphertext.Length -eq 0 -or ($Ciphertext.Length % 16) -ne 0) { throw 'Ciphertext is not whole AES blocks' }
$Aes = [System.Security.Cryptography.Aes]::Create()
try {
    $Aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $Aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $Aes.Key = $Key
    $Decryptor = $Aes.CreateDecryptor()
    try { [byte[]]$Raw = $Decryptor.TransformFinalBlock($Ciphertext, 0, $Ciphertext.Length) }
    finally { $Decryptor.Dispose() }
    $PadLength = [int]$Raw[$Raw.Length - 1]
    if ($PadLength -lt 1 -or $PadLength -gt 16) { throw "Invalid PKCS#7 length $PadLength" }
    for ($i = $Raw.Length - $PadLength; $i -lt $Raw.Length; $i++) {
        if ([int]$Raw[$i] -ne $PadLength) { throw "Invalid PKCS#7 byte at offset $i" }
    }
    $PlainLength = $Raw.Length - $PadLength
    [byte[]]$Plain = New-Object byte[] $PlainLength
    [Array]::Copy($Raw, 0, $Plain, 0, $PlainLength)
    $Encryptor = $Aes.CreateEncryptor()
    try { [byte[]]$Reencrypted = $Encryptor.TransformFinalBlock($Raw, 0, $Raw.Length) }
    finally { $Encryptor.Dispose() }
    $RoundTrip = (Convert-BytesToHex -Bytes $Reencrypted) -eq [string]$Material.ciphertext_hex
    $Flag = [System.Text.Encoding]::ASCII.GetString($Plain)
    Write-Output ("AES_KEY=" + (Convert-BytesToHex -Bytes $Key))
    Write-Output "CIPHERTEXT_BYTES=$($Ciphertext.Length)"
    Write-Output ("DECRYPTED_PADDED_HEX=" + (Convert-BytesToHex -Bytes $Raw))
    Write-Output "PKCS7_LENGTH=$PadLength"
    Write-Output 'PKCS7_VALID=PASS'
    Write-Output "PLAINTEXT_ASCII=$Flag"
    Write-Output "REENCRYPTION_ROUNDTRIP=$(if ($RoundTrip) { 'PASS' } else { 'FAIL' })"
    if (-not $RoundTrip) { throw 'AES round-trip mismatch' }
    if ($Flag -notmatch '^flag\{[ -~]+\}$') { throw 'Plaintext does not match the expected flag format' }
    Write-Output "CANDIDATE_FLAG=$Flag"
}
finally { $Aes.Dispose() }