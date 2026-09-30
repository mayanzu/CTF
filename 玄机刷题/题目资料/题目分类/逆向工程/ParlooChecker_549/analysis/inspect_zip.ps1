$ErrorActionPreference = 'Stop'
$archivePath = 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\ParlooChecker_549\originals\ParlooChecker_flag.zip'
Write-Output "ARCHIVE=$archivePath"
Write-Output '--- SHA256 ---'
Get-FileHash -LiteralPath $archivePath -Algorithm SHA256 | Format-List
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    $unsafe = [System.Collections.Generic.List[string]]::new()
    Write-Output '--- ZIP ENTRIES (metadata only; no extraction) ---'
    foreach ($entry in $zip.Entries) {
        $name = $entry.FullName
        $normalized = $name.Replace('\', '/')
        $segments = $normalized.Split('/')
        $isUnsafe = $normalized.StartsWith('/') -or $normalized -match '^[A-Za-z]:' -or ($segments -contains '..')
        if ($isUnsafe) { $unsafe.Add($name) }
        [pscustomobject]@{
            Name = $name
            Length = $entry.Length
            CompressedLength = $entry.CompressedLength
            IsDirectory = $name.EndsWith('/') -or $name.EndsWith('\')
            UnsafePath = $isUnsafe
        } | Format-Table -AutoSize
    }
    Write-Output "ENTRY_COUNT=$($zip.Entries.Count)"
    Write-Output "UNSAFE_ENTRY_COUNT=$($unsafe.Count)"
    foreach ($name in $unsafe) { Write-Output "UNSAFE_ENTRY=$name" }
}
finally { $zip.Dispose() }
