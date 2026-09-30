$ErrorActionPreference = 'Stop'
$archivePath = 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\ParlooChecker_549\originals\ParlooChecker_flag.zip'
$extractRoot = [System.IO.Path]::GetFullPath('C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\ParlooChecker_549\analysis\extracted')
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    foreach ($entry in $zip.Entries) {
        $normalized = $entry.FullName.Replace('\', '/')
        $segments = $normalized.Split('/')
        if ($normalized.StartsWith('/') -or $normalized -match '^[A-Za-z]:' -or ($segments -contains '..') -or $entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')) {
            throw "Refusing unsafe or non-file ZIP entry: $($entry.FullName)"
        }
        $destination = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($extractRoot, $entry.FullName))
        if (-not $destination.StartsWith($extractRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Destination escaped extraction root: $destination"
        }
        $parent = [System.IO.Path]::GetDirectoryName($destination)
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
        $inputStream = $entry.Open()
        $outputStream = [System.IO.File]::Create($destination)
        try { $inputStream.CopyTo($outputStream) }
        finally { $outputStream.Dispose(); $inputStream.Dispose() }
        Write-Output "EXTRACTED=$($entry.FullName) LENGTH=$($entry.Length) DESTINATION=$destination"
        Get-FileHash -LiteralPath $destination -Algorithm SHA256 | Format-List
    }
}
finally { $zip.Dispose() }
