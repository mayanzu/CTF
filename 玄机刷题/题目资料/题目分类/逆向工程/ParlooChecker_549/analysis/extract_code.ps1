$ErrorActionPreference = 'Stop'
$apkPath = 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\ParlooChecker_549\analysis\extracted\ParlooChecker_flag.apk'
$outputRoot = [System.IO.Path]::GetFullPath('C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\ParlooChecker_549\analysis\code')
$selected = @(
    'AndroidManifest.xml',
    'classes.dex',
    'classes2.dex',
    'classes3.dex',
    'lib/x86/libparloo.so',
    'lib/x86_64/libparloo.so',
    'lib/arm64-v8a/libparloo.so',
    'lib/armeabi-v7a/libparloo.so'
)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($apkPath)
try {
    foreach ($entry in $zip.Entries) {
        if ($entry.FullName -notin $selected) { continue }
        $normalized = $entry.FullName.Replace('\', '/')
        $segments = $normalized.Split('/')
        if ($normalized.StartsWith('/') -or $normalized -match '^[A-Za-z]:' -or ($segments -contains '..') -or $entry.FullName.EndsWith('/')) {
            throw "Refusing unsafe selected APK entry: $($entry.FullName)"
        }
        $destination = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($outputRoot, $entry.FullName))
        if (-not $destination.StartsWith($outputRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Destination escaped output root: $destination"
        }
        [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($destination)) | Out-Null
        $inputStream = $entry.Open()
        $outputStream = [System.IO.File]::Create($destination)
        try { $inputStream.CopyTo($outputStream) }
        finally { $outputStream.Dispose(); $inputStream.Dispose() }
        $hash = Get-FileHash -LiteralPath $destination -Algorithm SHA256
        Write-Output "EXTRACTED=$($entry.FullName) LENGTH=$($entry.Length) SHA256=$($hash.Hash)"
    }
}
finally { $zip.Dispose() }
