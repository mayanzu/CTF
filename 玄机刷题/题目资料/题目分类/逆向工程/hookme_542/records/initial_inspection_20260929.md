# 首轮附件检查（手工补记）

这些只读检查发生在首个 `Start-Transcript` 启动之前。为保持过程完整，按实际执行命令与工具回显补记。

## 1. 文件元数据

COMMAND:
```powershell
Get-Item -LiteralPath 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542\originals\hookme.rar' | Select-Object FullName,Length,LastWriteTime
```
OUTPUT:
```text
FullName: C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542\originals\hookme.rar
Length: 5125397
LastWriteTime: 2026/9/29 10:22:30
```

COMMAND:
```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542\originals\hookme.rar' | Format-List *
```
OUTPUT:
```text
Algorithm : SHA256
Hash      : 1DC981B273CB80A32863B9A89A09CFA82B731F6D4BC8E37D72C445DEB29E993F
Path      : C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542\originals\hookme.rar
```

## 2. 安全列档工具

COMMAND:
```powershell
Get-Command 7z,7za,unrar,rar,bsdtar -ErrorAction SilentlyContinue | Select-Object Name,Source | Format-Table -AutoSize
```
OUTPUT: no matching commands were installed.

COMMAND:
```powershell
Get-Command tar.exe,python.exe,py.exe,7z.exe,WinRAR.exe,Rar.exe -ErrorAction SilentlyContinue | Select-Object Name,Source | Format-Table -AutoSize
```
OUTPUT:
```text
tar.exe    C:\WINDOWS\system32\tar.exe
python.exe C:\Users\mzj\AppData\Local\Programs\Python\Python312\python.exe
py.exe     C:\WINDOWS\py.exe
```

## 3. RAR 成员清单（未执行成员）

COMMAND:
```powershell
tar.exe -tf 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542\originals\hookme.rar'
```
OUTPUT:
```text
hookme\HookMe.apk
hookme
```

COMMAND:
```powershell
tar.exe -tvf 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542\originals\hookme.rar'
```
OUTPUT:
```text
-rw-r--r--  0 0      0     7329635 4�� 24  2025 hookme\HookMe.apk
drwxr-xr-x  0 0      0           0 5�� 19  2025 hookme
```
乱码只影响 tar 输出里的日期字符，不影响成员名/文件大小。该条命令仅列档，没有启动 APK。

## 4. 提取目录事前检查

COMMAND:
```powershell
Get-ChildItem -LiteralPath 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542' -Force | Select-Object Name,Mode,Length
```
OUTPUT:
```text
Name      Mode  Length
originals d----
```
目标 `extracted/` 是本次新建目录，后续提取 transcript 记录于 `records\rar_extract_20260929.txt`。
