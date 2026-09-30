# 湘岚杯 cryptor（#539）

> **状态：已通过玄机平台验证。** 2026-09-29 主线程在玄机前台提交候选后，平台显示 flag 正确、步骤 1/1，并显示一血。附件分析代理没有访问平台；它提供了本地复核的候选和 WP。

## 1. 题目与附件

- 题目页：[https://xj.edisec.net/challenges/539](https://xj.edisec.net/challenges/539)
- 附件原件：[originals/cryptor.zip](originals/cryptor.zip)
- ZIP 大小：42,592 字节
- ZIP SHA-256：EF999BBF17CD64D9962C2FDC040D6258396FBC594227325404FC729A766D781E
- 成员：main.py、cryptor.cp310-win_amd64.pyd
- 提取后的 .pyd 大小：106,496 字节
- 提取后的 .pyd SHA-256：DBA7201DD55FDE2C9929EAF50FF85DFC0431CA7F04BDE67B3C95A4EDF16C07F7

原始 ZIP 保留在 originals/；分析副本在 analysis/extracted/。没有导入或执行附件里的 .pyd。该文件是 x64 Windows CPython 3.10 扩展，当前解释器为 Python 3.12，因此直接运行扩展既不必要也不合适。

## 2. 入口源码说明

main.py 的内容只有：

    import cryptor

    flag = input("Plz Input Your flag:")
    cryptor.check(flag)

这说明输入的 flag 由二进制扩展中的 cryptor.check 判断。破解重点是静态分析扩展中的常量与算法，而不是入口脚本本身。

## 3. 静态识别扩展

用 PE 工具检查时，文件识别为 pei-x86-64，导出入口为 PyInit_cryptor，依赖 python310.dll。可见 Cython 运行时标识 _cython_3_0_10。扩展字符串包括：

- cryptor.check
- AES.MODE_CBC, AES.MODE_ECB
- ZeroPadding、__ZeroPadding、__StripZeroPadding
- Success!、Wrong!
- Base64 密文：WegWMtim1YwucYelL2g+DU2x/B/VsQrFz2pNMJy95rE=
- IV 候选：1145140A01919810
- Key 候选：EzCrypt0ofPython

上述关键字符串由 strings.exe -t x -n 5 找到，偏移是文件偏移：

| 文件偏移 | 字符串 | 用途判断 |
|---|---|---|
| 0x15bf4 | AES.MODE_CBC, AES.MODE_ECB | 扩展支持的 AES 模式提示 |
| 0x161cc | ZeroPadding | 扩展支持零填充 |
| 0x16308 | Success! | 成功分支文案 |
| 0x16430 | Base64 密文 | 待解密数据 |
| 0x16590 | 1145140A01919810 | 16 字节 IV |
| 0x166c8 | EzCrypt0ofPython | 16 字节 AES-128 key |

密钥和 IV 按 ASCII/UTF-8 字节使用；尤其 IV 是 16 个 ASCII 字符，不是把十六进制文本解码成 8 字节。

## 4. 解密推理

1. Base64 解码密文，得到 32 字节，即两个 AES 分组。
2. 两个候选文本各为 16 字节，分别符合 AES-128 key 与 AES-CBC IV 的长度。
3. 先验证常见组合。ECB 或 PKCS#7 去填充没有产生有效明文；CBC 的 PKCS#7 会报 Padding is invalid and cannot be removed。
4. 扩展中出现零填充/零去填充函数。使用 AES-CBC 解密且关闭库自动填充后，明文是可读的 flag，后接 5 个 00 字节。
5. 去掉尾部的零填充后得到候选 flag。Python cryptography 和 OpenSSL 两个独立实现输出的 32 字节明文完全相同；脚本中也用断言验证了零填充长度和 flag 的大括号格式。

静态推导参数：

- 算法：AES-128-CBC
- Key（16 字节）：EzCrypt0ofPython
- IV（16 字节）：1145140A01919810
- 密文（Base64）：WegWMtim1YwucYelL2g+DU2x/B/VsQrFz2pNMJy95rE=
- 解密时：关闭标准自动填充；随后按题目扩展暴露的 ZeroPadding 语义移除末尾 NUL。

## 5. 本地复核结果

analysis/verify_independent.py 分别调用 Python cryptography 与 OpenSSL，不加载 .pyd。核心输出：

    cryptography ciphertext bytes: 32
    cryptography raw plaintext hex: 666c61677b417459705842683338664e766331796d735137764c7d0000000000
    cryptography raw plaintext repr: b'flag{AtYpXBh38fNvc1ymsQ7vL}\x00\x00\x00\x00\x00'
    cryptography stripped flag: flag{AtYpXBh38fNvc1ymsQ7vL}
    cryptography padding suffix: 5 NUL bytes
    OpenSSL raw plaintext hex: 666c61677b417459705842683338664e766331796d735137764c7d0000000000
    OpenSSL raw plaintext repr: b'flag{AtYpXBh38fNvc1ymsQ7vL}\x00\x00\x00\x00\x00'
    Independent implementations agree: True

已由玄机平台接受的 flag：

    flag{AtYpXBh38fNvc1ymsQ7vL}

平台已经接受此 flag，主线程报告页面显示正确、步骤数 1/1 和一血。题目可标记为已解决；主线程负责更新全局指南。

## 6. 复现命令

以下命令在项目 PowerShell 环境中执行。详细逐次记录（含错误尝试及原始输出）见 analysis/command_transcript_20260929.txt。

    $root = 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\cryptor_539'
    Get-FileHash -Algorithm SHA256 -LiteralPath "$root\originals\cryptor.zip"
    tar.exe -tf "$root\originals\cryptor.zip"
    Expand-Archive -LiteralPath "$root\originals\cryptor.zip" -DestinationPath "$root\analysis\extracted" -Force
    strings.exe -t x -n 5 "$root\analysis\extracted\cryptor.cp310-win_amd64.pyd"
    python "$root\analysis\verify_independent.py"

说明：直接把带中文的完整目录传给 MSYS2 objdump.exe 时曾遇到路径编码错误。之后用临时 Z: 映射到 analysis/extracted 后检查成功；映射在命令结束时移除。完整输出和错误都在命令记录中。

## 7. 失败尝试与边界

- cryptor 不是当前 Python 环境中可用的普通 Python 源码模块，真正校验逻辑在 CPython 3.10 .pyd 中。
- 初试 Crypto.Cipher 失败：当前环境没有 PyCryptodome（ModuleNotFoundError: No module named 'Crypto'）。未安装依赖，改用已有的 .NET、cryptography 和 OpenSSL。
- 初试 CBC/ECB + PKCS#7 均失败。记录该失败是为了说明填充模式判断过程；本题使用的线索指向 ZeroPadding。
- 最初的 Windows PowerShell 5.1 试算脚本使用了较新 .NET 才有的 Convert.ToHexString，在本机不可用；随后改用 [BitConverter]::ToString 并完成变体对比。
- 带中文全路径的首次 objdump 调用因 MSYS2 路径编码失败；使用临时盘符别名后成功读取 PE 信息。
- 本地解密证明候选与附件静态密文匹配；最终有效性由主线程在玄机前台提交并看到正确、1/1、一血后确认。

