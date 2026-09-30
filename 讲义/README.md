# 五个方向的入门讲义

从 PDF 阅读：Web、Crypto、Reverse、Pwn、Misc。对应的 `handout-*.tex` 是可编辑源稿，`handout-common.tex` 提供统一排版。

题目数据位于上一级 `labs/`，图片及截图原始实录位于上一级 `figures/`，辅助工具位于上一级 `tools/`。讲义中以 `labs/` 开头的命令均以 **CTF 根目录** 为当前目录执行。

修改源稿后，在 PowerShell 中运行：

```powershell
& .\讲义\build.ps1
```

只编译一册时，可传入 `-Book web`、`crypto`、`reverse`、`pwn` 或 `misc`。脚本需要 TeX Live 的 `xelatex`；编译中间文件写入 `tmp/handout-build/`，最终 PDF 留在本目录。
