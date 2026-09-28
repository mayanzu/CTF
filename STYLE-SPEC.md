# 五本讲义系统性重构规范书（所有子代理必读）

## 0. 背景与目标

读者画像：**CTF 零基础初学者**，学过 Python/C 和命令行，但基础知识薄弱。现有讲义的三大问题，本次重构必须全部解决：

1. **没有知识点铺垫** → 每本讲义必须有「零基础预备篇」和「方向基础知识」，任何术语第一次出现都要解释，难度必须平缓爬升；
2. **题面说不清楚** → 每道题必须有标准化「题面卡」：给什么、要什么、交付物、考点、前置知识、难度，读完题面卡就应该能动手；
3. **解题没有截图** → 每道题的带做必须配有**真实操作截图**（终端实录截图 / 真实网页截图 / 题目附件原图 / 原理示意图），看到截图能照着做。

同时做到：**系统性重构**（五本结构统一）、**大量增加内容**（每本内容显著扩充）、**优化表达**（口语化、短句、每步都说"为什么"）。

## 1. 文件与目录约定

```
项目根目录/
├── handout-common.tex      【共享排版宏——只准 \input，严禁修改】
├── STYLE-SPEC.md           【本文件】
├── tools/
│   ├── termcap.py          【真实命令执行 + 终端实录记录】
│   └── term2png.py         【终端实录 → 终端窗口截图 PNG】
├── figures/
│   ├── fig-<域>-NN-说明.png 【成品截图，直接被讲义引用】
│   └── raw/                【实录 txt（与 PNG 同名），保留证据】
├── handout-web.tex         【你只改自己负责的那一本】
├── handout-crypto.tex / handout-reverse.tex / handout-pwn.tex / handout-misc.tex
└── labs/                   【只读！禁止改动任何题目源码和附件】
```

- 图片命名：`fig-<域>-NN-短横线说明.png`，域取 `web / crypto / rev / pwn / misc / common`，NN 从 01 递增。示例：`fig-web-03-gate-admin.png`。
- 每张终端截图必须在 `figures/raw/` 留下同名 `.txt` 实录（`fig-web-03-gate-admin.txt`）。
- **只准改自己负责的 `handout-<域>.tex` 和 `figures/fig-<域>-*`、`figures/raw/fig-<域>-*`。** 其他讲义、`handout-common.tex`、`labs/`、`README.md` 一律不动。

## 2. 红线（违反任意一条即任务失败）

1. **不编造 flag**。只允许出现自己真实运行得到的 flag，或原讲义/README 中已有的已验证 flag。
2. **不伪造平台截图**。玄机平台（xj.edisec.net）页面无法截图，就不要放平台页面图；可以放"从题面文字整理的示意表格"，并注明"示意，非平台截图"。
3. **所有终端截图必须来自真实执行**：命令跑出来的输出 → `termcap.py` 记录 → `term2png.py` 渲染。禁止手打输出内容。
4. **不改动 `handout-common.tex`**，五本讲义排版一致性靠它保证。
5. **不破坏既有事实**：动手前必须完整读原 `handout-<域>.tex` 和 `README.md`，其中的已验证结论、未完成状态（如 573/583/570 未验证 flag）必须原样保留，"绝不编造 flag"原则照旧。
6. 编译必须**零错误**（warning 可容忍，error 不行）。

## 3. 截图流水线（照抄即可用）

### 3.1 终端实录截图

```powershell
# Windows PowerShell 命令（注意用 curl.exe 而不是 curl！-s 去掉进度条噪音）
python tools/termcap.py --out figures/raw/fig-web-03-gate-admin.txt --shell ps `
    --server "python labs/web/app.py" --wait 2 `
    --cmd "curl.exe -s -i http://127.0.0.1:8765/gate?role=admin"

python tools/term2png.py figures/raw/fig-web-03-gate-admin.txt figures/fig-web-03-gate-admin.png --title "查询 role=admin"
```

WSL 命令（ELF 程序、gcc、strings、objdump、readelf、xxd 都在 WSL 里跑）：

```powershell
python tools/termcap.py --out figures/raw/fig-pwn-04-run.txt --shell wsl --cwd "C:\Users\mzj\Desktop\CTF\CTF-training-problem-first-full" `
    --cmd "cd /mnt/c/Users/mzj/Desktop/CTF/CTF-training-problem-first-full && gcc -O0 -fno-stack-protector -no-pie -o labs/pwn/overflow labs/pwn/overflow.c" `
    --cmd "cd /mnt/c/Users/mzj/Desktop/CTF/CTF-training-problem-first-full && python3 -c \"import sys;sys.stdout.buffer.write(b'A'*24+b'\xef\xbe\xad\xde')\" | labs/pwn/overflow"
```

要点：
- PowerShell 里引号嵌套麻烦时，把命令拆成多条 `--cmd`；WSL 里用 `bash -lc` 可正常处理引号。
- `--server "python labs/web/app.py" --wait 2` 会在后台起服务、跑完命令自动关掉。
- `--timeout N` 让"服务启动画面"这类常驻命令跑 N 秒后截断（实录尾部会标注截断）。
- Python 输出乱码时给命令加 `python -X utf8` 或确保输出为 UTF-8；渲染器会自动剔除 ANSI 控制符。
- 每张图渲染完**必须用 read 工具看一眼 PNG**，确认输出真实、清晰、没截断错位，再写进讲义。
- `--title` 写这一步在做什么（如 "第 2 步：单引号触发 SQL 报错"），读者一眼看懂。

### 3.2 真实网页截图（Edge 无头模式，仅 Web 方向用）

```powershell
# 先后台启动本地靶场，再截图（必须用绝对路径！）
$p = Start-Process python -ArgumentList "labs/web/app.py" -PassThru -WindowStyle Hidden
Start-Sleep 2
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless=new --disable-gpu --no-first-run `
    --user-data-dir="$env:TEMP\edgeheadless-profile" --screenshot="C:\Users\mzj\Desktop\CTF\CTF-training-problem-first-full\figures\fig-web-05-notes-sqli.png" `
    --window-size=1024,700 "http://127.0.0.1:8765/notes?title=' OR 1=1 -- "
Stop-Process -Id $p.Id -Force
```

### 3.3 题目附件原图与示意图

- 题目附件图片（如 `labs/platform/attachments/583-pixel-cage/challenge.png`）可以直接引用或放大裁剪后引用，图注写明"题目附件原图"。
- 原理示意图（内存布局、协议结构、流程图等）用 matplotlib 画，风格统一：白底、黑灰主线、字号 12-14、输出 PNG 200dpi。画的是**结构关系**，不是装饰。

## 4. 统一结构（五本完全一致的骨架）

```latex
\documentclass[UTF8,12pt,oneside]{ctexbook}
\input{handout-common}
\handoutmark{<方向> 专攻版}          % 例如 Web 专攻版
\booktitle{CTF 网络安全入门：<方向>专攻版}
\begin{document}
\frontmatter
  标题页（沿用原讲义样式，可补充"本册特色"）
  使用说明（学习路线图、怎么用这本讲义、安全声明、截图说明、术语约定）
\mainmatter
  第 1 章  零基础预备：<环境、命令行与工具安装>   【带安装/验证截图】
  第 2 章  <方向>基础知识铺垫                    【概念逐个讲 + 原理示意图 + 常见误区】
  第 3 章  <方向>工具箱                          【每个工具：是什么/怎么装/基本用法/真实输出截图】
  第 4 章  题目：标准题面卡                      【每题一张 challenge 卡】
  第 5 章  逐题图解带做                          【每题：思路→分步操作+截图→核对→为什么→排错→变式】
  第 6 章  复盘：知识地图与易错清单              【流程图/思维导图 + "下次遇到这类题怎么办"】
  第 7 章  自测与参考答案                        【自测题 + 完整推演】
  附录 A   玄机平台真题状态与提交 checklist      【保留原状态说明，绝不编造】
  附录 B   命令速查表                            【两列表：想做什么 / 敲什么命令】
  附录 C   术语表                                【按首字母/拼音排序，一句话解释】
\end{document}
```

章节内小节自由安排，但以上章节名和顺序**必须保留**（可按方向措辞微调，如"第 2 章 Crypto 基础知识铺垫"）。

## 5. 题面卡格式（每题必用）

```latex
\begin{challenge}{题 W2：标题搜索里，哪个字节改变了查询？}
\field{题目来源}{本地靶场 \code{labs/web/app.py}（离线可做）}
\field{给定材料}{接口 \code{/notes?title=...}；源码 \code{labs/web/app.py} 中拼 SQL 的一行}
\field{目标}{让接口返回本来查不到的 staff 记录，读出其中的 flag}
\field{交付物}{一个 \code{flag\{...\}} 字符串，提交前检查大小写与花括号}
\field{考点}{SQL 注入：外部数据进入查询结构}
\field{前置知识}{2.x 节 HTTP 查询参数、3.x 节 curl、2.x 节 SQL 语法结构}
\field{难度}{★☆☆（入门）}
\end{challenge}
```

字段固定为：题目来源 / 给定材料 / 目标 / 交付物 / 考点 / 前置知识 / 难度（★ 体系）。目标和交付物必须写到"读完知道要干什么"。

## 6. 逐题带做格式（每题必用）

每题按顺序包含 6 个 `paragraph` 级模块：

1. **读题与思路**：从题面卡出发，讲"看到这题先想什么、为什么这么想"，禁止一上来就给 payload；
2. **分步操作与观察**（`\begin{enumerate}`）：每一步 = 一条命令/操作 + \figref 引用截图 + "应该看到什么"；关键步骤必须有图；
3. **结果与核对**：flag 怎么独立验证（对源码、重算、平台反馈），用 `\flagbox`；
4. **为什么会成功**：把现象归因到机制（一句话机制 + 展开 2-4 句）；
5. **排错指南**：`\debugtip{...}`，2-4 条"如果没看到预期输出"的具体检查；
6. **变式练习**：2-3 个"改一改再做"的小练习，难度递进，明确说改什么。

## 7. 写作标准（面向零基础）

- **术语首现必解释**：如"什么是 payload、字节序、栈帧、Cookie"，首次出现用一两句白话解释；
- **每步都说为什么**：不做"输入命令 X"式的流水账，紧跟一句"这一步是为了……"；
- **短句、主动语态、少套话**；避免"显然""众所周知""很简单"；
- 每个知识点收尾给 `\memory{}`（一句话记忆）；容易搞混的地方给 `\pitfall{}`（常见误区）；
- 难度平缓：先教"看类型、建基线"，再教"找线索"，最后教"利用与修复"；
- 数字、字节、地址等易混处配表格或示意图；
- 所有可运行内容给出**可复制的完整命令**（含路径），并注明在 Windows PowerShell 还是 WSL 里执行。

## 8. 图量与篇幅验收（硬指标）

| 指标 | 要求 |
| --- | --- |
| 嵌入图片 | 每本 **≥ 14 张**（终端截图 ≥ 10 张，且 ≥ 8 张出现在第 5 章带做里） |
| PDF 页数 | 每本 **≥ 30 页** |
| 源文件 | 每本 `.tex` **≥ 55 KB** |
| 编译 | `xelatex -interaction=nonstopmode handout-<域>.tex` 连跑两遍，0 error |

## 9. 各方向专属任务简报

### 9.1 Web（`handout-web.tex`，域前缀 `fig-web-`）
- 题目：W0-W4（labs/web/app.py 的 /gate、/notes；W3 参数化修复对照；W4 玄机 SU_photogallery 入口判断）。
- 必备截图方向：启动靶场画面、浏览器访问首页/gate?role=guest/gate?role=admin/notes?title=public（Edge 无头截图，其中 admin 和注入页面**必须出现真实 flag**）、curl 基线与注入对照（curl.exe -s -i）、单引号触发 SQL 报错、app.py 源码关键行、参数化修复后同样输入失效的对照。
- 知识铺垫重点：HTTP 请求/响应结构（配结构示意图）、URL 与 URL 编码、Cookie 与会话、SQL 基本语法与字符串拼接、SQL 注入 vs XSS vs 路径穿越的场景区分、认证 vs 授权。
- 原讲义事实：flag{http_query_is_input}、flag{sql_parameters_matter}（本地靶场）、570 状态"入口判断完成，答案未确认"。

### 9.2 Crypto（`handout-crypto.tex`，域前缀 `fig-crypto-`）
- 题目：C0-C4（xor.hex 单字节异或、五格电文、rsa.txt 小模数 RSA、共模回执）+ 玄机 586 五格电文、587 联号回执（用 labs/platform/solve_five_grid.py、solve_receipt.py 真实跑出 flag）。
- 必备截图方向：xxd/十六进制与字节对照、xor.hex 内容、异或穷举脚本真实输出、rsa.txt 内容、python pow/试除分解 n 的真实输出、solve_five_grid.py 与 solve_receipt.py 真实输出（含 flag）、模运算演示。
- 知识铺垫重点：ASCII/十六进制/字节、异或真值表与可逆性（配图）、为什么"单字节异或 256 种就穷举完"、频率/可读性判断、模运算与 RSA 三元组 (n,e,c)、私钥为什么不能公开、小模数与共模为什么危险。
- 原讲义事实：flag{xor_is_not_magic}、flag{rsa_small_modulus}（本地题）；586/587 平台已验证 flag 见 solve 脚本真实输出。

### 9.3 Reverse（`handout-reverse.tex`，域前缀 `fig-rev-`）
- 题目：R1（check1 二进制）、R2（verify2.py）+ 玄机 589 闸机票根（gate_ticket 是去符号 ELF，RC4 两次；solve_589_gate_ticket.py 真实跑出 ticket 与 flag）。
- 必备截图方向：file 识别 check1、echo 错误输入 | ./check1 得 nope、cat check1.c 源码、strings 与 objdump -d 关键片段（WSL）、python 破解脚本真实输出 → ./check1 得 correct、verify2.py 交互与破解、589 的 solve 脚本真实输出。
- 知识铺垫重点：程序如何被编译成机器码、源码↔汇编↔二进制的关系、字符串与常量藏在哪、逆向的"黑盒观察→白盒验证"路线、Python 字节运算（(b*3+7)&255 这类可逆变换怎么反推）、RC4 的 KSA/PRGA 概念（589 用）。
- 原讲义事实：check1 的校验是 XOR 0x23、verify2 是 (b*3+7)&255；589 是标准 RC4 两次调用，flag 由 solve 脚本真实输出给出。

### 9.4 Pwn（`handout-pwn.tex`，域前缀 `fig-pwn-`）
- 题目：P0-P4（overflow.c 栈上函数指针覆写、format.c 格式串泄漏、编译保护影响）+ 玄机 296 pwn-ezpwn（solve_pwn_ezpwn.py 需 HOST/PORT，保留"需在线实例"状态）。
- 必备截图方向：gcc 编译命令真实输出、cat overflow.c 源码、运行 ./overflow 得 "Try again."、python3 构造 24 字节+地址的 payload 跑出 flag{control_flow_redirected}、payload 十六进制视图、readelf/objdump 查看架构与 main、运行 ./format 用 %p %x 泄漏出 flag{format_string_leaks}。
- 知识铺垫重点：进程内存布局（栈/堆/代码段，配示意图）、局部变量与函数指针在栈上的相邻关系（覆写前后对照图）、字节序（小端序写地址，配图）、为什么 read 32 字节能越界、格式字符串原理（printf(input) 为什么危险、%s/%p 怎么读栈）、保护机制（canary/PIE/NX）是什么。
- 原讲义事实：flag{control_flow_redirected}、flag{format_string_leaks}（本地题）；296 需在线实例，状态照旧。WSL 无 gdb，用 objdump/readelf/python 内存演示代替，讲清"为什么本册不用调试器也能确认偏移"。

### 9.5 Misc（`handout-misc.tex`，域前缀 `fig-misc-`）
- 题目：M0-M4（pixel.png 元数据、尾随 ZIP、PCAP 分片）+ 玄机 581 外泄流量取证、583 像素囚笼、591 Poisoned Samples（solve 脚本真实输出）。
- 必备截图方向：file 识别、pixel.png 放大图（1×1 像素，放大成色块图并注明"放大示意"）、PNG 分块结构 dump（tEXt 里 base64 的 flag）、从 tEXt 提取 flag 的真实脚本输出、fragments.pcap 解析与重组真实输出、583 challenge.png 原图 + 尾部 ZIP 签名的 xxd 截图、581 screenshot.png 原图 + solve_581 输出、591 CSV 头部 + solve_591 输出。
- 知识铺垫重点：文件头/扩展名不可信、PNG 分块（IHDR/IDAT/tEXt/IEND）结构图、base64、十六进制查看文件尾、ZIP 文件头签名 PK\x03\x04、PCAP 与 UDP/IP 分片重组思路、取证的"保留原件、只读分析"习惯。
- 原讲义事实：flag{metadata_has_clues}、flag{follow_the_packets}（本地题）；581/591 平台已验证（solve 脚本真实输出）；583 "已确认尾部追加加密 ZIP，flag 未验证"；573/570 未验证，照 README 表述。

## 10. 编译与自查清单（每个子代理完成前逐项打勾）

1. `python tools/termcap.py` + `term2png.py` 生成全部截图，每个 PNG 用 read 工具检查过内容；
2. 讲义中每个 `\shot` 的文件名真实存在（`figures/` 下），每个 `\figref` 都有对应 `\label`；
3. `xelatex -interaction=nonstopmode handout-<域>.tex` 连跑两遍，log 中无 error、无 "Undefined control sequence"、无 "LaTeX Error"；
4. 页数 ≥ 30、图片 ≥ 14、源码 ≥ 55 KB；
5. 原讲义的已验证 flag 与未验证状态全部保留；新增内容没有引入新编造 flag；
6. 通读一遍目录，检查章节名、题号、交叉引用一致。

## 11. 完成后回报格式

返回：① 新讲义 PDF 页数与图数；② 生成的截图清单（文件名 + 一行说明）；③ 保留的既有事实（flag/状态）；④ 编译是否零错误；⑤ 你对内容做的最重要 3 个改进。
