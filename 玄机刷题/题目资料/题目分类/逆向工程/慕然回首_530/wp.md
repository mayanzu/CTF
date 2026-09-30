# 玄机题 #530：慕然回首，那人却在灯火阑珊处

## 结论

题目附件是一个 64 位 Windows 控制台迷宫程序。迷宫没有加密，直接以 10×10 字符数组保存在 PE 的 `.data` 段。按程序的方向定义从 `S` 走到 `E`，唯一的最短路为：

```text
ddddddssaaaaassdddssaa
```

按程序自己的提示格式推得候选 flag：

```text
flag{ddddddssaaaaassdddssaa}
```

**验证边界：** 静态代码确认程序到达 E 后只打印提示，不在程序内比较 flag；附件足以恢复候选，但要以玄机平台判断为准。2026-09-29 前台提交候选后，平台显示“FLAG 正确，恭喜你完成此挑战”，详情页显示已完成、步骤 1/1。

## 文件与证据

分析对象限定为题目目录中的 `originals/tom.zip` 与 `extracted/Jerry.exe`。ZIP 中仅有一个成员 `Jerry.exe`；成员 CRC-32 为 `66697c1e`，解压后大小为 159,118 字节，ZIP 完整性检查通过。ZIP 成员与现有 `extracted/Jerry.exe` 逐字节相同。

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `originals/tom.zip` | 51,073 字节 | `15832F8EA58617B1D40050CBDEB138E92A1DFA2E9DBEBEC1AF25446306B99EE9` |
| `extracted/Jerry.exe` | 159,118 字节 | `6E1E38D0C0036AC10EBA97D04F698C1B3771805A8F5B101A6328EC3583364BFF` |

关键 PE 属性来自文件头静态解析及 `objdump -x`：PE32+、机器类型 `0x8664`（x86-64）、Windows 控制台子系统、18 个节、映像基址 `0x400000`、入口 RVA `0x1500`（VA `0x401500`）。用户代码 `main` 位于 VA `0x401530`。节表中有 `.text`、`.data`、`.rdata`、`.pdata`、`.xdata`、`.bss`、`.idata`、`.CRT`、`.tls` 和若干调试节。COFF 头记录了 1,488 个符号；节数据后的 33,166 字节正好由 COFF 符号表（26,784 字节）和字符串表（6,382 字节）解释，二者结束偏移为 `0x26d8e`，与文件长度相等。

导入表只有 `KERNEL32.dll` 和 `msvcrt.dll`，包括 `scanf`、`puts`、`exit` 等常规控制台/运行库函数；未见加密库、`LoadLibrary` 或 `GetProcAddress` 导入。Security Directory 为零。PE 时间戳字段解读为 `2025-03-25 12:45:15 UTC`，字符串中还留有 GCC 4.9.2 与 `C:\Users\86131\Desktop\Jerry.cpp` 等构建路径信息；这些都是二进制内的构建元数据，不能单独作为可信的来源证明。

可复现解析器和机器可读结果分别在 `analysis/static_analyze.py`、`analysis/static_analysis.json`。所有 PowerShell 命令和完整标准输出/错误输出（包括失败尝试与修正）记录于 `analysis/commands_output.log`。脚本只读取 ZIP/EXE 字节、解析 PE 结构和搜索迷宫，不启动或加载 EXE；可从题目目录运行：

```powershell
python analysis/static_analyze.py
```

## 迷宫数据与坐标

`objdump` 的 `.data` 转储在 VA `0x403040` 显示迷宫起始字节 `53 2a 2a 2a ...`，即 ASCII `S***...`。PE 映射关系将它定位到 RVA `0x3040`、文件偏移 `0x2640`。从这里连续读取的 100 字节只含 `S`、`E`、`*`、`#`，按程序的行宽 10 切分为：

```text
S******###
######*###
#******###
#*########
#****#####
####*#####
##E**#####
##########
##########
##########
```

在 `main` 中，当前行号保存在全局 `x`（VA `0x407030`），列号保存在 `y`（VA `0x407034`）。二者位于 `.bss`，初值为零；起点因此是 `(0,0)`。地址计算指令由 `x` 乘 10 再加 `y`，访问 `maze[x*10+y]`。终点 `E` 位于零起点坐标 `(6,2)`。

## 算法与控制流

`main` 首先在 `0x40153d`–`0x40155c` 打印欢迎语、方向说明和输入提示，然后在 `0x401561`–`0x40156f` 以格式串 `%c` 读取一个字符。格式串位于 VA `0x404079`；相关提示字符串位于 `.rdata`，偏移可在静态结果中查到。

控制流根据输入字符分支：`w`（`0x77`）上移、`a`（`0x61`）左移、`s`（`0x73`）下移、`d`（`0x64`）右移。每个分支先确认坐标不越界，再检查目标格是否为 `#`；仅当目标不是墙时才更新坐标。由此可还原为：

```text
while true:
    move = scanf("%c")
    if move == 'w' and x > 0 and maze[(x-1)*10+y] != '#': x -= 1
    elif move == 'a' and y > 0 and maze[x*10+(y-1)] != '#': y -= 1
    elif move == 's' and x <= 8 and maze[(x+1)*10+y] != '#': x += 1
    elif move == 'd' and y <= 8 and maze[x*10+(y+1)] != '#': y += 1
    elif move not in 'wasd':
        puts("Invalid move!")
        continue
    if maze[x*10+y] == 'E':
        puts("You are so clever! This is Jerry!")
        puts("xixi Now enter the flag in the format 'flag{your_path} ':")
        exit(0)
```

指令证据：方向比较在 `0x40157b`–`0x40159f`；四个移动分支读取并比较 `#` 后更新 `x` 或 `y`，大致位于 `0x4015a5`–`0x4016f3`；非法字符打印分支从 `0x4016f5` 开始；`0x401703`–`0x401735` 读取当前位置并比较 `E`；成功分支在 `0x401737`–`0x401754` 打印两条消息并调用 `exit(0)`。成功提示后没有下一次 `scanf`，也没有与 flag 常量进行比较。输入按 `%c` 每次消费一个字符；如果在抵达终点前读到换行，换行会落入非法字符分支。

## 路径求解与静态验证

将每个非墙格视作图节点，四邻接边分别标为 `w/a/s/d`，用 BFS 从 `S` 搜索到 `E`。`analysis/static_analyze.py` 同时统计最短路径数量并逐步模拟所得路径；结果是长度 22，最短路径数为 1，终点字符为 `E`。路线分段如下：

| 输入 | 到达坐标（行,列） | 说明 |
|---|---:|---|
| 起点 | `(0,0)` | `S` |
| `d×6` | `(0,6)` | 沿首行向右 |
| `s×2` | `(2,6)` | 沿通道向下 |
| `a×5` | `(2,1)` | 第二条通道向左 |
| `s×2` | `(4,1)` | 沿左侧通道向下 |
| `d×3` | `(4,4)` | 向右到竖直通道 |
| `s×2` | `(6,4)` | 向下到末行 |
| `a×2` | `(6,2)` | 到达 `E` |

因此路径字符串为 `ddddddssaaaaassdddssaa`。每步都在边界内且目标格不是墙，末步落在 `E`。格式化后得到前述候选 `flag{ddddddssaaaaassdddssaa}`。

## 解密与验证说明、局限

这里没有需要逆向的加密算法：迷宫字符直接以 ASCII 明文存放在 `.data`，程序逻辑只执行移动、墙格过滤和终点判断。`analysis/static_analyze.py` 独立从 PE RVA 映射读取这些字节、按 10 列还原网格、用 BFS 求路，并静态模拟所有移动；这些检查验证了路径与二进制中迷宫及控制流的一致性。

由于不运行/加载 EXE，本报告没有程序运行时交互结果。静态 BFS 与逐步模拟确认唯一最短路径；候选随后由玄机平台前台提交接受，题目步骤显示 1/1。提示文本末尾的空格不是 flag 的一部分。


## 玄机平台提交与验收记录（2026-09-29）

- 题目页：https://xj.edisec.net/challenges/530
- 静态求得候选：flag{ddddddssaaaaassdddssaa}
- 操作：Chrome 前台打开题目页，点击“提交FLAG”，输入候选并点击“提交”。
- 平台反馈：“FLAG 正确，恭喜你完成此挑战”；题目页标记“已完成”，唯一步骤 1/1。
- 候选来源是迷宫唯一最短路与程序提示格式的静态推导；程序自身不执行 flag 比较。
- 验收截图在 computer-use 会话中捕获并展示，没有保存 PNG 到项目目录。