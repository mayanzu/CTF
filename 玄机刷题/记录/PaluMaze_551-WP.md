# 帕鲁迷宫（玄机 ID 551）离线分析记录

> **状态：未解决 / 未通过平台验证。** 本文记录了附件静态分析、迷宫复现、两条最短路线和平台拒绝结果。下文的路线摘要都只是失败实验，不是可用 flag。主线程已要求停止继续提交猜测。

## 1. 题目与附件

- 题目：第二届 Parloo 杯「帕鲁迷宫」，玄机题目 ID 551。
- 附件：`D:\Downloads\game_flag.exe`，大小 6,731,652 字节，下载时间 2026-09-28 20:20:13。
- SHA-256：`319DE70C476CC7C2761A57D88B83A5529D06CFD0A909D0EC48EC9CD588F82556`。
- 主线程前台查看到的题意要求访问全部 5 个出口；附件输出的格式提示为 `flag{md5(最短路径步骤)}`，并给出路径长度提示 `295`。

本代理没有控制浏览器，也没有运行原始 EXE。所有分析仅针对用户下载的附件；原始文件未修改。

## 2. 文件格式与静态提取

用 `objdump -f/-h` 检查，附件是 PE32+ x86-64 可执行文件。文件末尾找到 PyInstaller cookie：

- cookie 偏移：`0x66b72c`
- Python 版本标记：`311`
- Python DLL：`python311.dll`
- PyInstaller 包长度：`6,407,556` 字节
- TOC 偏移/长度：`6,404,140 / 3,328`
- 包内主脚本：条目名 `game`，压缩后 3,927 字节，解压后 7,955 字节；这是 CPython 3.11 marshal 编译代码。

`pyi_extract.py` 按 cookie 和 TOC 解出归档条目到 `题目资料\PaluMaze_551\extracted`，并对每个压缩条目校验解压长度。分析脚本没有执行原始 EXE。

## 3. 从主脚本还原的规则

从主代码对象的常量、变量名和字节码可复核到以下规则：

1. `generate_maze` 默认种子为 `5822171`；主流程以 `32 × 32` 调用。
2. 迷宫先填墙值 `1`，从 `(1,1)` 开始深度优先挖通道。每次以 `[(0,2),(2,0),(0,-2),(-2,0)]` 洗牌后尝试相邻格；走到尚为墙的格时，打通中间格与目标格。
3. 起始玩家格为 `(1,1)`。五个出口坐标是：
   - `(1,30)`
   - `(30,30)`
   - `(30,16)`
   - `(30,1)`
   - `(16,1)`

   建图时出口相邻的有效格被打通，出口格标记为 `2`。
4. 移动键对应的坐标增量：`w=(-1,0)`、`s=(1,0)`、`a=(0,-1)`、`d=(0,1)`。移动有效时 `total_steps` 加一；进入出口时出口坐标加入 `visited_exits`。访问数达到 5 后才输出完成信息。
5. 主脚本明确提示 `Hint:最短路径长度为295`。

主模块的名称表包括 `visited_exits` 和 `total_steps`，但未出现 `hashlib`、路径字符串列表或路径序列化函数；`move` 只接收当前按键并更新位置、出口集合和整数步数。附件只明确了 flag 文案，没有实现 `md5` 的输入构造。因此，仅凭该附件无法确认应该对小写按键串、大小写变体、坐标序列、整数 `295` 或其他文本取 MD5。

## 4. 迷宫复现与最短路搜索

`solve_maze.py` 用 Python 的 `random.seed(5822171)` 复现 DFS 迷宫，按程序坐标定义生成 5 个出口。之后以四邻接 BFS 求起点和出口之间的距离，并用 Held–Karp 位掩码动态规划枚举出口访问顺序，求覆盖五个出口的最短行走路径。脚本将路线回放并打印访问出口序列、总步数和 MD5。

`enumerate_tours.py` 枚举全部 `5! = 120` 个出口顺序。在该脚本的固定 BFS 邻居顺序下得到两条 295 步最优路线：

| 顺序（出口坐标） | 长度 | 小写 WASD 直拼串的 MD5 | 平台结果 |
|---|---:|---|---|
| `(16,1) → (30,1) → (30,30) → (30,16) → (1,30)` | 295 | `755a1e3b44693d063ec0058572392668` | 主线程报告：拒绝 |
| `(16,1) → (30,1) → (30,16) → (30,30) → (1,30)` | 295 | `73826d4b386ef387a8b45de4bf2b40bf` | 主线程报告：拒绝 |

`state_bfs.py` 又直接在 `(位置, 已访问出口位掩码)` 状态空间上搜索。保持相同迷宫、目标长度仍为 295 时，只改变邻居扩展顺序也会得到其他路线串。这进一步说明题面未给出唯一的“最短路径步骤”平局规则；不能把任意等长路线的摘要当成已解 flag。

### 失败路线记录

第一条失败路线（295 个小写按键）：

```text
ddddddssaassaassddssddssaassaawwaassssssddddddwwwwddssssssssddssaaaaaaaassddddssssaawwaassaaswddwwddssddddddwwwwddddssddwwwwwwddwwddssddwwddwwddddssssssssssaawwwwwwaassssaaaassddssddddddsdwaaaaaaaaaaaaaaswdddddddwwaawwddddwwwwddssssssddwwwwwwwwwwwwwwwwaaaaaawwwwwwaawwddddddssssaassddddwwwwwwwwd
```

第二条失败路线（295 个小写按键）：

```text
ddddddssaassaassddssddssaassaawwaassssssddddddwwwwddssssssssddssaaaaaaaassddddssssaawwaassaaswddwwddssddddddwwwwddddssddwwwwwwddwwddssddwwddwwddddssssssssssaawwwwwwaassssaaaassddssaaaaaaaswdddddddddddddsdwaaaaaaawwaawwddddwwwwddssssssddwwwwwwwwwwwwwwwwaaaaaawwwwwwaawwddddddssssaassddddwwwwwwwwd
```

以上路线只能证明在当前复现模型下存在 295 步的可行解，不能证明它们是平台规定的摘要输入。平台拒绝结果由主线程通过前台 UI 报告；本代理没有访问或操作平台。

## 5. 复现文件和命令

完整 PowerShell 命令、原始输出、静态提取条目、路线结果及主线程报告的验证结果见：

`C:\Users\mzj\Desktop\CTF\玄机刷题\记录\PaluMaze_551-终端记录.txt`

主要分析文件：

- `C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\pyi_extract.py`：解析 PyInstaller cookie/TOC 并解压归档。
- `C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\summarize_code.py`：列出主代码对象、函数名、常量和 Unicode 提示。
- `C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\solve_maze.py`：复现迷宫并求一条最短路线。
- `C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\enumerate_tours.py`：枚举出口访问顺序并列出最优路线。
- `C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\state_bfs.py`：对 `(位置, 出口掩码)` 做完整 BFS，观察平局路线。
- `C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\audit_route.py`：核对 Held–Karp 路线的分段长度和拼接一致性。

可复现的核心运行命令：

```powershell
python 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\pyi_extract.py'
python 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\summarize_code.py'
python 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\solve_maze.py'
python 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\enumerate_tours.py'
python 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\state_bfs.py'
```

其中完整终端输出应以终端记录文件为准。

## 6. 结论与后续所需证据

- 复现的迷宫模型给出 295 步最短长度，与附件提示相符。
- 两条 295 步小写 WASD 直拼路线都未通过平台验证。
- 本题**未解决、未通过平台验证**；不应将任一失败摘要写成 flag。
- 附件没有说明 MD5 输入的标准化方式，也没有实现哈希过程。继续求解必须先获得题目对“步骤”的确切序列化约定（例如是否是按键串、坐标列表、步数整数，及大小写/分隔符规则），或其他能定义唯一预期输入的题目材料。


## 主线程平台验证记录

1. 前台提交 `flag{755a1e3b44693d063ec0058572392668}`，平台返回 `FLAG 不正确~`，题目仍为 `0/1`。
2. 前台提交第二条经相同 295 步下界复核的候选 `flag{73826d4b386ef387a8b45de4bf2b40bf}`，平台再次返回 `FLAG 不正确~`，题目仍为 `0/1`。

这两次结果已在玄机题目页通过 Computer Use 核验。由于附件不包含 MD5 输入序列化定义，不继续猜测或重复提交；本题保持**未解决、未通过平台验证**。本轮截图在 Computer Use 界面展示，但没有保存为图片文件。
