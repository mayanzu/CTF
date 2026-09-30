# 第二届 Parloo 杯「帕鲁迷宫」WP（玄机 ID 551）

> **状态：已通过玄机平台验证。** 最终 flag：`flag{634e3323bef7c35e91078eb19cb31210}`。页面回执为“FLAG 正确~, 恭喜你完成此挑战~”，题目状态显示绿色“已完成”，步骤 1/1。

## 1. 题目与附件

- 题目要求帕鲁以最短路径走完全部 5 个出口。
- flag 格式：`flag{md5(最短路径步骤)}`；程序提示最短路径长度为 295。
- 附件：`game_flag.exe`，大小 6,731,652 字节。
- SHA-256：`319DE70C476CC7C2761A57D88B83A5529D2DEA53C1F73DC23926D21ABC86EE019`。
- 本题只对附件做静态分析，没有运行原始 EXE。

## 2. 静态提取与反汇编

附件是 PyInstaller 打包的 PE32+ x86-64 程序。末尾 PyInstaller cookie 标记 Python 3.11，归档中 `game` 条目解压后为 7,955 字节的 marshal 代码对象。分析要点：

1. 解析末尾 88 字节 cookie（magic `4d45490c0b0a0b0e`）、包长度、TOC 偏移和长度。
2. 读取 TOC 的 `game` 项，按标记进行 zlib 解压。
3. 为 marshal 数据加上 Python 3.11 magic `a7 0d 0d 0a` 和 12 字节 pyc 头，再用 `pydisasm -F classic` 反汇编。

> 注意：不能把 Python 3.11 marshal 数据直接交给 CPython 3.12 的 `marshal.loads`/`dis` 当作同版本字节码解释。先前的 3.12 交叉解读有 opcode 偏移误判；最终依据是 `pydisasm` 按 CPython 3.11、magic 3495 输出的 listing。

## 3. 从字节码复原游戏逻辑

### 3.1 迷宫生成

- 主流程调用 `generate_maze(32, 32)`；函数默认 seed 为 `5822171`，并实际调用 `random.seed(seed)`。
- 生成 32×32 网格，墙值为 `1`；从 `(1,1)` 递归深度优先挖通道。每次将 `[(0,2),(2,0),(0,-2),(-2,0)]` 洗牌，遇到尚为墙值 `1` 的目标格时，把中间格和目标格改为通路值 `0`。
- 玩家起点格是 `(1,1)`，标记值 `3`。
- 五个出口按程序数组顺序生成（坐标按行、列，也就是 `(x,y)`）：

  1. `(1,30)`
  2. `(30,30)`
  3. `(30,16)`
  4. `(30,1)`
  5. `(16,1)`

- 每个出口四邻域中仍在网格范围内的格子被打开为 `0`，出口自身标记为 `2`。

### 3.2 移动与胜利判定

`get_player_pos()` 扫描网格中值为 `3` 的格子作为当前位置。`move()` 的按键分支顺序及坐标变化如下：

| 分支顺序 | 按键 | 坐标变化 |
|---:|:---:|:---|
| 1 | `w` | `x -= 1` |
| 2 | `s` | `x += 1` |
| 3 | `a` | `y -= 1` |
| 4 | `d` | `y += 1` |

下一格只要不等于墙值 `1` 就可进入。离开旧位置时旧格改为 `0`；若进入值为 `2` 的出口，就把坐标加进 `visited_exits` 并把出口改成 `4`；随后新位置标记为 `3`。每次有效移动步数加一，访问出口数量等于 5 时游戏报告完成。

### 3.3 为什么使用 `wsad` 作为平局顺序

多个最短移动串存在时，BFS 需要固定邻居展开顺序才能给出可重复的一条路径。这里按 `move()` 的 `if/elif` 分支顺序展开 `w,s,a,d`，因此得到 `wsad`。这是复现本题通过路线所用的确定性 tie-break。题目图本身共有 512 条 295 步最短移动串；任取一条不保证 MD5 与平台预设值相同。

## 4. 求解步骤

1. 用 seed `5822171` 精确重建迷宫，并按值 `1` 判定墙、值 `2` 判定出口。
2. 在状态 `(当前位置, 已访问出口位掩码)` 上做 BFS。每一步枚举顺序固定为 `w,s,a,d`，第一次出队到达完整掩码即得到本规则下的第一条最短路径。
3. 得到路线长度 `295`。用实际 `move()` 状态转换逐字符复放：每个新位置不为墙，每次进入出口时记录坐标，最终访问五个出口。
4. 将 295 个小写按键字符直接拼接，不加空格、逗号、换行或分隔符；对 ASCII 字节计算 MD5。

复现脚本：[verify_accepted_route.py](../题目资料/PaluMaze_551/verify_accepted_route.py)

程序输出记录：[verify_accepted_route.txt](../题目资料/PaluMaze_551/verify_accepted_route.txt)

## 5. 完整最短路线、出口复放与摘要

以下是完整 295 字符的小写方向串；计算 MD5 时按这一行连续内容，不包含代码块换行：

```text
ddddddssaassaassddssddssaassaawwaassssssddddddwwwwddssssssssddssaaaaaaaassddddssssaawwaassasawddwwddssddddddwwwwddddssddwwwwwwddwwddssddwwddwwddddssssssssssaawwwwwwaassssaaaassddssaaaaaasawdddddddddddddsdwaaaaaaawwaawwddddwwwwddssssssddwwwwwwwwwwwwwwwwaaaaaawwwwwwaawwddddddssssaassddddwwwwwwwwd
```

逐步复放得到：

| 步数 | 进入的出口 | 出口数组下标（从 0 开始） |
|---:|:---:|---:|
| 39 | `(16,1)` | 4 |
| 93 | `(30,1)` | 3 |
| 188 | `(30,16)` | 2 |
| 204 | `(30,30)` | 1 |
| 295 | `(1,30)` | 0 |

- 最终位置：`(1,30)`
- 访问出口数：`5/5`
- 步数：`295`
- MD5 输入：完整的小写 WASD 路线 ASCII 字节串
- MD5：`634e3323bef7c35e91078eb19cb31210`
- 最终 flag：`flag{634e3323bef7c35e91078eb19cb31210}`

## 6. 先前被平台拒绝的候选

这些候选均曾由主线程在玄机题页提交，并收到不正确反馈；它们是排错记录，不是最终答案：

| 候选 flag | 候选来源 | 平台结果 |
|---|---|---|
| `flag{755a1e3b44693d063ec0058572392668}` | Held–Karp 出口访问顺序路线；一种 295 步路线 | 拒绝 |
| `flag{73826d4b386ef387a8b45de4bf2b40bf}` | 状态 BFS，方向展开 `w,a,s,d` 的第一条 295 步路线 | 拒绝 |
| `flag{49182f81e6a13cf5eaa496d51fea6406}` | 对十进制步数文本 `295` 计算 MD5 | 拒绝 |
| `flag{66cb1d0b30b836207f93ca2705f22dcd}` | 状态 BFS，方向展开 `d,s,a,w` 的第一条 295 步路线 | 拒绝 |

排错后保留地图、起点和出口规则，改用与附件 `move()` 分支一致的 `wsad` 平局顺序。新路线经平台验证成功。

## 7. 平台验证回执

主线程在玄机页面提交：

```text
flag{634e3323bef7c35e91078eb19cb31210}
```

平台原文回执：**“FLAG 正确~, 恭喜你完成此挑战~”**；题目页显示绿色“已完成”，步骤为 `1/1`。回执截图在 Computer Use 交互工具中显示，没有保存为本地图片。

## 8. 分析文件与终端记录

- PyInstaller 静态提取、3.11 反汇编和过程记录：见 [PaluMaze_551-终端记录.txt](PaluMaze_551-终端记录.txt)、[PaluMaze_551-fresh-static.txt](PaluMaze_551-fresh-static.txt) 与 [pydisasm_focus.txt](../题目资料/新题批次/PaluMaze_551/pydisasm_focus.txt)。
- 可复核命令：`pydisasm -F classic -m generate_maze -m move 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\新题批次\PaluMaze_551\game_311.pyc'`；最终复放命令：`py -3.12 -B 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\verify_accepted_route.py'`。
- 最终路径复放脚本和输出：见 [verify_accepted_route.py](../题目资料/PaluMaze_551/verify_accepted_route.py) 和 [verify_accepted_route.txt](../题目资料/PaluMaze_551/verify_accepted_route.txt)。
- 最终平台回执和本次复算命令已追加在 `PaluMaze_551-终端记录.txt` 末尾。

