"""生成 Pwn 讲义的三张原理示意图（与本地实测输出一致，数据来自 fig-pwn-* 实录）：

  fig-pwn-19-memory-layout.png  进程地址空间 + Session 结构在栈上的布局 + read 越界写入
  fig-pwn-20-format-principle.png printf("%s", input) 与 printf(input, secret) 的对比
  fig-pwn-21-pipeline-map.png    Pwn 解题流程与保护机制作用点（第 6 章知识地图）

风格：白底、黑灰主线、字号 12-14、200dpi。
运行：python figures/raw/fig-pwn-diagrams.py（在项目根目录）
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

MONO = "Consolas"
CN = "Microsoft YaHei"
OUT = "figures/"


def canvas(w=11.2, h=7.2):
    fig, ax = plt.subplots(figsize=(w, h), dpi=200)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")
    return fig, ax


def box(ax, x, y, w, h, fc="#f6f6f6", ec="#333333", lw=1.1):
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                                boxstyle="round,pad=0.6,rounding_size=1.1",
                                linewidth=lw, edgecolor=ec, facecolor=fc))


def label(ax, x, y, txt, size=11.5, bold=False, color="#111111", ha="left", va="center", fam=CN):
    ax.text(x, y, txt, fontsize=size, ha=ha, va=va, color=color,
            fontfamily=fam, fontweight=("bold" if bold else "normal"))


def arrow(ax, x1, y1, x2, y2, color="#333333", lw=1.3, style="-|>", rad=0.0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                                 mutation_scale=13, linewidth=lw, color=color,
                                 connectionstyle=f"arc3,rad={rad}"))


def save(fig, name):
    fig.savefig(OUT + name, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("saved", name)


# ===========================================================================
# 图 19：进程地址空间 + 栈帧布局 + 越界写入
# ===========================================================================
fig, ax = canvas(11.4, 7.6)
label(ax, 50, 96.5, "进程的内存长什么样：P1 的 32 字节写到了哪里", size=15, bold=True, ha="center")
label(ax, 50, 92.6, "左：Linux x86-64 进程地址空间（示意）　　右：main 的栈帧里 Session 结构的真实布局（本机实测）",
      size=10.4, color="#444444", ha="center")

# ---- 左侧：地址空间 ----
X0, W = 3.5, 27
zones = [
    (73, 15, "栈 stack", "向下增长\n局部变量、函数指针在这里", "#eef3fa"),
    (56, 15, "堆 heap", "向上增长\nmalloc 申请的内存", "#f6f6f6"),
    (39, 15, ".bss / .data", "全局变量、字符串常量\n（flag 字符串就在这里）", "#f6f6f6"),
    (22, 15, ".text 代码段", "只读、可执行\nwin / normal 的机器码", "#eef7ee"),
]
for y, h, name, desc, fc in zones:
    box(ax, X0, y, W, h, fc=fc)
    label(ax, X0 + 1.5, y + h - 3.6, name, size=12, bold=True)
    label(ax, X0 + 1.5, y + h - 8.2, desc, size=9.6, color="#444444", va="top")
label(ax, X0 + W / 2, 90.5, "高地址 0x7fff...（栈从这里向下长）", size=9.6, color="#666666", ha="center")
label(ax, X0 + W / 2, 18.6, "低地址 0x400000 起（本练习的代码段）", size=9.6, color="#666666", ha="center")

# ---- 中间：栈帧放大 ----
BX, BY, BW, BH = 34, 20, 36, 66
box(ax, BX, BY, BW, BH, fc="#fcfcfc")
label(ax, BX + BW / 2, BY + BH - 4.2, "main 的栈帧（放大）", size=12.5, bold=True, ha="center")
label(ax, BX + BW / 2, BY + BH - 9.0, "struct Session { char name[24]; void (*next)(void); };",
      size=8.6, color="#444444", ha="center", fam=MONO)
label(ax, BX + BW / 2, BY + BH - 14.4, "read(STDIN_FILENO, session.name, 32)", size=10.2,
      color="#a03030", ha="center", fam=MONO)

# name[24]
box(ax, BX + 2.5, BY + 32, 31, 16, fc="#eef3fa")
label(ax, BX + 4, BY + 44.4, "name[24]", size=12, bold=True)
label(ax, BX + 4, BY + 39.8, "偏移 0 .. 23", size=9.8, color="#444444")
label(ax, BX + 4, BY + 35.6, "正常只该写这 24 字节", size=9.8, color="#444444")
# next 指针
box(ax, BX + 2.5, BY + 12, 31, 15, fc="#fdf1f1")
label(ax, BX + 4, BY + 23.4, "next 函数指针（8 字节）", size=12, bold=True)
label(ax, BX + 4, BY + 18.8, "偏移 24 .. 31　值 = normal", size=9.8, color="#444444")
label(ax, BX + 4, BY + 14.6, "session.next() 调用时跳到这里", size=9.8, color="#444444")

# 越界箭头：从 read 处指向 next 框
arrow(ax, BX + BW - 4.0, BY + BH - 16.4, BX + BW - 6.0, BY + 28.6, color="#a03030", lw=1.6)
label(ax, BX + BW / 2, BY + 7.4, "第 25~32 个字节直接盖在 next 上", size=10.4,
      color="#a03030", ha="center")

# 覆写前后对照
LY = 20
box(ax, 72.5, LY, 24.5, 66, fc="#fdfdfd")
label(ax, 84.7, LY + 61.8, "覆写前后", size=12.4, bold=True, ha="center")
label(ax, 74.5, LY + 55.4, "覆写前：", size=10.6, bold=True)
label(ax, 74.5, LY + 51.2, "next = normal", size=10.2, fam=MONO)
label(ax, 74.5, LY + 47.4, "→ 打印 Try again.", size=10.2, color="#444444")
label(ax, 74.5, LY + 41.0, "覆写后：", size=10.6, bold=True)
label(ax, 74.5, LY + 36.8, "next = win 的地址", size=10.2)
label(ax, 74.5, LY + 33.0, "→ 打印 flag", size=10.2, color="#2a6f2a")
label(ax, 74.5, LY + 26.6, "怎么造这 8 字节：", size=10.4, bold=True)
label(ax, 74.5, LY + 22.4, "struct.pack('<Q', win)", size=9.6, fam=MONO)
label(ax, 74.5, LY + 18.2, "win 由 nm 从当前产物读出", size=9.6, color="#444444")
label(ax, 74.5, LY + 12.0, "长度检查：", size=10.4, bold=True)
label(ax, 74.5, LY + 7.8, "len(payload) == 32", size=9.6, fam=MONO)

label(ax, 50, 12.0,
      "read 的第三个参数是 sizeof session = 32，比 name[24] 大 8 字节——这 8 字节就是这道题的全部漏洞。",
      size=10.6, color="#333333", ha="center")

save(fig, "fig-pwn-19-memory-layout.png")


# ===========================================================================
# 图 20：格式串原理对比
# ===========================================================================
fig, ax = canvas(11.4, 7.4)
label(ax, 50, 96.6, "同一句 printf，为什么一种安全、一种泄密：格式串到底由谁控制", size=15, bold=True, ha="center")
label(ax, 50, 92.6, "格式串（format string）是 printf 的“说明书”：它决定要打印什么、以及从哪里取数据",
      size=10.4, color="#444444", ha="center")

# 上：安全版本
box(ax, 3, 60, 94, 28, fc="#f7fbf7", ec="#2a6f2a")
label(ax, 5.5, 84.6, "① 安全写法：printf(\"%s\", input)　—— 格式串是程序写死的常量", size=12.4, bold=True, color="#205a20")
box(ax, 6, 63, 40, 17.5, fc="#ffffff")
label(ax, 8, 77.4, "printf(\"%s\", input);", size=11.2, bold=True, fam=MONO)
label(ax, 8, 72.6, "rdi = \".\\%s\" 的地址（代码段常量）", size=10.0, color="#333333")
label(ax, 8, 68.8, "rsi = input 的地址（栈缓冲区）", size=10.0, color="#333333")
label(ax, 8, 65.4, "→ %s 只能取 rsi：打印输入文本本身", size=10.4, color="#205a20")
label(ax, 52, 77.4, "输入 %s 时输出：", size=10.6, bold=True)
label(ax, 52, 73.0, "%s", size=11.4, fam=MONO)
label(ax, 52, 68.6, "百分号被当成普通字符", size=10.2, color="#444444")
label(ax, 52, 65.2, "（没有格式说明可“执行”）", size=10.2, color="#444444")

# 下：危险版本
box(ax, 3, 24, 94, 30, fc="#fdf6f6", ec="#a03030")
label(ax, 5.5, 50.6, "② 危险写法：printf(input, secret)　—— 格式串来自用户输入", size=12.4, bold=True, color="#8a2020")
box(ax, 6, 27, 40, 19.5, fc="#ffffff")
label(ax, 8, 43.4, "printf(input, secret);", size=11.2, bold=True, fam=MONO)
label(ax, 8, 38.6, "rdi = input 的地址（用户能改！）", size=10.0, color="#8a2020")
label(ax, 8, 34.8, "rsi = secret 的地址（flag 字符串）", size=10.0, color="#8a2020")
label(ax, 8, 30.8, "→ 输入里的 %s 会去 rsi 取地址再读字符串", size=10.4, color="#8a2020")
label(ax, 52, 43.4, "输入 %s 时输出：", size=10.6, bold=True)
label(ax, 52, 39.0, "flag{format_string_leaks}", size=11.0, fam=MONO, color="#8a2020")
label(ax, 52, 34.6, "输入 %p 时输出：", size=10.6, bold=True)
label(ax, 52, 30.6, "0x5dd37a0b8004", size=11.0, fam=MONO, color="#8a2020")
label(ax, 52, 27.2, "%p 把对应位置的字节当指针打印", size=10.0, color="#444444")

label(ax, 3, 19.0, "一句话机制：", size=11.4, bold=True)
label(ax, 15.5, 19.0, "printf 把“格式语言”和“数据”混在同一个参数里；当外部输入进了格式串，输入就不再是数据，而成了指令。",
      size=11.0, color="#333333")
label(ax, 3, 13.0, "修复原则：", size=11.4, bold=True)
label(ax, 15.5, 13.0, "格式串永远是程序里的常量；外部输入只放到参数位置（printf(\"%s\", input) 或 fputs(input, stdout)）。",
      size=11.0, color="#333333")
label(ax, 3, 7.0, "代价：", size=11.4, bold=True)
label(ax, 15.5, 7.0, "读错地址的 %s 会让程序崩溃——所以格式串漏洞的验证必须在本地靶程序或授权的在线实例里做。",
      size=11.0, color="#333333")

save(fig, "fig-pwn-20-format-principle.png")


# ===========================================================================
# 图 21：解题流程与保护机制作用点
# ===========================================================================
fig, ax = canvas(11.4, 7.6)
label(ax, 50, 96.6, "Pwn 题的通用解题流程（附：每种保护机制卡在哪一步）", size=15, bold=True, ha="center")
label(ax, 50, 92.8, "每一步都要求“有证据、可复现”：先看再猜，先基线再破坏", size=10.6, color="#444444", ha="center")

steps = [
    (3.0, 66.0, "1 分诊", "file / readelf\n看架构与保护", "#eef3fa"),
    (27.0, 66.0, "2 读材料", "读源码或反汇编\n找数组、函数指针、调用点", "#eef3fa"),
    (51.0, 66.0, "3 建基线", "用正常输入跑一遍\n记下标准输出", "#eef3fa"),
    (75.0, 66.0, "4 测布局", "offsetof / 布局小程序\n确认字段偏移", "#f7f4ea"),
    (3.0, 39.0, "5 取地址", "nm / readelf\n抄当前产物的 win 地址", "#f7f4ea"),
    (27.0, 39.0, "6 造字节", "struct.pack('<Q', win)\n检查长度与 hex", "#f7f4ea"),
    (51.0, 39.0, "7 送入并观察", "管道或脚本送二进制\n先看现象，再看 flag", "#f0f7f0"),
    (75.0, 39.0, "8 核对答案", "对源码 / 重算 / 平台反馈\n脚本打印 flag 只是第一步", "#f0f7f0"),
]
BW, BH = 22.0, 21.0
for x, y, title, body, fc in steps:
    box(ax, x, y, BW, BH, fc=fc)
    label(ax, x + 1.4, y + BH - 3.6, title, size=11.8, bold=True)
    label(ax, x + 1.4, y + BH - 8.4, body, size=9.4, color="#333333", va="top")
for row in (66.0, 39.0):
    xs = sorted(s[0] for s in steps if s[1] == row)
    for i in range(len(xs) - 1):
        arrow(ax, xs[i] + BW + 0.4, row + BH / 2, xs[i + 1] - 0.4, row + BH / 2, color="#555555", lw=1.2)
arrow(ax, 86.0, 65.2, 86.0, 61.0, color="#888888", lw=1.1)
label(ax, 50.0, 33.5, "（1→4 走完再回到 5→8；每一步都要留下可复查的记录）", size=9.6,
      color="#666666", ha="center")

label(ax, 3.0, 30.0, "保护机制分别卡在哪一步（先问“它阻止的是哪一步”，再谈怎么绕）", size=12.0, bold=True)
rows = [
    ("PIE + ASLR", "卡第 5 步：每次运行地址都变，抄不到固定地址", "#a03030"),
    ("栈保护 Canary", "卡第 7 步：越界写先破坏金丝雀，程序主动退出", "#a03030"),
    ("NX（不可执行栈）", "卡第 7 步：往栈上写机器码也执行不了", "#a03030"),
    ("RELRO / 只读 GOT", "卡“改函数指针表”这类思路，不影响本题的结构体覆盖", "#a03030"),
]
y = 25.0
for name, desc, col in rows:
    label(ax, 4.5, y, "·", size=13, bold=True, color=col)
    label(ax, 6.5, y, name, size=10.6, bold=True)
    label(ax, 31.0, y, desc, size=10.4, color="#333333")
    y -= 5.2
label(ax, 3.0, 4.0, "本册本地题的编译参数 -O0 -fno-stack-protector -no-pie 是故意的教学设置：只留下“越界写入 + 结构体覆盖”这一条线索，其余保护另行讲解。",
      size=10.2, color="#555555")

save(fig, "fig-pwn-21-pipeline-map.png")
print("all done")