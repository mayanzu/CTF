"""生成 Pwn 讲义第 5 章 mqtt 题（玄机 167）的原理示意图：

  fig-pwn-30-mqtt-toctou.png  消息流 + set_vin 的 TOCTOU 时间窗

图上每个数字/消息都来自真实复现（fig-pwn-28 / fig-pwn-29 的实录）。
风格：白底、黑灰主线、字号 10-14、200dpi。
运行：python figures/raw/fig-pwn-30-diagram.py（在项目根目录）
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

MONO = "Consolas"
CN = "Microsoft YaHei"


def canvas(w=11.4, h=7.6):
    fig, ax = plt.subplots(figsize=(w, h), dpi=200)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")
    return fig, ax


def box(ax, x, y, w, h, fc="#f6f6f6", ec="#333333", lw=1.1):
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                                boxstyle="round,pad=0.6,rounding_size=1.1",
                                linewidth=lw, edgecolor=ec, facecolor=fc))


def label(ax, x, y, txt, size=11.0, bold=False, color="#111111", ha="left", va="center", fam=CN):
    ax.text(x, y, txt, fontsize=size, ha=ha, va=va, color=color,
            fontfamily=fam, fontweight=("bold" if bold else "normal"))


def arrow(ax, x1, y1, x2, y2, color="#333333", lw=1.3, style="-|>", rad=0.0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                                 mutation_scale=13, linewidth=lw, color=color,
                                 connectionstyle=f"arc3,rad={rad}"))


fig, ax = canvas()

label(ax, 50, 96.8, "mqtt 题的攻击链：一次 TOCTOU 竞态如何变成任意命令执行", size=15, bold=True, ha="center")
label(ax, 50, 93.0, "上：双方消息流（攻击者以 MQTT 客户端身份接入，目标连接 tcp://localhost:9999）　　下：set_vin 里“先校验、后使用”的 2 秒时间窗",
      size=10.2, color="#444444", ha="center")

# ---------------- 上半：消息流 ----------------
box(ax, 3, 62, 25, 26, fc="#eef3fa")
label(ax, 4.5, 84.4, "攻击者（我们）", size=12, bold=True)
label(ax, 4.5, 80.0, "以 MQTT 客户端接入同一 broker", size=9.6, color="#333333")
label(ax, 4.5, 76.2, "订阅 diag / diag/resp", size=9.6, color="#333333")
label(ax, 4.5, 72.4, "往 diag 投毒（目标订阅它）", size=9.6, color="#333333")
label(ax, 4.5, 68.2, "本地调试：自己当假 broker", size=9.6, color="#333333")

box(ax, 37, 62, 27, 26, fc="#fdf1f1")
label(ax, 38.5, 84.4, "目标 IVI 客户端（pwn）", size=12, bold=True)
label(ax, 38.5, 80.0, "订阅 diag，回显发到 diag/resp", size=9.6, color="#333333")
label(ax, 38.5, 76.2, "每 10s 上报 {\"vin\":...}（泄漏）", size=9.6, color="#333333")
label(ax, 38.5, 72.4, "set_vin：校验通过 → sleep(2)", size=9.6, color="#333333")
label(ax, 38.5, 68.2, "→ popen(echo -n %s>/mnt/VIN;cat /mnt/VIN)", size=9.0, color="#8a2020")

box(ax, 71, 62, 26, 26, fc="#f7fbf7")
label(ax, 72.5, 84.4, "为什么能读到 flag", size=12, bold=True)
label(ax, 72.5, 80.0, "flag 在 /flag，注入 ;cat /flag; 即可", size=9.6, color="#333333")
label(ax, 72.5, 76.2, "命令回显被目标自己 publish 出来", size=9.6, color="#333333")
label(ax, 72.5, 72.4, "→ 不需要反弹 shell、不需要绕 ASLR", size=9.6, color="#333333")
label(ax, 72.5, 68.2, "PIE/Full RELRO/NX 都不挡这条路", size=9.6, color="#333333")

# 消息箭头
arrow(ax, 36.6, 81.0, 28.4, 81.0, color="#2a6f2a", lw=1.5)
label(ax, 32.5, 83.0, "① 泄漏 VIN", size=9.6, color="#2a6f2a", ha="center")
arrow(ax, 28.4, 70.0, 36.6, 70.0, color="#8a2020", lw=1.5)
label(ax, 32.5, 67.6, "② 投毒命令", size=9.6, color="#8a2020", ha="center")
label(ax, 32.5, 75.8, "token =", size=8.8, color="#444444", ha="center")
label(ax, 32.5, 73.2, "hash(VIN)", size=8.8, color="#444444", ha="center")

label(ax, 50, 58.0, "① diag/resp ← {\"vin\":\"LSVNV2182E2123456\"}　② token=470bc8e0，先发合法 set_vin(arg=1234567890)，再在 2 秒内发 arg=\";cat /flag;id;#\" 覆写全局",
      size=9.6, color="#333333", ha="center")

# ---------------- 下半：TOCTOU 时间轴 ----------------
label(ax, 3, 52.5, "set_vin 的 2 秒时间窗（真实复现的时序）", size=12, bold=True)
AX_Y = 39.0
ax.plot([5, 96], [AX_Y, AX_Y], color="#555555", lw=1.6)

# 抢跑窗口底纹（横跨 t0+2s 之前的那段）
ax.add_patch(FancyBboxPatch((31, AX_Y - 1.2), 40, 6.4,
                            boxstyle="round,pad=0.3,rounding_size=0.8",
                            linewidth=0.9, edgecolor="#a03030", facecolor="#fdf1f1", alpha=0.9))
label(ax, 51, AX_Y + 2.4, "sleep(2) —— 攻击者的抢跑窗口", size=10.6, bold=True, color="#8a2020", ha="center")

# 时间点
for x, name in [(13, "t0 校验"), (31, "t0+0 校验通过"), (71, "t0+2s 使用")]:
    ax.plot([x, x], [AX_Y - 1.4, AX_Y + 1.4], color="#333333", lw=2.0)
    label(ax, x, AX_Y + 8.6, name, size=10.6, bold=True, ha="center")

arrow(ax, 33.5, AX_Y - 4.4, 69.5, AX_Y - 4.4, color="#8a2020", lw=1.3)
label(ax, 51, AX_Y - 7.4, "攻击者在窗口内反复发 unknown_command(arg=\";cat /flag;id;#\")，覆写全局 arg", size=9.8, color="#8a2020", ha="center")

label(ax, 5, 25.5, "· t0：set_vin 校验全局 arg —— 必须纯字母数字、长度 10--63；校验通过后 sleep(2)", size=10.4, color="#333333")
label(ax, 5, 21.0, "· t0+2s：popen 拼接的是“此刻”的全局 arg —— 校验的是旧值，被使用的却是被覆写后的新值", size=10.4, color="#333333")

label(ax, 3, 14.0, "一句话机制：", size=11.6, bold=True)
label(ax, 17.0, 14.0, "校验的结果没有被“跟着值一起”复制下来，校验与使用之间隔着 2 秒且共享全局变量，于是值被换掉。", size=10.8, color="#333333")
label(ax, 3, 8.0, "修复方向：", size=11.6, bold=True)
label(ax, 17.0, 8.0, "校验后立刻复制到局部变量再用；不要用全局字符串拼 shell；用 execve 参数数组替代 popen。", size=10.8, color="#333333")

fig.savefig("figures/fig-pwn-30-mqtt-toctou.png", bbox_inches="tight", facecolor="white")
print("saved figures/fig-pwn-30-mqtt-toctou.png")