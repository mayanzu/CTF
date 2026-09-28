"""fig-web-19-http-anatomy.png —— "一次 HTTP 请求的解剖图" 原理示意图。

内容与本地靶场实测一致：
  GET /gate?role=guest HTTP/1.1   -> fig-web-03 的真实请求
  响应                            -> fig-web-03 的真实响应头
风格：白底、黑灰主线、字号 12-13、200dpi。
运行：python figures/raw/fig-web-19-http-anatomy.py
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(11.2, 7.4), dpi=200)
ax.set_xlim(0, 100)
ax.set_ylim(0, 100)
ax.axis("off")

# ---------- 标题 ----------
ax.text(50, 96.5, "一次 HTTP 请求的解剖图（以本地靶场 /gate?role=guest 为例）",
        ha="center", va="center", fontsize=15, fontweight="bold")
ax.text(50, 92.6, "上：浏览器 / curl 发出的请求　　下：服务器返回的响应　　→ 右侧为逐段解释",
        ha="center", va="center", fontsize=10.5, color="#444444")

MONO = "Consolas"

def code_box(x, y, w, h, lines, title):
    box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.6,rounding_size=1.2",
                         linewidth=1.1, edgecolor="#333333", facecolor="#f4f4f4")
    ax.add_patch(box)
    ax.text(x + 1.2, y + h - 2.0, title, fontsize=11, fontweight="bold", color="#222222")
    for i, (txt, col) in enumerate(lines):
        fam = MONO if all(ord(ch) < 0x2E80 for ch in txt) else "Microsoft YaHei"
        ax.text(x + 2.0, y + h - 5.6 - i * 3.55, txt, fontsize=11.2,
                fontfamily=fam, color=col, va="center")

def note(x, y, title, body):
    ax.text(x, y, title, fontsize=11, fontweight="bold", color="#000000", va="center")
    ax.text(x, y - 3.4, body, fontsize=10.4, color="#333333", va="top", linespacing=1.45)

def arrow(x1, y1, x2, y2):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>",
                                 mutation_scale=11, linewidth=1.0, color="#666666"))

GREY = "#555555"
DARK = "#111111"

# ---------- 请求块 ----------
code_box(2, 52, 52, 33, [
    ("GET /gate?role=guest HTTP/1.1", DARK),
    ("Host: 127.0.0.1:8765", GREY),
    ("User-Agent: curl/8.21.0", GREY),
    ("Accept: */*", GREY),
    ("（空行）", "#999999"),
    ("（GET 请求通常没有请求体）", "#999999"),
], "① 请求 request：客户端发给服务器")

note(62, 79, "请求行：方法 + 路径 + 查询串 + 协议版本",
     "GET 是方法，/gate 是路径，?role=guest 是查询串。\n查询串里的 role=guest 就是「参数」——它的值\n由发请求的一方填写，服务器无法假设它可信。")
arrow(54.5, 80.6, 56, 80.6)

note(62, 66.5, "请求头 headers：每行「名字: 值」",
     "Host 指出要连哪个站点；User-Agent 自报客户端；\nAccept 说明能接收什么。头不是权限凭证。")
arrow(54.5, 68.4, 56, 68.4)

note(62, 56.5, "空行 + 请求体 body",
     "空行表示请求头结束。GET 的参数放 URL 里，\nPOST 常把参数放请求体里——但「放在 POST 里」\n并不使数据变可信，改 POST 照样能自己构造。")
arrow(54.5, 57.2, 56, 57.2)

# ---------- 响应块 ----------
code_box(2, 12, 52, 33, [
    ("HTTP/1.0 200 OK", DARK),
    ("Server: BaseHTTP/0.6 Python/3.12.10", GREY),
    ("Content-Type: text/plain; charset=utf-8", GREY),
    ("Content-Length: 14", GREY),
    ("（空行）", "#999999"),
    ("Access denied", "#0055aa"),
], "② 响应 response：服务器返回给客户端")

note(62, 39, "状态行：协议 + 状态码 + 短语",
     "200 OK 表示成功；404 找不到；500 服务器出错。\n做题时先看状态码，再看正文。")
arrow(54.5, 40.6, 56, 40.6)

note(62, 28.5, "响应头：正文的「说明书」",
     "Content-Type 说明正文是纯文本还是网页；\nContent-Length 说明正文有多少字节。")
arrow(54.5, 30.2, 56, 30.2)

note(62, 17, "响应体 body：页面内容 / flag 就在这里",
     "换一个参数值 role=admin，这行就变成\nflag{http_query_is_input}（见第 5 章带做）。")
arrow(54.5, 18.6, 56, 18.6)

# ---------- 中间说明 ----------
ax.text(28, 47.2, "中间的空行把「头」和「体」分开——请求、响应都遵守这条规则",
        ha="center", va="center", fontsize=10, color="#8a0000")

plt.tight_layout()
plt.savefig("figures/fig-web-19-http-anatomy.png", dpi=200, facecolor="white")
print("saved figures/fig-web-19-http-anatomy.png")
