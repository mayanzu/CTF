# CTF 零基础自学资料

本资料按题目引入和讲解 Web、Crypto、Reverse、Pwn、Misc 五个方向，面向学过 Python/C 和命令行、但刚接触 CTF 的学生。题目正文之后有逐题带做记录：每题包括第一次尝试、操作步骤、观察结果、答案核对、引申知识和变式练习。已验证真题给出完整 flag；没有得到平台正确反馈的题明确写出未完成环节。

## 文件结构

- `handout-web.tex` / `handout-crypto.tex` / `handout-reverse.tex` / `handout-pwn.tex` / `handout-misc.tex`：五本方向讲义，编译后生成同名的 `handout-*.pdf`。
- `handout-common.tex`：五本共享的导言区与排版宏，单本讲义不得修改。
- `STYLE-SPEC.md`：五本讲义的重构规范（统一结构、题面卡格式、截图流水线、验收指标）。
- `figures/`：讲义插图；`figures/raw/` 保存每张终端截图对应的实录文本与演示脚本。
- `tools/`：终端实录与渲染工具（`termcap.py`、`term2png.py`）。
- `labs/`：离线题目的源码、数据、复现脚本和玄机附件副本。

`labs/platform/attachments/` 当前保存题目 296、557、573、581、583、586、587、589、591 的附件 ZIP。583 的 `challenge.png` 已解压为独立图片并嵌入讲义；573 的 `trigger.png` 和 `trigger-detail.png` 由本地脚本生成，分别展示完整输入和左上触发区域放大图。591 附件的 CSV/JSON 解包副本位于同目录的 `591-poisoned-samples/` 子目录。平台页面截图没有伪造；文中的图是题目原始附件、真实执行的终端实录截图或本地脚本输出，每张终端截图在 `figures/raw/` 留有同名实录文本，可逐行核对。

## 玄机题目的离线范围

本资料引用了 10 道玄机题。9 道提供的附件 ZIP 已收进 `labs/platform/attachments/`；题目 570 的页面只提供在线环境启动，没有“下载附件”，所以本地包不含它的题目服务端文件。请按下表安排练习：

| 题号 | 本地材料 | 断网时能做到什么 |
| --- | --- | --- |
| 557、586、587、581、589、591 | 原始附件 ZIP 和对应复现脚本 | 解出并打印完整 flag；命令见上文 |
| 573 | 原始附件 ZIP、触发图恢复脚本和两张本地示意图 | 复算触发向量并生成输入图；取得服务端 flag 仍需题目在线环境 |
| 583 | 原始附件 ZIP、解出的 `challenge.png` | 可练习 PNG 文件尾部与追加 ZIP 的识别；ZipCrypto 口令和最终 flag 尚未恢复 |
| 296 | 原始附件 ZIP、远程交互求解脚本 | 可检查附件；拿到当前实例的 HOST/PORT 后才能运行脚本并读取服务端 flag |
| 570 | 无可下载附件 | 只能在玄机启动在线环境后练习；`labs/web/app.py` 是独立的本地 Web 入门题，不是该平台题目的副本 |

因此，“资料包可离线打开”不等于“10 道玄机题都能断网完整解出”。如果上课网络不可用，可直接使用上表标为可打印 flag 的 6 道题和 `labs/` 中的本地练习；573、583、296、570 的限制已在带做记录中注明。

平台题解脚本默认读取本资料中的附件，学生无需先从个人下载目录找文件：

```sh
python3 labs/platform/solve_five_grid.py
python3 labs/platform/solve_receipt.py
python3 labs/platform/solve_qgd.py
python3 labs/platform/solve_581_network_forensics.py
python3 labs/platform/solve_589_gate_ticket.py
python3 labs/platform/solve_591_poisoned_samples.py
```

程序也接受 ZIP 路径参数，便于替换附件后复算。CIFAR-10 脚本需要显式给 ZIP 和输出图片：

```sh
python3 labs/platform/solve_cifar_trigger.py \
  labs/platform/attachments/573-cifar10.zip trigger.png
```

`solve_pwn_ezpwn.py` 需要题目当前实例的 HOST/PORT；启动实例后从对应题目页面读取，不可使用过期地址：

```sh
python3 labs/platform/solve_pwn_ezpwn.py HOST PORT
```

## 编译讲义

对每一本分别连跑两次 XeLaTeX，以更新目录和引用（下面以 Web 分册为例）：

```text
xelatex -interaction=nonstopmode handout-web.tex
xelatex -interaction=nonstopmode handout-web.tex
```

五本文件名依次为 `handout-web.tex`、`handout-crypto.tex`、`handout-reverse.tex`、`handout-pwn.tex`、`handout-misc.tex`。Windows 需安装 TeX Live 或 MiKTeX 和 `ctex` 宏包；WSL/Ubuntu 可安装 TeX Live。讲义用朴素黑白排版，插图只使用本地文件，不需网络资源。

## 离线练习环境

Windows 学生可在 WSL/Ubuntu 或 Linux 虚拟机完成 Linux ELF/Pwn/Reverse 练习。Web、Crypto 和基础 Misc 练习需要 Python 3；Pwn 练习需要 x86-64 GCC。CIFAR-10 图片恢复脚本需要 NumPy 和 Pillow；581 流量复现脚本需要 Pillow。可用以下命令安装平台复现脚本的 Python 依赖：

```sh
python3 -m pip install -r requirements.txt
```

先生成课程练习数据并编译程序：

```sh
python3 labs/crypto/make_challenges.py
python3 labs/misc/make_challenges.py
gcc -O0 -o labs/reverse/check1 labs/reverse/check1.c
gcc -O0 -fno-stack-protector -no-pie -o labs/pwn/overflow labs/pwn/overflow.c
gcc -O0 -o labs/pwn/format labs/pwn/format.c
```

`overflow.c` 的越界写入是本地教学题特意设置的行为，GCC 可能给出警告。Web 靶场在本机回环地址启动：

```sh
python3 labs/web/app.py
```

浏览器访问 `http://127.0.0.1:8765/`。练习结束后在服务端终端按 `Ctrl+C`。

## 玄机真题状态

- 586 五格电文、587 联号回执、557 qgd、581 外泄流量取证、296 pwn-ezpwn、589 闸机票根、591 Poisoned Samples：已在平台提交并得到正确反馈。589 与 591 的本地附件解法可直接运行。
- 573 CIFAR-10：附件算法恢复出唯一触发向量并可生成输入图片；当时的在线服务没有返回可用响应，因此没有已验证 flag。
- 583 像素囚笼：已确认 PNG 尾部追加了加密 ZIP，但尚未得到经过验证的解密口令或 flag。
- 570 SU_photogallery：平台实例此前无有效响应，尚无本实例确认的利用过程或 flag。

已确认的真题答案在带做记录中给出。在线靶场需要仍有效的实例；该资料不会保存账号密码。所有操作仅用于对应平台授权题目和本地练习。

## 玄机平台刷题归档
刷题指南、逐题记录、附件和分析材料已集中到 玄机刷题/。整理后的目录说明见 玄机刷题/README.md。
