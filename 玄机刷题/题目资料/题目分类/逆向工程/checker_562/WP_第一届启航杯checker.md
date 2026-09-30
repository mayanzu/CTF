# WP：第一届启航杯 checker（玄机 ID 562）

## 题目信息

- 平台：玄机（xj.edisec.net）
- 题目：第一届启航杯checker（ID 562）
- 分类 / 难度：REVERSE / 中等
- 附件：`checker.exe`（Windows PE32，i386，42,857 字节）
- 附件来源：`D:\Downloads\checker (5).zip`，于 2026-09-29 15:37 下载。目录内另有更早的同名 checker 下载；六份 ZIP 大小均为 17,498 字节且 SHA256 相同。本题存档保留了最新下载的原始 ZIP。
- 附件 SHA256：`598E457DCDFFCB89F4A1B5CF56133E1D8A194E737B8C25C6C0EA722854426D36`
- 解压后二进制 SHA256：`449D9F4569A0ED70FCB9BC8B96737719B62CFD8AE7C1E99D2864A3999887FDF5`

## 当前结论：未解决

玄机平台对主代理提交的本地 checker 反算值返回“FLAG 不正确”，题目仍显示 0/1。因此本题必须记为未解决；这个附件字符串只是本地程序的接受值，不是已验证的平台 flag。为避免重复误报，当前批次不将本题计入已完成，也不再重复提交或猜测其他字符串。

### 被平台拒绝的本地候选

本地附件按下述算法唯一反算出的候选是：

```text
flag{enp17I4p8TZmAriao2lq5tAArZ2P1wxBUwXU2}
```

该字符串由附件 `.data` 密文逐字节 XOR `0x23` 得到。主代理确认其通过玄机 ID 562 页面前台提交；页面原文为“FLAG 不正确”，题目进度仍为 0/1。当前没有可写入本地的拒绝截图文件，本段记录主代理提供的前台结果，未伪造截图。

### 独立复核结果与冲突边界

收到平台拒绝后，直接从保存的原始 ZIP 使用 Python `zipfile` 再读唯一成员 `checker.exe`，确认与独立提取件逐字节相同；再次解析 PE 节表，将全局比较值 VA `0x404020` 映射到文件偏移 `0x3220`，以 NUL 为终止符得到 43 字节密文，独立 XOR 反算后与前次候选一致。独立检查确认输入没有 NUL、LF 或 CR；输入加 LF 为 44 字节，小于 `fgets(buffer,50,stdin)` 最多读取的 49 字节。

主代理先前要求独立正向验证后，我在收到随后“不要运行未知 EXE”的指示之前，已按附件本身的静态调用路径核对后，对从原始 ZIP 独立解出的 checker.exe 做了一次本地输入验证。进程退出码为 0、无 stderr，stdout 显示 `Correct! You have the flag.`。这一结果仅证实附件 checker 接受该字符串；玄机平台当场拒绝是相反且更直接的平台证据。此后不再运行该二进制。

### 精确的本地校验路径

`_main` 调用 `fgets(buf, 0x32, stdin)`，随后调用 `strcspn(buf, "\n")` 并在该位置写 NUL，再调用 `_check_flag(buf)`。`_check_flag` 先调用 `_fake_check`，然后编码用户输入、与地址 `0x404020` 比较。`_fake_check` 只输出两行提示并睡眠 1 秒，没有改变输入。

从 `_encrypt_flag`（VA `0x401490`）反汇编得到的等价伪代码：

```c
void encrypt_flag(const unsigned char *input, unsigned char *out) {
    size_t n = strlen((const char *)input);
    for (size_t i = 0; i < n; i++)
        out[i] = input[i] ^ 0x23;
    out[n] = '\0';
}

int check_flag(const char *input) {
    unsigned char out[...];
    fake_check();
    encrypt_flag((const unsigned char *)input, out);
    return strcmp((const char *)out, (const char *)0x404020) == 0;
}
```

反算候选并经本地程序接受，仍不能推出平台答案。当前可证明的是“附件里的本地 checker 接受值”和“线上服务接受值”不一致；无法从本 ZIP 判断服务器是否另用动态 `/flag`、是否下载到了与该页面关联但不匹配的附件，或是否有其它题目侧配置。附件入口由主代理确认是在玄机 ID 562 页面前台下载。因为平台拒绝，以上原因仍是待证假设，不能把任何一个写成事实。

## 附件核验和文件布局

1. 从 Downloads 中按最后写入时间核对到最新项为 `checker (5).zip`（17,498 字节，2026-09-29 15:37:48）。为防止仅凭文件名猜测，逐列出各 `checker*.zip` 的创建时间、长度和 SHA256；六份文件的摘要完全相同。
2. 将最新 ZIP 原样复制到 `originals\checker_platform_download_20260929_051349.zip`。复制前后 SHA256 均为 `598E457DCDFFCB89F4A1B5CF56133E1D8A194E737B8C25C6C0EA722854426D36`。
3. 归档清单只有 `checker.exe`。提取后确认文件长 42,857 字节。
4. PE 头显示 `pei-i386` / PE32、ImageBase `0x00400000`。符号表保留了 `checker.c`、`_fake_check`、`_encrypt_flag`、`_check_flag`、`_main` 和全局 `_encrypted_flag` 的符号。因含符号信息，可以直接定位源函数对应汇编。
5. `.data` 节的 VMA 是 `0x00404000`，文件偏移 `0x3200`。符号 `_encrypted_flag` 位于 VA `0x00404020`，故数据文件偏移为 `0x3220`。

## 逐步逆向过程

### 1. 先区分干扰逻辑和核心校验

入口 `_main`（VA `0x40152a`）的调用流程为：

1. 输出输入提示；
2. `fgets(buffer, 0x32, stdin)` 读入最多 49 个字符加终止符；
3. 用 `strcspn(buffer, "\n")` 将换行替换为 NUL；
4. 调用 `_check_flag(buffer)`；
5. 根据返回值打印成功或失败消息。

`_check_flag`（`0x4014f0`）先调用 `_fake_check`，后者只打印 `Performing initial checks...`，睡眠 1,000 毫秒，再打印 `Checks completed.`。它不改变输入、不访问 `/flag`，也不参与真伪比较；这是一段延迟/干扰。

### 2. 还原真实变换

`_encrypt_flag`（`0x401490`）的关键指令含义：

- `[ebp-0x10] = 0x23`：固定 XOR 常数；
- 循环边界由 `strlen(input)` 决定；
- 每轮读取 `input[i]`，执行 `0x23 XOR input[i]`，写入输出 `out[i]`；
- 循环后在 `out[strlen(input)]` 写 NUL。

等价伪代码：

```c
for (i = 0; i < strlen(input); i++)
    out[i] = input[i] ^ 0x23;
out[strlen(input)] = '\0';
```

`_check_flag` 将加密结果与 VA `0x404020` 的 `_encrypted_flag` 调用 `strcmp` 比较，并以相等作为成功条件。因此逆变换也是 XOR 同一个常数：

```text
flag[i] = encrypted_flag[i] XOR 0x23
```

### 3. 从文件中定位并读取密文

数据节十六进制转储中，`0x404020` 处开始的非零 C 字符串为 43 字节：

```text
454f424458464d5312146a17531b77794e62514a424c114f52165762625179117312545b6176547b76115e
```

最后一个字节之后紧跟 NUL。脚本 `solve_checker.py` 按 PE 节表将 VA `0x404020` 映射到文件偏移 `0x3220`，而不是从截图或人工复制的一段数据猜测。

### 4. 逐字节解码并做正向核验

对上述 43 字节执行 `byte XOR 0x23`，输出 `flag{enp17I4p8TZmAriao2lq5tAArZ2P1wxBUwXU2}`。脚本再次对候选逐字节 XOR `0x23`，并验证结果与附件密文字节完全相等（`forward XOR match=True`）；还检查了 `flag{` 前缀及 `}` 后缀。

候选是 43 个 ASCII 字节，无 NUL、无换行。输入加换行总计 44 字节，小于 `fgets` 的 50 字节容量，因此可被主程序完整读入。`strcspn` 会移除输入行末换行，再进入 `_check_flag`。

## 关于“读取 /flag”的题面提示

题面提示让人考虑读取 `/flag`，但随附件提供的 `checker.exe` 中，真实验证流程不是去打开本机 `/flag` 文件，而是将输入 XOR 后与程序内 `.data` 中的 `_encrypted_flag` 比较。仅从该附件无法、也无需访问平台服务器的 `/flag` 文件；本题解依赖附件中已经存在的比较数据。

导入表里有 `FindFirstFileA` / `FindNextFileA`，但它们属于该 MinGW 程序所带的运行时符号；已定位的 `_main`、`_check_flag` 和 `_encrypt_flag` 路径没有文件打开/读入流程。不要把运行时导入项误当成本题真实 flag 读取点。

## 可复现文件

- `originals\checker_platform_download_20260929_051349.zip`：下载附件原样副本。
- `checker.exe`：解压后的 PE。
- `solve_checker.py`：仅用 Python 标准库解析 PE 节表、读取目标 VA 处的 C 字符串、执行 XOR 并正向核验。
- `关键函数反汇编.txt`：`_fake_check`、`_encrypt_flag`、`_check_flag` 和 `_main` 反汇编。
- `data_区段.txt`、`sections.txt`、`symbols_full.txt`：数据、节表与完整符号表。
- `strings_ascii.txt`：ASCII 字符串提取结果。
- `命令与输出记录.txt`：按执行顺序记录本题 PowerShell 输入及终端输出。

## 方法小结

对自带 checker 的逆向题，可以先定位比较函数和比较常量，再逆转算法；不要只被提示里的 `/flag` 或启动时延迟蒙蔽。确认解出的字节能被输入路径完整读取，并对解码结果做正向复算，可避免长度、NUL 截断和换行处理造成的误判。
- `正向复算输出.txt`：脚本完整 stdout，含候选长度、输入容量检查和正向 XOR 结果。
## ���˲���

- `independent_forward_check.py`���� ZIP ֱ��ȡԭʼ��Ա������ӳ�� PE �ڱ���˶���ʷ����ֵ�����Ժ�ѡ�� LF ����һ�α��� checker��������ظ�չʾ��ѡ�ı���
- `����_����\checker.exe`���ɴ浵 ZIP �ڶ��ζ�����ȡ���������
- `����ִ�и������.txt`������ ZIP/PE У��ͱ��ؽ��� stdout/stderr���˳��룻ǰ̨ƽ̨�ܾ�״̬������������¼�ڱ� WP �С�
- `SHA256SUMS.txt`��������ϵ�ժҪ��
- `�����������¼.txt`�����������ű�����������Ľ������ǰ PE ����������·������ʧ�ܵĴ���PowerShell ������ն������


## Fresh static re-derivation from the original ZIP (2026-09-29)

A separate verifier, `independent_rederive_from_original_zip.py`, was created without embedding or reading the earlier candidate. It reads `originals\checker_platform_download_20260929_051349.zip` directly, hashes the archive and its single `checker.exe` member, and confirms that both saved extraction copies are byte-identical to that member. It independently parses the PE32 section table and checks the actual instruction bytes setting the XOR key, XORing each input byte, bounding the loop by `strlen`, passing comparison VA `0x404020` to the comparison routine, and reading input with `fgets(..., 50, ...)` while stripping LF.

The fresh derivation reconstructs the only input accepted by this local PE and verifies a byte-for-byte XOR round trip against the embedded NUL-terminated target. This result reproduces the previously rejected local-only candidate; it is not a new platform candidate and has not been submitted. The attachment proves the exact local predicate only. Because the platform rejection record conflicts with that predicate and this task is offline-only, the platform's expected value remains unresolved. No alternative input is supported by the attachment evidence.

Exact input ZIP reference: `originals\checker_platform_download_20260929_051349.zip` (original download recorded as `D:\Downloads\checker (5).zip`); SHA-256 `598E457DCDFFCB89F4A1B5CF56133E1D8A194E737B8C25C6C0EA722854426D36`. Its sole member `checker.exe` is 42,857 bytes, SHA-256 `449D9F4569A0ED70FCB9BC8B96737719B62CFD8AE7C1E99D2864A3999887FDF5`.

Reproduction command: `python .\independent_rederive_from_original_zip.py`. The complete PowerShell Start-Transcript record is `rederive_562_transcript_20260929.txt`; captured script stdout is `independent_rederive_output.txt`. The script statically reads the binary and does not launch it.
