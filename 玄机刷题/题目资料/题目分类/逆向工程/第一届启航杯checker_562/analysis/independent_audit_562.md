# 启航杯 checker（ID 562）独立静态审计

## 审计边界与附件

只读取并反汇编 PE 文件，未执行 `checker.exe`，未联网或提交平台。附件 SHA-256：`449D9F4569A0ED70FCB9BC8B96737719B62CFD8AE7C1E99D2864A3999887FDF5`。

PE 为 x86 PE32，ImageBase `0x400000`，`.data` 节 RVA `0x4000`、文件偏移 `0x3200`。启动提示和比较消息的静态引用位于 main 附近，可据此独立定位校验路径。

## 静态校验路径

- main 位于 `0x40152a`。显示 `Enter the flag:`，以 `fgets` 从 stdin 读取最多 `0x32` 字节，再用 `strcspn` 删除换行符，随后调用 `0x4014f0`；其返回值决定显示 `Correct!` 或 `Incorrect flag.`。
- `0x4014f0` 调用 `0x401490` 将输入逐字节变换到局部缓冲区，再调用 `strcmp` 比较。其比较目标由 `0x40150d` 明确引用为 VA `0x404020`。
- `0x401490` 的循环对每个输入字节执行 `output[i] = input[i] XOR 0x23`，最后写 NUL。循环长度由 `strlen(input)` 决定。
- `0x403b70` 是 `strcmp` 的导入跳板，跳转至 IAT `0x408208`；`0x403b58` 是 `strlen` 跳板，`0x403bc8` 是 `fgets` 跳板。
- VA `0x404020` 映射 `.data` 的原始文件偏移 `0x3220`。目标 NUL 终止常量长度为 43 字节。

因此候选可直接从常量逐字节 XOR `0x23` 得到，无需运行样本。

## 候选与独立前向复算

```text
flag{enp17I4p8TZmAriao2lq5tAArZ2P1wxBUwXU2}
```

独立脚本读取目标 PE 字节，不加载或执行 PE；它计算 `candidate = target XOR 0x23`，再单独计算 `candidate XOR 0x23` 并与目标 43 字节逐字节比较。输出为 `target match: True`，并通过 `flag{...}` 前后缀检查。候选尚未提交玄机平台验证。

可复现命令（PowerShell，项目根目录）：

```powershell
python .\题目资料\第一届启航杯checker_562\analysis\independent_audit_562_candidate.py
```

脚本输出见 [independent_audit_562_candidate_output.txt](independent_audit_562_candidate_output.txt)。PE 头、节表、导入、字符串、xref 和静态反汇编等输出记录在 [independent_audit_562_output.txt](independent_audit_562_output.txt)；独立反汇编/XREF脚本也保存在本目录，文件名均以 `independent_audit_562_` 开头。
