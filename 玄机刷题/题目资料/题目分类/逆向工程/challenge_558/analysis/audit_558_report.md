# #558 独立审计报告

日期：2026-09-29

## 范围

依据请求独立复核题目 #558「第三届黄河流域公安院校网络安全技能挑战赛 R」的现有静态还原和候选。未联网、未执行 `R.exe`、未提交平台。求解器和既有验证资料未改动；按后续请求只澄清 `wp.md` 中一处 key 索引说明措辞，没有改算法结论或解题过程。

## 结论

候选 `flag{8a1c2a73c29b2}` 与静态算法和程序比较目标一致，逐字节验证通过。

独立脚本 `audit_558_independent.py` 不导入原求解器，也不运行附件。它从 WP 中记录的初始 key 和 19 字节目标重新实现 KSA、逐字节状态更新及正反变换。输出确认：

- ZIP 与 R.exe SHA-256 都匹配 `analysis\SHA256SUMS.txt`；ZIP 元数据仅列出 `R.exe`。
- 预处理 key 为 `loverust`，目标长 19 字节。
- 逆算候选十六进制为 `666c61677b386131633261373363323962327d`。
- 候选正向变换重新生成 `18590728f4adc8c3b63f2d39ca34d18ef503b0`，与目标 19 字节逐字节相同。
- 解密和加密两遍的 19 个 keystream mask 全部一致。

独立输出详见 `audit_558_recalculation_output.txt`；同时重新运行现有主求解器和 `third_route_verify_20260929.py`，其完整输出分别保存在 `audit_558_original_solver_output.txt` 与 `audit_558_existing_verify_output.txt`。两者得到同一候选；原逐字节校验器报告 `all_19_byte_masks_and_ciphertext_match=True`。

## WP 与复现步骤审查

现有 `wp.md` 的关键逻辑与实现相互一致：main 先将 `lntfvpus` 按索引 XOR，得到 `loverust`；KSA 再对 `key[i % 8] XOR 0x66` 累加；PRGA 将 8 位截断、交换、查表、半字节对换和两次加一的顺序说明完整。逐字节逆式与正向式互为逆变换。WP 给出目标、19 行计算结果、候选十六进制、正向完整密文及可从项目根目录运行的 Python 命令。附带的 state-table 文档和转录中保存了静态反汇编、状态表行和逐字节 forward check。

WP 中“这里没有隐藏的 `% len`”紧接状态表索引说明，容易被理解为整个算法不做取模；KSA 实际仍通过 `i % 8` 选 key 字节。按复核结果，已将其改为“状态表的 i、j 下标由显式低字节截断限制在 0–255；KSA 选取密钥字节时另按 `i % 8` 索引”。修改仅澄清 key 索引，没有改变算法结论或解题步骤。

## 静态证据与边界

附件 SHA-256 与现有清单吻合，中央目录显示 ZIP 仅有 1 个条目 `R.exe`，186,880 字节。原反汇编全文与寄存器/状态表分析保留在：

- `analysis\third_route_state_table_transcript_20260929.txt`
- `analysis\third_route_state_table_20260929.md`
- `analysis\powershell_transcript_20260929.txt`
- `analysis\independent_static_audit_transcript_20260929.txt`

本次从工作区 CTF 根目录直接调用 `objdump` 检查带中文目录的 exe 路径时，MSYS `objdump` 将路径字符转码错误并报告“文件不存在”。没有执行附件；对汇编语义的交叉检查依据上述既有静态转录和 state-table 文档，再由新脚本独立复算。候选尚无平台接受记录。

## 审计产物

- `analysis\audit_558_independent.py`：独立计算与附件 hash/ZIP 元数据核验
- `analysis\audit_558_recalculation_output.txt`：独立复算完整输出
- `analysis\audit_558_original_solver_output.txt`：既有主求解器复跑输出
- `analysis\audit_558_existing_verify_output.txt`：既有逐字节 verifier 复跑输出
- `audit_558_commands_output.log`：本次命令及输出记录
- `analysis\audit_558_report.md`：本报告

## 复现命令

从 `C:\Users\mzj\Desktop\CTF` 执行：

```powershell
python .\玄机刷题\题目资料\challenge_558\analysis\audit_558_independent.py
python .\玄机刷题\题目资料\challenge_558\analysis\solve_558.py
python .\玄机刷题\题目资料\challenge_558\analysis\third_route_verify_20260929.py
```
