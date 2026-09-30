# Digital Key UWB（玄机 #520）完整 WP

## 题目与结论

- 题目：第二届 CCF 智能汽车大赛 - Digital Key UWB
- 题型：车载日志取证 / ECDSA / SM4
- 附件：`digital_key_trace.sqlite`
- 本地复现结果：`flag{digital_key_uwb_nonce_reuse}`
- 证据状态：基于玄机平台真实 SQLite 完成签名恢复、公钥匹配、两条 ECDSA 验签、SM4-CBC 解密、PKCS#7 检查与原密文重加密比对；flag 已在玄机前台提交，平台明确接受。

真实附件 SHA-256：

```text
74BA2CE83C3B7DB4B237FC747B67D4F57492172F42B02B03BDD61E19A1FD6EF3
```

## 一、识别题目给出的攻击面

题目描述指出：车辆数字钥匙通过 BLE 唤醒、UWB 测距，并怀疑认证签名期间随机数发生复用。SQLite 的 `meta.analyst_note` 也明确写明：

```text
Two successful auth signatures share the same nonce_tag. In ECDSA this is fatal.
```

核心逻辑是：同一 ECDSA 私钥对不同消息签名时，如果重用相同随机数 `k`，签名的 `r` 会相同。两条签名提供的消息摘要 `z`、签名值 `s` 与共同的 `r` 可以反推出 `k` 和私钥 `d`。题目随后把 `d` 用作密钥派生材料，从 SM4-CBC 保护的车辆记录取出 flag。

## 二、只读检查附件与 SQLite 结构

使用 PowerShell 计算附件哈希，并通过 Python `sqlite3` 只读打开数据库：

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\新题批次\DigitalKey_UWB_520\extracted\digital_key_trace.sqlite'
@'
import sqlite3
from pathlib import Path
p = Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\新题批次\DigitalKey_UWB_520\extracted\digital_key_trace.sqlite')
con = sqlite3.connect(p.as_uri() + '?mode=ro', uri=True)
for row in con.execute("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"):
    print(row[0], row[1])
con.close()
'@ | py -3.12 -
```

表结构重点如下：

```text
auth_signatures(ts, session_id, curve, hash_alg, nonce_tag,
                signed_json, digest_hex, r_hex, s_hex)
meta(key PRIMARY KEY, value)
protected_vehicle_blob(id PRIMARY KEY, alg, key_hint, iv_hex, ciphertext_b64)
ble_advertisements(ts, session_id, phone_id, rssi, adv_nonce, note)
uwb_ranging(ts, session_id, distance_cm, status, note)
```

`meta` 给出 VIN `LFPH0DK202600004`、曲线 `secp256r1`、公钥坐标以及重用 nonce 提示。日志中 session `DK-2026-0729-0007` 与 `DK-2026-0729-0019` 分别对应可信手机的正常 BLE 广播，并且 UWB 状态为 `ok`、距离为 118 cm 和 126 cm。另一个 `DK-2026-0729-0011` 会话标记为 `unknown-relay`，RSSI 为 -88，测距 4890 cm，状态 `reject`；它是被拒绝的中继噪声，不参与这两条成功签名的计算。

## 三、定位重复 ECDSA nonce

查询 `auth_signatures`：

```sql
SELECT ts, session_id, curve, hash_alg, nonce_tag,
       digest_hex, r_hex, s_hex
FROM auth_signatures
ORDER BY ts;
```

附件内实际的两条签名为：

| 字段 | 会话 0007 | 会话 0019 |
|---|---|---|
| 曲线 | `secp256r1` | `secp256r1` |
| hash | `sha256` | `sha256` |
| `nonce_tag` | `rng-slot-07` | `rng-slot-07` |
| `digest_hex` (`z`) | `d11ef13079938077b29ad9ce9f8c8a6963bb75a5aba1f738a228c7a7dc48f2e7` | `ebb1a7e2ce5351ca8bc71464cce8679034d4b22e86c65e5d507d20b75c6c6ac8` |
| `r_hex` | `67d6db4e0744fe60746c510d6938e64f4a893e64e06b90c2030d1b981ec17d5e` | 与左侧完全相同 |
| `s_hex` (`s`) | `610a011f7503af143a99eef6a90668cd2572872ae6c5644b9d7edda3cb3d989e` | `d0b34225e983269a67d787ee754c3ecf1f79c62af4e5ee3c1b971584c131d3b1` |

先验证 `digest_hex` 的来源：分别对数据库内原始 `signed_json` 字符串按 UTF-8 编码计算 SHA-256，两个摘要均与对应 `digest_hex` 相同。故后续计算使用的是原始签名消息摘要，没有从别处抄入或重新拼装消息。

两条记录的 `nonce_tag` 相同、`r` 完全相同而 `z` 不同，符合 ECDSA 重用 `k` 的特征。`r` 相同在同曲线同密钥情况下强烈指向复用同一个 nonce；继续用实际数值求解并验签作确定性验证。

## 四、用两条签名恢复 `k` 和私钥 `d`

ECDSA 签名方程为：

```text
s = k^(-1) * (z + r*d) mod n
```

对两条签名分别写出：

```text
s1 = k^(-1) * (z1 + r*d) mod n
s2 = k^(-1) * (z2 + r*d) mod n
```

两式相减，消去共同项 `r*d`，得到：

```text
k = (z1 - z2) * inverse(s1 - s2, n) mod n
```

代回任意一条签名，求 `d`：

```text
d = (s1*k - z1) * inverse(r, n) mod n
```

secp256r1 的阶 `n`：

```text
FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
```

实际求得：

```text
k = 59fa85c87e39d4fb3078bd32df349af00e88542cf6548625a3c9c5a506f80a11
d = a71e2c5a98b4214e76f209a1d65e9f34b80d22e4028e624f8be2bfa223934f19
```

复核不是只看公式结果：

1. 对两个数据库内 `signed_json` 的 SHA-256 分别重算，均等于原记录 `digest_hex`。
2. 检查两个签名的标准 ECDSA 公钥验证，均通过。
3. 将 `d` 乘以 secp256r1 标准基点 `G`，得到的公钥坐标和 `meta.public_key_x/public_key_y` 完全一致。
4. 直接检查两条签名方程 `(s_i*k - z_i - r*d) mod n == 0`，均成立。

独立验证器输出：

```text
digest_matches_signed_json[DK-2026-0729-0007]=True
digest_matches_signed_json[DK-2026-0729-0019]=True
nonce_tag=rng-slot-07 shared_r=True
derived_public_key_matches_meta=True
ecdsa_standard_verify[1]=True
ecdsa_standard_verify[2]=True
```

## 五、从私钥派生 SM4 key

题目 `key_hint` 给出精确规则：

```text
sha256(recovered_ecdsa_private_key_32bytes_big_endian)[:16]
```

注意 `d` 必须转为固定 32 字节的大端字节串，而不是对十六进制字符串求哈希：

```python
d32 = d.to_bytes(32, "big")
sm4_key = hashlib.sha256(d32).digest()[:16]
```

计算结果：

```text
sm4_key = e038de51cc70112dc55ed0d2bd01cd42
```

## 六、解密受保护车辆记录

数据库中 `protected_vehicle_blob` 记录为：

```text
alg = SM4-CBC-PKCS7
iv  = 20260729000102030405060708090a0b
ciphertext_b64 = VpQQ28WTcnOzLz4oZbJ2K+n45+lXynIcBOmIH61oAIbY3RkimUPcp7gtwXl6yLnhZWSBswbDYrdBRK5pPyc3tXEr204LX7dHx9YzRmw0QkZBky9jultrztbZNUeYBEW4ZJhX1ze+3eqQbTfLmOt6kHGGeY7IM6ccxFRJ2fhKkpY=
```

Base64 密文解码长度为 128 字节，是 16 字节分组的整数倍。使用 OpenSSL 3 的 SM4-CBC 解密时先用 `-nopad` 得到完整 padded 明文，再手动验证 PKCS#7：最后一个字节是 `0x0b`，末尾 11 个字节均为 `0x0b`，填充合法。去掉填充后按 UTF-8 解码并解析 JSON：

```json
{"vehicle":"LFPH0DK202600004","permission":"digital_key_forensics_result","flag":"flag{digital_key_uwb_nonce_reuse}"}
```

其中 VIN 与 `meta.vehicle_vin` 一致，车辆权限字段也符合题意，JSON 有效。

## 七、加密闭环与最终 flag

为排除“错误 key 恰好解出可读文本”的可能，将上一步得到的无填充 JSON 按 SM4-CBC-PKCS7 重新加密，使用相同 key 和 IV。重加密结果逐字节等于 SQLite 中原始 128 字节密文：

```text
openssl_reencrypt_matches_original=True
plaintext_sha256=2637a51eb56987deae5ad907ac9f50c6ad29b73c009121943b392adcec8be837
```

最终 flag：

```text
flag{digital_key_uwb_nonce_reuse}
```

## 八、可重复执行的命令与记录

求解器从指定 SQLite 或平台 ZIP 直接读取数据：

```powershell
python -B C:\Users\mzj\Desktop\CTF\labs\platform\solve_520_digital_key_uwb.py C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\新题批次\DigitalKey_UWB_520\extracted\digital_key_trace.sqlite
```

独立闭环验证器另外检查原消息摘要、secp256r1 公钥、标准 ECDSA 验签、SM4 重加密比对：

```powershell
python -B C:\Users\mzj\Desktop\CTF\labs\platform\verify_520_digital_key_uwb.py C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\新题批次\DigitalKey_UWB_520\extracted\digital_key_trace.sqlite
```

两条命令的完整输入、退出码和输出均记录在：

```text
C:\Users\mzj\Desktop\CTF\玄机刷题\记录\代理-520-附件普查及公式验证.txt
```

辅助源码：

- `C:\Users\mzj\Desktop\CTF\labs\platform\solve_520_digital_key_uwb.py`
- `C:\Users\mzj\Desktop\CTF\labs\platform\verify_520_digital_key_uwb.py`

## 玄机平台提交验证

- 题目页：https://xj.edisec.net/challenges/520。
- 提交内容：flag{digital_key_uwb_nonce_reuse}。
- 页面回执：“FLAG 正确~, 恭喜你完成此挑战~”；显示绿色“已完成”，步骤 #1 为 1/1，完成进度由 27% 变为 33%。
- Computer Use 前台截图在当时交互输出中展示，没有保存为本地图片。

## 外部线索说明

公开第三方 WP 曾提供了 nonce 重用公式和相同的签名标量，可作为线索；本 WP 的最终结论来自玄机实际下载的 SQLite 数据，并经公钥、验签和密文重加密独立验证。前期曾把该公开文章后段 TSP 题的密文误配给 UWB 参数，那个失败实验已经在终端日志中保留并明确更正，不参与本题结论。平台已接受该 flag；精确回执与步骤状态见上一节。
