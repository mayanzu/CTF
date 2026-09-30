# 2025鹏城杯-babyRSA 解题记录

- 平台：玄机；题目 ID：358；类别：Crypto；难度：中等；费用：免费。
- 状态：已提交并由平台验证正确。
- 附件：`babyRSA-附件\task.py`，SHA256：`5208DCEEA3A61D0A100C71CEC66E83C8472F01CE00C053C6F4918C0FF337D2FE`。

## 1. 题目说明

脚本构造 RSA：生成 1024 位素数 p、q，保证 p>q；加密 m 得 c，并给出 d、c 以及高精度小数 leak。题目提示“参数咋这么少呢？”，关键是利用泄漏恢复 p/q，再由 d 直接解密。

附件还把 leak、d、c 的十进制值写在注释中；分析时读取这些已给数据，不需要联网。
## 2. 推导泄漏关系

附件代码计算：

    leak = (3*p*p - 1) / (3*p*q)
        = p/q - 1/(3*p*q)

因此 leak 非常接近有理数 p/q，且略小于它。p、q 是 1024 位素数，所以 2^1023 ≤ q < 2^1024，泄漏公式的误差满足：

    0 < p/q - leak = 1/(3*p*q) < 1/(3*q^2) < 1/(2*q^2)

连分数有理逼近定理说明：若有理数逼近误差小于 1/(2q²)，该分数必是原数的某个连分数收敛分数。附件给出 1024 位有效数字；十进制舍入误差远小于上面的界，因此可用最大分母 `2^1024-1` 做有理重构，恢复既约分数 p/q。两个素数不同且互素，所以分子、分母就是 p、q。
## 3. 具体分析步骤

1. 从玄机题目页确认题目免费，下载附件并记录 SHA256。
2. 查看 `task.py`：脚本公开了 leak、d、c 的十进制注释值；p、q 用 1024 位素数生成。题目并非缺少全部参数，而是希望从 leak 还原因子。
3. 把十进制 leak 作为精确分数输入 `Fraction`，调用 `limit_denominator(2^1024-1)`。有理重构得到的分子、分母即 p、q。
4. 检查 p、q 位数均为 1024、p>q、gcd(p,q)=1；随后算 n=p*q。
5. 已知 RSA 私钥指数 d 和密文 c，直接计算 m=c^d mod n；将整数 m 转成大端字节，得到明文 flag。
6. 在玄机题目页提交明文 flag，平台返回正确提示，题目标为已完成。

以下是复现核心逻辑（省去附件中的长十进制常量，运行时从 `task.py` 注释读取）：

    from fractions import Fraction
    import re
    from pathlib import Path

    s = Path('task.py').read_text()
    leak = re.search(r'#leak = ([0-9.]+)', s).group(1)
    d = int(re.search(r'#d = (\d+)', s).group(1))
    c = int(re.search(r'#c= (\d+)', s).group(1))
    r = Fraction(leak).limit_denominator((1 << 1024) - 1)
    p, q = r.numerator, r.denominator
    n = p * q
    m = pow(c, d, n)
    flag = m.to_bytes((m.bit_length() + 7) // 8, 'big')
## 4. 结果与验证

核心计算输出如下：

    leak decimal digits = 1024
    p bit length = 1024, q bit length = 1024
    p > q = True, gcd(p,q) = 1
    n bit length = 2048
    plaintext hex = 666c61677b746831735f31735f345f747572655f666c34677d
    plaintext bytes = b'flag{th1s_1s_4_ture_fl4g}'
    plaintext ascii = flag{th1s_1s_4_ture_fl4g}

重新按 Decimal 精度 1024 计算泄漏后，结果与附件注释一致；素数位数也符合 1024 位范围。最后在题目页提交该 flag，页面显示“FLAG 正确，恭喜你完成此挑战”，标题显示“已完成”，步骤显示 1/1。

## 5. 易错点与结论

- `Fraction` 必须从十进制字符串构造，保留小数的精确有理表示；若先转成二进制浮点数，会丢失所需精度。
- 最大分母要按题目给出的因子位数设为 `2^1024-1`，不能用小默认值。
- p>q 与 gcd=1 是恢复方向和既约性的校验；n 的位长应为 2048。
- 本题给了 d，恢复因子后无需求 e，也无需破解私钥。
- 附件 SHA256：`5208DCEEA3A61D0A100C71CEC66E83C8472F01CE00C053C6F4918C0FF337D2FE`；flag 仅记录在本地指南，平台已验证。

## 6. 操作记录来源

本题页面可见操作、附件读取、重构代码及完整终端输出均由本轮前台操作完成；PowerShell 命令与输出持续写入 `玄机刷题-终端完整记录.txt`。首次超长粘贴曾使 Markdown 被 PowerShell 当作命令并报错，该过程也在 transcript 中保留；随后用短块重建了本指南。
