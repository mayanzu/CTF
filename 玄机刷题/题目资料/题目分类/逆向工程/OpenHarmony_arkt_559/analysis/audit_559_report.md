# #559 OpenHarmony arkt：独立候选与 38 项前向复核

## 结论

独立从本地 `modules.abc` 解析得到的候选为：

```text
flag{b80ebf0f0e210ad73664bdd19c16387e}
```

纯 Python 静态复算将候选经题目加密链正向处理后，逐项比较 38 个 `targetCipher` 字符串：38/38 完全相同，重复条目也按原索引保留。未运行 HAP/应用或附件中的可执行文件；未联网或提交平台。

## 附件与数组核验

- 平台 ZIP SHA-256：`81D7F3225DC36345A968A2F498E00AAD570C08B8DCAD89E13405BD3195A4263B`
- HAP SHA-256：`AFF302A750AF02C649ECCC1FB504F348B74F76366B708389CE38971A0B58F3DA`
- `modules.abc` SHA-256：`AA0579A16AF1D76438040F1470C46A007B5C7AE386AFF775C09EB82C0BE6F03F`
- ABC literal-array header reports 21 arrays and index table offset `0x6c`; entry 17 resolves to offset `0x265a`.
- Constructor method listing in `arkt_crypto_audit_methods_20260929.txt` ties `createarraywithbuffer` to literal array `0x265a`, stored as `targetCipher`.
- Array header count is 76 slots. Parsing 38 tag/value pairs yields exactly 38 strings, all STRING tag `0x05`.

## 独立计算

1. Each target token maps from the custom Base64 alphabet `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/` back to the standard Base64 alphabet. The decoded payload is canonical decimal ASCII.
2. The bytecode values `n=75067` and `e=7` factor as `271 × 277`; `phi(n)=74520` and `d=42583`. Each of the 38 RSA preimages is a single byte and re-encrypts with `pow(m,7,75067)` to the corresponding decimal target.
3. The key used is `OHCTF2026`, as the page lifecycle disassembly records `onPageShow` replacing the constructor's `OHCTF2025` default before input checking.
4. The RC4-style KSA uses `j=(j+S[j]+key[j mod keylen]) mod 256`, and the PRGA output combines with plaintext using addition modulo 256. Inversion subtracts the stream byte modulo 256.
5. The candidate replays that transform, RSA exponentiation, decimal ASCII conversion, Base64, and alphabet substitution. `audit_559_output.txt` includes all target and generated tokens side by side under `ITEM[00]` through `ITEM[37]`; every row is `MATCH=True`, and the final count assertion is `all_38_match=True`.

The independent verifier is [audit_559_reproduce.py](audit_559_reproduce.py). It parses the ABC header/index table and the literal array itself, performs the reverse and forward calculations, prints each of the 38 comparisons, and exits nonzero on any mismatch. Run it with:

```powershell
python -B -u "C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\OpenHarmony_arkt_559\analysis\audit_559_reproduce.py"
```

## Saved audit artifacts

- `audit_559_reproduce.py` — independent parser, reverse calculation, and per-token forward comparison.
- `audit_559_output.txt` — successful complete output, including all 38 matches.
- `audit_559_transcript.txt` — commands and output, including two initial Base64-padding errors and the corrected successful reruns.
- `audit_559_report.md` — this review.

The candidate is strongly validated against the local target data. Platform acceptance remains unverified until the authorized submission flow is completed.
