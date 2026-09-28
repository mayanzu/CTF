# 第2章 第1节配套：Base64 与十六进制是同一份字节的两种显示
import base64

data = b'flag{hex}'
h = data.hex()
b64 = base64.b64encode(data).decode()

print('原始字节        :', data, ' 字节数', len(data))
print('十六进制显示    :', h, ' 字符数', len(h), ' (比值 2 倍)')
print('Base64 显示     :', b64, ' 字符数', len(b64), ' (比值约 1.33 倍)')

print()
print('识别规律：hex 只出现 0-9a-f');
print('          Base64 会出现大写、小写、数字和 + /，末尾常带 =');

print()
print('两者都能无损还原原始字节：')
print('bytes.fromhex(hex)       ->', bytes.fromhex(h), ' 一致:', bytes.fromhex(h) == data)
print('base64.b64decode(base64) ->', base64.b64decode(b64), ' 一致:', base64.b64decode(b64) == data)