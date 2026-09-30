$key = [Convert]::FromHexString('f470bbc031caee5e58b272ea02f3ffe6')
$target = [Convert]::FromHexString('027532640ce1c1b999349f08b1c457df202a5e01b4655cdde3dce131a2e834408b')
$mask = [Convert]::FromHexString('1acf9382d81f8ef9c605ca4d598fd365d9ae3f4cb57c3140fda22c7889497769')
$usedTarget = [byte[]]::new(32)
[Array]::Copy($target, 0, $usedTarget, 0, 16)
[Array]::Copy($target, 17, $usedTarget, 16, 16)
$cipher = [byte[]]::new(32)
for ($i = 0; $i -lt 32; $i++) { $cipher[$i] = $usedTarget[$i] -bxor $mask[$i] }
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
$aes.Padding = [System.Security.Cryptography.PaddingMode]::None
$aes.Key = $key
$decryptor = $aes.CreateDecryptor()
$plain = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
'key       = ' + [Convert]::ToHexString($key).ToLower()
'target    = ' + [Convert]::ToHexString($target).ToLower()
'used      = ' + [Convert]::ToHexString($usedTarget).ToLower()
'mask      = ' + [Convert]::ToHexString($mask).ToLower()
'cipher    = ' + [Convert]::ToHexString($cipher).ToLower()
'plain hex = ' + [Convert]::ToHexString($plain).ToLower()
'plain     = ' + [Text.Encoding]::ASCII.GetString($plain)
