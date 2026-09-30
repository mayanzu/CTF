$k1 = [System.Text.Encoding]::UTF8.GetBytes('EzCrypt0ofPython')
$k2 = [System.Text.Encoding]::UTF8.GetBytes('1145140A01919810')
$iv1 = $k1
$iv2 = $k2
$ct = [Convert]::FromBase64String('WegWMtim1YwucYelL2g+DU2x/B/VsQrFz2pNMJy95rE=')
"key_len=$($k1.Length) iv_len=$($iv2.Length) ciphertext_len=$($ct.Length)"
$keys = @(@{Name='EzCrypt0ofPython'; Bytes=$k1}, @{Name='1145140A01919810'; Bytes=$k2})
$ivs = @(@{Name='EzCrypt0ofPython'; Bytes=$iv1}, @{Name='1145140A01919810'; Bytes=$iv2})
foreach ($key in $keys) {
  foreach ($mode in @([System.Security.Cryptography.CipherMode]::CBC, [System.Security.Cryptography.CipherMode]::ECB)) {
    $ivOptions = if ($mode -eq [System.Security.Cryptography.CipherMode]::CBC) { $ivs } else { @(@{Name='(unused)'; Bytes=$iv1}) }
    foreach ($iv in $ivOptions) {
      foreach ($padding in @([System.Security.Cryptography.PaddingMode]::PKCS7, [System.Security.Cryptography.PaddingMode]::None)) {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key.Bytes
        $aes.Mode = $mode
        $aes.Padding = $padding
        if ($mode -eq [System.Security.Cryptography.CipherMode]::CBC) { $aes.IV = $iv.Bytes }
        try {
          $dec = $aes.CreateDecryptor()
          $pt = $dec.TransformFinalBlock($ct, 0, $ct.Length)
          $hex = [BitConverter]::ToString($pt)
          $text = [System.Text.Encoding]::UTF8.GetString($pt)
          if ($padding -eq [System.Security.Cryptography.PaddingMode]::None) {
            $trimmed = [System.Text.Encoding]::UTF8.GetString($pt).TrimEnd([char]0)
            "key=$($key.Name) mode=$mode iv=$($iv.Name) padding=$padding bytes=$hex text=$text trim0=$trimmed"
          } else {
            "key=$($key.Name) mode=$mode iv=$($iv.Name) padding=$padding bytes=$hex text=$text"
          }
        } catch {
          "key=$($key.Name) mode=$mode iv=$($iv.Name) padding=$padding error=$($_.Exception.GetType().Name): $($_.Exception.Message)"
        } finally {
          if ($dec) { $dec.Dispose() }
          $aes.Dispose()
          $dec = $null
        }
      }
    }
  }
}
