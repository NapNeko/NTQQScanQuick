
# NTQQScanQuick
快速对NTQQ进行Scan分析Offset

## 特点
- [x] 几乎不受版本约束？
- [x] 速度遥遥领先IDA！
- [x] 暴力的方法就是豪.

## 进度
- [x] Aes Scan
- [x] 业务Tea Scan
- [x] 登录Tea Scan

## 测试
效率极佳

```bash
PS E:\NewDevelop\PeRedirect\out\build\Visual Studio Community 2022 Release - amd64\Debug> ."E:/NewDevelop/PeRedirect/out/build/Visual Studio Community 2022 Release - amd64/Debug/PeRedirect.exe"
=== PE TEA Scanner ===


=== Scanning TEA Crypt Functions ===
Target file: F:\IDA-Wrapper\40768\wrapper.node

[INFO] ImageBase: 0x180000000
[INFO] .rdata range: 0x30E5000 - 0x4692670
[INFO] .text range: 0x1000 - 0x30E4836

[INFO] Found 393510 functions

[]----------[]
[*] Searching for TEA encryption functions (delta = 0x9E3779B9)...
[INFO] Found 15 delta patterns
[debug] Maybe TEA Crypt Inner: 0x180AC30C4
[debug] Maybe TEA Crypt Inner Xref: 0x180AC33D7
[result] TEA Crypt Outer: 0x180AC32FF
[debug] Maybe TEA Crypt Inner: 0x180B0A930
[debug] Maybe TEA Crypt Inner Xref: 0x180B0ACC4
[result] TEA Crypt Outer: 0x180B0ABD0
[debug] Maybe TEA Crypt Inner: 0x180B7EFA1
[debug] Maybe TEA Crypt Inner Xref: 0x180B7F24D
[result] TEA Crypt Outer: 0x180B7F144
[debug] Maybe TEA Crypt Inner: 0x182640E88
[debug] Maybe TEA Crypt Inner Xref: 0x182EEB728
[result] TEA Crypt Outer: 0x182EEB4B0
[debug] Maybe TEA Crypt Inner: 0x1826F1C1C
[debug] Maybe TEA Crypt Inner Xref: 0x1826F1BB8
[result] TEA Crypt Outer: 0x1826F1B4C
[debug] Maybe TEA Crypt Inner: 0x182B5044E
[debug] Maybe TEA Crypt Inner: 0x182BFDE4C
[debug] Maybe TEA Crypt Inner Xref: 0x182BFE105
[result] TEA Crypt Outer: 0x182BFE02D
[debug] Maybe TEA Crypt Inner: 0x182E01494
[debug] Maybe TEA Crypt Inner Xref: 0x182E013EC
[result] TEA Crypt Outer: 0x182E013D0
[debug] Maybe TEA Crypt Inner: 0x182E59884
[]----------[]

[*] Searching for TEA decryption functions (sum = 0xE3779B90)...
[INFO] Found 3 sum patterns
[debug] Maybe TEA Decrypt Inner: 0x180AC318B
[debug] Maybe TEA Decrypt Inner Xref: 0x180AC35A3
[result] TEA Decrypt Outer: 0x180AC3557
[debug] Maybe TEA Decrypt Inner: 0x180B7F069
[debug] Maybe TEA Decrypt Inner Xref: 0x180B7F41E
[result] TEA Decrypt Outer: 0x180B7F3B4
[debug] Maybe TEA Decrypt Inner: 0x182BFDF3E
[debug] Maybe TEA Decrypt Inner Xref: 0x182BFE2D1
[result] TEA Decrypt Outer: 0x182BFE285
[]----------[]

=== Summary ===
TEA Encryption Functions Found: 7
  [1] 0x180AC32FF
  [2] 0x180B0ABD0
  [3] 0x180B7F144
  [4] 0x182EEB4B0
  [5] 0x1826F1B4C
  [6] 0x182BFE02D
  [7] 0x182E013D0

TEA Decryption Functions Found: 3
  [1] 0x180AC3557
  [2] 0x180B7F3B4
  [3] 0x182BFE285

[INFO] Scan completed in 0.798918 seconds
```
