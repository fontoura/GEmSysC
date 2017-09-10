"C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\cl" ^
/EHsc ^
/I .\GEmSysC ^
/I .\GEmSysC-WolfCrypt ^
/I .\WolfSSL ^
/I .\Test-GEmSysC ^
/I .\Test-GEmSysC-WolfCrypt-win32 ^
.\WolfSSL\wolfcrypt\src\aes.c ^
.\WolfSSL\wolfcrypt\src\arc4.c ^
.\WolfSSL\wolfcrypt\src\asn.c ^
.\WolfSSL\wolfcrypt\src\des3.c ^
.\WolfSSL\wolfcrypt\src\hash.c ^
.\WolfSSL\wolfcrypt\src\hmac.c ^
.\WolfSSL\wolfcrypt\src\integer.c ^
.\WolfSSL\wolfcrypt\src\md5.c ^
.\WolfSSL\wolfcrypt\src\memory.c ^
.\WolfSSL\wolfcrypt\src\pwdbased.c ^
.\WolfSSL\wolfcrypt\src\random.c ^
.\WolfSSL\wolfcrypt\src\rsa.c ^
.\WolfSSL\wolfcrypt\src\sha.c ^
.\WolfSSL\wolfcrypt\src\sha256.c ^
.\WolfSSL\wolfcrypt\src\sha512.c ^
.\GEmSysC-WolfCrypt\cl\cl.c ^
.\GEmSysC-WolfCrypt\cl\cl-aes.c ^
.\GEmSysC-WolfCrypt\cl\cl-rsa.c ^
.\GEmSysC-WolfCrypt\cl\cl-sha256.c ^
.\Test-GEmSysC\main.c ^
.\Test-GEmSysC\test\test-aes-cl.c ^
.\Test-GEmSysC\test\test-aes-wolfssl.c ^
.\Test-GEmSysC\test\test-aes.c ^
.\Test-GEmSysC\test\test-compat-win32.cpp ^
.\Test-GEmSysC\test\test-rsa-cl.c ^
.\Test-GEmSysC\test\test-rsa-wolfssl.c ^
.\Test-GEmSysC\test\test-rsa.c ^
.\Test-GEmSysC\test\test-sha256-cl.c ^
.\Test-GEmSysC\test\test-sha256-wolfssl.c ^
.\Test-GEmSysC\test\test-sha256.c ^
.\Test-GEmSysC\test\test.c ^
/link ^
Advapi32.lib ^
/out:Test-GEmSysC-WolfCrypt-win32.exe