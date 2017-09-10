"C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\cl" ^
/EHsc ^
/I .\GEmSysC ^
/I .\GEmSysC-OpenSSL ^
/I .\OpenSSL ^
/I .\Test-GEmSysC ^
/I .\Test-GEmSysC-OpenSSL-win32 ^
.\GEmSysC-OpenSSL\cl\cl.c ^
.\GEmSysC-OpenSSL\cl\cl-aes.c ^
.\GEmSysC-OpenSSL\cl\cl-rsa.c ^
.\GEmSysC-OpenSSL\cl\cl-sha256.c ^
.\Test-GEmSysC\main.c ^
.\Test-GEmSysC\test\test-aes-cl.c ^
.\Test-GEmSysC\test\test-aes-openssl.c ^
.\Test-GEmSysC\test\test-aes.c ^
.\Test-GEmSysC\test\test-compat-win32.cpp ^
.\Test-GEmSysC\test\test-rsa-cl.c ^
.\Test-GEmSysC\test\test-rsa-openssl.c ^
.\Test-GEmSysC\test\test-rsa.c ^
.\Test-GEmSysC\test\test-sha256-cl.c ^
.\Test-GEmSysC\test\test-sha256-openssl.c ^
.\Test-GEmSysC\test\test-sha256.c ^
.\Test-GEmSysC\test\test.c ^
/link ^
/LIBPATH:.\OpenSSL\lib-win32 ^
libeay32MD.lib ^
ssleay32MD.lib ^
/out:Test-GEmSysC-OpenSSL-win32.exe