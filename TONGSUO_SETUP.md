# Tongsuo setup (cgo)

This project uses Tongsuo via cgo. You need the Tongsuo headers and libraries installed on each machine.

Recommended portable setup

1) Install/build Tongsuo and note its install prefix.
2) Set environment variables for the build:
   - CGO_CFLAGS:  -I<TOGSUO_PREFIX>/include -DOPENSSL_API_COMPAT=0x10100000L
   - CGO_LDFLAGS: -L<TOGSUO_PREFIX> -lkeyexchange -lcrypto -lssl

If your OS needs a runtime library path:
- Windows: add <TONGSUO_PREFIX> to PATH so the DLLs are found.
- Linux: set LD_LIBRARY_PATH or install to a system lib dir.
- macOS: set DYLD_LIBRARY_PATH or install to a system lib dir.

Example (PowerShell)

  $env:TONGSUO_HOME = "D:\\Tongsuo-8.3-stable"
  $env:CGO_CFLAGS   = "-I$env:TONGSUO_HOME/include -DOPENSSL_API_COMPAT=0x10100000L"
  $env:CGO_LDFLAGS  = "-L$env:TONGSUO_HOME -lkeyexchange -lcrypto -lssl"
  $env:PATH         = "$env:TONGSUO_HOME;$env:PATH"

Notes
- If Tongsuo is installed in a system include/lib path, you can omit CGO_CFLAGS/CGO_LDFLAGS.
- If you do not use the SM2 key exchange features, -lkeyexchange may be omitted.