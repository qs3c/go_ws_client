# Tongsuo setup (cgo)

This project uses Tongsuo via cgo. The cgo include/library paths are set to:
  third_party/tongsuo

Submodule

Tongsuo is tracked as a git submodule (8.3-stable). Initialize it with:
  git submodule update --init --recursive

Build prerequisites (from Tongsuo README)

- make
- Perl 5 and the Text::Template module
- C compiler
- C library

Build (per platform)

The scripts below follow the README build steps:
- Linux:  ./scripts/build_tongsuo_linux.sh
- macOS:  ./scripts/build_tongsuo_macos.sh
- Windows:
  .\scripts\build_tongsuo_windows.ps1

On Windows, the script will try to locate VsDevCmd.bat and re-run itself inside a
Developer Command Prompt if needed.

Scripts build in a separate directory (third_party/tongsuo-build) and install into
third_party/tongsuo by default to match the cgo paths.

Optional build knobs (env vars)

- TONGSUO_PREFIX: install prefix (default: third_party/tongsuo)
- TONGSUO_BUILD_DIR: build directory (default: third_party/tongsuo-build)
- TONGSUO_CONFIG_OPTS: extra Configure options (e.g. enable-ntls, no-rsa)
- TONGSUO_INSTALL_TARGETS: make install targets (default: install)`n- TONGSUO_TARGET: Windows Configure target (default: VC-WIN64A)

README notes

- Windows build uses: perl Configure enable-ntls; nmake; nmake install (script adds VC-WIN64A by default unless a target is provided)
- You can run tests with: make test
- Install variants: make install_runtime_libs, make install_dev, make install_programs
- Configure options use enable-xxx / no-xxx

Runtime

Windows (PowerShell):
  .\scripts\set_tongsuo_env.ps1

Linux/macOS (bash, must be sourced to affect current shell):
  source ./scripts/set_tongsuo_env.sh

Per-OS runtime helpers:
- Linux:  scripts/set_tongsuo_env_linux.sh
- macOS:  scripts/set_tongsuo_env_macos.sh

Linux: sets LD_LIBRARY_PATH to include third_party/tongsuo or third_party/tongsuo/lib
macOS: sets DYLD_LIBRARY_PATH to include third_party/tongsuo or third_party/tongsuo/lib

Notes
- Windows/amd64 binaries do not work on Linux/macOS or ARM.
- If you do not use the SM2 key exchange features, -lkeyexchange may be omitted.