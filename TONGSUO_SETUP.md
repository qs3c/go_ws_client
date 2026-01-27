# Tongsuo setup (cgo)

This project uses Tongsuo via cgo. The cgo include/library paths are set to:
  third_party/tongsuo

Submodule

Tongsuo is tracked as a git submodule on the 8.3-stable branch. Initialize it with:
  git submodule update --init --recursive

Note: submodules are checked out at a specific commit (detached HEAD). That is fine for builds.
If you want to update to the latest 8.3-stable commit, run:
  git submodule update --remote --depth 1

Build (per platform)

Tongsuo is platform- and arch-specific. For each target platform, build inside:
  third_party/tongsuo

After building, ensure:
- Headers are in third_party/tongsuo/include
- Libraries are in third_party/tongsuo/ or third_party/tongsuo/lib

Runtime (Windows)

Run the helper script to add the DLL directory to PATH:
  .\scripts\set_tongsuo_env.ps1

Notes
- Windows/amd64 binaries do not work on Linux/macOS or ARM.
- If you do not use the SM2 key exchange features, -lkeyexchange may be omitted.