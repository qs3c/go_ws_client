#!/usr/bin/env bash
set -euo pipefail

# 回到我们最接近成功的一次配置！
# 1. 之前 MSYS perl 其实成功完成了 Configure，但是由于 MAKE 环境变量带有带括号的路径，导致 Bash 执行出错。
# 2. 我们彻底抛弃 Strawberry Perl，回退使用 MSYS perl。
# 3. 核心是：一定要显式覆盖 MAKE 环境变量，禁止其使用带有包含空格和括号的 Windows 路径。

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_BASH="$(cd "$SCRIPT_DIR/.." && pwd)"

# 必须使用在 Makefile 里的相对路径处理 PERL5LIB，避免 `:` 分隔符在 MSYS 中引起的 bug
export PERL5LIB="../tongsuo"

# 取消可能干扰的 MSWin32 Perl
unset PERL

NDK_HOME="D:/Android/Sdk/ndk/20.0.5594570"
NDK_HOME_BASH="/d/Android/Sdk/ndk/20.0.5594570"
HOST_TAG="windows-x86_64"
TOOLCHAIN_BASH="$NDK_HOME_BASH/toolchains/llvm/prebuilt/$HOST_TAG"
API=24

# 建立无空格无括号的安全路径并导出给工具链
FAKE_BIN_BASH="$ROOT_BASH/third_party/fake-bin"
# 由于前面已经将 make.exe 物理拷贝到了这个目录，我们强行覆盖 MAKE 变量！
export MAKE="$FAKE_BIN_BASH/make.exe"

# 纯净的 PATH，去除 Strawberry 和乱七八糟的 MinGW 原生带括号的路径
export PATH="$FAKE_BIN_BASH:$TOOLCHAIN_BASH/bin:/usr/bin:/bin"
export ANDROID_NDK_HOME="$NDK_HOME"

INSTALL_BASE_WIN="$ROOT_BASH/third_party/tongsuo-install/android"

build_arch() {
    local arch=$1
    local target=$2
    local triple=$3
    local cross_prefix=$4
    
    echo "=========================================="
    echo "Building for $arch ($target) API $API"
    echo "=========================================="
    
    local clang_exe="${triple}${API}-clang"
    cat <<EOF > "$FAKE_BIN_BASH/${cross_prefix}gcc"
#!/bin/bash
exec "$clang_exe" "\$@"
EOF
    chmod +x "$FAKE_BIN_BASH/${cross_prefix}gcc"

    local prefix="$INSTALL_BASE_WIN/$arch"
    local build_dir_bash="$ROOT_BASH/third_party/tongsuo-build-$arch"
    
    mkdir -p "$build_dir_bash"
    cd "$build_dir_bash"
    
    local src_rel="../tongsuo"
    
    [ -f Makefile ] && "$MAKE" clean || true
    rm -f Makefile configdata.pm

    # 执行 Configure
    perl "$src_rel/Configure" "$target" \
        --prefix="$prefix" \
        -D__ANDROID_API__=$API \
        no-shared no-tests \
        enable-ntls

    # 执行编译
    # 彻底解决 mingw32-make 在 Windows 下的环境灾难：
    # 1. 强制使用 Windows 风格的以 ';' 分隔的 PATH，否则 mingw32-make 无法找到 sh.exe。
    # 2. 显式指定 SHELL 为 MSYS 的 sh.exe。
    local old_path="$PATH"
    local win_path="$(cygpath -w -p "$PATH")"
    export PATH="$win_path"
    export SHELL="E:/Git/bin/sh.exe"

    "$MAKE" build_libs -j8 SHELL="E:/Git/bin/sh.exe"
    "$MAKE" install_dev SHELL="E:/Git/bin/sh.exe"
    
    # 恢复 MSYS PATH
    export PATH="$old_path"

    # 编译 libkeyexchange.a
    echo "Building libkeyexchange.a for $arch..."
    local keyexch_src_rel="../../crypto/sm2keyexch"
    local keyexch_out_rel="$ROOT_BASH/crypto/sm2keyexch/android/$arch"
    mkdir -p "$keyexch_out_rel"
    
    "$clang_exe" -c -fPIC "$keyexch_src_rel/keyexchange.c" -o "$keyexch_out_rel/keyexchange.o" \
        -I"$prefix/include" -I"../../third_party/tongsuo/include" -DOPENSSL_API_COMPAT=0x10100000L
    
    "${cross_prefix}ar" rcs "$keyexch_out_rel/libkeyexchange.a" "$keyexch_out_rel/keyexchange.o"
    rm "$keyexch_out_rel/keyexchange.o"
    
    echo "Successfully built $arch"
}

build_arch "arm64-v8a" "android-arm64" "aarch64-linux-android" "aarch64-linux-android-"
build_arch "armeabi-v7a" "android-arm" "armv7a-linux-androideabi" "arm-linux-androideabi-"

echo "All Android builds completed!"
