# cmake/zig-cross.cmake — Zig-driven cross-compilation toolchain for the CLI
#
# Use:
#   cmake -B build/cli-linux-amd64 \
#       -DCMAKE_TOOLCHAIN_FILE=cmake/zig-cross.cmake \
#       -DPARANOID_TARGET=x86_64-linux-musl \
#       -DCMAKE_BUILD_TYPE=Release
#   cmake --build build/cli-linux-amd64 --target paranoid_cli
#
# Supported PARANOID_TARGET values:
#   x86_64-linux-musl       (static Linux amd64)
#   aarch64-linux-musl      (static Linux arm64)
#   x86_64-macos-none       (macOS Intel, libSystem dynamic)
#   aarch64-macos-none      (macOS Apple Silicon, libSystem dynamic)
#
# This toolchain ONLY applies to the CLI path. It disables the WASM
# branch and skips OpenSSL discovery by not touching paranoid_core.

if(NOT DEFINED PARANOID_TARGET)
    message(FATAL_ERROR "zig-cross.cmake requires -DPARANOID_TARGET=<triple>")
endif()

find_program(ZIG_EXECUTABLE zig REQUIRED)

# Derive CMAKE_SYSTEM_NAME from the triple so CMake sets sensible defaults.
if(PARANOID_TARGET MATCHES "linux")
    set(CMAKE_SYSTEM_NAME Linux)
elseif(PARANOID_TARGET MATCHES "macos")
    set(CMAKE_SYSTEM_NAME Darwin)
elseif(PARANOID_TARGET MATCHES "windows")
    set(CMAKE_SYSTEM_NAME Windows)
else()
    message(FATAL_ERROR "Unknown PARANOID_TARGET: ${PARANOID_TARGET}")
endif()

if(PARANOID_TARGET MATCHES "^x86_64")
    set(CMAKE_SYSTEM_PROCESSOR x86_64)
elseif(PARANOID_TARGET MATCHES "^aarch64")
    set(CMAKE_SYSTEM_PROCESSOR aarch64)
endif()

# Tell CMake to use zig as the C compiler and archiver.
set(CMAKE_C_COMPILER "${ZIG_EXECUTABLE}")
set(CMAKE_C_COMPILER_ARG1 "cc;-target;${PARANOID_TARGET}")

set(CMAKE_AR "${ZIG_EXECUTABLE}")
set(CMAKE_C_COMPILER_AR_ARG1 "ar")

set(CMAKE_RANLIB "${ZIG_EXECUTABLE}")
set(CMAKE_C_COMPILER_RANLIB_ARG1 "ranlib")

# Musl targets produce fully static binaries.
if(PARANOID_TARGET MATCHES "musl")
    set(CMAKE_EXE_LINKER_FLAGS_INIT "-static")
endif()

# Don't let CMake try to run compiled test binaries (we're cross-compiling).
set(CMAKE_CROSSCOMPILING TRUE)

# Force the CLI-only code path: don't require OpenSSL, don't build tests
# that need a native runner. This has to be evaluated by the top-level
# CMakeLists, which already gates on CMAKE_SYSTEM_NAME STREQUAL "WASI"
# (WASM) vs else (native). For cross CLI builds we are in the "else"
# branch but want to skip test_native/test_paranoid/test_statistics
# since they link OpenSSL.
set(PARANOID_CROSS_CLI TRUE)

# Silence CMake's try_compile wanting to run a binary.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
