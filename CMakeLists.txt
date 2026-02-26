# ================================================================
# paranoid — CMake Build System
#
# Two targets:
#   1. WASM (wasm32-wasi via Zig): cross-compiled with platform_wasm.c
#      + sha256_compact.c. Uses WASI random_get for CSPRNG.
#   2. Native: compiled with system cc + platform_native.c (OpenSSL
#      backend) for running tests locally before WASM compilation.
#
# WASM build:
#   cmake -B build/wasm \
#       -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake \
#       -DCMAKE_BUILD_TYPE=Release
#   cmake --build build/wasm
#
# Native build (tests):
#   cmake -B build/native -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build/native
#   ctest --test-dir build/native --output-on-failure
#
# paranoid.c uses the platform abstraction layer (paranoid_platform.h).
# The build links the appropriate backend:
#   - Native: platform_native.c (delegates to OpenSSL)
#   - WASM:   platform_wasm.c + sha256_compact.c (WASI + compact SHA)
# ================================================================

cmake_minimum_required(VERSION 3.20)
project(paranoid VERSION 3.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Version string passed as a compile definition
set(PARANOID_VERSION_STRING "${PROJECT_VERSION}")

# ── Core source (platform-independent) ──────────────────────
# This is the single C file containing ALL computation:
# generation, rejection sampling, chi-squared, serial correlation,
# collision detection, entropy proofs, pattern checks, SHA-256.

set(PARANOID_CORE_SOURCES
    src/paranoid.c
)

set(PARANOID_HEADERS
    include/paranoid.h
    include/paranoid_platform.h
)

# ── Vendor dependency paths ──────────────────────────────────
# OpenSSL for native: system package (openssl-dev / brew install openssl)
# WASM target does NOT use OpenSSL (compact SHA-256 + WASI random_get)
# Acutest: header-only test framework (vendor/acutest)

set(ACUTEST_DIR "${CMAKE_SOURCE_DIR}/vendor/acutest")


# ================================================================
# WASM TARGET — wasm32-wasi via Zig
# ================================================================
if(CMAKE_SYSTEM_NAME STREQUAL "WASI")
    message(STATUS "Building WASM target (wasm32-wasi via Zig)")
    message(STATUS "  Using platform_wasm.c + sha256_compact.c (no OpenSSL)")

    # ── WASM binary ──
    # paranoid.c uses platform abstraction (paranoid_platform.h).
    # platform_wasm.c provides WASI random_get + compact SHA-256.
    # No wasm_entry.c needed — built with --no-entry (reactor module).
    add_executable(paranoid_wasm
        ${PARANOID_CORE_SOURCES}
        src/platform_wasm.c
        src/sha256_compact.c
    )

    # Output as "paranoid.wasm" (not "paranoid_wasm.wasm")
    set_target_properties(paranoid_wasm PROPERTIES
        OUTPUT_NAME "paranoid"
    )

    target_include_directories(paranoid_wasm PRIVATE
        include
        src  # for sha256_compact.h (used by platform_wasm.c)
    )

    # Note: PARANOID_VERSION_STRING is defined in paranoid.h.
    # Do NOT pass it as -D on the command line -- that causes a
    # -Wmacro-redefined error with -Werror. The header is the
    # single source of truth for the version string.

    target_compile_options(paranoid_wasm PRIVATE
        -Wall -Wextra -Werror
        -O2
        -fdata-sections
        -ffunction-sections
    )

    # No external library dependencies -- WASM target uses only
    # platform_wasm.c (WASI random_get) + sha256_compact.c.
    # OpenSSL is no longer needed for the WASM build.

    # ── WASM exports ──────────────────────────────────────────
    # Every function from paranoid.h that JS needs, plus malloc/free
    # for the JS bridge to allocate strings in WASM linear memory.
    #
    # app.js directly calls:
    #   paranoid_run_audit, paranoid_get_result_ptr, malloc, free,
    #   paranoid_offset_password_length, paranoid_offset_chi2_statistic,
    #   paranoid_offset_current_stage, paranoid_offset_all_pass
    #
    # Additional exports for testing/debugging/verification:
    #   paranoid_version, paranoid_generate, paranoid_get_result_size,
    #   paranoid_sha256, paranoid_sha256_hex, paranoid_chi_squared,
    #   paranoid_serial_correlation, paranoid_count_collisions
    set(WASM_EXPORTS
        paranoid_version
        paranoid_generate
        paranoid_generate_multiple
        paranoid_generate_constrained
        paranoid_validate_charset
        paranoid_check_compliance
        paranoid_run_audit
        paranoid_get_result_ptr
        paranoid_get_result_size
        paranoid_offset_password_length
        paranoid_offset_chi2_statistic
        paranoid_offset_current_stage
        paranoid_offset_all_pass
        paranoid_sha256
        paranoid_sha256_hex
        paranoid_chi_squared
        paranoid_serial_correlation
        paranoid_count_collisions
        malloc
        free
    )

    # Build export linker flags from the list
    set(EXPORT_LINK_FLAGS "")
    foreach(fn IN LISTS WASM_EXPORTS)
        list(APPEND EXPORT_LINK_FLAGS "-Wl,--export=${fn}")
    endforeach()

    target_link_options(paranoid_wasm PRIVATE
        # Strip debug symbols from WASM binary
        -s
        # This is a reactor/library, not a command — no _start entry
        -Wl,--no-entry
        # Garbage-collect unreferenced sections (reduces binary size)
        -Wl,--gc-sections
        # All exported functions
        ${EXPORT_LINK_FLAGS}
    )
    # Note: -lwasi-emulated-getpid removed — was only needed for OpenSSL.
    # The platform_wasm.c backend has zero external dependencies beyond
    # WASI random_get and the compact SHA-256 implementation.

    # ── Post-build: wasm-opt + wasm-strip + wasm-validate ────
    # wasm-opt fixes Zig WASM codegen issues and optimizes size.
    # wasm-strip removes remaining debug info.
    # wasm-validate is a hard gate — catches structural issues
    # that browsers would silently reject.
    find_program(WASM_OPT wasm-opt)
    find_program(WASM_STRIP wasm-strip)
    find_program(WASM_VALIDATE wasm-validate)

    if(WASM_OPT)
        add_custom_command(TARGET paranoid_wasm POST_BUILD
            COMMAND ${WASM_OPT} -O2 --enable-bulk-memory
                -o $<TARGET_FILE:paranoid_wasm>
                $<TARGET_FILE:paranoid_wasm>
            COMMENT "Post-processing with wasm-opt (fixes Zig codegen + optimizes size)"
        )
    endif()

    if(WASM_STRIP)
        add_custom_command(TARGET paranoid_wasm POST_BUILD
            COMMAND ${WASM_STRIP} $<TARGET_FILE:paranoid_wasm>
            COMMENT "Stripping WASM binary"
        )
    endif()

    # wasm-validate runs AFTER opt+strip to catch any corruption.
    # This is a hard gate — build fails if the binary is invalid.
    if(WASM_VALIDATE)
        add_custom_command(TARGET paranoid_wasm POST_BUILD
            COMMAND ${WASM_VALIDATE} $<TARGET_FILE:paranoid_wasm>
            COMMENT "Validating WASM binary (hard gate)"
        )
    else()
        message(WARNING "wasm-validate not found — WASM validation skipped! Install wabt.")
    endif()

    # Report binary size after build
    add_custom_command(TARGET paranoid_wasm POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo
            "WASM binary: $<TARGET_FILE:paranoid_wasm>"
    )


# ================================================================
# NATIVE TARGET — system cc + system OpenSSL (for tests)
# ================================================================
else()
    message(STATUS "Building native target (with system OpenSSL via platform abstraction)")

    # ── Find system OpenSSL ──────────────────────────────────
    # Native builds use the system OpenSSL package via platform_native.c.
    # paranoid.c calls paranoid_platform_random() and paranoid_platform_sha256(),
    # which platform_native.c implements using OpenSSL RAND_bytes/EVP.
    find_package(OpenSSL REQUIRED)
    message(STATUS "  OpenSSL version: ${OPENSSL_VERSION}")
    message(STATUS "  OpenSSL libraries: ${OPENSSL_CRYPTO_LIBRARY}")

    # ── Core library (static) ────────────────────────────────
    # Compiles paranoid.c + platform_native.c (OpenSSL backend).
    # paranoid.c uses platform abstraction; platform_native.c
    # provides the OpenSSL implementation.
    add_library(paranoid_core STATIC
        ${PARANOID_CORE_SOURCES}
        src/platform_native.c
    )

    target_include_directories(paranoid_core PUBLIC
        include
    )

    target_link_libraries(paranoid_core PUBLIC
        OpenSSL::Crypto
        m
    )

    target_compile_definitions(paranoid_core PRIVATE
        PARANOID_PLATFORM_NATIVE=1
        # PARANOID_VERSION_STRING is defined in paranoid.h -- not
        # redefined here to avoid -Wmacro-redefined with -Werror.
    )

    target_compile_options(paranoid_core PRIVATE
        -Wall -Wextra -Werror
    )

    # ── Compact SHA-256 library ──────────────────────────────
    # sha256_compact.h defines the interface. The .c implementation
    # will be created in Phase 1A (task B3). When it exists, this
    # target will compile it for native testing independently of
    # the WASM build.
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/sha256_compact.c")
        add_library(sha256_compact STATIC
            src/sha256_compact.c
        )

        target_include_directories(sha256_compact PUBLIC
            include
            src
        )

        target_compile_options(sha256_compact PRIVATE
            -Wall -Wextra -Werror
        )

        # SHA-256 tests (requires both sha256_compact.c and acutest)
        if(EXISTS "${CMAKE_SOURCE_DIR}/tests/test_sha256.c"
           AND EXISTS "${ACUTEST_DIR}/include/acutest.h")
            add_executable(test_sha256
                tests/test_sha256.c
            )
            target_include_directories(test_sha256 PRIVATE
                src
                ${ACUTEST_DIR}/include
            )
            target_link_libraries(test_sha256 PRIVATE
                sha256_compact
            )
            target_compile_options(test_sha256 PRIVATE
                -Wall -Wextra -Werror
            )
            add_test(NAME sha256_tests COMMAND test_sha256)
        endif()
    else()
        message(STATUS "  sha256_compact.c not found -- skipping compact SHA-256 target")
        message(STATUS "  (Will be created in Phase 1A, task B3)")
    endif()

    # ── Test: test_native (acutest framework) ────────────────
    # Comprehensive unit tests using acutest header-only framework.
    # Tests SHA-256 (NIST vectors), rejection sampling boundaries,
    # chi-squared statistics, serial correlation, collision detection,
    # password generation, full audit pipeline, and stress tests.
    if(EXISTS "${ACUTEST_DIR}/include/acutest.h")
        add_executable(test_native
            tests/test_native.c
            ${PARANOID_CORE_SOURCES}
            src/platform_native.c
        )

        target_include_directories(test_native PRIVATE
            include
            ${ACUTEST_DIR}/include
        )

        target_link_libraries(test_native PRIVATE
            OpenSSL::Crypto
            m
        )

        # On Linux, pthreads and dl are needed for OpenSSL
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            target_link_libraries(test_native PRIVATE
                pthread
                dl
            )
        endif()

        target_compile_definitions(test_native PRIVATE
            PARANOID_PLATFORM_NATIVE=1
        )

        target_compile_options(test_native PRIVATE
            -Wall -Wextra -Werror
        )

        add_test(NAME native_tests COMMAND test_native)
    else()
        message(STATUS "  vendor/acutest not found -- skipping test_native target")
        message(STATUS "  Clone it: git clone https://github.com/mity/acutest.git vendor/acutest")
    endif()

    # ── Test: test_statistics (chi-squared + serial correlation KATs) ──
    # Known-answer tests for statistical functions using acutest.
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/test_statistics.c"
       AND EXISTS "${ACUTEST_DIR}/include/acutest.h")
        add_executable(test_statistics
            tests/test_statistics.c
            ${PARANOID_CORE_SOURCES}
            src/platform_native.c
        )

        target_include_directories(test_statistics PRIVATE
            include
            ${ACUTEST_DIR}/include
        )

        target_link_libraries(test_statistics PRIVATE
            OpenSSL::Crypto
            m
        )

        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            target_link_libraries(test_statistics PRIVATE
                pthread
                dl
            )
        endif()

        target_compile_definitions(test_statistics PRIVATE
            PARANOID_PLATFORM_NATIVE=1
        )

        target_compile_options(test_statistics PRIVATE
            -Wall -Wextra -Werror
        )

        add_test(NAME statistics_tests COMMAND test_statistics)
    endif()

    # ── Test: test_paranoid (standalone test framework) ───────
    # Simpler test file with its own built-in test macros.
    # Validates the same core functionality as test_native but
    # without the acutest dependency.
    if(EXISTS "${CMAKE_SOURCE_DIR}/tests/test_paranoid.c")
        add_executable(test_paranoid
            tests/test_paranoid.c
            ${PARANOID_CORE_SOURCES}
            src/platform_native.c
        )

        target_include_directories(test_paranoid PRIVATE
            include
        )

        target_link_libraries(test_paranoid PRIVATE
            OpenSSL::Crypto
            m
        )

        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            target_link_libraries(test_paranoid PRIVATE
                pthread
                dl
            )
        endif()

        target_compile_definitions(test_paranoid PRIVATE
            PARANOID_PLATFORM_NATIVE=1
        )

        # Note: -Werror is intentionally omitted here. test_paranoid.c
        # uses a custom TEST() macro that declares a _failed variable
        # which triggers -Wunused-variable. The original Makefile did
        # not compile this file at all (only test_native.c was built).
        target_compile_options(test_paranoid PRIVATE
            -Wall -Wextra
        )

        add_test(NAME paranoid_tests COMMAND test_paranoid)
    endif()

    # ── CTest integration ────────────────────────────────────
    enable_testing()

endif()
