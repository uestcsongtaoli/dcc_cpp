cmake_minimum_required(VERSION 3.10)
project(dcc_encrypt CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -O0")

find_package(Threads REQUIRED)

add_executable(dcc_encrypt
    src/main.cpp
    src/sm4.cpp
    src/sm4_avx512.cpp
)

# sm4_avx512.cpp must see __AVX512F__ so its intrinsics compile.
# The #ifdef inside the file ensures graceful fallback on non-AVX-512 hosts.
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-mavx512f" HAS_AVX512F)
if(HAS_AVX512F)
    set_source_files_properties(src/sm4_avx512.cpp PROPERTIES
        COMPILE_FLAGS "-mavx512f")
    message(STATUS "AVX-512F: available — sm4_avx512 compiled with -mavx512f")
else()
    message(STATUS "AVX-512F: not supported by compiler — sm4_avx512 uses scalar fallback")
endif()

target_include_directories(dcc_encrypt PRIVATE src)
target_link_libraries(dcc_encrypt PRIVATE Threads::Threads)

# GCC < 9 needs explicit stdc++fs; GCC >= 9 has it built-in
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
  target_link_libraries(dcc_encrypt PRIVATE stdc++fs)
endif()

# ── Static linking (Linux only) ───────────────────────────────────────────────
# On Linux: statically link libstdc++ and libgcc so the binary runs on any
# distro without matching GCC runtime installed.
# glibc is intentionally kept dynamic: fully static glibc breaks getaddrinfo
# (DNS uses dlopen internally). glibc is ABI-stable across distros anyway.
#
# Build modes:
#   cmake -B build -DSTATIC_RUNTIME=ON   → -static-libgcc -static-libstdc++
#   cmake -B build -DSTATIC_RUNTIME=OFF  → normal dynamic (default on macOS)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  option(STATIC_RUNTIME "Statically link libstdc++ and libgcc" OFF)
  if(STATIC_RUNTIME)
    # Ask the compiler where its own libstdc++.a lives.
    # g++ -print-file-name=libstdc++.a returns the full path when found,
    # or just "libstdc++.a" (no slash) when not found.
    execute_process(
      COMMAND ${CMAKE_CXX_COMPILER} -print-file-name=libstdc++.a
      OUTPUT_VARIABLE _stdcxx_a
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(_stdcxx_a MATCHES "/")          # full path → file exists
      get_filename_component(_stdcxx_dir "${_stdcxx_a}" DIRECTORY)
      target_link_options(dcc_encrypt PRIVATE
        -static-libgcc
        -static-libstdc++
        -L${_stdcxx_dir})
      message(STATUS "Static runtime: ON  (libstdc++.a = ${_stdcxx_a})")
    else()
      message(FATAL_ERROR
        "Static runtime requested but libstdc++.a not found.\n"
        "On CentOS/RHEL: yum install libstdc++-static\n"
        "Or disable with: cmake -DSTATIC_RUNTIME=OFF")
    endif()
  else()
    message(STATUS "Static runtime: OFF (dynamic libstdc++, requires GCC runtime on target)")
  endif()
endif()
