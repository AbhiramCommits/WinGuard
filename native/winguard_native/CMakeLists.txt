cmake_minimum_required(VERSION 3.20)

project(winguard_native LANGUAGES CXX)

# ---------------------------------------------------------------------------
# WinGuard native telemetry shim
#
# This library is Windows-only. It is compiled on Windows toolchains (MSVC via
# CMake) and P/Invoked from the managed agent (WinGuard.Agent). The managed
# agent refuses to load it on any other platform (PlatformNotSupportedException)
# and falls back to ReplayTelemetrySource, which keeps the detection engine,
# API, dashboard, tests and evaluation harness fully runnable on macOS/Linux.
# ---------------------------------------------------------------------------

if(NOT WIN32)
  message(FATAL_ERROR
    "winguard_native only builds on Windows. It is the real Win32/ETW collector; "
    "non-Windows builds use the managed ReplayTelemetrySource instead.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(winguard_native SHARED
  collector.cpp
  etw_consumer.cpp
  winguard_native.h
)

target_compile_definitions(winguard_native PRIVATE
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX
)

# Advapi32  -> WinVerifyTrust / WinTrust (Authenticode)
# Wintrust  -> WINTRUST_FILE_INFO helpers
# Crypt32   -> CryptQueryObject / CryptMsg* / Cert* (signer name lookup)
# Tdh       -> ETW TDH event decoding
# Psapi     -> EnumProcessModulesEx / GetModuleFileNameExW
target_link_libraries(winguard_native PRIVATE
  advapi32
  wintrust
  crypt32
  tdh
  psapi
)

set_target_properties(winguard_native PROPERTIES
  OUTPUT_NAME "winguard_native"
  PREFIX ""
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# The managed agent looks for this exact filename next to its own binaries.
set_target_properties(winguard_native PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
)
