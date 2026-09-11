cmake_minimum_required(VERSION 3.21)

if(WIN32)
  if(CMAKE_GENERATOR MATCHES "^Visual Studio")
    message(FATAL_ERROR
      "The Visual Studio generator cannot be used.\n"
      "Use: cmake --preset windows\n"
      "or:  cmake -G Ninja -S . -B build")
  endif()

  if(NOT CMAKE_C_COMPILER)
    find_program(LLVM_CLANG_CL clang-cl
      HINTS "$ENV{LLVM_ROOT}/bin"
            "C:/Program Files/LLVM/bin"
            "C:/Program Files (x86)/LLVM/bin"
            "C:/llvm/bin")
    if(LLVM_CLANG_CL)
      set(CMAKE_C_COMPILER "${LLVM_CLANG_CL}")
      message(STATUS "Using clang-cl: ${LLVM_CLANG_CL}")
    else()
      message(FATAL_ERROR
        "clang-cl.exe not found.\n"
        "Install LLVM (https://llvm.org) or pass -DLLVM_ROOT=<install dir>.")
    endif()
  endif()
endif()

project(x86dec LANGUAGES C)

option(X86DEC_UNITY_BUILD "Batch sources into unity files for faster code" ON)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")

add_executable(x86dec ${SOURCES} ${HEADERS})

if(X86DEC_UNITY_BUILD)
  set_target_properties(x86dec PROPERTIES UNITY_BUILD ON UNITY_BUILD_BATCH_SIZE 50)
endif()

target_include_directories(x86dec PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include/x86dec
  ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_options(x86dec PRIVATE
  /std:c17 /EHa /O2 /Ot /Oi /DNDEBUG
  /DWIN32_LEAN_AND_MEAN
  /DCOBJMACROS
  /D_CRT_SECURE_NO_WARNINGS
  /D_WINSOCK_DEPRECATED_NO_WARNINGS)

target_link_options(x86dec PRIVATE /SUBSYSTEM:CONSOLE)

target_link_libraries(x86dec PRIVATE
  kernel32)

file(GLOB_RECURSE BENCH_LIB_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
list(REMOVE_ITEM BENCH_LIB_SOURCES
  "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")

add_executable(x86dec-bench-zydis
  bench/bench_zydis.c
  vendor/zydis/Zydis.c
  ${BENCH_LIB_SOURCES})

set_target_properties(x86dec-bench-zydis PROPERTIES UNITY_BUILD OFF)

target_include_directories(x86dec-bench-zydis PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include/x86dec
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/vendor/zydis)

target_compile_options(x86dec-bench-zydis PRIVATE
  /std:c17 /EHa /O2 /Ot /Oi /DNDEBUG
  /DWIN32_LEAN_AND_MEAN
  /DCOBJMACROS
  /D_CRT_SECURE_NO_WARNINGS
  /D_WINSOCK_DEPRECATED_NO_WARNINGS)

target_link_options(x86dec-bench-zydis PRIVATE /SUBSYSTEM:CONSOLE)

target_link_libraries(x86dec-bench-zydis PRIVATE
  kernel32)
