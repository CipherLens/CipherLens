cmake_minimum_required(VERSION 3.16)
project(mlspp_caller_audit LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

foreach(required MLSPP_ROOT MLSPP_BUILD)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "${required} is required")
  endif()
endforeach()

find_package(OpenSSL REQUIRED)

add_executable(
  mlspp_rsa_trailing_garbage
  mlspp_rsa_trailing_garbage.cpp
)

target_compile_definitions(
  mlspp_rsa_trailing_garbage
  PRIVATE WITH_OPENSSL3 SANITIZERS
)

target_include_directories(
  mlspp_rsa_trailing_garbage
  PRIVATE
    "${MLSPP_ROOT}/lib/hpke/include"
    "${MLSPP_ROOT}/lib/bytes/include"
    "${MLSPP_ROOT}/lib/tls_syntax/include"
    "${MLSPP_ROOT}/include"
    "${MLSPP_BUILD}/include"
)

target_compile_options(
  mlspp_rsa_trailing_garbage
  PRIVATE
    -Wall
    -Wextra
    -fsanitize=address
    -fsanitize=undefined
    -fno-omit-frame-pointer
)

target_link_options(
  mlspp_rsa_trailing_garbage
  PRIVATE
    -fsanitize=address
    -fsanitize=undefined
)

target_link_libraries(
  mlspp_rsa_trailing_garbage
  PRIVATE
    "${MLSPP_BUILD}/lib/hpke/libhpke.a"
    "${MLSPP_BUILD}/lib/bytes/libbytes.a"
    "${MLSPP_BUILD}/lib/tls_syntax/libtls_syntax.a"
    OpenSSL::Crypto
)
