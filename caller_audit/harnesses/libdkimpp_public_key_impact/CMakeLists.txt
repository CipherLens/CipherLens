cmake_minimum_required(VERSION 3.16)

project(libdkimpp_public_key_impact LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED LIBDKIMPP_ROOT)
  message(FATAL_ERROR "LIBDKIMPP_ROOT is required")
endif()

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

pkg_check_modules(
  SODIUM
  REQUIRED
  IMPORTED_TARGET
  libsodium
)

file(
  GLOB_RECURSE
  LIBDKIMPP_SOURCES
  CONFIGURE_DEPENDS
  "${LIBDKIMPP_ROOT}/src/*.cpp"
)

add_executable(
  parser_matrix_cpp
  parser_matrix.cpp
  ${LIBDKIMPP_SOURCES}
)

target_include_directories(
  parser_matrix_cpp
  PRIVATE
    "${LIBDKIMPP_ROOT}/src"
    "${OPENSSL_INCLUDE_DIR}"
)

target_compile_definitions(parser_matrix_cpp PRIVATE HAS_RES_NINIT)

target_compile_options(
  parser_matrix_cpp
  PRIVATE
    -Wall
    -Wextra
    -fsanitize=address
    -fsanitize=undefined
    -fno-omit-frame-pointer
)

target_link_options(
  parser_matrix_cpp
  PRIVATE
    -fsanitize=address
    -fsanitize=undefined
)

target_link_libraries(
  parser_matrix_cpp
  PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::SODIUM
    Threads::Threads
    resolv
    dl
)

message(STATUS "Impact OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "Impact OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "Impact OpenSSL crypto: ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "Impact OpenSSL ssl: ${OPENSSL_SSL_LIBRARY}")

add_executable(
  dkim_regression_matrix
  dkim_regression_matrix.cpp
  ${LIBDKIMPP_SOURCES}
)

target_include_directories(
  dkim_regression_matrix
  PRIVATE
    "${LIBDKIMPP_ROOT}/src"
    "${LIBDKIMPP_ROOT}/tests/src"
    "${OPENSSL_INCLUDE_DIR}"
)

target_compile_definitions(dkim_regression_matrix PRIVATE HAS_RES_NINIT)

target_compile_options(
  dkim_regression_matrix
  PRIVATE
    -Wall
    -Wextra
    -fsanitize=address
    -fsanitize=undefined
    -fno-omit-frame-pointer
)

target_link_options(
  dkim_regression_matrix
  PRIVATE
    -fsanitize=address
    -fsanitize=undefined
)

target_link_libraries(
  dkim_regression_matrix
  PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::SODIUM
    Threads::Threads
    resolv
    dl
)
