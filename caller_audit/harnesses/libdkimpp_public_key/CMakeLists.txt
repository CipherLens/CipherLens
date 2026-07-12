cmake_minimum_required(VERSION 3.16)

project(libdkimpp_public_key_audit LANGUAGES CXX)

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
  libdkimpp_public_key_audit
  main.cpp
  ${LIBDKIMPP_SOURCES}
)

target_include_directories(
  libdkimpp_public_key_audit
  PRIVATE
    "${LIBDKIMPP_ROOT}/src"
    "${OPENSSL_INCLUDE_DIR}"
)

target_compile_definitions(
  libdkimpp_public_key_audit
  PRIVATE
    HAS_RES_NINIT
)

target_compile_options(
  libdkimpp_public_key_audit
  PRIVATE
    -Wall
    -Wextra
    -fsanitize=address
    -fsanitize=undefined
    -fno-omit-frame-pointer
)

target_link_options(
  libdkimpp_public_key_audit
  PRIVATE
    -fsanitize=address
    -fsanitize=undefined
)

target_link_libraries(
  libdkimpp_public_key_audit
  PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::SODIUM
    Threads::Threads
    resolv
    dl
)

message(STATUS "Audit OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "Audit OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "Audit OpenSSL crypto: ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "Audit OpenSSL ssl: ${OPENSSL_SSL_LIBRARY}")
