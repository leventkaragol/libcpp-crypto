cmake_minimum_required(VERSION 3.14)

project(test)

find_package(OpenSSL REQUIRED)
find_package(GTest CONFIG REQUIRED)

add_executable(test test.cpp)

target_link_libraries(test PRIVATE libcpp-crypto OpenSSL::SSL OpenSSL::Crypto)
