cmake_minimum_required(VERSION 3.14)

project(examples)

find_package(OpenSSL REQUIRED)

add_executable(examples main.cpp)

target_link_libraries(examples PRIVATE libcpp-crypto OpenSSL::SSL OpenSSL::Crypto)
