cmake_minimum_required(VERSION 3.14)

project(libcpp-crypto)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(libcpp-crypto INTERFACE)

target_include_directories(libcpp-crypto INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_subdirectory(examples)
add_subdirectory(test)
