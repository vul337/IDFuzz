cmake_minimum_required(VERSION 3.5)
# support C++14 features used by LLVM 10.0.0
set(CMAKE_CXX_STANDARD 14)
SET(CMAKE_CXX_FLAGS "-Wall -fno-rtti")

find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
add_subdirectory(getFunctionName)
