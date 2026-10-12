cmake_minimum_required(VERSION 3.20)
project(secguard CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Release 开优化;Debug 开 sanitizer 抓内存越界和未定义行为
set(CMAKE_CXX_FLAGS_RELEASE "-O2")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -fsanitize=address,undefined")

add_compile_options(-Wall -Wextra -Wpedantic)

# cpp-httplib 内部用线程,显式声明依赖
find_package(Threads REQUIRED)

add_executable(secguard src/main.cpp)
target_include_directories(secguard PRIVATE include third_party)
target_link_libraries(secguard PRIVATE Threads::Threads)
