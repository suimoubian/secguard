cmake_minimum_required(VERSION 3.20)
project(secguard CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Release 开优化;Debug 开 sanitizer 抓内存越界和未定义行为(寓言集第 63 讲)
# 注意:sanitizer 版本慢好几倍,性能数据必须从 Release 出。
set(CMAKE_CXX_FLAGS_RELEASE "-O2")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -O1 -fsanitize=address,undefined")

add_compile_options(-Wall -Wextra -Wpedantic)

# ---------------------------------------------------------------------------
# 依赖
# ---------------------------------------------------------------------------
find_package(Threads REQUIRED)

# MySQL Connector/C++(系统包 libmysqlcppconn-dev)
find_path(MYSQLCPPCONN_INCLUDE_DIR
          NAMES mysql_driver.h
          PATHS /usr/include /usr/local/include)
find_library(MYSQLCPPCONN_LIBRARY
             NAMES mysqlcppconn
             PATHS /usr/lib/x86_64-linux-gnu /usr/local/lib)
if(NOT MYSQLCPPCONN_INCLUDE_DIR OR NOT MYSQLCPPCONN_LIBRARY)
    message(FATAL_ERROR
        "找不到 MySQL Connector/C++。安装:sudo apt-get install libmysqlcppconn-dev")
endif()
message(STATUS "MySQL Connector/C++: ${MYSQLCPPCONN_LIBRARY}")

# OpenSSL(随机数;SHA-256/HMAC 自己实现,见 src/crypto/sha256.h)
find_package(OpenSSL REQUIRED)

# ---------------------------------------------------------------------------
# 目录
# ---------------------------------------------------------------------------
set(SG_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    ${MYSQLCPPCONN_INCLUDE_DIR})

set(SG_ENGINE_SOURCES "")
foreach(f src/engine/pattern_library.cpp)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${f})
        list(APPEND SG_ENGINE_SOURCES ${f})
    endif()
endforeach()

# 按存在性过滤,便于分步落地
set(SG_APP_SOURCES
    src/main.cpp
    src/util/config.cpp
    src/util/log.cpp
    src/db/connection_pool.cpp
    src/db/dao.cpp
    src/net/http_server.cpp
    src/net/handlers_auth.cpp
    src/net/handlers_content.cpp
    src/net/handlers_audit.cpp)
set(SG_APP_SOURCES_EXISTING "")
foreach(f ${SG_APP_SOURCES})
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${f})
        list(APPEND SG_APP_SOURCES_EXISTING ${f})
    endif()
endforeach()

# ---------------------------------------------------------------------------
# 1) 对拍测试(无外部依赖)
# ---------------------------------------------------------------------------
add_executable(ac_test tests/ac_test.cpp ${SG_ENGINE_SOURCES})
target_include_directories(ac_test PRIVATE ${SG_INCLUDE_DIRS})
target_link_libraries(ac_test PRIVATE Threads::Threads)

# ---------------------------------------------------------------------------
# 2) 性能基准(强制 -O2:sanitizer 版本的数据不可用)
# ---------------------------------------------------------------------------
add_executable(ac_bench tests/bench.cpp ${SG_ENGINE_SOURCES})
target_include_directories(ac_bench PRIVATE ${SG_INCLUDE_DIRS})
target_compile_options(ac_bench PRIVATE -O2)
target_link_libraries(ac_bench PRIVATE Threads::Threads)

# ---------------------------------------------------------------------------
# 3) 主程序
# ---------------------------------------------------------------------------
if(SG_APP_SOURCES_EXISTING)
    add_executable(secguard ${SG_APP_SOURCES_EXISTING})
    target_include_directories(secguard PRIVATE ${SG_INCLUDE_DIRS})
    target_link_libraries(secguard PRIVATE
        Threads::Threads
        ${MYSQLCPPCONN_LIBRARY}
        OpenSSL::SSL
        OpenSSL::Crypto)
endif()

# ---------------------------------------------------------------------------
# 测试注册
# ---------------------------------------------------------------------------
enable_testing()
add_test(NAME ac_test COMMAND ac_test 2000)

message(STATUS "构建类型: ${CMAKE_BUILD_TYPE}")
message(STATUS "引擎源文件: ${SG_ENGINE_SOURCES}")
