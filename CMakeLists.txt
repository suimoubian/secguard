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

# OpenSSL(随机数、SHA-256/HMAC、PBKDF2)
find_package(OpenSSL REQUIRED)

# libcurl:LLM API 调用(W6)
find_path(CURL_INCLUDE_DIR NAMES curl/curl.h
          PATHS /usr/include/x86_64-linux-gnu /usr/include /usr/local/include)
find_library(CURL_LIBRARY NAMES curl PATHS /usr/lib/x86_64-linux-gnu /usr/local/lib)
if(CURL_INCLUDE_DIR AND CURL_LIBRARY)
    message(STATUS "libcurl: ${CURL_LIBRARY}")
else()
    message(WARNING "找不到 libcurl —— AI 分析层将无法编译")
endif()

# hiredis:Redis 客户端(限流 / 封禁 / 重放的共享状态)
find_path(HIREDIS_INCLUDE_DIR NAMES hiredis/hiredis.h PATHS /usr/include /usr/local/include)
find_library(HIREDIS_LIBRARY NAMES hiredis PATHS /usr/lib/x86_64-linux-gnu /usr/local/lib)
if(HIREDIS_INCLUDE_DIR AND HIREDIS_LIBRARY)
    message(STATUS "hiredis: ${HIREDIS_LIBRARY}")
else()
    message(WARNING "找不到 hiredis —— Redis 相关功能将无法编译")
endif()

# ---------------------------------------------------------------------------
# 目录
# ---------------------------------------------------------------------------
set(SG_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    ${MYSQLCPPCONN_INCLUDE_DIR}
    ${CURL_INCLUDE_DIR})

# 引擎源文件 + 它依赖的日志模块(engine.cpp 里会用日志报建表信息)
set(SG_ENGINE_SOURCES "")
foreach(f src/util/log.cpp src/engine/engine.cpp)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${f})
        list(APPEND SG_ENGINE_SOURCES ${f})
    endif()
endforeach()

set(SG_ENGINE_HEADERS include/aho_corasick.h include/engine.h)

# 按存在性过滤,便于分步落地
set(SG_APP_SOURCES
    src/main.cpp
    src/util/config.cpp
    src/util/log.cpp
    src/db/connection_pool.cpp
    src/db/dao.cpp
    src/db/audit_writer.cpp
    src/cache/redis_client.cpp
    src/cache/distributed_guard.cpp
    src/crypto/auth_crypto.cpp
    src/engine/engine.cpp
    src/ai/llm_client.cpp
    src/ai/prompt.cpp
    src/ai/analyzer.cpp
    src/ai/webhook.cpp
    src/net/app_context.cpp
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
# 3) 单元自检:密码 / JWT / 引擎 / 翻译 / 封禁
# ---------------------------------------------------------------------------
add_executable(unit_test
    tests/unit_test.cpp
    src/crypto/auth_crypto.cpp
    src/util/config.cpp
    src/util/log.cpp
    src/engine/engine.cpp
    src/net/app_context.cpp
    src/cache/redis_client.cpp
    src/cache/distributed_guard.cpp
    src/ai/prompt.cpp
    src/ai/llm_client.cpp)
target_include_directories(unit_test PRIVATE ${SG_INCLUDE_DIRS})
target_link_libraries(unit_test PRIVATE
    Threads::Threads
    OpenSSL::Crypto
    ${HIREDIS_LIBRARY}
    ${CURL_LIBRARY})

# ---------------------------------------------------------------------------
# 4) 主程序
# ---------------------------------------------------------------------------
if(SG_APP_SOURCES_EXISTING)
    add_executable(secguard ${SG_APP_SOURCES_EXISTING})
    target_include_directories(secguard PRIVATE ${SG_INCLUDE_DIRS})
    target_link_libraries(secguard PRIVATE
        Threads::Threads
        ${MYSQLCPPCONN_LIBRARY}
        ${HIREDIS_LIBRARY}
        ${CURL_LIBRARY}
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
