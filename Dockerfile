# SecGuard 生产镜像
#
# 两阶段构建:
#   第一阶段(builder)装编译器与开发包,把程序编出来
#   第二阶段(runtime)只装运行库,把编好的二进制拷进来
#
# 为什么这么做:编译工具链加起来几百 MB,运行完全用不上。
# 镜像小不只是省硬盘 —— 拉取快、攻击面小、漏洞扫描噪音少。
#
# 基础镜像用 ubuntu:22.04 而不是 alpine:
#   程序依赖 libmysqlcppconn / OpenSSL 3 / hiredis,
#   alpine 用的是 musl libc,这些库要么没有要么得自己编。
#   为了省 50MB 镜像去换一堆 ABI 麻烦,不值。

# ---------------------------------------------------------------------------
# 第一阶段:编译
# ---------------------------------------------------------------------------
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        g++ \
        libssl-dev \
        libmysqlcppconn-dev \
        libhiredis-dev \
        libcurl4-openssl-dev \
        nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# 先只拷构建脚本和源码,让依赖层能命中缓存
COPY CMakeLists.txt ./
COPY include/ ./include/
COPY src/ ./src/
COPY tests/ ./tests/
COPY rules/ ./rules/
# third_party 里有 cpp-httplib(header-only),漏了这一个目录 app 就编不过
COPY third_party/ ./third_party/

# 编译(-j 用满核心)
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build -j"$(nproc)"

# ---------------------------------------------------------------------------
# 测试阶段:镜像构建时就能验证正确性
#   docker build --target test .
# 不作为默认路径 —— 每次构建都跑测试太慢,放在 CI 里用。
# ---------------------------------------------------------------------------
FROM builder AS test

WORKDIR /src
RUN ./build/ac_test 5000 && ./build/unit_test

# ---------------------------------------------------------------------------
# 第二阶段:运行
# ---------------------------------------------------------------------------
FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# 只装运行库:
#   libmysqlcppconn7v5  MySQL 连接器运行库(提供 libmysqlcppconn.so.7,
#                       它自己会带上 libmysqlclient21)
#   libssl3             OpenSSL 3
#   libhiredis0.14      Redis 客户端(soname 是 libhiredis.so.0.14)
#   libcurl4            LLM API 调用(W6)
#   ca-certificates     出网调 LLM 时要校验证书
#   curl                健康检查用
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmysqlcppconn7v5 \
        libssl3 \
        libhiredis0.14 \
        libcurl4 \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# 非 root 运行:容器里也是最小权限原则
RUN groupadd -r secguard && useradd -r -g secguard -s /sbin/nologin secguard

WORKDIR /app

COPY --from=builder /src/build/secguard /app/secguard
COPY --from=builder /src/rules/ /app/rules/

RUN chown -R secguard:secguard /app

USER secguard

# 文档用途:实际端口由 SECGUARD_PORT 决定
EXPOSE 8080

# 健康检查:容器编排靠它判断"是不是真的能干活"
# 注意探的是 /health,它会真去 ping 数据库,不是只回一句 200
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${SECGUARD_PORT:-8080}/health" || exit 1

# exec 形式:让 secguard 成为 PID 1,能直接收到 SIGTERM,
# 优雅停机的信号才走得到(第 69 讲)
ENTRYPOINT ["/app/secguard"]
