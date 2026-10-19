#!/bin/bash
# 本地开发启动脚本(不是生产用;生产走 docker compose)
#
# 规矩:秘密只从环境变量或 .env 来,脚本里不写死。
# (踩过的坑:之前这里硬编码过一个口令,后来数据库口令改了,
#  脚本里那份就成了错的,排查半天才定位到是脚本没跟上。)
set -euo pipefail

cd "$(dirname "$0")"

# 有 .env 就加载,没有就靠调用者自己 export
if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
fi

: "${SECGUARD_DB_USER:?请先设置 SECGUARD_DB_USER,或在 .env 里配}"
: "${SECGUARD_DB_PASS:?请先设置 SECGUARD_DB_PASS,或在 .env 里配}"
: "${SECGUARD_JWT_SECRET:?请先设置 SECGUARD_JWT_SECRET,或在 .env 里配}"

export SECGUARD_DB_HOST="${SECGUARD_DB_HOST:-127.0.0.1}"
export SECGUARD_DB_PORT="${SECGUARD_DB_PORT:-3306}"
export SECGUARD_DB_NAME="${SECGUARD_DB_NAME:-secguard}"
export SECGUARD_REDIS_HOST="${SECGUARD_REDIS_HOST:-127.0.0.1}"
export SECGUARD_REDIS_PORT="${SECGUARD_REDIS_PORT:-6379}"
export SECGUARD_PORT="${SECGUARD_PORT:-8080}"
export SECGUARD_LOG_LEVEL="${SECGUARD_LOG_LEVEL:-info}"
export SECGUARD_PATTERN_FILE="${SECGUARD_PATTERN_FILE:-$PWD/rules/attack_patterns.txt}"

if [ ! -x ./build/secguard ]; then
    echo "没找到 ./build/secguard,先编译:"
    echo "  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j\$(nproc)"
    exit 1
fi

exec ./build/secguard
