#!/bin/bash
# SecGuard 压测套件
#
# 三个必须做对的实验条件,否则数字是假的:
#
#   1. 把服务绑到 2 个核上跑。
#      这台开发机是 20 核,直接压出来的数字对"2 核 4G 的服务器"毫无参考价值。
#
#   2. 线程数必须 >= 并发连接数。
#      httplib 的 keep-alive 是"一个线程守一条连接":线程不够时,
#      多出来的连接会一直在队列里等,表现为 P99 飙升十几倍而 QPS 不变。
#      这不是 bug,是模型使然 —— 但配置错了数字就没意义。
#
#   3. 压测期间停掉 docker 那套容器。
#      它们占同一个机器的 CPU 和 IO,会让 P99 抖出几百毫秒的假尾巴。
#
# 用法:
#   ./bench/run.sh

set -u
cd "$(dirname "$0")/.." || exit 1

BIN=./build/secguard
PORT=8099
BASE="http://127.0.0.1:${PORT}"
SERVER_CPUS="${SERVER_CPUS:-0,1}"
WRK_CPUS="${WRK_CPUS:-4,5,6,7}"
DURATION="${DURATION:-10s}"
CONNS="${CONNS:-64}"
THREADS="${THREADS:-4}"
# 线程数跟连接数对齐(见上面第 2 条)
SG_THREADS="${SG_THREADS:-$CONNS}"

RESULT="docs/性能基线.md"
TMP=$(mktemp -d)
CPID=""

hr() { echo "----------------------------------------------------------------"; }

start_server() {
    export SECGUARD_DB_USER=secguard
    export SECGUARD_DB_PASS=secguard_dev_2026
    export SECGUARD_JWT_SECRET=bench-secret-please-change-in-production
    export SECGUARD_PATTERN_FILE="$PWD/rules/attack_patterns.txt"
    export SECGUARD_PORT=$PORT
    export SECGUARD_LOG_LEVEL=warn
    export SECGUARD_THREADS=$SG_THREADS
    export SECGUARD_REDIS_HOST=127.0.0.1
    export SECGUARD_RATE_PER_SEC=1000000
    export SECGUARD_RATE_BURST=1000000
    export SECGUARD_HIT_THRESHOLD=100000000
    export SECGUARD_AUDIT_BATCH=500
    export SECGUARD_AUDIT_FLUSH_MS=200
    export SECGUARD_AI_ENABLE=0

    for kv in "$@"; do export "$kv"; done

    taskset -c "$SERVER_CPUS" "$BIN" > "$TMP/server.log" 2>&1 &
    CPID=$!

    for _ in $(seq 1 40); do
        if curl -fsS "$BASE/health" > /dev/null 2>&1; then return 0; fi
        sleep 0.5
    done
    echo "!! 服务没起来"; tail -20 "$TMP/server.log"; return 1
}

stop_server() {
    if [ -n "$CPID" ] && kill -0 "$CPID" 2>/dev/null; then
        kill -TERM "$CPID" 2>/dev/null
        for _ in $(seq 1 20); do
            kill -0 "$CPID" 2>/dev/null || break
            sleep 0.3
        done
        kill -9 "$CPID" 2>/dev/null
    fi
    CPID=""
    sleep 1
}

run_case() {
    local name="$1" url="$2" script="${3:-}" conns="${4:-$CONNS}" threads="${5:-$THREADS}"
    local out="$TMP/case.txt"

    if [ -n "$script" ]; then
        taskset -c "$WRK_CPUS" wrk -t"$threads" -c"$conns" -d"$DURATION" --latency \
            -s "$script" "$url" > "$out" 2>&1
    else
        taskset -c "$WRK_CPUS" wrk -t"$threads" -c"$conns" -d"$DURATION" --latency \
            "$url" > "$out" 2>&1
    fi

    local rps p50 p99
    rps=$(grep -oE 'Requests/sec:[[:space:]]+[0-9.]+' "$out" | grep -oE '[0-9.]+$')
    p50=$(grep -E '^[[:space:]]*50%' "$out" | awk '{print $2}')
    p99=$(grep -E '^[[:space:]]*99%' "$out" | awk '{print $2}')
    printf '| %s | %s | %s | %s |\n' "$name" "${rps:-0}" "${p50:-?}" "${p99:-?}"
}

prepare_user() {
    local user="$1"
    curl -s -o /dev/null -X POST "$BASE/api/register" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"$user\",\"password\":\"bench-password-2026\"}"
    sed "s/benchuser/$user/g" bench/login.lua > "$TMP/login-$user.lua"
}

LONG_QUERY=$(head -c 2000 /dev/zero | tr '\0' 'a')

# ---------------------------------------------------------------------------
echo "=================================================================="
echo " SecGuard 压测"
echo "=================================================================="
echo " 机器      : $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
echo " 总核数    : $(nproc)"
echo " 服务绑定  : CPU $SERVER_CPUS(模拟 2 核服务器)"
echo " 服务线程  : $SG_THREADS"
echo " 压测端    : CPU $WRK_CPUS"
echo " 每场景    : ${DURATION},${CONNS} 连接"
hr

# 压测期间停掉 docker,避免同机干扰
CONTAINERS_STOPPED=0
if sudo -n docker ps --format '{{.Names}}' 2>/dev/null | grep -q secguard; then
    echo " 停掉 docker 容器(避免同机干扰)..."
    sudo -n docker compose stop > /dev/null 2>&1 && CONTAINERS_STOPPED=1
fi

# ---------------------------------------------------------------------------
echo
echo "【A】完整链路:Redis 分布式限流 + 特征匹配 + 异步审计"
start_server || exit 1
prepare_user benchuser
hr
echo '| 场景 | QPS | P50 | P99 |'
echo '|---|---|---|---|'
{
  run_case "GET /health(基线,含 DB ping)" "$BASE/health"
  run_case "GET /?q=hello(完整检测链路)" "$BASE/?q=hello"
  run_case "GET /?q=<2KB>(长文本匹配)" "$BASE/?q=$LONG_QUERY"
  run_case "GET /?q=union select 1(命中即拦)" "$BASE/?q=union%20select%201"
  run_case "POST /api/check(纯检测)" "$BASE" "bench/check.lua"
  run_case "POST /api/login(PBKDF2 12万轮)" "$BASE" "$TMP/login-benchuser.lua" 8 2
} | tee "$TMP/rowsA.txt"
stop_server

# ---------------------------------------------------------------------------
echo
echo "【B】线程数的影响(并发 64 不变,只改服务线程数)"
hr
echo '| 线程数 | QPS | P50 | P99 |'
echo '|---|---|---|---|'
{
  for t in 4 16 32 64; do
      SG_THREADS=$t start_server || exit 1
      run_case "线程 $t" "$BASE/?q=hello" "" "$CONNS" "$THREADS"
      stop_server
  done
} | tee "$TMP/rowsB.txt"

# ---------------------------------------------------------------------------
echo
echo "【C】关掉 Redis(限流退回单机内存):量化分布式状态的代价"
SG_THREADS=$SG_THREADS start_server SECGUARD_REDIS_ENABLE=0 || exit 1
hr
echo '| 场景 | QPS | P50 | P99 |'
echo '|---|---|---|---|'
run_case "GET /?q=hello(无 Redis)" "$BASE/?q=hello" | tee "$TMP/rowsC.txt"
stop_server

# ---------------------------------------------------------------------------
echo
echo "【D】审计同步写库(关掉无锁队列):对比异步的价值"
start_server SECGUARD_AUDIT_ASYNC=0 || exit 1
hr
echo '| 场景 | QPS | P50 | P99 |'
echo '|---|---|---|---|'
run_case "GET /?q=hello(审计同步)" "$BASE/?q=hello" | tee "$TMP/rowsD.txt"
stop_server

# ---------------------------------------------------------------------------
echo
echo "【E】登录成本:PBKDF2 迭代轮数"
start_server SECGUARD_PBKDF2_ITER=10000 || exit 1
prepare_user lowiter
hr
echo '| 场景 | QPS | P50 | P99 |'
echo '|---|---|---|---|'
run_case "POST /api/login(1万轮)" "$BASE" "$TMP/login-lowiter.lua" 8 2 | tee "$TMP/rowsE.txt"
stop_server

# ---------------------------------------------------------------------------
if [ "$CONTAINERS_STOPPED" = "1" ]; then
    echo
    echo " 恢复 docker 容器..."
    sudo -n docker compose start > /dev/null 2>&1
fi

echo
echo "=================================================================="
echo " 汇总"
echo "=================================================================="
{
    echo "### A. 完整链路(2 核,线程 $SG_THREADS,Redis 限流 + 异步审计)"
    echo
    echo '| 场景 | QPS | P50 | P99 |'
    echo '|---|---|---|---|'
    cat "$TMP/rowsA.txt"
    echo
    echo "### B. 服务线程数的影响(并发 64)"
    echo
    cat "$TMP/rowsB.txt"
    echo
    echo "### C. 关掉 Redis(限流退回单机内存)"
    echo
    cat "$TMP/rowsC.txt"
    echo
    echo "### D. 审计同步写库(不用无锁队列)"
    echo
    cat "$TMP/rowsD.txt"
    echo
    echo "### E. 登录:PBKDF2 1 万轮"
    echo
    cat "$TMP/rowsE.txt"
} | tee /tmp/bench-summary.md

echo
echo "汇总已保存:/tmp/bench-summary.md"
