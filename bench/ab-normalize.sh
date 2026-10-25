#!/bin/bash
# 归一化层的端到端 A/B 复测(项目 A)
#
# 为什么不能只信 tools/waf_eval 的数字:
#   那套是"引擎级微基准" —— 直接把待检文本喂给 Engine::search。
#   真实链路上还有 HTTP 解析、路由、审计落库、限流封禁,归一化层的
#   相对代价会被这些固定开销稀释。面试被问"这个 +0.37µs 在线上是多少",
#   只有端到端数字能回答。
#
# 做法:
#   另起一个**独立的** benchmark 容器(不动 compose 里那套服务),
#   从宿主机 wrk 直连它的 8080,绕开 nginx 的 limit_conn(单 IP 50 连接),
#   用 64 连接 + 2 核绑定的口径,和 docs/性能数据.md 的条件对齐。
#
# 用法:
#   ./bench/ab-normalize.sh check     # 等主服务就绪 + 跑一遍自检(54 项)
#   ./bench/ab-normalize.sh bench     # 跑 A/B 压测,输出 markdown 表格
#   ./bench/ab-normalize.sh all
#
# 注意:压测期间不要跑 verify.sh —— 它自带 3 秒压测,叠加会把 nginx 打满,
#       表现是一堆 502,查起来很费劲(项目现状.md 第七节记过这个坑)。
set -u
cd "$(dirname "$0")/.." || exit 1

# 数据库口令这些放在 .env 里(compose 也读它)。压测容器和主服务共用一套库,
# 单独再配一遍只会多一个会不同步的地方。
if [ -z "${SECGUARD_DB_PASS:-}" ] && [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
fi

IMAGE="secguard-app:latest"
PORT="${PORT:-8099}"
# 线上入口端口从 .env 取(项目里默认是 8088,不是 80)。
# 写死 80 的后果是 check 模式白等 80 秒才报超时 —— 踩过。
HTTP_PORT="${SECGUARD_HTTP_PORT:-8088}"
SERVER_CPUS="${SERVER_CPUS:-0,1}"
WRK_CPUS="${WRK_CPUS:-4,5,6,7}"
DURATION="${DURATION:-8s}"
CONNS="${CONNS:-64}"
THREADS="${THREADS:-4}"
REPEAT="${REPEAT:-3}"
CNAME="secguard-bench"
TMP=$(mktemp -d)
CPID=""

cleanup() {
    [ -n "$CPID" ] && docker rm -f "$CNAME" >/dev/null 2>&1
    rm -rf "$TMP"
}
trap cleanup EXIT

hr() { echo "----------------------------------------------------------------"; }

# ---------------------------------------------------------------------------
# 起一个 benchmark 专用容器
#   $1 = 归一化开关(1/0)
# ---------------------------------------------------------------------------
start_bench() {
    local norm="$1"
    docker rm -f "$CNAME" >/dev/null 2>&1
    local net
    net=$(docker inspect secguard-app \
          -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null)
    [ -n "$net" ] || { echo "!! 找不到 secguard-app 所在的网络"; return 1; }

    # 限流/封禁关掉:它们会把压测变成"测 Redis",而不是测检测链路。
    # 这组值和 bench/run.sh 保持一致,便于和已有数据对比。
    docker run -d --name "$CNAME" --network "$net" \
        --cpuset-cpus "$SERVER_CPUS" \
        -p "127.0.0.1:${PORT}:8080" \
        -e SECGUARD_DB_HOST=mysql -e SECGUARD_DB_PORT=3306 \
        -e SECGUARD_DB_USER="${SECGUARD_DB_USER:-secguard}" \
        -e SECGUARD_DB_PASS="${SECGUARD_DB_PASS:?需要在环境变量里给 SECGUARD_DB_PASS}" \
        -e SECGUARD_DB_NAME="${SECGUARD_DB_NAME:-secguard}" \
        -e SECGUARD_JWT_SECRET=bench-secret-please-change-in-production \
        -e SECGUARD_REDIS_HOST=redis -e SECGUARD_REDIS_PORT=6379 \
        -e SECGUARD_PORT=8080 -e SECGUARD_BIND=0.0.0.0 \
        -e SECGUARD_THREADS="$CONNS" \
        -e SECGUARD_LOG_LEVEL=warn \
        -e SECGUARD_PATTERN_FILE=/app/rules/attack_patterns.txt \
        -e SECGUARD_RATE_PER_SEC=1000000 -e SECGUARD_RATE_BURST=1000000 \
        -e SECGUARD_HIT_THRESHOLD=100000000 -e SECGUARD_BAN_SECONDS=1 \
        -e SECGUARD_TRUST_PROXY=1 \
        -e SECGUARD_AI_ENABLE=0 \
        -e SECGUARD_ENGINE_NORMALIZE="$norm" \
        "$IMAGE" >/dev/null || return 1

    CPID="$CNAME"
    for _ in $(seq 1 40); do
        if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then return 0; fi
        sleep 0.5
    done
    echo "!! benchmark 容器没起来"
    docker logs --tail 20 "$CNAME" 2>&1
    return 1
}

stop_bench() {
    docker rm -f "$CNAME" >/dev/null 2>&1
    CPID=""
    sleep 1
}

# ---------------------------------------------------------------------------
# 功能验证:同一个编码载荷,归一化关=放行、开=拦截
# ---------------------------------------------------------------------------
func_check() {
    echo
    echo "### 功能验证(编码载荷在 HTTP 层是否被拦)"
    echo
    printf '| 载荷 | 归一化关 | 归一化开 |\n|---|---|---|\n'
    local payloads=(
        'id=1%20or%201=1--|SQL 注入(空格编码)'
        'q=%3Cscr%69pt%3E|XSS(标签名部分编码)'
        'file=%2e%2e%5c%2e%2e%5cwindows%5cwin.ini|路径穿越(反斜杠编码)'
        'q=java%0Ascript:1|XSS(scheme 内插换行)'
    )
    for item in "${payloads[@]}"; do
        local q="${item%%|*}" name="${item##*|}"
        local off on
        start_bench 0 >/dev/null 2>&1
        off=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/api/posts?${q}")
        stop_bench
        start_bench 1 >/dev/null 2>&1
        on=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/api/posts?${q}")
        stop_bench
        printf '| %s | %s | %s |\n' "$name" "$off" "$on"
    done
}

# ---------------------------------------------------------------------------
# 压测:两条工作负载 × 两种配置
#   plain   :没有变形标记 -> 归一化遍走快路,理论上零差异(对照组)
#   encoded :带 %XX      -> 归一化遍真的执行,这是要量的成本
# ---------------------------------------------------------------------------
run_wrk() {   # $1=url 输出 rps p99
    local out="$TMP/wrk.txt"
    taskset -c "$WRK_CPUS" wrk -t"$THREADS" -c"$CONNS" -d"$DURATION" --latency "$1" > "$out" 2>&1
    local rps p99
    rps=$(grep -oE 'Requests/sec:[[:space:]]+[0-9.]+' "$out" | grep -oE '[0-9.]+$')
    p99=$(grep -E '^[[:space:]]*99%' "$out" | awk '{print $2}')
    echo "${rps:-0} ${p99:-?}"
}

median() { sort -g | awk '{a[NR]=$1} END {print (NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2}'; }

warmup() {   # 让自动机、连接池、DB 缓存、审计队列都热起来,再开始计时
    taskset -c "$WRK_CPUS" wrk -t2 -c"$CONNS" -d5s "$1" >/dev/null 2>&1
    # 再完整扔一次并丢弃:容器刚起来的第一组样本会带 1s 级的冷启动尾巴
    # (连接池/预编译语句/审计队列都还没热),混进中位数里会把结论带偏。
    run_wrk "$1" >/dev/null 2>&1
}

# 交错测量:每一轮里"关/开"交替跑,而不是先把一档全跑完再跑另一档。
# 为什么:这台机器上 docker、WSL、其它容器都在抢 CPU,性能会缓慢漂移。
# 分组跑会把"漂移"算进"配置差异"里,得到好看但假的结论。
bench_interleaved() {   # $1=原始数据输出文件
    local out="$1"
    local arms=(
        "plain|http://127.0.0.1:${PORT}/api/posts?page=2&sort=desc"
        "encoded|http://127.0.0.1:${PORT}/api/posts?q=%E4%B8%AD%E6%96%87%E6%90%9C%E7%B4%A2&page=1"
    )
    local rep mode arm name url r p
    for rep in $(seq 1 "$REPEAT"); do
        for mode in 0 1; do
            start_bench "$mode" >/dev/null 2>&1 || { echo "!! benchmark 容器起不来"; return 1; }
            warmup "http://127.0.0.1:${PORT}/api/posts?page=2"
            for arm in "${arms[@]}"; do
                name="${arm%%|*}"; url="${arm##*|}"
                read -r r p <<< "$(run_wrk "$url")"
                printf '%s %s %s %s\n' "$name" "$mode" "$r" "$p" >> "$out"
            done
            stop_bench
        done
    done
}

do_bench() {
    echo
    echo "### 端到端 A/B(直连 app,绕开 nginx;2 核 / ${CONNS} 连接 / ${THREADS} 线程 / ${DURATION} × ${REPEAT} 轮交错)"
    echo
    bench_interleaved "$TMP/raw.txt" || return 1

    printf '| 工作负载 | 归一化关 QPS | 归一化开 QPS | 吞吐变化 | 关 P99 | 开 P99 |\n'
    printf '|---|---|---|---|---|---|\n'
    local arms=("plain|无变形标记(对照组)" "encoded|带 %XX 编码(第二遍执行)")
    for a in "${arms[@]}"; do
        local key="${a%%|*}" label="${a##*|}"
        local r0 r1 p0 p1 delta
        r0=$(awk -v k="$key" '$1==k && $2==0 {print $3}' "$TMP/raw.txt" | median)
        r1=$(awk -v k="$key" '$1==k && $2==1 {print $3}' "$TMP/raw.txt" | median)
        p0=$(awk -v k="$key" '$1==k && $2==0 {print $4}' "$TMP/raw.txt" | sort -g | tail -1)
        p1=$(awk -v k="$key" '$1==k && $2==1 {print $4}' "$TMP/raw.txt" | sort -g | tail -1)
        delta=$(awk -v a="$r0" -v b="$r1" 'BEGIN{ if(a>0) printf "%+.1f%%", (b-a)/a*100; else print "?" }')
        printf '| %s | %s | %s | %s | %s | %s |\n' "$label" "$r0" "$r1" "$delta" "$p0" "$p1"
    done
    echo
    echo "**怎么读这张表**:plain 是没有变形标记的对照组 —— 它走快路,"
    echo "两种配置执行的代码**完全相同**,所以它那一行的差异就是**噪声水平**。"
    echo "encoded 那一行的差异只有明显超过噪声,才能归因于归一化层。"
    echo
    echo "原始数据(每轮 关/开 交替,共 ${REPEAT} 轮):"
    echo '```'
    cat "$TMP/raw.txt"
    echo '```'
}

case "${1:-all}" in
    check)
        echo "[1] 等主服务就绪(经 nginx:${HTTP_PORT})"
        for _ in $(seq 1 40); do
            c=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${HTTP_PORT}/health" 2>/dev/null)
            [ "$c" = "200" ] && break
            sleep 2
        done
        echo "  /health -> ${c:-超时}"
        echo "[2] 跑自检(54 项)"
        ./scripts/verify.sh
        ;;
    bench) do_bench ;;
    func)  func_check ;;
    all)   func_check; do_bench ;;
    *) echo "用法: $0 [check|func|bench|all]"; exit 2 ;;
esac
