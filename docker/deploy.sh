#!/bin/bash
# SecGuard 服务器部署脚本
#
# 在一台干净的 Ubuntu 22.04 / 24.04 上,把项目跑起来。
# 用法:
#   ./docker/deploy.sh             # 部署/更新
#   ./docker/deploy.sh status      # 看状态
#   ./docker/deploy.sh logs        # 看日志
#   ./docker/deploy.sh stop        # 停服
#
# 前提:已装 docker 与 compose v2。脚本会先检查。

set -euo pipefail
cd "$(dirname "$0")/.."

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; NC=$'\033[0m'
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s%s%s\n' "$GREEN" "$*" "$NC"; }
warn() { printf '%s%s%s\n' "$YELLOW" "$*" "$NC"; }
die()  { printf '%s%s%s\n' "$RED" "$*" "$NC" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 前置检查:缺什么就说清楚缺什么,别让人猜
# ---------------------------------------------------------------------------
check_prereq() {
    command -v docker > /dev/null 2>&1 || die "没装 docker。先装:
  curl -fsSL https://get.docker.com | sh"
    docker compose version > /dev/null 2>&1 || die "没装 docker compose v2。先装:
  sudo apt install docker-compose-v2"
    docker info > /dev/null 2>&1 || die "docker 守护进程没起来,或者当前用户不在 docker 组。
  试: sudo systemctl start docker && sudo usermod -aG docker \$USER (然后重新登录)"
    [ -f .env ] || die "缺 .env。先执行:
  cp .env.example .env
  然后改掉里面的 MYSQL_ROOT_PASSWORD / SECGUARD_DB_PASS / SECGUARD_JWT_SECRET"

    # .env 里的占位值必须被改掉,否则等于没设密码
    if grep -q 'change-me' .env; then
        die ".env 里还有 change-me 占位值。生成一个真密钥:
  openssl rand -base64 48"
    fi
}

# ---------------------------------------------------------------------------
# 从 .env 读对外端口。多个子命令都要用,抽出来避免各处各写一遍。
# (踩过的坑:status 子命令忘了读 .env,于是去探 80 端口,而实际配的是 8088,
#  结果服务明明正常却报"健康检查失败"。)
read_port() {
    local port=80
    if [ -f .env ]; then
        local v
        v=$(grep -E '^SECGUARD_HTTP_PORT=' .env | cut -d= -f2 | tr -d '"' | tr -d ' ')
        port=${v:-80}
    fi
    printf '%s' "$port"
}

cmd_status() {
    docker compose ps
    say ""
    say "健康检查:"
    local port
    port=$(read_port)
    if curl -fsS "http://127.0.0.1:${port}/health" 2>/dev/null; then
        say ""
        ok "服务在线(http://127.0.0.1:${port})"
    else
        warn "健康检查失败(http://127.0.0.1:${port}/health)—— 看日志: ./docker/deploy.sh logs"
    fi
}

cmd_logs() {
    docker compose logs -f --tail=100 "${1:-}"
}

cmd_stop() {
    docker compose down
    ok "已停止(数据卷保留,重启不丢数据)"
}

cmd_deploy() {
    check_prereq

    say "==> 构建镜像"
    docker compose build

    say "==> 启动"
    docker compose up -d

    say "==> 等健康检查通过"
    local port
    port=$(read_port)

    local i
    for i in $(seq 1 30); do
        if curl -fsS "http://127.0.0.1:${port}/health" > /dev/null 2>&1; then
            ok "服务已就绪: http://127.0.0.1:${port}"
            curl -s "http://127.0.0.1:${port}/health" | head -c 400
            say ""
            return 0
        fi
        sleep 2
    done

    die "60 秒内没通过健康检查。看日志:
  docker compose logs --tail=80 app"
}

case "${1:-deploy}" in
    deploy) cmd_deploy ;;
    status) cmd_status ;;
    logs)   cmd_logs "${2:-}" ;;
    stop)   cmd_stop ;;
    *)      die "用法: $0 [deploy|status|logs|stop]" ;;
esac
