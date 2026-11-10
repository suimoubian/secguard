#!/bin/bash
# 从离线缓存恢复镜像
#
# 为什么需要它:这台服务器的外网到 Docker 官方 registry 不通,
# 靠的是镜像加速器。万一加速器挂了、或者镜像被 docker system prune 删了,
# 有这份本地缓存就能在完全离线的情况下把服务恢复起来。
#
# 用法:
#   ./scripts/offline-restore.sh              # 恢复所有缺的镜像
#   ./scripts/offline-restore.sh --check      # 只检查,不改动
#   CACHE_DIR=/path ./scripts/offline-restore.sh
#
# 缓存在哪:~/.image-cache/(deploy 时由 make-image-cache 生成)

set -uo pipefail

CACHE_DIR="${CACHE_DIR:-$HOME/.image-cache}"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; NC=$'\033[0m'
ok()   { printf '%s%s%s\n' "$GREEN" "$*" "$NC"; }
warn() { printf '%s%s%s\n' "$YELLOW" "$*" "$NC"; }
die()  { printf '%s%s%s\n' "$RED" "$*" "$NC" >&2; exit 1; }

# 服务需要的镜像:compose 里写死的那些
IMAGES=(
    "secguard-app:latest"
    "mysql:8.0"
    "redis:7-alpine"
    "nginx:1.27-alpine"
)

[ -d "$CACHE_DIR" ] || die "缓存目录不存在: $CACHE_DIR
先在有网的机器上生成,或者按下面方式导出:
  docker save <镜像> | gzip -1 > ~/.image-cache/<名字>.tar.gz"

missing=0
say() { printf '%s\n' "$*"; }

say "缓存目录: $CACHE_DIR"
say ""

for img in "${IMAGES[@]}"; do
    safe=$(printf '%s' "$img" | tr '/:' '__')
    tarball="$CACHE_DIR/${safe}.tar.gz"

    have_local=0
    docker image inspect "$img" > /dev/null 2>&1 && have_local=1

    if [ "$have_local" = "1" ]; then
        ok "  已存在   $img"
        continue
    fi

    if [ ! -f "$tarball" ]; then
        warn "  缺缓存   $img  (找不到 $tarball)"
        missing=$((missing + 1))
        continue
    fi

    if [ "$CHECK_ONLY" = "1" ]; then
        warn "  可恢复   $img  <- $(basename "$tarball") ($(du -h "$tarball" | cut -f1))"
        missing=$((missing + 1))
        continue
    fi

    say "  恢复中   $img ..."
    if gunzip -c "$tarball" | docker load; then
        ok "  已恢复   $img"
    else
        die "  恢复失败 $img —— 缓存文件可能损坏:$tarball"
    fi
done

say ""
if [ "$missing" -gt 0 ]; then
    if [ "$CHECK_ONLY" = "1" ]; then
        warn "有 $missing 个镜像需要恢复,执行不带 --check 即可"
        exit 0
    fi
    die "有 $missing 个镜像没有本地缓存,需要联网拉取:
  sudo docker compose pull"
fi

ok "全部就绪"
if [ "$CHECK_ONLY" != "1" ]; then
    say "下一步: ./docker/deploy.sh"
fi
