#!/bin/bash
# 打印"实际生效"的配置
#
# 为什么要这个:
#   配置散在 .env / docker-compose.yml / rules/ / 系统级文件 六个地方,
#   想知道"现在到底跑的是什么参数"得翻六个文件。
#   这个脚本直接从**运行中的容器**里读,那才是真相。
#
# 用法:
#   ./scripts/show-config.sh              # 打印(密钥打码)
#   ./scripts/show-config.sh --secrets    # 连密钥一起显示(慎用)
#   ./scripts/show-config.sh --diff       # 只显示与 .env.example 默认值不同的项

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

SHOW_SECRETS=0
DIFF_ONLY=0
for a in "$@"; do
  case "$a" in
    --secrets) SHOW_SECRETS=1 ;;
    --diff)    DIFF_ONLY=1 ;;
  esac
done

CONTAINER="${CONTAINER:-secguard-app}"
if ! sudo docker inspect "$CONTAINER" > /dev/null 2>&1; then
  echo "找不到容器 $CONTAINER(容器没跑?)" >&2
  exit 1
fi

# 从容器里拿出全部 SECGUARD_* 环境变量并排序
ENV_DUMP=$(sudo docker exec "$CONTAINER" printenv 2>/dev/null | grep '^SECGUARD_' | sort)

redact() {
  local k="$1" v="$2"
  case "$k" in
    *KEY*|*PASS*|*SECRET*|*TOKEN*) [ "$SHOW_SECRETS" = "1" ] && echo "$v" || echo "******(已打码)" ;;
    *) echo "$v" ;;
  esac
}

echo "=================================================================="
echo " SecGuard 实际生效配置"
echo " 容器: $CONTAINER"
echo " 时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "=================================================================="

n=0
while IFS='=' read -r k v; do
  [ -z "$k" ] && continue
  # --diff 模式:只显示和 .env.example 里不同、或 example 里没有的
  if [ "$DIFF_ONLY" = "1" ]; then
    ex=$(grep -E "^${k}=" .env.example 2>/dev/null | head -1 | cut -d= -f2-)
    if [ -n "$ex" ] && [ "$ex" = "$v" ]; then continue; fi
  fi
  printf '  %-34s %s\n' "$k" "$(redact "$k" "$v")"
  n=$((n+1))
done <<< "$ENV_DUMP"

echo "------------------------------------------------------------------"
echo "  共 $n 项"

echo
echo "------------------------------------------------------------------"
echo " 代码读的环境变量总数:  $(grep -rhoE '(env_str|env_int|env_double|env_bool|getenv)\("[A-Z_]+"' src/ \
  | sed 's/.*("//; s/"//' | sort -u | wc -l)"
echo " 容器实际收到的数量:    $(echo "$ENV_DUMP" | grep -c '^SECGUARD_')"
echo " (差值 = 用代码默认值运行的项,不算错 —— 但要能查到默认值,见 docs/配置清单.md)"

echo
echo "------------------------------------------------------------------"
echo " 其他位置的配置(不在容器环境变量里)"
echo "------------------------------------------------------------------"
printf '  %-40s %s\n' "审计保留天数"        "$(grep '^SECGUARD_AUDIT_RETENTION_DAYS=' .env 2>/dev/null | cut -d= -f2- || echo '(代码默认 30)')"
printf '  %-40s %s\n' "规则文件"            "$(stat -c '%y' rules/attack_patterns.txt 2>/dev/null | cut -d. -f1)"
printf '  %-40s %s\n' "规则条数"            "$(grep -vc '^#\|^$' rules/attack_patterns.txt 2>/dev/null)"
printf '  %-40s %s\n' "策略文件"            "rules/policy.conf"
printf '  %-40s %s\n' "白名单文件"          "rules/allowlist.conf"
printf '  %-40s %s\n' "数据库 schema"       "db/schema.sql"
printf '  %-40s %s\n' "nginx 配置"          "docker/nginx.conf"
printf '  %-40s %s\n' "管理员密码"          "服务器 ~/.admin_password(600)"
printf '  %-40s %s\n' "备份目录"            "服务器 ~/backups(700,cron 每天 03:30)"
printf '  %-40s %s\n' "docker 镜像源"       "/etc/docker/daemon.json"
printf '  %-40s %s\n' "SSH 加固"            "/etc/ssh/sshd_config(禁密码登录)"
