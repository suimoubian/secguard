#!/bin/bash
# 检查"配置三处清单"是否一致
#
# 背景:同一个配置要出现在三个地方才真正生效 ——
#   1. 代码里 env_str/env_int 读它           (src/util/config.cpp)
#   2. docker-compose.yml 传给容器           (或 env_file 把 .env 整体传进去)
#   3. .env.example 文档化                   (使用者才知道有这个开关)
#
# 这个坑踩过三次:
#   SECGUARD_AI_MERGE_IPS / SECGUARD_AUDIT_RETENTION_DAYS / SECGUARD_THREADS 等
#   —— 在 .env 里改了不生效,查很久。
#
# 本脚本做三件事:
#   A. .env 里设了、但代码根本不读的项   -> 拼错名字的典型症状,必须报错
#   B. 代码读、但 .env.example 没文档化的 -> 使用者不知道能调,报错
#   C. compose 有 environment 且没有 env_file 时,检查是否有变量漏传 -> 报错
#
# 退出码:有问题返回 1(可挂到 CI 或本地自检)

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; NC=$'\033[0m'
fail=0
err()  { printf '%s%s%s\n' "$RED" "$*" "$NC"; fail=1; }
ok()   { printf '%s%s%s\n' "$GREEN" "$*" "$NC"; }
warn() { printf '%s%s%s\n' "$YELLOW" "$*" "$NC"; }

# ---- 采集三份清单 ----
grep -rhoE '(env_str|env_int|env_double|env_bool|getenv)\("[A-Z_]+"' src/ \
  | sed 's/.*("//; s/"//' | sort -u > /tmp/_cfg_code.txt
# 注释形式(# SECGUARD_X=默认值)也算文档化 —— 这是"记录默认值、不覆盖"的写法
grep -oE '^#?[[:space:]]*([A-Z_]+)=' .env.example 2>/dev/null \
  | sed 's/^[#[:space:]]*//; s/=$//' | sort -u > /tmp/_cfg_example.txt
[ -f .env ] && grep -oE '^[A-Z_]+=' .env | tr -d '=' | sort -u > /tmp/_cfg_env.txt || : > /tmp/_cfg_env.txt

n_code=$(wc -l < /tmp/_cfg_code.txt)
n_ex=$(wc -l < /tmp/_cfg_example.txt)
n_env=$(wc -l < /tmp/_cfg_env.txt)

echo "=================================================================="
echo " 配置三处一致性检查"
echo "   代码读取      $n_code 项"
echo "   .env.example  $n_ex 项"
echo "   .env          $n_env 项"
echo "=================================================================="

# ---- 检查 A:.env 里设了但代码不读 ----
echo
echo "[A] .env 里设了、但代码根本不读(名字拼错会这样)"
dead=$(comm -23 /tmp/_cfg_env.txt /tmp/_cfg_code.txt | grep '^SECGUARD_' || true)
if [ -n "$dead" ]; then
  # compose 层面使用的变量不算错(如 SECGUARD_HTTP_PORT 只给 ports 用)
  truly_dead=""
  while read -r v; do
    [ -z "$v" ] && continue
    if ! grep -q "\${$v" docker-compose.yml 2>/dev/null && ! grep -q "^      $v:" docker-compose.yml 2>/dev/null; then
      truly_dead="$truly_dead $v"
    fi
  done <<< "$dead"
  if [ -n "$truly_dead" ]; then
    err "  ✗ 以下变量设了但没人读(检查拼写):$truly_dead"
  else
    ok "  ✓ 无( compose 层使用的变量已排除)"
  fi
else
  ok "  ✓ 无"
fi

# ---- 检查 B:代码读但 .env.example 没文档化 ----
echo
echo "[B] 代码读、但 .env.example 没写(使用者不知道能调)"
undoc=$(comm -23 /tmp/_cfg_code.txt /tmp/_cfg_example.txt | grep '^SECGUARD_' || true)
if [ -n "$undoc" ]; then
  err "  ✗ 未文档化 $(echo "$undoc" | wc -l) 项:"
  echo "$undoc" | sed 's/^/      /'
else
  ok "  ✓ 全部已文档化"
fi

# ---- 检查 C:compose 是否传进容器 ----
echo
echo "[C] 代码读的变量能否到达容器"
if grep -qE '^\s+env_file:' docker-compose.yml 2>/dev/null; then
  ok "  ✓ app 服务用了 env_file,.env 里的变量会整体传入"
  # 但要确认 environment 块没有把 .env 的覆盖掉成错误值
  bad_override=$(grep -E '^      [A-Z_]+: "\$?\$' docker-compose.yml 2>/dev/null || true)
  [ -n "$bad_override" ] && warn "  ! environment 里有可疑覆盖:" && echo "$bad_override" | sed 's/^/      /'
else
  grep -oE '^      [A-Z_]+:' docker-compose.yml | tr -d ' :' | sort -u > /tmp/_cfg_compose.txt
  missing=$(comm -23 /tmp/_cfg_code.txt /tmp/_cfg_compose.txt | grep '^SECGUARD_' || true)
  if [ -n "$missing" ]; then
    err "  ✗ 没有 env_file,且有 $(echo "$missing" | wc -l) 项漏传(容器里只能用默认值):"
    echo "$missing" | sed 's/^/      /'
  else
    ok "  ✓ 全部显式传入"
  fi
fi

echo
echo "=================================================================="
if [ "$fail" = "1" ]; then
  err " 检查未通过 —— 配置三处不一致"
else
  ok " 检查通过"
fi
echo "=================================================================="
exit "$fail"
