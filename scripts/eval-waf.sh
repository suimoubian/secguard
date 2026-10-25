#!/usr/bin/env bash
# 一键跑 WAF 检出力评测(项目 A)
#
# 用法:
#   ./scripts/eval-waf.sh              # 跑一遍,报告写到 docs/评测数据/
#   REPEAT=50 ./scripts/eval-waf.sh    # 多跑几轮取平均(性能数字更稳)
#   ./scripts/eval-waf.sh --gate       # 门禁模式:指标越界就返回非 0,给 CI 用
#
# 产出:
#   docs/评测数据/最新.md        总览 / 分类别 / 按手法 / 误报明细 / 性能
#   docs/评测数据/最新漏报.md    基线漏报 + 加固后仍漏报的逐条清单
#
# 为什么要有门禁:规则改动很容易"补了一个漏报、带出三个误报"。
# 只靠肉眼看报告看不出回归,必须让数字自己卡住。
set -euo pipefail

cd "$(dirname "$0")/.."

BUILD_DIR="${BUILD_DIR:-build}"
REPEAT="${REPEAT:-20}"
OUT_DIR="docs/评测数据"
GATE=0
for arg in "$@"; do
    case "$arg" in
        --gate) GATE=1 ;;
        *) echo "未知参数: $arg" >&2; exit 2 ;;
    esac
done

if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
    echo "[评测] 配置 $BUILD_DIR"
    cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release >/dev/null
fi
echo "[评测] 编译 waf_eval"
cmake --build "$BUILD_DIR" -j"$(nproc)" --target waf_eval >/dev/null

mkdir -p "$OUT_DIR"

ARGS=(--rules rules/attack_patterns.txt
      --policy rules/policy.conf
      --corpus tools/waf_eval/corpus
      --out "$OUT_DIR/最新.md"
      --miss "$OUT_DIR/最新漏报.md"
      --repeat "$REPEAT")

if [ "$GATE" = "1" ]; then
    # 阈值是这样定的:留出"正常增删规则"的余量,但拦住"明显变差"。
    # 漏报率 10%、误拦截率 25% 是当前水平的红线;要调整就明确改这里,
    # 并说明为什么 —— 改阈值比改检测逻辑容易,所以必须写下来。
    #
    # 注意门禁看的是**误拦截率**(真的返回 403),不是"命中率"。
    # 否则把规则全降级成 ALERT 就能让门禁变绿 —— 那是假绿。
    ARGS+=(--max-miss 0.10 --max-fp 0.25)
fi

"$BUILD_DIR/waf_eval" "${ARGS[@]}" 2>/dev/null | grep -vE '^\[引擎\]|INFO|WARN' || {
    rc=$?
    if [ "$GATE" = "1" ]; then
        echo "[评测] 门禁未通过" >&2
        exit "$rc"
    fi
    exit "$rc"
}

echo "[评测] 报告: $OUT_DIR/最新.md"
echo "[评测] 漏报: $OUT_DIR/最新漏报.md"
