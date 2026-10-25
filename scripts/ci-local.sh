#!/bin/bash
# 在本地模拟 CI 会做的事,提前发现问题
#
# 为什么要在本地模拟:CI 挂了要等推送之后才知道,来回一轮好几分钟。
# 这些检查本地都能跑,先过一遍再推。

cd /home/smb/projects/secguard || exit 1
FAIL=0

step() { printf '\n\033[1m>>> %s\033[0m\n' "$1"; }
ok()   { printf '  \033[32mOK\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31m失败\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }

step "1. 干净配置 + 编译"
rm -rf build-ci
if cmake -S . -B build-ci -DCMAKE_BUILD_TYPE=Release > /tmp/ci-cfg.log 2>&1; then
    ok "cmake 配置通过"
else
    bad "cmake 配置失败"; tail -20 /tmp/ci-cfg.log; exit 1
fi

if cmake --build build-ci -j"$(nproc)" > /tmp/ci-build.log 2>&1; then
    ok "编译通过"
else
    bad "编译失败"; grep -E 'error:' /tmp/ci-build.log | head -10; exit 1
fi

step "2. 编译警告(CI 会因警告失败)"
n_warn=$(grep -cE 'warning: [^ ]' /tmp/ci-build.log || true)
if [ "${n_warn:-0}" -eq 0 ]; then
    ok "零警告"
else
    bad "有 $n_warn 条警告"; grep -E 'warning: [^ ]' /tmp/ci-build.log | head -10
fi

step "3. AC 对拍 20000 次"
if ./build-ci/ac_test 20000 > /tmp/ci-ac.log 2>&1; then
    ok "$(grep -c '不一致 0 次' /tmp/ci-ac.log) 组对拍零差异"
else
    bad "对拍失败"; tail -10 /tmp/ci-ac.log
fi

step "4. 单元自检"
if ./build-ci/unit_test > /tmp/ci-unit.log 2>&1; then
    ok "全部通过"
else
    bad "单元自检失败"; tail -15 /tmp/ci-unit.log
fi

step "5. 引擎微基准可运行"
if ./build-ci/ac_bench 200 1024 > /tmp/ci-bench.log 2>&1; then
    ok "基准输出正常"
else
    bad "基准运行失败"
fi

step "5b. WAF 绕过评测(门禁)"
# 为什么有这一步:加规则/改归一化/调策略,很容易"补一个漏报、带出三个误报"。
# 光看报告看不出来,必须让数字自己卡住。阈值见 scripts/eval-waf.sh 的注释。
if ./build-ci/waf_eval --rules rules/attack_patterns.txt \
        --policy rules/policy.conf \
        --corpus tools/waf_eval/corpus --repeat 3 \
        --max-miss 0.10 --max-fp 0.25 > /tmp/ci-eval.log 2>&1; then
    ok "$(grep '变形样本' /tmp/ci-eval.log)"
    ok "$(grep '正常样本' /tmp/ci-eval.log)"
    ok "$(grep '策略' /tmp/ci-eval.log | head -1)"
else
    bad "评测门禁未通过"
    grep -E '变形样本|正常样本|门禁' /tmp/ci-eval.log | head -6
fi

step "6. DAO 层测试(没有数据库会自动跳过)"
if SECGUARD_DB_USER="${SECGUARD_DB_USER:-secguard}" \
   SECGUARD_DB_PASS="${SECGUARD_DB_PASS:-secguard_dev_2026}" \
   ./build-ci/dao_test > /tmp/ci-dao.log 2>&1; then
    if grep -q '跳过' /tmp/ci-dao.log; then
        ok "已跳过(连不上数据库)"
    else
        ok "$(grep -c '通过' /tmp/ci-dao.log) 项 DAO 断言通过"
    fi
else
    bad "DAO 测试失败"; tail -15 /tmp/ci-dao.log
fi

rm -rf build-ci

printf '\n==================================================\n'
if [ "$FAIL" -eq 0 ]; then
    printf ' \033[32mCI 预检全部通过,可以推送\033[0m\n'
else
    printf ' \033[31m有 %d 项失败,先修再推\033[0m\n' "$FAIL"
fi
printf '==================================================\n'
[ "$FAIL" -eq 0 ]
