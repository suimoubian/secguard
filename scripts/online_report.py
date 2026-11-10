#!/usr/bin/env python3
"""线上观测报告:把 audit_log 变成一份能进简历的 markdown。

为什么要有这个脚本
------------------
服务器跑起来之后,审计表每天都在涨,但"涨了多少"不等于"有人在打我"。
这份报告回答的是:

  - 谁在打?从哪来?(来源 IP / 网段)
  - 打的什么?(被探测的路径 —— 路径本身就是扫描器指纹)
  - 被拦住了吗?(BLOCK / ALERT / 放过)
  - 策略层有没有被利用?(只命中 ALERT、从未被拦的 IP)
  - 攻击有多工具化?(同一个载荷重复了多少次)

为什么只能做到这些
------------------
`audit_log` 里 **不存 payload 原文**:`params_digest` 只有
`sha256 前缀 + len=NNN`,是刻意设计的(审计不该成为第二个泄漏点)。
所以"攻击原文分析"做不了,只能靠路径、规则命中、长度和重复度反推。
这是取舍,不是缺陷 —— 报告里会把这条限制写在开头,免得读者误解。

用法(在服务器上跑)
------------------
    cd ~/secguard
    sudo python3 scripts/online_report.py                 # 最近 7 天,打到终端
    sudo python3 scripts/online_report.py --days 30
    sudo python3 scripts/online_report.py --out docs/观测记录/2026-10-26.md

`sudo` 是因为服务器上的 docker 需要 root(部署时用的也是 `sudo docker compose`)。
脚本自己会按文件位置定位项目根,不需要先 cd。

依赖:python3(标准库)+ 正在运行的 secguard-mysql 容器。
"""
import argparse
import ipaddress
import os
import re
import subprocess
import sys
from datetime import datetime

CONTAINER = "secguard-mysql"

# 项目根目录(scripts/ 的上一级)。用绝对路径,这样从任何目录跑都能找到
# .env 和 rules/,不用先 cd 到项目根。
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 路径特征 -> 推测的工具/攻击类型。
# 注意:审计表里没有 User-Agent,所以这里只能"按路径推测",不能断言是哪个工具。
# 这些路径的共同点是:正常业务不会访问,只有扫描器/漏洞利用工具才会打。
PATH_SIGNATURES = [
    (r"(^|/)\.git/", "源码仓库泄露探测"),
    (r"(^|/)\.env", "环境变量文件探测"),
    (r"(^|/)\.svn/", "SVN 泄露探测"),
    (r"(^|/)\.aws/|\.ssh/|id_rsa", "云凭证 / SSH 私钥探测"),
    (r"wp-login|wp-admin|/wordpress|xmlrpc\.php", "WordPress 扫描"),
    (r"phpmyadmin|/pma|/dbadmin", "phpMyAdmin 探测"),
    (r"actuator|/env$|/heapdump", "Spring Boot Actuator 探测"),
    (r"/solr/|/console/", "Solr 控制台探测"),
    (r"manager/html|/host-manager", "Tomcat Manager 探测"),
    (r"cgi-bin|/icons/|/scripts/", "Nikto 类扫描"),
    (r"phpunit|/vendor/", "PHPUnit / 依赖目录探测"),
    (r"/owa/|/ecp/|autodiscover", "Exchange 探测"),
    (r"backup|\.zip$|\.sql$|\.tar\.gz$|www\.zip|/db\.", "备份文件探测"),
    (r"nacos|/druid/|swagger|/api-docs", "国产组件 / 接口文档探测"),
    (r"struts|\.action$|/s2-|ognl", "Struts2 探测"),
    (r"HNAP1|/boaform/|/GponForm/", "路由器 / IoT 漏洞探测"),
    (r"admin|login|manage|/system", "后台入口探测"),
    (r"phpinfo|/test\.php|/shell\.php|/1\.php", "后门 / 探针探测"),
    (r"\.well-known|robots\.txt|sitemap", "站点结构探测(低危)"),
]

# 这些不是特征库里的规则,而是防护层自己写进 rule_hit 的"合成命中"。
# 必须和内容规则分开统计:混在一起,"检测能力"会被限流/封禁淹没 ——
# 限流挡下的请求只说明对方打太快,不说明我们认出了攻击。
GUARD_PSEUDO_RULES = {
    "IP_BANNED": ("防护:封禁", "该 IP 已在封禁名单里"),
    "RATE_LIMITED": ("防护:限流", "超过令牌桶速率"),
    "REPLAY_DUPLICATE": ("防护:重放", "nonce 重复"),
    "REPLAY_STALE": ("防护:重放", "时间戳过期"),
    "REPLAY_MISSING_HEADERS": ("防护:重放", "缺 timestamp/nonce"),
    "LOGIN_FAIL": ("防护:登录节流", "连续登录失败被锁定"),
}


# ---------------------------------------------------------------------------
# 基础设施
# ---------------------------------------------------------------------------
def load_env(path=".env"):
    """读 .env。不用 source,避免把 shell 语义带进来;也不打印口令。"""
    cfg = {}
    if not os.path.exists(path):
        return cfg
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")
    return cfg


def mysql(sql, cfg):
    """跑一条 SQL,返回 list[list[str]]。口令走 MYSQL_PWD 环境变量,不上命令行。"""
    user = cfg.get("SECGUARD_DB_USER", "secguard")
    pwd = cfg.get("SECGUARD_DB_PASS", "")
    db = cfg.get("SECGUARD_DB_NAME", "secguard")
    cmd = ["docker", "exec", "-i", "-e", f"MYSQL_PWD={pwd}", CONTAINER,
           "mysql", f"-u{user}", "-N", "-B", "-e", sql, db]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        sys.exit("找不到 docker 命令")
    except subprocess.TimeoutExpired:
        sys.exit("SQL 超时(数据量太大?试试 --days 7)")
    if out.returncode != 0:
        sys.exit(f"SQL 失败:{out.stderr.strip()[:300]}\n"
                 f"(容器 {CONTAINER} 在跑吗?口令对吗?在项目根目录跑吗?)")
    rows = []
    for line in out.stdout.splitlines():
        if line == "":
            continue
        rows.append(line.split("\t"))
    return rows


def load_rules(path="rules/attack_patterns.txt"):
    """规则 ID -> (类别, 级别)。用来把 rule_hit 翻译成人话。"""
    table = {}
    if not os.path.exists(path):
        return table
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 4:
                table[parts[1].strip()] = (parts[2].strip(), parts[3].strip())
    return table


def is_internal(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True                      # 解析不了的不当成公网
    return (a.is_private or a.is_loopback or a.is_link_local
            or a.is_reserved or a.is_multicast)


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "---|" * len(headers)]
    for r in rows:
        out.append("| " + " | ".join(str(x) for x in r) + " |")
    return "\n".join(out)


def pct(a, b):
    return f"{a * 100.0 / b:.1f}%" if b else "—"


def section_provenance(total, public, self_traffic):
    """数据来源构成:这批数据里有多少是"自己打自己"。

    为什么必须先说这件事:部署时的 verify.sh(52 项,含并发压限流那一组)、
    demo 脚本、开发时的探测请求,全都会写进同一张 audit_log,而且看起来
    和真实攻击一模一样。不分开的话,报告会得出"我们每天被攻击 N 次"这种
    自己骗自己的结论 —— 拿去面试会被一眼看穿。
    """
    lines = ["## 零、数据来源构成(先看这一节)", ""]
    if total == 0:
        return "\n".join(lines + ["(无数据)", ""])

    lines += [md_table(["来源", "请求数", "占比", "说明"],
                       [["公网(真实外部流量)", f"{public:,}", pct(public, total),
                         "可能是扫描器,也可能是正常访客"],
                        ["内网 / 自测", f"{self_traffic:,}", pct(self_traffic, total),
                         "verify.sh / demo / 本机探测(127.0.0.1、docker 网桥)"]]), ""]

    share = public / total if total else 0.0
    if share < 0.2:
        lines += ["> ⚠️ **公网流量只占 %.0f%%,这份报告目前基本是「自己打自己」。**" % (share * 100),
                  ">",
                  "> 原因通常是:服务刚上线、新 IP 还没被 Shodan/Fofa 收录、端口不常见。",
                  "> **在公网占比过半之前,不要拿它当「真实攻击观测」对外讲。**",
                  "> 判断方法:等 3~7 天;或直接看下面「扫描器在找什么」有没有内容 ——",
                  "> 有 404 探测才说明外面有人摸到你了。", ""]
    elif share < 0.5:
        lines += ["> 公网占比 %.0f%%:真实流量已经混进来了,但自测流量仍然占大头,"
                  "引用数字时要说清楚口径。" % (share * 100), ""]
    return "\n".join(lines)


# 自家业务路由,不参与"扫描器指纹"判定 —— 否则 /api/login 会被标成"后台入口探测",
# 而它本来就是正常入口。判断一个路径"可疑"的前提是:它不该被访问。
OWN_ROUTE_RE = re.compile(r"^/(api/|health$|metrics$|$)")


def classify_path(uri):
    if OWN_ROUTE_RE.match(uri):
        return None
    for pat, label in PATH_SIGNATURES:
        if re.search(pat, uri, re.IGNORECASE):
            return label
    return None


# ---------------------------------------------------------------------------
# 报告各节
# ---------------------------------------------------------------------------
def section_overview(days, meta, actions, cfg):
    (total, uniq_ip, first, last) = meta
    total = int(total or 0)
    act = {a: int(n) for a, n in actions}
    blocked = act.get("BLOCK", 0)
    alerted = act.get("ALERT", 0)
    passed = act.get("PASS", 0)

    lines = ["## 一、总览", ""]
    if total == 0:
        lines += ["**最近 %d 天没有任何审计记录。**" % days, "",
                  "检查:1) 服务在跑吗 `docker compose ps`;"
                  "2) 有没有流量打到 8088;3) 审计管道是否在写库。" ""]
        return "\n".join(lines)

    lines += [md_table(
        ["指标", "值", "说明"],
        [["观察窗口", f"{first} ~ {last}", f"最近 {days} 天"],
         ["总请求", f"{total:,}", "含正常访问与攻击探测"],
         ["独立来源 IP", f"{uniq_ip}", "全量,未去内网"],
         ["拦截 BLOCK", f"{blocked:,} ({pct(blocked, total)})", "返回 403"],
         ["告警 ALERT", f"{alerted:,} ({pct(alerted, total)})", "命中但策略放行"],
         ["放行 PASS", f"{passed:,} ({pct(passed, total)})", "未命中或已白名单"],
        ]), ""]

    if uniq_ip:
        lines += ["> `params_digest` 只存 `sha256 前缀 + len`,**不含 payload 原文**。",
                  "> 所以本报告靠「路径 + 规则命中 + 重复度」反推,不做 payload 内容分析。", ""]
    return "\n".join(lines)


def section_daily(days, rows):
    lines = ["## 二、按天趋势", ""]
    if not rows:
        return "\n".join(lines + ["(无数据)", ""])
    body = []
    for d, n, b, a, nf, ips in rows:
        n = int(n or 0)
        body.append([d, f"{n:,}", f"{int(b or 0):,}", f"{int(a or 0):,}",
                     f"{int(nf or 0):,}", ips])
    lines += [md_table(["日期", "请求", "拦截", "告警", "404 探测", "独立 IP"], body), ""]
    return "\n".join(lines)


def section_sources(days, ip_rows, subnet_rows):
    lines = ["## 三、来源分析", ""]
    pub = [r for r in ip_rows if not is_internal(r[0])]
    if not pub:
        lines += ["**最近 %d 天没有公网来源。**" % days,
                  "",
                  "如果服务器明明暴露在公网,说明审计没跟上 —— 或者流量根本没打进来。",
                  ""]
        return "\n".join(lines)

    body = []
    for ip, n, b, a, first, last in pub:
        body.append([f"`{ip}`", f"{int(n):,}", f"{int(b or 0):,}",
                     f"{int(a or 0):,}", first, last])
    lines += [md_table(["来源 IP", "请求", "拦截", "告警", "首次", "最近"], body), ""]

    if subnet_rows:
        sb = [[f"`{s}.0/24`", f"{int(n):,}", ips] for s, n, ips in subnet_rows
              if not is_internal(s + ".1")]
        if sb:
            lines += ["按 /24 网段聚合(扫描器常换 IP,网段比单 IP 稳):", "",
                      md_table(["网段", "请求", "独立 IP"], sb), ""]
    return "\n".join(lines)


def section_paths(probe_rows, attacked_rows):
    """两张表分开看:404 探测 = 扫描器在找什么;BLOCK/ALERT = 打的是哪个业务接口。"""
    lines = ["## 四、扫描器在找什么", ""]

    if probe_rows:
        body = []
        hit_kinds = {}
        for uri, n in probe_rows:
            kind = classify_path(uri)
            body.append([f"`{uri[:70]}`", f"{int(n):,}", kind or "—"])
            if kind:
                hit_kinds[kind] = hit_kinds.get(kind, 0) + int(n)
        lines += ["### 4.1 被探测但不存在的路径(404)", "",
                  "正常业务不会访问这些路径,只有扫描器/漏洞工具才会打。", "",
                  md_table(["路径", "请求", "推测类型"], body), ""]
        if hit_kinds:
            top = sorted(hit_kinds.items(), key=lambda kv: -kv[1])
            lines += ["按推测类型汇总:", "",
                      md_table(["类型", "请求数"],
                               [[k, f"{v:,}"] for k, v in top]), ""]
    else:
        lines += ["### 4.1 被探测但不存在的路径(404)", "",
                  "最近没有 404 探测 —— 说明还没有扫描器找到你,或者它们打的是别的端口。", ""]

    if attacked_rows:
        body = [[f"`{u[:70]}`", f"{int(b or 0):,}", f"{int(a or 0):,}",
                 classify_path(u) or "—"] for u, b, a in attacked_rows]
        lines += ["### 4.2 被攻击的业务路径(命中规则)", "",
                  md_table(["路径", "拦截", "告警", "推测类型"], body), ""]
    return "\n".join(lines)


def section_rules(rows, rules, block_mix):
    """rows: [(rule_hit 原文, 次数)];rule_hit 可能是逗号分隔的多条。"""
    if not rows:
        return "## 五、检出分布\n\n(最近没有命中任何规则)\n"

    by_rule = {}
    by_guard = {}
    combos = 0
    for raw, n in rows:
        n = int(n)
        ids = [x.strip() for x in raw.split(",") if x.strip()]
        ids = [x for x in ids if x != "..." and "(截断)" not in x]
        combos += n
        # 一条请求命中多条时,每条规则各记一次(所以下面的数会大于请求数)
        for rid in ids:
            if rid in GUARD_PSEUDO_RULES:
                cat, desc = GUARD_PSEUDO_RULES[rid]
                by_guard[(rid, cat, desc)] = by_guard.get((rid, cat, desc), 0) + n
            else:
                cat, sev = rules.get(rid, ("UNKNOWN", "MEDIUM"))
                by_rule[(rid, cat, sev)] = by_rule.get((rid, cat, sev), 0) + n

    lines = ["## 五、检出分布", ""]
    lines += [f"命中记录的请求共 {combos:,} 条(一条请求可能命中多条)。这里把"
              f"**内容规则**和**防护动作**分开列 —— 二者含义完全不同。", ""]

    content_total = sum(by_rule.values())
    if by_rule:
        top = sorted(by_rule.items(), key=lambda kv: -kv[1])[:20]
        body = [[f"`{rid}`", cat, sev, f"{n:,}"] for (rid, cat, sev), n in top]
        lines += [f"### 5.1 内容规则命中(特征库认出攻击)共 {content_total:,} 次", "",
                  md_table(["规则", "类别", "级别", "命中次数"], body), ""]
    else:
        lines += ["### 5.1 内容规则命中", "", "最近没有内容规则命中 —— "
                  "也就是说,这段时间**没有一条请求是被特征库认出来拦下的**。", ""]

    if by_guard:
        top = sorted(by_guard.items(), key=lambda kv: -kv[1])[:10]
        body = [[f"`{rid}`", cat, desc, f"{n:,}"]
                for (rid, cat, desc), n in top]
        lines += ["### 5.2 防护动作(限流 / 封禁 / 重放)", "",
                  md_table(["动作", "类别", "含义", "次数"], body), "",
                  "> 这些数字说明对方打得太快或已在名单里,**不说明我们认出了攻击**。"
                  "看检测能力请看 5.1。", ""]

    # 拦截构成:有多少 403 是"特征库认出来的",多少是"被限流/封禁挡下的"
    if block_mix:
        banned, limited, replay, content = (int(x or 0) for x in block_mix[0])
        total_block = banned + limited + replay + content
        if total_block > 0:
            lines += ["### 5.3 拦截的构成", "",
                      md_table(["来源", "次数", "占比", "含金量"],
                               [["特征库检出", f"{content:,}", pct(content, total_block),
                                 "真正认出了攻击"],
                                ["IP 封禁", f"{banned:,}", pct(banned, total_block),
                                 "对方已在名单里"],
                                ["限流", f"{limited:,}", pct(limited, total_block),
                                 "对方打太快"],
                                ["重放保护", f"{replay:,}", pct(replay, total_block),
                                 "重复提交"]]), "",
                      "> 对外讲拦截量时,只用「特征库检出」那一行。"
                      "把限流和封禁算进去是虚胖。", ""]
    return "\n".join(lines)


def section_alert(rows, only_alert_rows):
    lines = ["## 六、ALERT 明细(策略层的第一手验证)", ""]
    if not rows:
        lines += ["最近没有 ALERT 记录。", ""]
    else:
        body = [[t, f"`{ip}`", f"`{u[:60]}`", f"`{r[:40]}`", sc]
                for t, ip, u, r, sc in rows]
        lines += [md_table(["时间", "IP", "路径", "规则", "状态码"], body), ""]

    if only_alert_rows:
        lines += ["### 只命中 ALERT、从未被拦的 IP(重点看这一节)", "",
                  "这些 IP 触发了宽规则但没触发任何 BLOCK 级规则。**两种可能**:",
                  "正常的业务用户误伤(策略生效),或者攻击者在试探降级后的规则边界。", "",
                  md_table(["IP", "ALERT 次数", "涉及路径"],
                           [[f"`{ip}`", n, f"`{u[:70]}`"] for ip, n, u in only_alert_rows]),
                  ""]
    return "\n".join(lines)


def section_payload(days, digest_rows, repeat_rows, len_rows):
    """payload 原文拿不到,只能看"同一载荷重复了多少次"和长度分布。"""
    lines = ["## 七、攻击的工具化程度", ""]
    if not digest_rows:
        return "\n".join(lines + ["(无数据)", ""])

    total, uniq = (int(digest_rows[0][0]), int(digest_rows[0][1]))
    lines += [md_table(
        ["指标", "值", "怎么读"],
        [["有效请求", f"{total:,}", "带参数的请求"],
         ["唯一载荷", f"{uniq:,}", "按 sha256 前缀去重"],
         ["重复率", pct(total - uniq, total) if total else "—",
          "越高越像固定工具批量扫,越低越像人工"]]), ""]

    if repeat_rows:
        lines += ["重复次数最多的载荷(同一串参数被打了很多次):", "",
                  md_table(["载荷指纹", "次数"],
                           [[f"`{h[:24]}`", f"{int(n):,}"] for h, n in repeat_rows]), ""]

    if len_rows:
        lines += ["参数长度分布(短 = 扫描器探针,长 = 批量利用载荷):", "",
                  md_table(["长度区间(字节)", "请求数"],
                           [[f"{int(b)} ~ {int(b) + 50}", f"{int(n):,}"]
                            for b, n in len_rows]), ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="SecGuard 线上观测报告")
    ap.add_argument("--days", type=int, default=7, help="观察最近几天(默认 7)")
    ap.add_argument("--out", help="写到文件(默认打到终端)")
    ap.add_argument("--top", type=int, default=20, help="各 Top 榜单条数(默认 20)")
    args = ap.parse_args()

    days = max(1, args.days)
    where = f"created_at >= NOW() - INTERVAL {days} DAY"

    cfg = load_env(os.path.join(ROOT, ".env"))
    rules = load_rules(os.path.join(ROOT, "rules", "attack_patterns.txt"))
    n = args.top

    meta = mysql(
        f"SELECT COUNT(*), COUNT(DISTINCT ip), "
        f"COALESCE(MIN(created_at),'-'), COALESCE(MAX(created_at),'-') "
        f"FROM audit_log WHERE {where}", cfg)
    meta = meta[0] if meta else ["0", "0", "-", "-"]
    if len(meta) < 4:
        meta = (meta + ["-"] * 4)[:4]

    actions = mysql(
        f"SELECT action, COUNT(*) FROM audit_log WHERE {where} "
        f"GROUP BY action ORDER BY COUNT(*) DESC", cfg)

    daily = mysql(
        f"SELECT DATE(created_at) d, COUNT(*), SUM(action='BLOCK'), "
        f"SUM(action='ALERT'), SUM(status_code=404), COUNT(DISTINCT ip) "
        f"FROM audit_log WHERE {where} GROUP BY d ORDER BY d", cfg)

    ip_rows = mysql(
        f"SELECT ip, COUNT(*), SUM(action='BLOCK'), SUM(action='ALERT'), "
        f"MIN(created_at), MAX(created_at) FROM audit_log WHERE {where} "
        f"GROUP BY ip ORDER BY COUNT(*) DESC LIMIT 200", cfg)

    # 全量来源(只取 IP 和次数),用来算"公网 vs 自测"的占比。
    # 不直接用 SQL 的 LIKE 判断内网段:172.16/12 和 100.64/10 的边界用字符串
    # 匹配容易错,交给 ipaddress 模块更稳。
    ip_all = mysql(
        f"SELECT ip, COUNT(*) FROM audit_log WHERE {where} "
        f"GROUP BY ip ORDER BY COUNT(*) DESC LIMIT 5000", cfg)

    subnet_rows = mysql(
        f"SELECT SUBSTRING_INDEX(ip,'.',3) s, COUNT(*), COUNT(DISTINCT ip) "
        f"FROM audit_log WHERE {where} "
        f"GROUP BY s ORDER BY COUNT(*) DESC LIMIT 15", cfg)

    probe_rows = mysql(
        f"SELECT uri, COUNT(*) FROM audit_log WHERE {where} AND status_code=404 "
        f"GROUP BY uri ORDER BY COUNT(*) DESC LIMIT {n}", cfg)

    attacked_rows = mysql(
        f"SELECT uri, SUM(action='BLOCK'), SUM(action='ALERT') "
        f"FROM audit_log WHERE {where} AND action IN ('BLOCK','ALERT') "
        f"GROUP BY uri ORDER BY SUM(action='BLOCK') DESC LIMIT {n}", cfg)

    rule_rows = mysql(
        f"SELECT rule_hit, COUNT(*) FROM audit_log WHERE {where} "
        f"AND rule_hit IS NOT NULL AND rule_hit <> '' "
        f"GROUP BY rule_hit ORDER BY COUNT(*) DESC LIMIT 300", cfg)

    alert_rows = mysql(
        f"SELECT created_at, ip, uri, COALESCE(rule_hit,''), status_code "
        f"FROM audit_log WHERE {where} AND action='ALERT' "
        f"ORDER BY id DESC LIMIT {n}", cfg)

    only_alert = mysql(
        f"SELECT ip, SUM(action='ALERT') a, MIN(uri) "
        f"FROM audit_log WHERE {where} GROUP BY ip "
        f"HAVING a > 0 AND SUM(action='BLOCK') = 0 "
        f"ORDER BY a DESC LIMIT 10", cfg)

    digest_rows = mysql(
        f"SELECT COUNT(*), COUNT(DISTINCT params_digest) FROM audit_log "
        f"WHERE {where} AND params_digest IS NOT NULL AND params_digest <> ''", cfg)

    repeat_rows = mysql(
        f"SELECT params_digest, COUNT(*) c FROM audit_log "
        f"WHERE {where} AND params_digest IS NOT NULL AND params_digest <> '' "
        f"GROUP BY params_digest HAVING c > 1 ORDER BY c DESC LIMIT 10", cfg)

    len_rows = mysql(
        f"SELECT FLOOR(SUBSTRING_INDEX(params_digest,'len=',-1)/50)*50 b, COUNT(*) "
        f"FROM audit_log WHERE {where} AND params_digest LIKE '%len=%' "
        f"GROUP BY b ORDER BY b LIMIT 20", cfg)

    block_mix = mysql(
        f"SELECT SUM(rule_hit LIKE 'IP_BANNED%'), "
        f"SUM(rule_hit LIKE 'RATE_LIMITED%'), "
        f"SUM(rule_hit LIKE 'REPLAY%'), "
        f"SUM(rule_hit IS NOT NULL AND rule_hit<>'' "
        f"    AND rule_hit NOT LIKE 'IP_BANNED%' "
        f"    AND rule_hit NOT LIKE 'RATE_LIMITED%' "
        f"    AND rule_hit NOT LIKE 'REPLAY%') "
        f"FROM audit_log WHERE {where} AND action='BLOCK'", cfg)

    total_requests = int(meta[0] or 0)
    public_requests = sum(int(n) for ip, n in ip_all if not is_internal(ip))
    self_requests = max(0, total_requests - public_requests)

    parts = [
        "# SecGuard 线上观测报告", "",
        f"> 生成时间:{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"> 观察窗口:最近 {days} 天  ",
        f"> 数据来源:`audit_log`(容器 `{CONTAINER}`)",
        "",
        "---", "",
        section_provenance(total_requests, public_requests, self_requests),
        "---", "",
        section_overview(days, meta, actions, cfg),
        "---", "",
        section_daily(days, daily),
        "---", "",
        section_sources(days, ip_rows, subnet_rows),
        "---", "",
        section_paths(probe_rows, attacked_rows),
        "---", "",
        section_rules(rule_rows, rules, block_mix),
        "---", "",
        section_alert(alert_rows, only_alert),
        "---", "",
        section_payload(days, digest_rows, repeat_rows, len_rows),
        "---", "",
        "## 八、这份报告的边界", "",
        "- **不含 payload 原文**:`params_digest` 只存 sha256 前缀 + 长度(设计如此)。",
        "- **不含 User-Agent**:审计表没存 UA,工具指纹是按**路径**推测的,不是断言的。",
        "- **来源地不精确**:没有 IP 归属库,只能按网段聚合,不做国家/ASN 归属。",
        "- **告警依赖 AI 层**:`action=ALERT` 是策略降级,不是 LLM 告警;"
        "后者在 `alert` 表里。",
        "",
    ]
    text = "\n".join(parts)

    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"报告已写入 {args.out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
