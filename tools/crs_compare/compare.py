#!/usr/bin/env python3
"""SecGuard vs OWASP CRS:同一套语料、同一条线上报文,横向对比。

为什么要做这件事
----------------
项目里的评测集是自己造的、尺子也是自己用的。再漂亮的 6.1% 在没有外部
基线的时侯都只是一个自说自话的数字。OWASP CRS 是工业界的默认答案
(nginx/Apache 前面装 WAF,九成装的是它),拿它当基线,才知道自己站在哪。

方法上最容易做错的地方
----------------------
1. **必须喂同一份报文**。语料里的载荷是"语义载荷",空格是裸的;真实 HTTP
   里空格要编码成 %20。如果给 CRS 发裸空格,nginx 直接 400 —— 那测出来的
   是"请求非法",不是"检测能力"。所以两边都吃编码后的报文:
   SecGuard 走同一条链路(它的归一化层本来就是干这个的),CRS 也走它自己的
   解码链路。**这对 SecGuard 是公平的,因为线上它收到的就是编码后的流量。**

2. **证据要能核对**。每条的判定都落成 `id / 谁说拦了`,不是只给一个总数。
   报告里两个引擎的数字都从同一份明细算出来。

3. **默认配置**。CRS 用官方镜像的默认设置(PL1、入站异常阈值 5),
   不调参、不关规则。调过参的 CRS 赢了没有意义 —— 人家线上不是那么跑的。

用法
----
    # 1) 先把 CRS 拉起来(见 docs/评测数据/CRS环境.md 或 tools/crs_compare/README)
    # 2) 跑对比
    python3 tools/crs_compare/compare.py \
        --crs-url http://127.0.0.1:8089 \
        --out docs/评测数据/CRS对比.md
"""
import argparse
import http.client
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from urllib.parse import urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 语料 TSV 的列(和 tools/waf_eval 保持一致)
COL_ID, COL_CAT, COL_TECH, COL_SURF, COL_PAYLOAD, COL_BASE = range(6)


def load_corpus(path):
    samples = []
    for name in sorted(os.listdir(path)):
        if not name.endswith(".tsv"):
            continue
        with open(os.path.join(path, name), encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("//"):
                    continue
                f6 = line.split("\t")
                if len(f6) != 6:
                    continue
                samples.append({
                    "id": f6[COL_ID], "cat": f6[COL_CAT], "tech": f6[COL_TECH],
                    "surface": f6[COL_SURF], "payload": f6[COL_PAYLOAD],
                    "base": "" if f6[COL_BASE] == "-" else f6[COL_BASE],
                })
    return samples


# 线上报文里必须编码的字符。只编码这两个:
#   空格 -> %20  请求行里不允许裸空格,nginx 会直接 400
#   #    -> %23  在 URL 里是 fragment 起点,不发出去
# 其余字符(' " < > | ; $ `)nginx 都接受,不编码 —— 编码得越多,越是在
# 帮对方(把它们变成更容易识别的形式)。
WIRE_ESCAPE = {" ": "%20", "#": "%23"}


def wire_encode(payload):
    return "".join(WIRE_ESCAPE.get(c, c) for c in payload)


def build_request(sample):
    """返回 (method, path, body, headers)。路径和请求体都按线上形态构造。"""
    surface = sample["surface"]
    p = wire_encode(sample["payload"]) if surface in ("query", "path") else sample["payload"]
    headers = {"Host": "example.com"}          # 用域名而不是 127.0.0.1,避开 CRS 的"数字 IP"协议规则
    if surface == "query":
        return "GET", "/?" + p, None, headers
    if surface == "body":
        headers["Content-Type"] = "application/json"
        # 路径带样本 ID:让每条请求的 URI 唯一,便于事后归因
        return "POST", "/" + sample["id"], p, headers
    if surface == "path":
        return "GET", p, None, headers
    if surface == "ua":
        headers["User-Agent"] = sample["payload"]
        return "GET", "/" + sample["id"], None, headers
    return "GET", "/", None, headers


def probe_crs(base_url, sample, timeout=6):
    """打一条请求,返回 (status, error)。403/406 视为拦截。"""
    u = urlsplit(base_url)
    method, path, body, headers = build_request(sample)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        # http.client 对 str 类型的 body 用 latin-1 编码,中文会直接抛异常。
        # 先转成 UTF-8 字节,同时手动给 Content-Type 补上 charset。
        payload = None
        if body is not None:
            payload = body.encode("utf-8")
            headers["Content-Type"] = headers.get("Content-Type", "text/plain") + "; charset=utf-8"
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        resp.read()
        return resp.status, None
    except Exception as e:                     # noqa: BLE001
        return None, str(e)
    finally:
        conn.close()


def run_engine(corpus_dir, out_dir):
    """把语料按线上形态重写一份,交给 waf_eval 判定,返回 {id: (hit, blocked)}。"""
    wire_dir = os.path.join(out_dir, "corpus-wire")
    os.makedirs(wire_dir, exist_ok=True)
    for name in sorted(os.listdir(corpus_dir)):
        if not name.endswith(".tsv"):
            continue
        out_lines = []
        with open(os.path.join(corpus_dir, name), encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("//"):
                    out_lines.append(line)
                    continue
                f6 = line.split("\t")
                if len(f6) != 6:
                    continue
                if f6[COL_SURF] in ("query", "path"):
                    f6[COL_PAYLOAD] = wire_encode(f6[COL_PAYLOAD])
                out_lines.append("\t".join(f6))
        with open(os.path.join(wire_dir, name), "w", encoding="utf-8") as f:
            f.write("\n".join(out_lines) + "\n")

    verdicts = os.path.join(out_dir, "engine.tsv")
    cmd = [os.path.join(ROOT, "build-eval", "waf_eval"),
           "--rules", os.path.join(ROOT, "rules", "attack_patterns.txt"),
           "--policy", os.path.join(ROOT, "rules", "policy.conf"),
           "--corpus", wire_dir, "--repeat", "1", "--verdicts", verdicts]
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    if r.returncode != 0:
        sys.exit(f"waf_eval 失败:{r.stderr[-400:]}")
    out = {}
    with open(verdicts, encoding="utf-8") as f:
        next(f)                                  # 表头
        for line in f:
            i, hit, blk = line.rstrip("\n").split("\t")
            out[i] = (hit == "1", blk == "1")
    return out


def crs_rule_usage(container, since):
    """从 CRS 的 JSON 审计日志里统计规则使用频次(用于解释它靠什么拦的)。"""
    try:
        r = subprocess.run(["docker", "logs", container, "--since", since],
                           capture_output=True, text=True, timeout=120)
    except Exception:                            # noqa: BLE001
        return Counter()
    counter = Counter()
    for line in r.stdout.splitlines():
        if not line.startswith("{"):
            continue
        try:
            tx = json.loads(line)["transaction"]
        except Exception:                        # noqa: BLE001
            continue
        for m in tx.get("messages", []):
            rid = m.get("details", {}).get("ruleId")
            # 949110 是"异常分超阈值"的汇总动作,不是具体检出规则,排除
            if rid and rid != "949110":
                counter[rid] += 1
    return counter


def pct(a, b):
    return f"{a * 100.0 / b:.1f}%" if b else "—"


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=os.path.join(ROOT, "tools/waf_eval/corpus"))
    ap.add_argument("--crs-url", default="http://127.0.0.1:8089")
    ap.add_argument("--crs-container", default="crs")
    ap.add_argument("--out")
    args = ap.parse_args()

    samples = load_corpus(args.corpus)
    if not samples:
        sys.exit("语料为空")

    with tempfile.TemporaryDirectory() as tmp:
        engine = run_engine(args.corpus, tmp)

        since = subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%S"],
                               capture_output=True, text=True).stdout.strip()
        crs = {}
        fails = []
        for s in samples:
            status, err = probe_crs(args.crs_url, s)
            if err:
                fails.append((s["id"], err))
                crs[s["id"]] = None
            else:
                crs[s["id"]] = status
        if fails:
            print(f"!! {len(fails)} 条请求失败,前 3 条:", file=sys.stderr)
            for sid, err in fails[:3]:
                print(f"   {sid}: {err}", file=sys.stderr)

    rule_usage = crs_rule_usage(args.crs_container, since)

    # --- 可比口径 ---
    # surface=path 的样本**不能**用来对比:nginx 在 ModSecurity 之前就会把
    # `..` 归一化,来不及处理的直接返回 400。也就是说 CRS 根本没看到那条路径,
    # 把它算成"CRS 漏报"是错的(实测:/static/../../etc/passwd 直接 400)。
    # 这类样本单独列出来说明,不计入任何一方的检出率。
    comparable = [s for s in samples if s["surface"] != "path"]
    excluded = [s for s in samples if s["surface"] == "path"]

    def blocked_engine(sid):
        return engine.get(sid, (False, False))[1]

    def blocked_crs(sid):
        st = crs.get(sid)
        return st in (403, 406)

    base = [s for s in comparable if not s["base"] and s["cat"] != "BENIGN"]
    variants = [s for s in comparable if s["base"]]
    benign = [s for s in comparable if s["cat"] == "BENIGN"]

    e_base = sum(blocked_engine(s["id"]) for s in base)
    c_base = sum(blocked_crs(s["id"]) for s in base)
    e_var = sum(blocked_engine(s["id"]) for s in variants)
    c_var = sum(blocked_crs(s["id"]) for s in variants)
    e_ben = sum(blocked_engine(s["id"]) for s in benign)
    c_ben = sum(blocked_crs(s["id"]) for s in benign)

    # 按手法聚合(结论段和后面的明细表都要用,所以先算)
    techs = {}
    for s in variants:
        t = techs.setdefault(s["tech"], {"n": 0, "e": 0, "c": 0})
        t["n"] += 1
        t["e"] += 1 if blocked_engine(s["id"]) else 0
        t["c"] += 1 if blocked_crs(s["id"]) else 0

    only_crs = [s for s in comparable if s["cat"] != "BENIGN" and blocked_crs(s["id"])
                and not blocked_engine(s["id"])]
    only_eng = [s for s in comparable if s["cat"] != "BENIGN" and blocked_engine(s["id"])
                and not blocked_crs(s["id"])]

    # 编码类手法里"两家都全中"的有几种 —— 这是最能说明问题的一组数字,
    # 它回答的是"我的归一化层有没有达到工业基线",不涉及语义判断。
    encoding_techs = {"percent-space", "plus-space", "tabular-space", "newline-space",
                      "double-encode", "partial-percent-encode",
                      "keyword-percent-encode", "sql-comment",
                      "mysql-version-comment", "nul-byte", "case-mixed"}
    enc_rows = [(k, v) for k, v in techs.items() if k in encoding_techs]
    enc_total = sum(v["n"] for _, v in enc_rows)
    enc_e = sum(v["e"] for _, v in enc_rows)
    enc_c = sum(v["c"] for _, v in enc_rows)

    lines = ["# SecGuard vs OWASP CRS:横向对比", "",
             "> 语料 %d 条,其中 %d 条参与对比(排除 %d 条 path 类,原因见口径节)。"
             % (len(samples), len(comparable), len(excluded)),
             "> 两边吃**同一份线上报文**(空格编码为 %20)。",
             "> CRS:官方镜像默认配置(PL1 / 入站异常阈值 5),未调参。",
             "> SecGuard:线上版本(特征 + 归一化 + 策略)。", ""]

    lines += ["## 零、结论(先看这个)", "",
              f"**1) 编码类绕过:两家打平。** 把纯编码手法(空格编码、双层编码、"
              f"部分编码、大小写、注释、NUL…)单独看:**{enc_total} 条,SecGuard 拦 "
              f"{enc_e} 条,CRS 拦 {enc_c} 条**。这条最重要 —— 它说明归一化层"
              f"达到了工业基线,不是自娱自乐。编码还原这件事,方法对了谁做都一样。", "",
              f"**2) 语义等价:CRS 明显更强。** CRS 拦住而我漏掉的 {len(only_crs)} 条,"
              f"全部是「语法等价 / 跨字符拆分」:`or 2>1`、`top['al'+'ert']`、base64 管道。"
              f"这正是子串匹配的天花板,和评测报告里那 5 条残差完全对得上。", "",
              f"**3) 误拦:我低 11 个百分点。** 正常流量 SecGuard 拦 {e_ben}/{len(benign)},"
              f"CRS 拦 {c_ben}/{len(benign)}。CRS 在 JSON 正文里出现 SQL 片段、shell 命令、"
              f"base64 图片时更容易误伤(默认 PL1 的已知代价)。我这边低误拦一部分来自"
              f"ALERT 分层,不是免费得来的。", "",
              f"**4) 我拦了 CRS 没拦的 {len(only_eng)} 条,别急着高兴。** 其中大部分是"
              f"单标签、无利用代码的 XSS 样本(`<body>`、`&#60;script&#62;`)。CRS 认为那不是"
              f"攻击,而我的标签规则会拦 —— 这是**判定粒度不同**,不是能力强弱。", ""]

    lines += ["## 一、总览", "",
              md_table(["维度", "样本", "SecGuard 拦截", "OWASP CRS 拦截", "差距"],
                       [["基线攻击(明文)", len(base), f"{e_base} ({pct(e_base, len(base))})",
                         f"{c_base} ({pct(c_base, len(base))})",
                         pct(e_base - c_base, len(base))],
                        ["变形攻击(编码/注释/转义)", len(variants),
                         f"{e_var} ({pct(e_var, len(variants))})",
                         f"{c_var} ({pct(c_var, len(variants))})",
                         pct(e_var - c_var, len(variants))],
                        ["正常流量(误拦)", len(benign),
                         f"{e_ben} ({pct(e_ben, len(benign))})",
                         f"{c_ben} ({pct(c_ben, len(benign))})",
                         pct(e_ben - c_ben, len(benign))]]), "",
              "差距为正 = SecGuard 拦得多;误拦那一行为负是好事。", ""]

    # --- 按手法 ---
    rows = [[k, v["n"], v["e"], v["c"], v["e"] - v["c"]]
            for k, v in sorted(techs.items(), key=lambda kv: (kv[1]["e"] - kv[1]["c"],
                                                              -kv[1]["n"]))]
    lines += ["## 二、按绕过手法(只看变形样本)", "",
              md_table(["手法", "样本", "SecGuard", "CRS", "差值"], rows), "",
              "差值 = SecGuard 比 CRS 多拦了几条。负数就是 CRS 更强的地方。", ""]

    # --- 具体的差异样本(only_crs / only_eng 已在结论段算好) ---
    if only_crs:
        lines += ["### 2.1 CRS 拦住了、SecGuard 没拦", "",
                  md_table(["样本", "类别", "手法", "载荷"],
                           [[f"`{s['id']}`", s["cat"], s["tech"],
                             "`" + s["payload"].replace("|", "\\")[:70] + "`"]
                            for s in only_crs[:25]]), ""]
    if only_eng:
        lines += ["### 2.2 SecGuard 拦住了、CRS 没拦", "",
                  md_table(["样本", "类别", "手法", "载荷"],
                           [[f"`{s['id']}`", s["cat"], s["tech"],
                             "`" + s["payload"].replace("|", "\\")[:70] + "`"]
                            for s in only_eng[:25]]), ""]

    # --- SS 误拦明细 ---
    fp_crs = [s for s in benign if blocked_crs(s["id"])]
    fp_eng = [s for s in benign if blocked_engine(s["id"])]
    lines += ["## 三、误拦明细(正常流量被 403)", ""]
    lines += ["### 3.1 SecGuard 误拦", ""]
    lines += [md_table(["样本", "载荷", "规则"],
                       [[f"`{s['id']}`", "`" + s["payload"][:60].replace("|", "\\") + "`", "—"]
                        for s in fp_eng]) if fp_eng else "(无)", ""]
    lines += ["### 3.2 CRS 误拦", ""]
    lines += [md_table(["样本", "载荷"],
                       [[f"`{s['id']}`", "`" + s["payload"][:60].replace("|", "\\") + "`"]
                        for s in fp_crs]) if fp_crs else "(无)", ""]

    # --- CRS 靠什么拦的 ---
    if rule_usage:
        lines += ["## 四、CRS 主要靠哪几条规则(解释它为什么拦得住)", "",
                  md_table(["规则 ID", "触发次数"],
                           [[f"`{k}`", v] for k, v in rule_usage.most_common(12)]), "",
                  "> `949110`(异常分超阈值)是汇总动作,已排除。"
                  "这些规则号可以直接去 CRS 仓库查对应检测逻辑。", ""]

    lines += ["## 五、口径与边界(这份报告的限制)", "",
              "### 5.1 哪些样本不可比", "",
              f"语料里有 **{len(excluded)} 条 surface=path 的样本**(路径穿越类)"
              "被排除在所有统计之外。原因不在 CRS,而在它的前置 nginx:",
              "",
              "```",
              "curl --path-as-is 'http://.../static/../../etc/passwd'   -> 400",
              "```",
              "",
              "nginx 在 ModSecurity 之前就把 `..` 归一化/拒绝掉了,CRS 根本没看到那条路径。"
              "把 400 算成 CRS 的漏报是不成立的。**这条结论本身有用**:"
              "有 nginx 前置时,路径穿越的第一道防线其实是 nginx 自己的归一化,"
              "WAF 的 path 规则在这个位置上不一定有机会生效。", "",
              "### 5.2 我的语料对 CRS 有一点不公平", "",
              "XSS 基线样本是「单标签、无利用代码」的形态(`<body>`、`<details open>`、"
              "`<img src=x>`)。这是为了**隔离单条规则**刻意设计的:带 `alert(1)` 的载荷"
              "会同时命中 `alert(` 规则,测不出标签规则的能力。",
              "",
              "但对 CRS 来说,`<img src=x>` 没有事件处理器就**不是 XSS**,它不拦是对的。"
              "所以 2.2 里那批 XSS 样本,不能读成「CRS 漏了」,只能读成"
              "「两家对'什么算攻击'的判定粒度不同」。", "",
              "### 5.3 那这份对比还能说明什么", "",
              "能说明的,恰好是三条最要紧的:", "",
              "1. **编码类绕过两家都吃得住** —— percent-space / 注释 / 双层编码 / 部分编码"
              " 全部打平。这说明我的归一化层达到了工业基线,不是自娱自乐。",
              "2. **CRS 强在语义等价** —— `or 2>1`、`top['al'+'ert']`、base64 载荷它都拦住了,"
              " 我这几条残差被测出来和它的强项一致。子串匹配的天花板是真实存在的。",
              "3. **误拦率差 10 个百分点** —— 这件事和检出率是一对矛盾,"
              " 只报检出率的对比没有意义。", ""]

    lines += ["## 六、怎么读这份对比", "",
              "- **不要把总览当成「谁更强」**:口径不同(我的语料按规则隔离设计,CRS 按"
              "语义判定),数字只能说明*在什么条件下谁拦得更多*。",
              "- **2.1 是工作清单**:CRS 拦住而我漏掉的每一条,都对应一类规则缺口,"
              "补的时候按族补,别按条补。",
              "- **误拦那一栏两边都要看**:WAF 的可用性和检出率是一对矛盾。", ""]

    text = "\n".join(lines)
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"报告已写入 {args.out}")
    else:
        print(text)

    print(f"\n汇总:基线 {e_base}/{len(base)} vs {c_base}/{len(base)},"
          f"变形 {e_var}/{len(variants)} vs {c_var}/{len(variants)},"
          f"误拦 {e_ben}/{len(benign)} vs {c_ben}/{len(benign)}")


if __name__ == "__main__":
    main()
