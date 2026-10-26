# SecGuard vs OWASP CRS:横向对比

> 语料 169 条,其中 147 条参与对比(排除 22 条 path 类,原因见口径节)。
> 两边吃**同一份线上报文**(空格编码为 %20)。
> CRS:官方镜像默认配置(PL1 / 入站异常阈值 5),未调参。
> SecGuard:线上版本(特征 + 归一化 + 策略)。

## 零、结论(先看这个)

**1) 编码类绕过:两家打平。** 把纯编码手法(空格编码、双层编码、部分编码、大小写、注释、NUL…)单独看:**35 条,SecGuard 拦 35 条,CRS 拦 35 条**。这条最重要 —— 它说明归一化层达到了工业基线,不是自娱自乐。编码还原这件事,方法对了谁做都一样。

**2) 语义等价:CRS 明显更强。** CRS 拦住而我漏掉的 4 条,全部是「语法等价 / 跨字符拆分」:`or 2>1`、`top['al'+'ert']`、base64 管道。这正是子串匹配的天花板,和评测报告里那 5 条残差完全对得上。

**3) 误拦:我低 11 个百分点。** 正常流量 SecGuard 拦 2/44,CRS 拦 7/44。CRS 在 JSON 正文里出现 SQL 片段、shell 命令、base64 图片时更容易误伤(默认 PL1 的已知代价)。我这边低误拦一部分来自ALERT 分层,不是免费得来的。

**4) 我拦了 CRS 没拦的 10 条,别急着高兴。** 其中大部分是单标签、无利用代码的 XSS 样本(`<body>`、`&#60;script&#62;`)。CRS 认为那不是攻击,而我的标签规则会拦 —— 这是**判定粒度不同**,不是能力强弱。

## 一、总览

| 维度 | 样本 | SecGuard 拦截 | OWASP CRS 拦截 | 差距 |
|---|---|---|---|---|
| 基线攻击(明文) | 32 | 32 (100.0%) | 30 (93.8%) | 6.2% |
| 变形攻击(编码/注释/转义) | 71 | 66 (93.0%) | 62 (87.3%) | 5.6% |
| 正常流量(误拦) | 44 | 2 (4.5%) | 7 (15.9%) | -11.4% |

差距为正 = SecGuard 拦得多;误拦那一行为负是好事。

## 二、按绕过手法(只看变形样本)

| 手法 | 样本 | SecGuard | CRS | 差值 |
|---|---|---|---|---|
| equivalent-rewrite | 2 | 0 | 2 | -2 |
| equivalent-syntax | 3 | 2 | 3 | -1 |
| base64-pipe | 1 | 0 | 1 | -1 |
| percent-space | 11 | 11 | 11 | 0 |
| separator-encode | 7 | 7 | 7 | 0 |
| sql-comment | 5 | 5 | 5 | 0 |
| double-encode | 5 | 5 | 5 | 0 |
| partial-percent-encode | 4 | 4 | 4 | 0 |
| keyword-percent-encode | 3 | 3 | 3 | 0 |
| tabular-space | 2 | 2 | 2 | 0 |
| whitespace-scheme | 2 | 2 | 2 | 0 |
| ifs-separator | 2 | 2 | 2 | 0 |
| plus-space | 1 | 1 | 1 | 0 |
| newline-space | 1 | 1 | 1 | 0 |
| mysql-version-comment | 1 | 1 | 1 | 0 |
| function-space | 1 | 1 | 1 | 0 |
| function-comment | 1 | 1 | 1 | 0 |
| trailing-comment-removed | 1 | 1 | 1 | 0 |
| case-mixed | 1 | 1 | 1 | 0 |
| json-unicode-escape | 1 | 1 | 1 | 0 |
| js-unicode-escape | 1 | 1 | 1 | 0 |
| nul-byte | 1 | 1 | 1 | 0 |
| control-case | 1 | 1 | 1 | 0 |
| control-percent | 1 | 1 | 1 | 0 |
| backslash-escape | 1 | 0 | 0 | 0 |
| duplicate-space | 1 | 1 | 1 | 0 |
| equivalent-command | 3 | 3 | 2 | 1 |
| html-entity-scheme | 1 | 1 | 0 | 1 |
| html-entity-attr | 1 | 1 | 0 | 1 |
| js-hex-escape | 1 | 1 | 0 | 1 |
| form-urlencoded | 1 | 1 | 0 | 1 |
| control-js-hex | 1 | 1 | 0 | 1 |
| html-entity | 2 | 2 | 0 | 2 |

差值 = SecGuard 比 CRS 多拦了几条。负数就是 CRS 更强的地方。

### 2.1 CRS 拦住了、SecGuard 没拦

| 样本 | 类别 | 手法 | 载荷 |
|---|---|---|---|
| `sqli-v29` | SQL_INJECTION | equivalent-syntax | `id=1'%20or%202>1--` |
| `xss-v18` | XSS | equivalent-rewrite | `q=top['al'+'ert'](1)` |
| `xss-v19` | XSS | equivalent-rewrite | `q=window['ale'+'rt'](document['cookie'])` |
| `cmd-v13` | CMD_INJECTION | base64-pipe | `file=; echo Y2F0IC9ldGMvcGFzc3dk\base64 -d\sh` |

### 2.2 SecGuard 拦住了、CRS 没拦

| 样本 | 类别 | 手法 | 载荷 |
|---|---|---|---|
| `xss-b06` | XSS | baseline | `q=<body>` |
| `xss-b07` | XSS | baseline | `q=<details open>` |
| `xss-v05` | XSS | html-entity | `q=&#60;&#x73;cript&#62;` |
| `xss-v06` | XSS | html-entity | `q=&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;` |
| `xss-v07` | XSS | html-entity-scheme | `q=java&#115;cript:1` |
| `xss-v08` | XSS | html-entity-attr | `q=&#111;nerror=1` |
| `xss-v12` | XSS | js-hex-escape | `{"c":"\x3cimg\x3e"}` |
| `xss-v17` | XSS | form-urlencoded | `content=%3Csvg%2F%3E` |
| `xss-v22` | XSS | control-js-hex | `{"c":"\x3cscript"}` |
| `cmd-v11` | CMD_INJECTION | equivalent-command | `host=1.1.1.1; id` |

## 三、误拦明细(正常流量被 403)

### 3.1 SecGuard 误拦

| 样本 | 载荷 | 规则 |
|---|---|---|
| `ben-08` | `{"content":"the union select committee met today"}` | — |
| `ben-33` | `file=../../docs/readme.md` | — |

### 3.2 CRS 误拦

| 样本 | 载荷 |
|---|---|
| `ben-08` | `{"content":"the union select committee met today"}` |
| `ben-09` | `{"img":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="}` |
| `ben-15` | `q=${HOME}/data` |
| `ben-19` | `{"sql":"select * from users where id = 1"}` |
| `ben-33` | `file=../../docs/readme.md` |
| `ben-36` | `{"content":"SELECT * FROM orders WHERE status = 2"}` |
| `ben-41` | `{"cmd":"ls -la /tmp"}` |

## 四、CRS 主要靠哪几条规则(解释它为什么拦得住)

| 规则 ID | 触发次数 |
|---|---|
| `942100` | 369 |
| `942190` | 106 |
| `941160` | 106 |
| `941100` | 99 |
| `930120` | 84 |
| `932235` | 84 |
| `942360` | 64 |
| `932260` | 63 |
| `932160` | 63 |
| `942160` | 56 |
| `941110` | 50 |
| `930100` | 49 |

> `949110`(异常分超阈值)是汇总动作,已排除。这些规则号可以直接去 CRS 仓库查对应检测逻辑。

## 五、口径与边界(这份报告的限制)

### 5.1 哪些样本不可比

语料里有 **22 条 surface=path 的样本**(路径穿越类)被排除在所有统计之外。原因不在 CRS,而在它的前置 nginx:

```
curl --path-as-is 'http://.../static/../../etc/passwd'   -> 400
```

nginx 在 ModSecurity 之前就把 `..` 归一化/拒绝掉了,CRS 根本没看到那条路径。把 400 算成 CRS 的漏报是不成立的。**这条结论本身有用**:有 nginx 前置时,路径穿越的第一道防线其实是 nginx 自己的归一化,WAF 的 path 规则在这个位置上不一定有机会生效。

### 5.2 我的语料对 CRS 有一点不公平

XSS 基线样本是「单标签、无利用代码」的形态(`<body>`、`<details open>`、`<img src=x>`)。这是为了**隔离单条规则**刻意设计的:带 `alert(1)` 的载荷会同时命中 `alert(` 规则,测不出标签规则的能力。

但对 CRS 来说,`<img src=x>` 没有事件处理器就**不是 XSS**,它不拦是对的。所以 2.2 里那批 XSS 样本,不能读成「CRS 漏了」,只能读成「两家对'什么算攻击'的判定粒度不同」。

### 5.3 那这份对比还能说明什么

能说明的,恰好是三条最要紧的:

1. **编码类绕过两家都吃得住** —— percent-space / 注释 / 双层编码 / 部分编码 全部打平。这说明我的归一化层达到了工业基线,不是自娱自乐。
2. **CRS 强在语义等价** —— `or 2>1`、`top['al'+'ert']`、base64 载荷它都拦住了, 我这几条残差被测出来和它的强项一致。子串匹配的天花板是真实存在的。
3. **误拦率差 10 个百分点** —— 这件事和检出率是一对矛盾, 只报检出率的对比没有意义。

## 六、怎么读这份对比

- **不要把总览当成「谁更强」**:口径不同(我的语料按规则隔离设计,CRS 按语义判定),数字只能说明*在什么条件下谁拦得更多*。
- **2.1 是工作清单**:CRS 拦住而我漏掉的每一条,都对应一类规则缺口,补的时候按族补,别按条补。
- **误拦那一栏两边都要看**:WAF 的可用性和检出率是一对矛盾。

