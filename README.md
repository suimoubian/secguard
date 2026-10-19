# SecGuard

用 C++ 实现的高性能安全审计引擎:手写 **AC 自动机(Aho-Corasick)** 做多模式攻击特征匹配,
配合 Web 接入层与多级防护,构成完整的流量审计告警系统。

## 一句话讲清楚它做什么

每个进来的 HTTP 请求,都被翻译成一段"待检文本",送进 AC 自动机与 225 条攻击特征比对。
命中就拦(403)并写审计日志;没命中就放行,同样留一条审计记录。

```
请求 ──> 封禁检查 ──> 限流 ──> 重放防护 ──> AC 自动机匹配 ──> 业务逻辑
          (Redis)     (Redis)   (Redis)      (微秒级)          │
                                                              └──> 审计队列 ──> 批量落库
```

## 当前进度

| 周次 | 内容 | 状态 |
|---|---|---|
| W1 | 工程骨架、`/health`、数据库表 | ✅ 完成 |
| W2 | 注册/登录 + JWT、帖子/评论 CRUD、连接池 | ✅ 完成 |
| W3 | **AC 自动机**(Trie + BFS 建 fail + search) | ✅ 完成 |
| W4 | 225 条攻击特征、Web 层接入、性能基准 | ✅ 完成 |
| W5 | 分布式限流、重放防护、无锁队列审计管道 | ✅ 完成 |
| W6 | AI 分析层(LLM 接入、结构化输出、置信度) | 未开始 |
| W7 | Docker 部署、压测 | 部署已完成,压测待做 |
| W8 | 项目讲稿 | 未开始 |

## 核心性能数据

AC 自动机 vs 朴素逐串匹配(文本 2079 字节,Release `-O2`):

| 特征数 | AC | 朴素 | 加速比 |
|---|---|---|---|
| 200 | 4.71 微秒 | 50.19 微秒 | **10.6x** |
| 500 | 4.61 微秒 | 129.71 微秒 | **28.1x** |
| 1000 | 4.96 微秒 | 260.15 微秒 | **52.5x** |

**特征数翻 5 倍,AC 耗时基本不变(1.05x),朴素涨 5.2 倍。**
这正是 O(n+m) 与 O(n×k) 的差别 —— 特征库越大,优势越明显。

正确性验证:

| 验证 | 内容 | 结果 |
|---|---|---|
| 暴力对拍 | 15000 次随机 + 9 项特例 | 零不一致 |
| sanitizer | ASan + UBSan 跑完整 10000 次 | 零报错 |
| 无锁队列 | 8 线程 × 1 万条,校验和比对 | 无丢失无重复 |
| 审计对账 | 落库行数 vs 停机日志计数 | 完全一致 |

## 一键部署

```bash
cp .env.example .env
# 改掉 .env 里的三个秘密,比如:
#   openssl rand -base64 48    # 生成 SECGUARD_JWT_SECRET
./docker/deploy.sh
```

起来的四个服务:

| 服务 | 作用 | 对外端口 |
|---|---|---|
| nginx | 唯一入口,反代 + 传真实 IP | 80 |
| app | SecGuard 主程序 | 不暴露 |
| mysql | 业务库(首次启动自动建表) | 不暴露 |
| redis | 限流/封禁/重放的共享状态 | 不暴露 |

> **为什么 app 不直接暴露端口**:程序信任 `X-Forwarded-For` 来取客户端 IP。
> 如果直接对外,攻击者伪造一个 XFF 就能绕过 IP 封禁。
> 只让 nginx 进来,并在 nginx 里用 `$remote_addr` **覆盖**这个头(不是追加)。

验证:

```bash
curl http://localhost/health
curl "http://localhost/?q=union%20select%201"    # 405/403,被拦
```

## 本地开发

```bash
# 依赖(Ubuntu 22.04)
sudo apt install build-essential cmake libssl-dev \
     libmysqlcppconn-dev libhiredis-dev nlohmann-json3-dev

# 编译
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# 跑测试
./build/ac_test 10000        # AC 自动机对拍
./build/ac_bench 2000 2048   # 性能基准
./build/unit_test            # 密码/JWT/引擎/队列/防护

# 起服务(需要 .env)
./run.sh
```

## 技术栈

| 层 | 选型 | 说明 |
|---|---|---|
| 语言 | C++20 | |
| 构建 | CMake 3.22 | |
| Web | [cpp-httplib](https://github.com/yhirose/cpp-httplib) | header-only,随仓库提交 |
| JSON | [nlohmann/json](https://github.com/nlohmann/json) | |
| 数据库 | MySQL 8 + Connector/C++ | 全部预编译参数化,无字符串拼 SQL |
| 缓存 | Redis 6+ + hiredis | 限流/封禁/重放的共享状态,Lua 保证原子 |
| 密码/令牌 | OpenSSL | PBKDF2-HMAC-SHA256 + JWT(HS256) |

## 目录结构

```
secguard/
├── Dockerfile                 # 多阶段构建(builder -> runtime)
├── docker-compose.yml         # 四个服务的编排
├── .env.example               # 配置模板(.env 本身不入库)
├── run.sh                     # 本地开发启动(秘密从 .env 读)
├── CMakeLists.txt
├── include/
│   ├── aho_corasick.h         # AC 自动机(核心)
│   └── engine.h               # 特征库加载 + 热更新
├── src/
│   ├── main.cpp               # 组装 + 优雅停机
│   ├── crypto/auth_crypto.*   # PBKDF2 / HMAC / JWT / base64url
│   ├── cache/
│   │   ├── redis_client.*     # 连接池 + Lua(EVALSHA)
│   │   └── distributed_guard.*# 限流 / 封禁 / 重放,带降级
│   ├── db/
│   │   ├── connection_pool.*  # RAII 借还 + 探活
│   │   ├── dao.*              # 全部预编译参数化
│   │   └── audit_writer.*     # 无锁队列 + 后台批量落库
│   ├── engine/engine.cpp
│   ├── net/                   # HTTP 服务与各业务处理器
│   └── util/
│       ├── config.*           # 全程环境变量 + 校验
│       ├── log.*              # 分级 + 自动脱敏
│       └── mpsc_queue.h       # 无锁 MPSC 环形队列
├── rules/attack_patterns.txt  # 225 条攻击特征
├── db/schema.sql
├── docker/nginx.conf
├── docker/deploy.sh
├── docs/性能基线.md
└── tests/
```

## 设计取舍(面试会被问到的几个点)

**为什么用 AC 自动机而不是正则**:N 条规则就要扫 N 遍文本,复杂度 O(n×k)。
AC 把"同时匹配所有规则"压缩成一次扫描,O(n+m),代价是内存(每节点一张 256 项的转移表)。

**为什么限流走 Redis 而不是本地**:本地的限流在"多实例部署"下等于没限 ——
3 个实例各有一份计数,限额被放大 3 倍。共享状态必须集中。

**为什么用 Lua 而不是"先查再改"**:两步之间会被别人插一脚(check-then-act 竞态)。
Redis 执行 Lua 时单线程、不处理其他命令,整段 read-modify-write 天然原子。

**Redis 挂了怎么办**:降级为单机内存版并打日志。宁可保护变弱,
也不能让服务变哑 —— 安全组件不能成为新的故障点。

**为什么审计用异步队列**:写库是毫秒级,匹配是微秒级。同步写库会让主链路
被数据库拖慢。代价是崩溃会丢队列里的日志,这是有意接受的取舍。

**WAF 能防住注入吗**:不能,也不该指望它。SQL 注入的正解是参数化查询
(本项目 DAO 层全部用预编译),路径穿越的正解是 realpath 校验。
WAF 是纵深防御的一层,不是替代品。

## 数据库

```bash
sudo mysql < db/schema.sql
```

建出 `secguard` 库和 5 张表:`user` / `post` / `comment` / `audit_log` / `alert`。
脚本用 `CREATE ... IF NOT EXISTS`,可重复执行。

`audit_log` 是核心表,索引按查询设计:

| 索引 | 服务的查询 |
|---|---|
| `idx_ip_time (ip, created_at)` | 按 IP + 时间窗聚合(封禁、送检) |
| `idx_analyzed (analyzed, created_at)` | 定时拉取待分析日志(W6) |
