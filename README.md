# SecGuard

用 C++ 实现的高性能安全审计引擎:手写 **AC 自动机(Aho-Corasick)** 做多模式攻击特征匹配,
配合 Web 接入层与 LLM 智能分析,构成完整的流量审计告警系统。

## 当前状态

开发中。已完成 **W1:工程骨架 + `/health`**。

| 周次 | 内容 | 状态 |
|---|---|---|
| W1 | 工程骨架、`/health`、数据库表 | 已完成 |
| W2 | 用户注册/登录 + JWT、帖子/评论 CRUD | 未开始 |
| W3 | **AC 自动机**(Trie + BFS 建 fail + search) | 未开始 |
| W4 | 攻击特征库、Web 层接入、性能对比基准 | 未开始 |
| W5 | 令牌桶限流、重放防护、无锁队列日志管道 | 未开始 |
| W6 | AI 分析层(LLM API 接入、结构化输出、置信度过滤) | 未开始 |
| W7 | Docker 部署、wrk 压测、perf 优化 | 未开始 |
| W8 | README 完善、项目讲稿 | 未开始 |

## 技术栈

| 层 | 选型 | 说明 |
|---|---|---|
| 语言 | C++20 | |
| 构建 | CMake 3.20+ | |
| Web | [cpp-httplib](https://github.com/yhirose/cpp-httplib) v0.56.0 | header-only,随仓库提交 |
| JSON | [nlohmann/json](https://github.com/nlohmann/json) | 系统包 `nlohmann-json3-dev` |
| 数据库 | MySQL 8 + MySQL Connector/C++ | 待接入(W2) |
| 缓存/限流 | Redis + hiredis | 待接入(W5) |
| HTTP 客户端 | libcurl | 待接入(W6) |

## 目录结构

```
secguard/
├── CMakeLists.txt
├── src/                        # 源码
│   └── main.cpp
├── include/                    # 自己的头文件(AC 自动机放这里)
├── tests/                      # 单元测试与基准
├── third_party/                # 第三方库
│   └── cpp-httplib/httplib.h
└── db/
    └── schema.sql              # 建库建表脚本,可重复执行
```

## 构建

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## 运行

```bash
./build/secguard
```

服务监听 `0.0.0.0:8080`。验证:

```bash
curl -i http://localhost:8080/health
# HTTP/1.1 200 OK
# {"service":"secguard","status":"ok"}
```

按 `Ctrl + C` 停止。

## 数据库

```bash
sudo mysql < db/schema.sql
```

建出 `secguard` 库和 5 张表:`user` / `post` / `comment` / `audit_log` / `alert`。

其中 `audit_log` 是核心表,索引按后续查询设计:

| 索引 | 服务的查询 |
|---|---|
| `idx_ip_time (ip, created_at)` | 按 IP + 时间窗聚合(W5 封禁、W6 送检) |
| `idx_analyzed (analyzed, created_at)` | 定时拉取待分析日志(W6) |

脚本用 `CREATE ... IF NOT EXISTS`,可以重复执行;重建库:

```bash
sudo mysql -e "DROP DATABASE secguard;"
sudo mysql < db/schema.sql
```

> 应用连接用的账号/口令不在本仓库里(见 `.gitignore`)。

## 性能数据

待 W7 压测后补充(AC 自动机 vs 朴素匹配的吞吐对比、单机 QPS / P99)。**此处不放未经验证的数字。**
