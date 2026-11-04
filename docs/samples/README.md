# 真实攻击样本

这个目录放的是**从线上备份里抢救出来的原始攻击数据**,不是构造的示例。

## attack-sample-20261026.sql.gz

- **来源**:线上 `secguard-20261102-033001.sql.gz` 备份
- **内容**:`69.5.7.147` 与 `101.47.50.201` 两个攻击者的审计记录,共 400 行
- **表结构**:就是 `audit_log` 表(`db/schema.sql` 里有建表语句)

### 为什么要单独存

线上审计有保留策略(`SECGUARD_AUDIT_RETENTION_DAYS`,默认 7 天)。
2026-11-04 清理任务把 10-26/10-27 两天的数据删了 —— 而那两天正好包含
**最大的一次真实攻击**(69.5.7.147,33,821 次)。

原始数据只能从 11-02 的备份里恢复。为了不再依赖保留窗口,导出这 400 行
作为**永久样本**:演示时可以当场导入,证明这些不是编的。

### 怎么用

```bash
# 建一个临时库导进去看
docker exec secguard-mysql mysql -uroot -p"$MYSQL_ROOT_PASSWORD" \
  -e "CREATE DATABASE demo_sample CHARACTER SET utf8mb4;"
gunzip -c docs/samples/attack-sample-20261026.sql.gz \
  | docker exec -i secguard-mysql mysql -uroot -p"$MYSQL_ROOT_PASSWORD" demo_sample

docker exec secguard-mysql mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -t -e \
  "USE demo_sample;
   SELECT ip, COUNT(*) n, SUM(action='BLOCK') blocked
   FROM audit_log GROUP BY ip;
   SELECT LEFT(uri,40) uri, COUNT(*) n FROM audit_log
   WHERE ip='69.5.7.147' GROUP BY uri ORDER BY n DESC LIMIT 10;"
```

### 注意

- 里面**只有攻击者的来源 IP、时间、URI、命中规则** —— 没有请求体、没有凭据
- IP 是租用的云主机,查不到人(这个问题在 `docs/演示素材.md` 里讨论过)
- 数据是真实线上产生的,所以格式化可能不统一(那是当时的实际样子)
