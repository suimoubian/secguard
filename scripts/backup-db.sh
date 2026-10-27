#!/bin/bash
# 数据库备份 / 校验 / 恢复测试
#
# 用法:
#   ./scripts/backup-db.sh                    备份一次
#   ./scripts/backup-db.sh --list             看已有备份
#   ./scripts/backup-db.sh --verify <文件>    校验某个备份能不能解开
#   ./scripts/backup-db.sh --restore-test     拿最新备份恢复到一个临时库,比对行数
#
# 设计取舍:
#   1. 用 root 而不是应用账号 —— mysqldump 需要额外的权限(LOCK TABLES / PROCESS),
#      应用账号只有 DML,会直接失败。密码从 .env 的 MYSQL_ROOT_PASSWORD 读。
#   2. --single-transaction:InnoDB 下用一致性快照导出,不锁表。
#      不锁表意味着导出期间业务照常跑,不用挑凌晨。
#   3. 备份完立刻 gzip -t 校验 —— 一个损坏的备份比没有备份更危险,
#      因为你以为有。
#   4. 备份目录 700:里面是全库数据(含用户口令哈希)。
#
# 已知局限(必须说清):备份和数据库在同一块磁盘上。
# 磁盘坏了备份一起没。要真抗灾,得把备份推到别的机器/对象存储 —— 见文档。

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; NC=$'\033[0m'
ok()   { printf '%s%s%s\n' "$GREEN" "$*" "$NC"; }
warn() { printf '%s%s%s\n' "$YELLOW" "$*" "$NC"; }
die()  { printf '%s%s%s\n' "$RED" "$*" "$NC" >&2; exit 1; }

BACKUP_DIR="${BACKUP_DIR:-$HOME/backups}"
KEEP_DAYS="${KEEP_DAYS:-7}"

[ -f .env ] || die "当前目录没有 .env"
DB_NAME=$(grep '^SECGUARD_DB_NAME=' .env | cut -d= -f2-)
DB_NAME=${DB_NAME:-secguard}
ROOT_PW=$(grep '^MYSQL_ROOT_PASSWORD=' .env | cut -d= -f2-)
[ -n "$ROOT_PW" ] || die ".env 里没有 MYSQL_ROOT_PASSWORD"

# 容器里的 mysql 客户端
myexec() { sudo docker exec secguard-mysql "$@"; }
# 需要往容器里喂标准输入的场合必须加 -i:
# 不加 -i 时 docker exec 会立刻关闭 stdin,管道里的 SQL 根本进不去 mysql,
# 结果是"恢复成功但库里什么都没有"。这个坑很安静 —— 退出码是 0。
myexec_i() { sudo docker exec -i secguard-mysql "$@"; }

# ---------------------------------------------------------------------------
cmd_backup() {
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"

    local ts file tmp
    ts=$(date +%Y%m%d-%H%M%S)
    file="$BACKUP_DIR/${DB_NAME}-${ts}.sql.gz"
    tmp="${file}.part"

    echo "备份 $DB_NAME -> $file"

    # --single-transaction: 一致性快照,不锁表
    # --routines --triggers --events: 别漏掉存储过程/触发器
    # --no-tablespaces: 普通账号也能跑(避免 PROCESS 权限要求)
    if ! myexec mysqldump -uroot -p"$ROOT_PW" \
            --single-transaction --quick --no-tablespaces \
            --routines --triggers --events \
            --default-character-set=utf8mb4 \
            "$DB_NAME" 2>/tmp/dump.err | gzip -6 > "$tmp"; then
        rm -f "$tmp"
        die "mysqldump 失败:$(tail -2 /tmp/dump.err | tr '\n' ' ')"
    fi

    # gzip 完整性校验:一个解不开的备份等于没有备份
    if ! gzip -t "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        die "备份文件 gzip 校验失败"
    fi

    local size
    size=$(stat -c%s "$tmp")
    if [ "$size" -lt 1024 ]; then
        rm -f "$tmp"
        die "备份文件只有 ${size} 字节,不正常"
    fi

    # 粗校验:必须含建表语句,否则可能导了个空库
    #
    # 这里**不能**用 `zcat ... | grep -q 'CREATE TABLE'`:
    # grep -q 一匹配到就退出,zcat 收到 SIGPIPE 非零退出,
    # 而本脚本开了 set -o pipefail,整个管道就变成非零 ——
    # 于是"校验通过"被误判成"没有建表语句",把好备份删掉。
    # 实测踩过这个坑:825KB 的备份被当成空库删了两次。
    #
    # 用 grep -c(读完全部输入,不会提前退出)代替。
    local tables rows
    tables=$(zcat "$tmp" | grep -c '^CREATE TABLE' || true)
    if [ "${tables:-0}" -lt 1 ]; then
        rm -f "$tmp"
        die "备份里没有 CREATE TABLE,可能是空库"
    fi

    mv "$tmp" "$file"
    chmod 600 "$file"

    rows=$(zcat "$file" | grep -c '^INSERT INTO' || true)
    printf 'created=%s\ntables=%s\ninsert_statements=%s\nbytes=%s\n' \
        "$ts" "$tables" "$rows" "$size" > "${file}.meta"

    ok "完成:$(du -h "$file" | cut -f1)  表 ${tables} 个  INSERT ${rows} 条"

    # 清理过期备份
    local removed
    removed=$(find "$BACKUP_DIR" -name "${DB_NAME}-*.sql.gz" -mtime "+${KEEP_DAYS}" -print -delete | wc -l)
    [ "$removed" -gt 0 ] && echo "清理了 ${removed} 个超过 ${KEEP_DAYS} 天的旧备份"

    echo
    echo "现有备份:"
    ls -lht "$BACKUP_DIR"/*.sql.gz 2>/dev/null | awk 'NR<=10 {printf "  %-42s %s\n", $9, $5}'
    echo "  目录合计: $(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)"
}

cmd_list() {
    [ -d "$BACKUP_DIR" ] || die "还没有备份目录:$BACKUP_DIR"
    echo "备份目录:$BACKUP_DIR"
    echo
    ls -lht "$BACKUP_DIR"/*.sql.gz 2>/dev/null | \
        awk '{printf "  %-38s %8s  %s %s %s\n", $9, $5, $6, $7, $8}'
    echo
    echo "合计 $(lc=$(ls "$BACKUP_DIR"/*.sql.gz 2>/dev/null | wc -l); echo $lc) 个,$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)"
}

cmd_verify() {
    local f="${1:-}"
    [ -n "$f" ] || die "用法:$0 --verify <备份文件>"
    [ -f "$f" ] || die "文件不存在:$f"
    gzip -t "$f" 2>/dev/null || die "gzip 校验失败,文件已损坏"
    local tables
    tables=$(zcat "$f" | grep -c '^CREATE TABLE')
    ok "gzip 完整,含 ${tables} 个 CREATE TABLE,$(du -h "$f" | cut -f1)"
    [ -f "${f}.meta" ] && { echo "元信息:"; sed 's/^/  /' "${f}.meta"; }
}

# ---------------------------------------------------------------------------
# 恢复测试:真的把备份导进一个临时库,再比对行数
# 为什么必须做这一步:"备份成功了"和"备份能恢复"是两件事。
# ---------------------------------------------------------------------------
cmd_restore_test() {
    local latest
    latest=$(ls -t "$BACKUP_DIR"/${DB_NAME}-*.sql.gz 2>/dev/null | head -1)
    [ -n "$latest" ] || die "没有找到备份文件,先跑一次备份"

    local scratch="restore_test_$$"
    echo "拿最新备份做恢复测试:$(basename "$latest")"
    echo "临时库名:$scratch"

    myexec mysql -uroot -p"$ROOT_PW" -e "DROP DATABASE IF EXISTS $scratch; CREATE DATABASE $scratch CHARACTER SET utf8mb4;" 2>/dev/null \
        || die "建临时库失败"

    # 注意:用 myexec_i(-i 才能把管道数据送进去)
    # 退出码不可靠:zcat 可能因 SIGPIPE(141)被 pipefail 判为失败,
    # 所以下面不做退出码判断,直接数临时库里有多少张表 —— 那才是事实。
    zcat "$latest" | myexec_i mysql -uroot -p"$ROOT_PW" "$scratch" 2>/tmp/restore.err

    local restored
    restored=$(myexec mysql -uroot -p"$ROOT_PW" -N -e \
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$scratch';" 2>/dev/null | tr -d '\r')
    if [ "${restored:-0}" -lt 1 ]; then
        myexec mysql -uroot -p"$ROOT_PW" -e "DROP DATABASE IF EXISTS $scratch;" 2>/dev/null
        die "恢复失败:临时库里一张表都没有。mysql 报错:
$(grep -v 'Using a password' /tmp/restore.err | head -3)"
    fi
    ok "数据已导入临时库(${restored} 张表)"

    echo
    echo "行数比对(生产库 vs 恢复库):"
    local t a b okall=0 bade=0
    for t in user post comment audit_log alert; do
        a=$(myexec mysql -uroot -p"$ROOT_PW" -N -e "SELECT COUNT(*) FROM ${DB_NAME}.${t};" 2>/dev/null | tr -d '\r')
        b=$(myexec mysql -uroot -p"$ROOT_PW" -N -e "SELECT COUNT(*) FROM ${scratch}.${t};" 2>/dev/null | tr -d '\r')
        # audit_log 在备份之后还在增长,所以恢复的 <= 生产的 就是对的
        if [ "$t" = "audit_log" ]; then
            if [ "${b:-0}" -le "${a:-0}" ] && [ "${b:-0}" -gt 0 ]; then
                printf '  %-10s 生产 %-8s 恢复 %-8s  (备份后新增 %s)\n' "$t" "$a" "$b" "$((a-b))"
                okall=$((okall+1))
            else
                printf '  %-10s 生产 %-8s 恢复 %-8s  !! 异常\n' "$t" "$a" "$b"; bade=$((bade+1))
            fi
        else
            if [ "${a:-0}" = "${b:-0}" ]; then
                printf '  %-10s 生产 %-8s 恢复 %-8s  一致\n' "$t" "$a" "$b"
                okall=$((okall+1))
            else
                printf '  %-10s 生产 %-8s 恢复 %-8s  !! 不一致\n' "$t" "$a" "$b"; bade=$((bade+1))
            fi
        fi
    done

    myexec mysql -uroot -p"$ROOT_PW" -e "DROP DATABASE IF EXISTS $scratch;" 2>/dev/null
    echo
    echo "临时库已删除"
    if [ "$bade" -gt 0 ]; then
        die "恢复测试失败:${bade} 张表行数不符"
    fi
    ok "恢复测试通过:${okall} 张表全部对得上"
}

case "${1:-}" in
    ""|--backup)    cmd_backup ;;
    --list)         cmd_list ;;
    --verify)       cmd_verify "${2:-}" ;;
    --restore-test) cmd_restore_test ;;
    *)              die "用法:$0 [--backup|--list|--verify <文件>|--restore-test]" ;;
esac
