-- SecGuard 数据库结构  |  W1
-- 来源:career-plan/01-项目实施与寒假实习执行手册.md §2.4
CREATE DATABASE IF NOT EXISTS secguard
  DEFAULT CHARSET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE secguard;

-- 用户表
CREATE TABLE IF NOT EXISTS `user` (
  `id`            BIGINT       NOT NULL AUTO_INCREMENT,
  `username`      VARCHAR(64)  NOT NULL,
  `password_hash` VARCHAR(128) NOT NULL COMMENT '哈希后存储,严禁明文',
  `email`         VARCHAR(128) DEFAULT NULL,
  `status`        TINYINT      NOT NULL DEFAULT 1 COMMENT '1正常 0封禁',
  `created_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 帖子表
CREATE TABLE IF NOT EXISTS `post` (
  `id`         BIGINT       NOT NULL AUTO_INCREMENT,
  `user_id`    BIGINT       NOT NULL,
  `title`      VARCHAR(255) NOT NULL,
  `content`    TEXT         NOT NULL,
  `status`     TINYINT      NOT NULL DEFAULT 1,
  `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 审计日志表(核心表)
CREATE TABLE IF NOT EXISTS `audit_log` (
  `id`            BIGINT       NOT NULL AUTO_INCREMENT,
  `trace_id`      VARCHAR(64)  NOT NULL,
  `ip`            VARCHAR(64)  NOT NULL,
  `user_id`       BIGINT       DEFAULT NULL,
  `uri`           VARCHAR(512) NOT NULL,
  `method`        VARCHAR(16)  NOT NULL,
  `params_digest` VARCHAR(1024) DEFAULT NULL COMMENT '参数摘要,需脱敏',
  `rule_hit`      VARCHAR(128) DEFAULT NULL COMMENT '命中的特征 ID',
  `matched_len`   INT          DEFAULT 0   COMMENT 'AC 自动机匹配长度',
  `action`        VARCHAR(32)  NOT NULL COMMENT 'PASS/BLOCK/ALERT',
  `status_code`   INT          NOT NULL,
  `cost_us`       BIGINT       NOT NULL DEFAULT 0 COMMENT '耗时(微秒,引擎级精度)',
  `analyzed`      TINYINT      NOT NULL DEFAULT 0,
  `created_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_ip_time` (`ip`, `created_at`),
  KEY `idx_analyzed` (`analyzed`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 告警表
CREATE TABLE IF NOT EXISTS `alert` (
  `id`          BIGINT        NOT NULL AUTO_INCREMENT,
  `ip`          VARCHAR(64)   NOT NULL,
  `threat_type` VARCHAR(64)   NOT NULL,
  `severity`    VARCHAR(16)   NOT NULL COMMENT 'LOW/MEDIUM/HIGH/CRITICAL',
  `confidence`  DECIMAL(4,3)  NOT NULL,
  `reasoning`   TEXT          COMMENT 'LLM 判断依据',
  `log_ids`     VARCHAR(1024) DEFAULT NULL,
  `status`      TINYINT       NOT NULL DEFAULT 0 COMMENT '0待处理 1已确认 2误报',
  `created_at`  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_status` (`status`),
  KEY `idx_ip` (`ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 评论表(W2 有"评论 CRUD",2.4 原文缺这张表)
CREATE TABLE IF NOT EXISTS `comment` (
  `id`         BIGINT   NOT NULL AUTO_INCREMENT,
  `post_id`    BIGINT   NOT NULL,
  `user_id`    BIGINT   NOT NULL,
  `content`    TEXT     NOT NULL,
  `status`     TINYINT  NOT NULL DEFAULT 1,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_post_id` (`post_id`),
  KEY `idx_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
