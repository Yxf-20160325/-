-- ============================================================
-- 聊天室 MySQL Schema  (数据库: 11_sunlightor @ urljx5.h.filess.io:3307)
-- 覆盖 4 个模块：用户 / 房间 / 消息 / 好友&私聊&禁言&黑名单
-- 字符集：utf8mb4  引擎：InnoDB
-- ============================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ------------------------------------------------------------
-- 模块 4：用户
-- ------------------------------------------------------------

DROP TABLE IF EXISTS user_ai_settings;
DROP TABLE IF EXISTS user_settings;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  username         VARCHAR(64)  NOT NULL,
  password_hash    VARCHAR(255) NULL COMMENT 'bcrypt 哈希；旧用户暂留空',
  nickname         VARCHAR(64)  NULL,
  avatar           VARCHAR(512) NULL,
  ip               VARCHAR(64)  NULL,
  role             ENUM('user','admin') NOT NULL DEFAULT 'user',
  is_banned        TINYINT(1)   NOT NULL DEFAULT 0,
  experience       INT          NOT NULL DEFAULT 0,
  created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  last_seen_at     DATETIME     NULL,
  PRIMARY KEY (username),
  KEY idx_last_seen (last_seen_at),
  KEY idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户主表';

CREATE TABLE user_settings (
  username            VARCHAR(64) NOT NULL,
  target_language     VARCHAR(16) NOT NULL DEFAULT 'zh-CN',
  auto_translate      TINYINT(1)  NOT NULL DEFAULT 0,
  sound_notification  TINYINT(1)  NOT NULL DEFAULT 1,
  theme               VARCHAR(32) NOT NULL DEFAULT 'light',
  font_size           VARCHAR(16) NOT NULL DEFAULT 'medium',
  notifications       JSON        NULL COMMENT '各类通知开关',
  updated_at          DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (username),
  CONSTRAINT fk_us_user FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户偏好设置';

CREATE TABLE user_ai_settings (
  username            VARCHAR(64) NOT NULL,
  enable              TINYINT(1)  NOT NULL DEFAULT 0,
  model               VARCHAR(32) NOT NULL DEFAULT 'glm4',
  glm4_api_key        VARCHAR(512) NULL,
  deepseek_api_key    VARCHAR(512) NULL,
  siliconflow_api_key VARCHAR(512) NULL,
  custom_api_url      VARCHAR(512) NULL,
  custom_api_key      VARCHAR(512) NULL,
  custom_model_name   VARCHAR(128) NULL,
  updated_at          DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (username),
  CONSTRAINT fk_uas_user FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户 AI 配置';

-- ------------------------------------------------------------
-- 模块 2：房间
-- ------------------------------------------------------------

DROP TABLE IF EXISTS room_theme;
DROP TABLE IF EXISTS room_settings;
DROP TABLE IF EXISTS rooms;

CREATE TABLE rooms (
  room_name        VARCHAR(128) NOT NULL,
  password_hash    VARCHAR(255) NULL,
  creator          VARCHAR(64)  NULL,
  is_deleted       TINYINT(1)   NOT NULL DEFAULT 0,
  total_messages   INT          NOT NULL DEFAULT 0,
  total_users      INT          NOT NULL DEFAULT 0,
  peak_users       INT          NOT NULL DEFAULT 0,
  created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  last_activity    DATETIME     NULL,
  PRIMARY KEY (room_name),
  KEY idx_creator (creator),
  KEY idx_last_activity (last_activity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='房间主表';

CREATE TABLE room_settings (
  room_name            VARCHAR(128) NOT NULL,
  max_users            INT         NOT NULL DEFAULT 100,
  allow_public_access  TINYINT(1)  NOT NULL DEFAULT 1,
  allow_messages       TINYINT(1)  NOT NULL DEFAULT 1,
  allow_files          TINYINT(1)  NOT NULL DEFAULT 1,
  allow_audio          TINYINT(1)  NOT NULL DEFAULT 1,
  allow_video          TINYINT(1)  NOT NULL DEFAULT 1,
  allow_calls          TINYINT(1)  NOT NULL DEFAULT 1,
  allow_whiteboard     TINYINT(1)  NOT NULL DEFAULT 1,
  allow_polls          TINYINT(1)  NOT NULL DEFAULT 1,
  allow_games          TINYINT(1)  NOT NULL DEFAULT 1,
  updated_at           DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (room_name),
  CONSTRAINT fk_rs_room FOREIGN KEY (room_name) REFERENCES rooms(room_name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='房间功能开关';

CREATE TABLE room_theme (
  room_name    VARCHAR(128) NOT NULL,
  background   VARCHAR(64)  NOT NULL DEFAULT 'default',
  color_scheme VARCHAR(16)  NOT NULL DEFAULT 'light',
  custom_css   TEXT         NULL,
  updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (room_name),
  CONSTRAINT fk_rt_room FOREIGN KEY (room_name) REFERENCES rooms(room_name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='房间主题';

-- ------------------------------------------------------------
-- 模块 1：消息
-- ------------------------------------------------------------

DROP TABLE IF EXISTS deleted_messages;
DROP TABLE IF EXISTS messages;

CREATE TABLE messages (
  id          VARCHAR(64)  NOT NULL COMMENT '客户端生成的字符串 id（与内存消息对象一一对应），不走 AUTO_INCREMENT',
  room_name   VARCHAR(128) NOT NULL,
  sender      VARCHAR(64)  NULL COMMENT 'NULL 表示系统消息',
  type        VARCHAR(32)  NOT NULL DEFAULT 'text' COMMENT 'text/image/file/audio/video/location/system/ai/announcement',
  content     MEDIUMTEXT   NULL,
  metadata    JSON         NULL COMMENT '扩展：文件大小、坐标、@mentions 等',
  reply_to    VARCHAR(64)  NULL COMMENT '引用消息的 id',
  is_deleted  TINYINT(1)   NOT NULL DEFAULT 0,
  created_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_room_created (room_name, created_at),
  KEY idx_room_active  (room_name, is_deleted, created_at),
  KEY idx_sender       (sender),
  KEY idx_reply_to     (reply_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='房间消息（每条独立一行）';

CREATE TABLE deleted_messages (
  message_id        VARCHAR(64)  NOT NULL,
  room_name         VARCHAR(128) NOT NULL,
  deleted_by        VARCHAR(64)  NULL,
  reason            VARCHAR(255) NULL,
  original_content  MEDIUMTEXT   NULL,
  created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (message_id),
  KEY idx_dm_room (room_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='被删除消息（审核追溯用）';

-- ------------------------------------------------------------
-- 模块 5：好友 / 私聊 / 禁言 / 黑名单
-- ------------------------------------------------------------

DROP TABLE IF EXISTS banned_ips;
DROP TABLE IF EXISTS muted_users;
DROP TABLE IF EXISTS private_messages;
DROP TABLE IF EXISTS friend_requests;
DROP TABLE IF EXISTS friendships;

CREATE TABLE friendships (
  user_a     VARCHAR(64) NOT NULL COMMENT '字典序较小的用户名',
  user_b     VARCHAR(64) NOT NULL COMMENT '字典序较大的用户名',
  is_forced  TINYINT(1)  NOT NULL DEFAULT 0 COMMENT '管理员强制好友，不可删',
  created_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_a, user_b),
  KEY idx_user_b (user_b),
  KEY idx_user_a (user_a)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='好友关系（用字典序保证不重复）';

CREATE TABLE friend_requests (
  id         BIGINT       NOT NULL AUTO_INCREMENT,
  from_user  VARCHAR(64)  NOT NULL,
  to_user    VARCHAR(64)  NOT NULL,
  reason     VARCHAR(255) NULL,
  status     ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_to_status (to_user, status),
  KEY idx_from_user (from_user)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='好友申请';

CREATE TABLE private_messages (
  id          VARCHAR(64)  NOT NULL COMMENT '客户端生成的字符串 id（与内存私聊对象一一对应）',
  chat_id     VARCHAR(128) NOT NULL COMMENT '两个用户名按字典序拼成：alice__bob',
  from_user   VARCHAR(64)  NOT NULL,
  to_user     VARCHAR(64)  NOT NULL,
  type        VARCHAR(32)  NOT NULL DEFAULT 'text',
  content     MEDIUMTEXT   NULL,
  metadata    JSON         NULL,
  is_read     TINYINT(1)   NOT NULL DEFAULT 0,
  created_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_chat_created (chat_id, created_at),
  KEY idx_to_unread    (to_user, is_read, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='私聊消息';

CREATE TABLE muted_users (
  username   VARCHAR(64) NOT NULL,
  end_time   DATETIME    NULL COMMENT 'NULL 表示永久禁言',
  reason     VARCHAR(255) NULL,
  muted_by   VARCHAR(64)  NULL,
  created_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='禁言名单';

CREATE TABLE banned_ips (
  ip         VARCHAR(64) NOT NULL,
  reason     VARCHAR(255) NULL,
  banned_by  VARCHAR(64)  NULL,
  created_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='IP 黑名单';

SET FOREIGN_KEY_CHECKS = 1;

-- ------------------------------------------------------------
-- 种子数据：默认 main 房间
-- ------------------------------------------------------------
INSERT INTO rooms (room_name, creator, total_messages, total_users, peak_users, last_activity)
VALUES ('main', 'system', 0, 0, 0, NOW())
ON DUPLICATE KEY UPDATE last_activity = NOW();

INSERT INTO room_settings (room_name) VALUES ('main')
ON DUPLICATE KEY UPDATE room_name = room_name;

INSERT INTO room_theme (room_name) VALUES ('main')
ON DUPLICATE KEY UPDATE room_name = room_name;
