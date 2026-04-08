# 项目记忆

## 项目概述

Node.js + Express + Socket.IO 聊天室项目，前端为单文件 `public/index.html`（约25000行），管理后台为 `public/admin.html`（约8500行），服务端为 `server.cjs`。

---

## 已修复的 Bug

### 2026-04-03: CodeMirror rust.min.js defineSimpleMode 错误
- **原因**：CodeMirror 5.65.16 移除了 `defineSimpleMode` API
- **修复**：移除 `public/index.html` 中的 rust.min.js 引用

### 2026-04-03: socket.on 事件监听器在 socket 未初始化时调用
- **原因**：公告相关 `socket.on()` 在脚本顶层执行，socket 尚未初始化
- **修复**：包装为 `registerAnnouncementEventListeners()` 函数，在 `socket.on('connect')` 中调用

### 2026-04-03: 公告标签页切换后内容为空
- **原因**：`data-tab="announcementTab"` + JS 加"Tab" = `announcementTabTab`
- **修复**：改为 `data-tab="announcement"`

### 2026-04-03: 图片发送时自动添加水印
- **功能**：Canvas 在图片右下角添加水印 "made with liaotianshi.onrender.com"

### 2026-04-06: 消息撤回失败（重连后 socket.id 变化）
- **原因**：服务端校验 `message.senderSocketId !== socket.id`，重连后 socket.id 变了
- **修复**：改为校验 `message.username !== user.username`（`server.cjs` 第8695行）

### 2026-03-23: confirmDeviceSelect pendingCallAction 未定义
- **修复**：在全局变量区域添加 `pendingCallAction`、`selectedVideoDeviceId` 等声明

### 2026-03-21: 调试面板函数未定义
- **修复**：添加 `debugTestConnection`、`debugReconnect`、`debugClearCache` 实现

### 2026-03-21: 实时位置发送失败
- **原因**：`server.cjs` 消息处理代码缩进错误，实时位置消息未发送给其他客户端
- **修复**：调整代码缩进

---

## 已添加功能

### 2026-04-06: admin.html API 管理标签页
- **位置**：`public/admin.html` — "更多"菜单 → "API管理" 标签
- **功能**：查看所有内置 API、启用/禁用内置 API、添加/编辑/删除/测试自定义 API
- **后端**：`server.cjs` 中新增 `/api/admin/api-manager/*` 系列接口
  - `GET /api/admin/api-manager/list` — 列出所有 API
  - `POST /api/admin/api-manager/toggle-builtin` — 启用/禁用内置 API
  - `POST /api/admin/api-manager/add` — 添加自定义 API
  - `PUT /api/admin/api-manager/update` — 更新自定义 API
  - `POST /api/admin/api-manager/toggle-custom` — 启用/禁用自定义 API
  - `DELETE /api/admin/api-manager/custom` — 删除自定义 API
  - `POST /api/admin/api-manager/test` — 测试 API

### 2026-04-04: 通话降噪功能改进
- 降噪级别: low(-55dB)/medium(-45dB)/high(-35dB)
- 基于 RMS、dB、零交叉率、峰峭因子的语音检测

---

## 技术债务

- `substr()` 大量使用（已废弃，建议替换为 `substring()` 或 `slice()`）
- `public/index.html` 体积过大（约25000行），建议拆分模块

---

## 已知限制

- 每房间最多保存 100 条历史消息（`server.cjs` 中可配置）
- 最大文件上传：30MB（图片5MB，音频10MB）
- 实时位置需 HTTPS 环境

---

## Android APK 构建（2026-04-08）

- **方式**：GitHub Actions 云构建，零本地磁盘占用
- **工作流文件**：`.github/workflows/build-apk.yml`
- **触发方式**：push 到 master 自动构建，或手动触发
- **APK 下载**：https://github.com/Yxf-20160325/-/releases/tag/apk-latest
- **构建进度**：https://github.com/Yxf-20160325/-/actions
- **一键推送脚本**：`push-and-build.bat`
- **Capacitor 配置**：`capacitor.config.json`，appId=`com.chatroom.app`，webDir=`public`
- **注意**：`android/gradle/wrapper/gradle-wrapper.properties` 用了阿里云镜像，CI 中已自动替换为官方源

---

## 项目配置

- 管理员密码默认：`admin123`（`server.cjs` 第2311行 `ADMIN_PASSWORD`）
- 静态文件：`public/` 目录
- 文件上传：`uploads/` 目录
- 病毒隔离：`viruses/` 目录
