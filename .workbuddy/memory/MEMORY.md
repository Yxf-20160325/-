# 项目记忆

## 项目概述

Node.js + Express + Socket.IO 聊天室项目，前端为单文件 `public/index.html`（约25000行），管理后台为 `public/admin.html`（约8500行），服务端为 `server.cjs`。

---

## 已修复的 Bug

### 2026-04-20: XSS 跨站脚本漏洞修复
- **原因**：index.html 和 admin.html 中大量 innerHTML 使用未转义的用户输入
- **修复**：对所有用户可控数据添加 `escapeHtml()` 转义，包括：
  - 用户名 (username)
  - 游戏名称 (gameType)
  - 玩家名称 (playerNames)
  - 文档名称 (title)
  - 贴纸名称 (name)
  - 错误消息 (message)
  - 聊天日志 (log)

### 2026-04-20: multipart/form-data 与 express.json 中间件冲突
- **原因**：全局 express.json() 在 formidable 之前处理文件上传请求
- **修复**：添加条件判断，跳过 multipart/form-data 类型请求的 JSON 解析

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

### 2026-04-09: 互动中心 PC 虚拟账户联机
- **位置**：`server.cjs` 全局变量区 + 游戏事件处理区
- **常量**：`PC_SOCKET_ID='pc-bot-virtual-socket'`，`PC_USERNAME='pc'`
- **触发**：在线用户列表自动出现 pc；向 pc 发邀请自动接受并创建游戏
- **支持游戏**：五子棋（贪心AI）、猜数字（二分法）、猜拳（随机）、数字炸弹（余数策略）
- **先手**：玩家先手（五子棋/猜数字），自然体验

### 2026-04-14: APP 管理与推送功能
- **位置**：`public/admin.html` — "更多"菜单 → "APP管理" 标签
- **服务端**：`server.cjs` 新增 APP 管理 API
  - `GET /api/admin/apps/list` — 获取APP列表和推送历史
  - `POST /api/admin/apps/upload` — 上传APP安装包（支持 apk/ipa/xapk/aab 等）
  - `DELETE /api/admin/apps/:id` — 删除APP
  - `POST /api/admin/apps/:id/toggle` — 启用/禁用APP
  - `POST /api/admin/apps/push` — 推送APP更新给用户（Socket.IO广播）
  - `GET /apps/download/:id` — 下载APP（增加下载计数）
  - `GET /api/apps/check-update` — 客户端检查APP更新
  - `GET /apps/install/:id` — 生成iOS manifest.plist（itms-services用）
  - `GET /apps/itms/:id` — iOS安装跳转（重定向到itms-services）
  - `GET /api/apps/install-link/:id` — 获取安装链接
- **iOS安装**：支持 itms-services 协议，企业证书签名ipa可通过此方式安装
- **存储目录**：`apps/` 目录存储APP文件，`storage/apps.json` 存储APP元数据
- **客户端**：接收 `app-update-push` 事件，自动检测iOS并使用itms安装

### 2026-04-11: admin.html 新增管理标签页
- **互动中心管理**：玩家配对管理、游戏权限管理、当前游戏局管理
- **页面权限管理**：页面访问权限（聊天、语音、视频、游戏等）、功能按钮权限
- **表情包管理**：发送/搜索/自定义表情包权限、表情包库管理、表情包统计
- **服务端 API**：新增 `/api/admin/interaction/*`、`/api/admin/page-permissions/*`、`/api/admin/emoji-*` 系列接口

### 2026-04-22: admin.html 显示用户位置
- **服务端**：`server.cjs` 的 `admin-get-room-users` 事件返回用户最近发送的位置消息
- **前端**：`admin.html` 用户列表显示用户位置信息（位置名称、坐标、是否实时共享）
- **数据来源**：从房间历史消息中查找 `type: 'location'` 的消息，取每个用户最新的位置

### 2026-04-25: 手机端无法下载文件
- **原因**：`<a download>` 属性在手机端（iOS Safari / Android WebView）不支持，点击会直接在浏览器内打开而非下载；`/uploads` 静态服务也没有 `Content-Disposition: attachment` 头
- **修复**：新增 `downloadFile(url, fileName)` 函数（服务端 `/download/` 路由 + iOS 直接跳转），Capacitor 原生端用 `APP_SERVER_URL` 拼接完整 URL；替换 index.html 中所有文件下载链接改用此函数
- **同步修复**：私聊文件默认名 `'文件null'` 改为 `'文件'`

### 2026-04-25: iOS 上传文件 NetworkError
- **原因**：CORS `allowedHeaders` 缺少 `X-Filename`/`X-Path` 等自定义头，Capacitor 跨域预检被拒
- **修复**：CORS allowedHeaders 补全所有自定义头；XHR 拦截器继承原始原型链；全局 JSON 中间件只处理 application/json

### 2026-04-22: admin.html 直接请求用户位置（立刻）
- **功能**：管理员点击"📍要位置"按钮，向指定用户请求实时位置
- **流程**：admin.html → `admin-request-location` → server.cjs → `location-request` → index.html用户
- **用户端**：收到请求弹窗，用户同意后发送 `location-response` 事件
- **服务端**：接收响应后调用高德API获取位置名称，广播给房间内所有人

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
