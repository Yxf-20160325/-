# 项目记忆

## 已修复的 Bug

### 2026-04-03: CodeMirror rust.min.js defineSimpleMode 错误

**问题描述**：控制台报错 `rust.min.js:1 Uncaught TypeError: e.defineSimpleMode is not a function`

**根本原因**：CodeMirror 5.65.16 版本移除了 `defineSimpleMode` API，但 `rust.min.js` 文件仍使用该方法。

**修复方案**：移除 `public/index.html` 中的 rust.min.js 引用：
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/rust/rust.min.js"></script>
```

**影响**：Rust 代码将不再有语法高亮，但不会影响其他功能。

---

### 2026-04-03: socket.on 事件监听器在 socket 未初始化时调用

**问题描述**：控制台报错 `(索引):11691 Uncaught TypeError: Cannot read properties of undefined (reading 'on')`

**根本原因**：公告相关的 `socket.on()` 调用（`room-announcements-list`、`room-announcement-added`）在脚本顶层执行，但此时 `socket` 变量尚未初始化（`initSocket()` 在页面加载后期才调用）。

**修复方案**：
1. 将公告相关的 `socket.on()` 调用包装到 `registerAnnouncementEventListeners()` 函数中
2. 在 `socket.on('connect')` 事件回调中调用该函数

**修复文件**：`public/index.html`

---

### 2026-04-03: 管理员登录后才能发布公告

**功能需求**：只有管理员登录后才能使用公告发布功能

**修复方案**：
1. 添加 `isAdminLoggedIn` 变量跟踪管理员登录状态
2. 监听 `admin-login-success` 事件更新登录状态
3. 在 `submitAnnouncement()` 中添加登录检查

**修复文件**：`public/index.html`

---

### 2026-04-03: 公告标签页切换后内容为空

**问题描述**：点击"发布公告"标签后，下方内容区域为空

**根本原因**：标签按钮的 `data-tab="announcementTab"` 已包含 "Tab" 后缀，但 JavaScript 又在后面加了 "Tab"，变成 `announcementTabTab`

**修复方案**：将 `data-tab="announcementTab"` 改为 `data-tab="announcement"`

**修复文件**：`public/index.html`

---

### 2026-04-03: 图片发送时自动添加水印

**功能需求**：用户发送图片时自动添加水印 "made with liaotianshi.onrender.com"

**实现方案**：
1. 添加 `addWatermarkToImage()` 函数，使用 Canvas 在图片右下角添加水印
2. 水印位置：右下角大字 + 左下角小字
3. 水印样式：白色半透明文字 + 黑色描边
4. 同时修改普通图片和私聊图片上传逻辑

**修复文件**：`public/index.html`

---

### 2026-03-23: 选择设备模态框 pendingCallAction 未定义错误

**问题描述**：点击"选择设备"模态框的确认按钮时，控制台报错 `Uncaught ReferenceError: pendingCallAction is not defined`

**根本原因**：`confirmDeviceSelect()` 函数中使用了全局变量 `pendingCallAction`，但该变量从未在代码开头被声明为全局变量。虽然在某些分支中该变量被赋值，但当作为全局变量使用时，JavaScript 引擎无法找到它的定义。

**修复方案**：在全局变量声明区域（第 19959-19967 行）添加以下变量声明：
```javascript
let pendingCallAction = null;      // 挂起的通话操作（设备选择前的通话信息）
let selectedVideoDeviceId = null;  // 选中的摄像头设备ID
let selectedAudioDeviceId = null;  // 选中的音频设备ID
let availableVideoDevices = [];    // 可用的摄像头设备列表
let availableAudioDevices = [];    // 可用的音频设备列表
```

**修复文件**：
- `public/index.html`（第 19963-19967 行）
- `public/index - 副本.html`（相同位置）

**验证**：修复后，点击确认按钮应该不再报错。

---

### 2026-03-21: 调试面板函数未定义

**问题描述**：管理员调试面板中 3 个按钮（测试连接、重新连接、清除缓存）点击时报 `ReferenceError: xxx is not defined`

**根本原因**：HTML 模板引用了 `debugTestConnection`、`debugReconnect`、`debugClearCache` 三个函数，但 JavaScript 中只有其他 6 个调试函数的定义，缺少这 3 个

**修复方案**：在 `debugSimulateMessage` 之前添加了 3 个缺失函数的实现：
- `debugTestConnection()`：检查 socket 连接状态并显示结果
- `debugReconnect()`：断开并重新连接 socket
- `debugClearCache()`：清除 localStorage 和 sessionStorage

**修复文件**：`public/index.html`（约第 4400 行区域）

---

### 2026-03-21: 实时位置发送失败

**问题描述**：发送实时位置会失败

**根本原因**：服务器端代码逻辑错误。在 `server.cjs` 第 3369-3432 行，处理消息的代码结构有缺陷。实时位置消息的处理在 `if` 分支中，但发送消息的逻辑在 `if-else` 语句外面，导致实时位置消息从未被发送给其他客户端。

**修复方案**：调整代码缩进，确保发送消息的逻辑对所有消息类型（包括实时位置）都执行。

**影响范围**：实时位置共享功能

**修复文件**：`c:\Users\win\Desktop\代码\聊天室\server.cjs`

---

## 技术债务

### 已弃用的 API 使用

#### `substr()` 方法

**问题描述**：代码中大量使用了已废弃的 `substr()` 方法

**影响范围**：
- `server.cjs`：至少 15 处使用
- `public/index.html`：至少 3 处使用
- `server - 副本.cjs`：多处使用

**优先级**：低（目前所有现代浏览器仍支持，但建议将来修复）

**建议替换**：`substr(start, length)` → `substring(start, end)` 或 `slice(start, end)`

**示例**：
```javascript
// 旧代码
const id = Date.now().toString() + Math.random().toString(36).substr(2, 9);

// 新代码
const id = Date.now().toString() + Math.random().toString(36).substring(2, 11);
// 或
const id = Date.now().toString() + Math.random().toString(36).slice(2, 11);
```

**为什么不是 Bug**：`substr()` 虽然已废弃，但在所有现代浏览器中仍然正常工作，且效果与 `substring()` 完全相同。只是将来某个时间点可能会被移除。

---

## 已知限制

### 1. 浏览器兼容性

**限制**：某些旧版浏览器可能不支持以下特性

**不支持的功能**：
- ES6+ 语法（箭头函数、async/await、模板字符串等）
- Socket.IO（需要 WebSocket 支持）
- 地理定位 API
- Web Audio API
- File API

**影响范围**：IE 11 及更早版本、某些移动浏览器旧版本

**建议**：建议用户使用现代浏览器（Chrome 70+、Firefox 65+、Safari 12+、Edge 79+）

### 2. 实时位置功能的限制

**限制**：实时位置功能依赖浏览器地理定位 API，有以下限制

**影响范围**：
- 需要用户授权位置权限
- 在 HTTPS 环境下才能正常工作（HTTP 环境下部分浏览器会限制）
- 定位精度取决于设备和环境
- 定位可能失败（室内、GPS 信号弱等）

**错误处理**：代码中已包含完整的错误处理逻辑，会提示用户具体错误原因

### 3. 文件上传限制

**限制**：服务器端对文件大小和类型有限制

**当前限制**：
- 最大文件大小：30MB
- 最大图片大小：5MB
- 最大音频大小：10MB
- 不允许上传的文件类型：.php, .jsp, .asp, .aspx, .shtml, .cgi, .pl, .sh, .vbs 等

**原因**：安全考虑，防止上传恶意文件

**不可绕过**：这是服务器端的硬限制

### 4. 消息历史限制

**限制**：每个房间最多保存 100 条消息历史

**影响范围**：
- 新消息会挤掉旧消息
- 无法查看超过 100 条的历史消息
- 刷新页面后只能加载最新的 100 条消息

**原因**：性能和存储考虑

**可配置**：修改 `server.cjs` 中的 `room.messages.length > 100` 限制

---

## 待优化项

### 1. 性能优化

**问题**：前端文件（`public/index.html`）过大（约 20,000 行代码）

**影响**：
- 首次加载时间较长
- 代码维护困难
- 不利于团队协作

**建议**：
- 将 JavaScript 代码拆分成多个模块文件
- 将 CSS 样式提取到独立文件
- 使用打包工具（Webpack、Vite 等）

**优先级**：中

### 2. 安全性增强

**建议添加的安全措施**：

1. **CSRF Token 验证**：虽然已有 CSRF token 生成逻辑，但需要确保所有敏感操作都验证 token
2. **内容安全策略（CSP）**：添加 CSP 头以防止 XSS 攻击
3. **输入验证增强**：对所有用户输入进行更严格的验证和过滤
4. **速率限制**：为 API 端点添加速率限制，防止 DDoS 攻击

**优先级**：中

### 3. 用户体验改进

**建议改进**：

1. **加载状态指示器**：长时间操作时显示加载动画
2. **离线检测**：检测网络状态，提示用户网络已断开
3. **消息搜索优化**：优化搜索算法，支持更复杂的查询
4. **移动端优化**：进一步优化移动端体验

**优先级**：低

---

## 代码规范建议

### 1. 命名规范

**建议**：
- 变量名使用 camelCase（如 `messageId`）
- 常量使用 UPPER_SNAKE_CASE（如 `MAX_FILE_SIZE`）
- 类名使用 PascalCase（如 `MessageHandler`）

**当前状态**：部分遵循，部分不遵循

### 2. 注释规范

**建议**：
- 为复杂逻辑添加详细注释
- 使用 JSDoc 格式为函数添加文档注释
- 标注 TODO、FIXME、HACK 等待处理的事项

**当前状态**：注释较少，部分代码缺乏说明

### 3. 错误处理

**建议**：
- 所有异步操作都应包含错误处理
- 向用户显示友好的错误提示
- 记录详细的错误日志

**当前状态**：部分代码缺少错误处理

---

## 配置建议

### 开发环境配置

**建议**：
- 启用详细的日志输出
- 禁用缓存
- 启用热重载

### 生产环境配置

**建议**：
- 启用代码压缩和混淆
- 启用 HTTP/2
- 配置 CDN
- 启用 HTTPS
- 配置备份和监控

---

## 测试建议

### 单元测试

**建议添加**：
- 核心业务逻辑的单元测试
- API 端点的单元测试
- 工具函数的单元测试

### 集成测试

**建议添加**：
- Socket.IO 通信的集成测试
- 文件上传的集成测试
- 用户权限的集成测试

### E2E 测试

**建议添加**：
- 使用 Cypress 或 Playwright 进行端到端测试
- 测试关键用户流程（登录、发送消息、上传文件等）

---

## 监控和日志

### 建议添加的监控

1. **错误监控**：使用 Sentry 或类似工具监控运行时错误
2. **性能监控**：监控页面加载时间、API 响应时间等
3. **用户行为分析**：分析用户使用情况，优化用户体验

### 日志建议

1. **结构化日志**：使用 JSON 格式的结构化日志
2. **日志分级**：ERROR、WARN、INFO、DEBUG
3. **日志聚合**：使用 ELK、Splunk 等工具聚合和分析日志

---

## 文档建议

### 缺失的文档

1. **API 文档**：详细的 API 接口文档
2. **部署文档**：服务器部署和配置指南
3. **故障排查指南**：常见问题和解决方案
4. **性能优化指南**：性能调优建议

---

## 版本控制建议

### 建议的分支策略

1. **主分支（master/main）**：稳定的生产代码
2. **开发分支（develop）**：最新的开发代码
3. **功能分支（feature/*）**：开发新功能
4. **修复分支（bugfix/*）**：修复 Bug
5. **发布分支（release/*）**：准备发布

### 建议的提交规范

使用 Conventional Commits 规范：
- `feat:` 新功能
- `fix:` 修复 Bug
- `docs:` 文档更新
- `style:` 代码格式调整
- `refactor:` 代码重构
- `test:` 测试相关
- `chore:` 构建/工具链相关

---

## 总结

当前项目整体状态良好，核心功能正常。主要的 Bug 已修复，存在一些技术债务和待优化项，但不影响正常使用。建议逐步改进代码质量和项目结构。

**优先级排序**：
1. 🔴 高优先级：无
2. 🟡 中优先级：性能优化、安全性增强、代码规范
3. 🟢 低优先级：用户体验改进、文档完善、测试覆盖
