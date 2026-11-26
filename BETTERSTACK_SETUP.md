# Better Stack 状态监控部署指南

本项目已内置两种接入方式，任选其一即可。

## 服务端已完成的改动

- `GET /health` —— 公开健康检查端点，返回 JSON（status / uptimeSeconds / timestamp），无需鉴权、不受 CSRF 与限流影响。
- `GET /health/ping` —— 返回纯文本 `pong`，用于最简单的探活。
- Heartbeat 主动上报：配置 `BETTERSTACK_HEARTBEAT_URL` 后，服务启动 3 秒后上报一次，之后按 `BETTERSTACK_HEARTBEAT_INTERVAL_MS`（默认 60 秒）定时上报。

## 方式一：HTTP Uptime 监控（推荐，无需服务器改配置）

1. 登录 https://betterstack.com ，进入 **Uptime → Monitors → Add monitor**。
2. 类型选 **HTTP**，URL 填：`https://你的域名/health`。
   - 本地/内网穿透场景用对应可公网访问的地址。
3. Check frequency 建议 30 秒～1 分钟；选择探测地区（可多选）。
4. 保存后打开 **Status page**，把状态页链接发给用户即可。

> 该方式完全由 Better Stack 从外部探测，服务端无需任何环境变量。

## 方式二：Heartbeat（Cron）监控

适合探测「服务进程是否还活着 / 定时任务是否正常」。

1. Better Stack → **Uptime → Monitors → Add monitor → Heartbeat (Cron)**。
2. 复制生成的 Heartbeat URL，形如：
   `https://incidents.betterstack.com/api/v1/heartbeat/<TOKEN>`
3. 在服务端环境（Render Dashboard → Environment，或本地 `.env`）添加：

   ```
   BETTERSTACK_HEARTBEAT_URL=https://incidents.betterstack.com/api/v1/heartbeat/<TOKEN>
   BETTERSTACK_HEARTBEAT_INTERVAL_MS=60000
   ```

4. **关键**：Better Stack 监控的 Schedule / Grace period 必须大于上报间隔。
   例如上报 60 秒一次，则 Schedule 设为 1 分钟、Grace period 设 2 分钟。
5. 重启服务，日志出现 `[BetterStack] 心跳上报已启用` 即生效。

## 状态页（Status page）

1. Better Stack → **Status pages → Create status page**。
2. 绑定上面的 monitor。
3. 自定义域名（可选）：在 Better Stack 里配置 CNAME，并在 DNS 添加记录。

## 验证

```
curl https://你的域名/health
# {"status":"ok","uptimeSeconds":123,"timestamp":"..."}
```

在 Better Stack 面板看到该 monitor 变为 **Up / green** 即部署完成。

## 安全说明

- `/health` 只暴露运行时长和时间戳，不含任何敏感信息。
- Heartbeat URL 内含 token，只应放在服务端环境变量中，**不要**写进前端或提交到仓库（`.env` 已在 `.gitignore`）。
