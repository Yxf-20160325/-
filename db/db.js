// ============================================================
// db/db.js — 聊天室数据库访问层
// 覆盖模块：用户(4) / 房间(2) / 消息(1) / 好友&私聊&禁言&黑名单(5)
// 设计原则：
//   - 所有函数都是 async，内部 try/catch，DB 不可用时静默降级，绝不抛错打断实时链路
//   - 写入采用 fire-and-forget（.catch 吞错），不阻塞 socket.io 广播
//   - 内存 Map 仍是实时工作状态；DB 是跨重启的持久化层
// ============================================================
const mysql = require('mysql2/promise');

const CONFIG = {
    host: process.env.DB_HOST || 'urljx5.h.filess.io',
    port: parseInt(process.env.DB_PORT || '3307', 10),
    user: process.env.DB_USER || '11_sunlightor',
    password: process.env.DB_PASSWORD || '0466cba860dfedb6354c0f44e70cd576221538e7',
    database: process.env.DB_NAME || '11_sunlightor',
    charset: 'utf8mb4',
    // filess.io 对该用户限制 max_user_connections=5；池上限设 3，给管理/测试工具的独立连接留出余量
    connectionLimit: 3,
    waitForConnections: true,
    connectTimeout: 10000,
    // filess.io 的 MySQL 偶尔会 idle 断连，加上自动重连参数
    enableKeepAlive: true,
    keepAliveInitialDelay: 30000
};

let pool = null;
let DB_ENABLED = true; // 可通过环境变量 USE_DB=0 关闭，瞬间回退到纯内存

function isEnabled() {
    return DB_ENABLED && process.env.USE_DB !== '0';
}

async function init() {
    if (!isEnabled()) {
        console.log('[DB] USE_DB=0，数据库功能已关闭（纯内存模式）');
        return false;
    }
    try {
        pool = mysql.createPool(CONFIG);
        const conn = await pool.getConnection();
        await conn.ping();
        conn.release();
        console.log('[DB] 连接池已建立 ✓');
        return true;
    } catch (err) {
        console.error('[DB] 初始化失败，应用将以纯内存模式运行:', err.code || err.message);
        DB_ENABLED = false;
        pool = null;
        return false;
    }
}

// 通用查询（自动降级）
async function query(sql, params = []) {
    if (!isEnabled() || !pool) return null;
    try {
        const [rows] = await pool.query(sql, params);
        return rows;
    } catch (err) {
        console.error('[DB] query error:', err.code || err.message, '|', String(sql).slice(0, 120));
        return null;
    }
}

async function execute(sql, params = []) {
    if (!isEnabled() || !pool) return null;
    try {
        const [result] = await pool.execute(sql, params);
        return result;
    } catch (err) {
        console.error('[DB] execute error:', err.code || err.message, '|', String(sql).slice(0, 120));
        return null;
    }
}

// fire-and-forget：用于写入，不阻塞主流程
function fire(sql, params = []) {
    execute(sql, params).catch(() => {});
}

function j(v) { return v === undefined ? null : JSON.stringify(v); }

// ============================================================
// 模块 4：用户
// ============================================================
async function upsertUser(u) {
    if (!u || !u.username) return;
    fire(
        `INSERT INTO users (username, nickname, avatar, ip, role, experience, last_seen_at)
         VALUES (?,?,?,?,?,?,NOW())
         ON DUPLICATE KEY UPDATE
            nickname = VALUES(nickname),
            avatar = VALUES(avatar),
            ip = VALUES(ip),
            role = VALUES(role),
            experience = VALUES(experience),
            last_seen_at = NOW()`,
        [u.username, u.profile?.nickname || null, u.profile?.avatar || null, u.ip || null,
         u.role || 'user', u.experience || 0]
    );
}

async function touchUserLastSeen(username) {
    if (!username) return;
    fire('UPDATE users SET last_seen_at = NOW() WHERE username = ?', [username]);
}

async function saveUserSettings(username, s) {
    if (!username || !s) return;
    fire(
        `INSERT INTO user_settings (username, target_language, auto_translate, sound_notification, theme, font_size, notifications)
         VALUES (?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE
            target_language=VALUES(target_language), auto_translate=VALUES(auto_translate),
            sound_notification=VALUES(sound_notification), theme=VALUES(theme),
            font_size=VALUES(font_size), notifications=VALUES(notifications)`,
        [username, s.targetLanguage || 'zh', s.autoTranslate ? 1 : 0, s.soundNotification ? 1 : 0,
         s.theme || 'light', s.fontSize || 'medium', j(s.notifications)]
    );
}

async function saveUserAiSettings(username, a) {
    if (!username || !a) return;
    fire(
        `INSERT INTO user_ai_settings (username, enable, model, glm4_api_key, deepseek_api_key, siliconflow_api_key, custom_api_url, custom_api_key, custom_model_name)
         VALUES (?,?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE enable=VALUES(enable), model=VALUES(model),
            glm4_api_key=VALUES(glm4_api_key), deepseek_api_key=VALUES(deepseek_api_key),
            siliconflow_api_key=VALUES(siliconflow_api_key), custom_api_url=VALUES(custom_api_url),
            custom_api_key=VALUES(custom_api_key), custom_model_name=VALUES(custom_model_name)`,
        [username, a.enable ? 1 : 0, a.model || 'glm4', a.glm4?.apiKey || null,
         a.deepseek?.apiKey || null, a.siliconflow?.apiKey || null,
         a.custom?.apiUrl || null, a.custom?.apiKey || null, a.custom?.modelName || null]
    );
}

// ============================================================
// 模块 2：房间
// ============================================================
// 启动时把 DB 里的房间加载进内存 rooms Map
async function loadAllRooms(roomsMap) {
    const rows = await query(
        `SELECT r.room_name, r.password_hash, r.creator, r.is_deleted, r.total_messages,
                r.total_users, r.peak_users, r.last_activity,
                s.max_users, s.allow_public_access, s.allow_messages, s.allow_files,
                s.allow_audio, s.allow_video, s.allow_calls, s.allow_whiteboard, s.allow_polls, s.allow_games,
                t.background, t.color_scheme, t.custom_css
         FROM rooms r
         LEFT JOIN room_settings s ON r.room_name = s.room_name
         LEFT JOIN room_theme t ON r.room_name = t.room_name
         WHERE r.is_deleted = 0`
    );
    if (!rows) return 0;
    for (const row of rows) {
        const roomName = row.room_name;
        const room = {
            roomName,
            password: row.password_hash || null,
            creator: row.creator,
            createdAt: row.last_activity || new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            users: [],
            messages: [],
            announcements: [],
            theme: {
                background: row.background || 'default',
                colorScheme: row.color_scheme || 'light',
                customCSS: row.custom_css || ''
            },
            stats: {
                totalMessages: row.total_messages || 0,
                totalUsers: row.total_users || 0,
                peakUsers: row.peak_users || 0,
                currentUsers: 0,
                createdAt: row.last_activity || new Date().toISOString(),
                lastActivity: new Date()
            },
            history: { messageHistory: [], userHistory: [], eventHistory: [] },
            settings: {
                maxUsers: row.max_users || 100,
                allowPublicAccess: row.allow_public_access !== 0,
                allowMessages: row.allow_messages !== 0,
                allowFiles: row.allow_files !== 0,
                allowAudio: row.allow_audio !== 0,
                allowVideo: row.allow_video !== 0,
                allowCalls: row.allow_calls !== 0,
                allowWhiteboard: row.allow_whiteboard !== 0,
                allowPolls: row.allow_polls !== 0,
                allowGames: row.allow_games !== 0
            }
        };
        // 恢复最近消息历史（跨重启）—— 上限 100 条，避免启动过慢
        try {
            room.messages = await getRecentMessages(roomName, 100);
        } catch (e) {
            room.messages = [];
        }
        roomsMap.set(roomName, room);
    }
    return rows.length;
}

async function saveRoom(room) {
    if (!room || !room.roomName) return;
    const s = room.settings || {};
    const t = room.theme || {};
    await execute(
        `INSERT INTO rooms (room_name, password_hash, creator, is_deleted, total_messages, total_users, peak_users, last_activity)
         VALUES (?,?,?,0,?,?,?,NOW())
         ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), creator=VALUES(creator),
            total_messages=VALUES(total_messages), total_users=VALUES(total_users),
            peak_users=VALUES(peak_users), last_activity=NOW()`,
        [room.roomName, room.password || null, room.creator || null,
         room.stats?.totalMessages || 0, room.stats?.totalUsers || 0, room.stats?.peakUsers || 0]
    );
    // settings / theme 与房间主记录同等重要，且写入频率低（仅建房/改房时），
    // 用 await 而非 fire，确保 loadAllRooms 在重启后能完整恢复，而不是 best-effort 丢失。
    await execute(
        `INSERT INTO room_settings (room_name, max_users, allow_public_access, allow_messages, allow_files, allow_audio, allow_video, allow_calls, allow_whiteboard, allow_polls, allow_games)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE max_users=VALUES(max_users), allow_public_access=VALUES(allow_public_access),
            allow_messages=VALUES(allow_messages), allow_files=VALUES(allow_files), allow_audio=VALUES(allow_audio),
            allow_video=VALUES(allow_video), allow_calls=VALUES(allow_calls), allow_whiteboard=VALUES(allow_whiteboard),
            allow_polls=VALUES(allow_polls), allow_games=VALUES(allow_games)`,
        [room.roomName, s.maxUsers || 100, s.allowPublicAccess ? 1 : 0, s.allowMessages ? 1 : 0,
         s.allowFiles ? 1 : 0, s.allowAudio ? 1 : 0, s.allowVideo ? 1 : 0, s.allowCalls ? 1 : 0,
         s.allowWhiteboard ? 1 : 0, s.allowPolls ? 1 : 0, s.allowGames ? 1 : 0]
    );
    await execute(
        `INSERT INTO room_theme (room_name, background, color_scheme, custom_css)
         VALUES (?,?,?,?)
         ON DUPLICATE KEY UPDATE background=VALUES(background), color_scheme=VALUES(color_scheme), custom_css=VALUES(custom_css)`,
        [room.roomName, t.background || 'default', t.colorScheme || 'light', t.customCSS || '']
    );
}

function deleteRoom(roomName) {
    if (!roomName) return;
    fire('UPDATE rooms SET is_deleted = 1 WHERE room_name = ?', [roomName]);
}

function touchRoomActivity(roomName, stats) {
    if (!roomName) return;
    fire(
        'UPDATE rooms SET last_activity = NOW(), total_messages=?, total_users=?, peak_users=? WHERE room_name = ?',
        [stats?.totalMessages || 0, stats?.totalUsers || 0, stats?.peakUsers || 0, roomName]
    );
}

// ============================================================
// 模块 1：消息
// ============================================================
function insertMessage(roomName, msg) {
    if (!roomName || !msg || !msg.id) return;
    const meta = {
        fileName: msg.fileName, fileSize: msg.fileSize, contentType: msg.contentType,
        latitude: msg.latitude, longitude: msg.longitude, locationName: msg.locationName,
        stickerUrl: msg.stickerUrl, stickerName: msg.stickerName,
        replyToMessage: msg.replyToMessage, replyToUsername: msg.replyToUsername,
        lang: msg.lang, poll: msg.poll, readBy: msg.readBy
    };
    fire(
        `INSERT INTO messages (id, room_name, sender, type, content, metadata, reply_to, is_deleted, created_at)
         VALUES (?,?,?,?,?,?,?,0,?)
         ON DUPLICATE KEY UPDATE content=VALUES(content)`,
        [msg.id, roomName, msg.username || null, msg.type || 'text', msg.message || null,
         j(meta), msg.replyTo || null, new Date(msg.timestamp || Date.now())]
    );
}

// 读取房间最近消息（跨重启恢复历史）；返回前端能直接用的格式
async function getRecentMessages(roomName, limit = 100) {
    const rows = await query(
        `SELECT id, sender AS username, type, content, metadata, reply_to, created_at
         FROM messages
         WHERE room_name = ? AND is_deleted = 0
         ORDER BY created_at DESC LIMIT ?`,
        [roomName, limit]
    );
    if (!rows) return [];
    const out = rows.reverse().map(r => {
        // mysql2 对 JSON 列会自动解析为对象；若拿到字符串再解析（兼容手动查询结果）
        const m = r.metadata ? (typeof r.metadata === 'string' ? JSON.parse(r.metadata) : r.metadata) : {};
        return {
            id: r.id,
            username: r.username,
            type: r.type,
            message: r.content,
            timestamp: new Date(r.created_at).getTime(),
            ...m
        };
    });
    return out;
}

function deleteMessage(roomName, msgId, by, reason, originalContent) {
    if (!msgId) return;
    fire('UPDATE messages SET is_deleted = 1 WHERE id = ?', [msgId]);
    fire(
        'INSERT INTO deleted_messages (message_id, room_name, deleted_by, reason, original_content, created_at) VALUES (?,?,?,?,?,NOW())',
        [msgId, roomName, by || null, reason || null, originalContent || null]
    );
}

// ============================================================
// 模块 5：好友 / 私聊 / 禁言 / 黑名单
// ============================================================
// 好友关系按字典序存 (user_a, user_b)
function _pair(a, b) { return a < b ? [a, b] : [b, a]; }

function addFriendship(unameA, unameB) {
    if (!unameA || !unameB || unameA === unameB) return;
    const [a, b] = _pair(unameA, unameB);
    fire('INSERT IGNORE INTO friendships (user_a, user_b, is_forced) VALUES (?,?,0)', [a, b]);
}

function removeFriendship(unameA, unameB) {
    if (!unameA || !unameB) return;
    const [a, b] = _pair(unameA, unameB);
    fire('DELETE FROM friendships WHERE user_a = ? AND user_b = ?', [a, b]);
}

function setForcedFriendship(unameA, unameB) {
    if (!unameA || !unameB) return;
    const [a, b] = _pair(unameA, unameB);
    fire('INSERT INTO friendships (user_a, user_b, is_forced) VALUES (?,?,1) ON DUPLICATE KEY UPDATE is_forced=1', [a, b]);
}

// 返回某用户的所有好友用户名数组
async function getFriendUsernames(username) {
    const rows = await query(
        'SELECT user_a, user_b FROM friendships WHERE user_a = ? OR user_b = ?',
        [username, username]
    );
    if (!rows) return [];
    const set = new Set();
    for (const r of rows) {
        if (r.user_a === username) set.add(r.user_b);
        else set.add(r.user_a);
    }
    return Array.from(set);
}

function insertPrivateMessage(chatId, msg) {
    if (!chatId || !msg || !msg.id) return;
    const meta = { fileName: msg.fileName, fileSize: msg.fileSize, contentType: msg.contentType };
    // chat_id 格式为 "userA__userB"（按字典序），to_user 取非发送者的那一方用户名，
    // 绝不能存 socket.id —— 否则跨重启恢复历史时无法按用户名匹配。
    const parts = chatId.split('__');
    const toUser = parts.length === 2
        ? (parts[0] === msg.fromUsername ? parts[1] : parts[0])
        : null;
    fire(
        `INSERT INTO private_messages (id, chat_id, from_user, to_user, type, content, metadata, is_read, created_at)
         VALUES (?,?,?,?,?,?,?,0,?)
         ON DUPLICATE KEY UPDATE content=VALUES(content)`,
        [msg.id, chatId, msg.fromUsername || null, toUser,
         msg.type || 'text', msg.message || null, j(meta), new Date(msg.timestamp || Date.now())]
    );
}

async function getPrivateMessages(chatId, limit = 100) {
    const rows = await query(
        `SELECT id, from_user AS fromUsername, to_user AS toSocketId, type, content, metadata, created_at
         FROM private_messages WHERE chat_id = ? ORDER BY created_at DESC LIMIT ?`,
        [chatId, limit]
    );
    if (!rows) return [];
    return rows.reverse().map(r => {
        const m = r.metadata ? (typeof r.metadata === 'string' ? JSON.parse(r.metadata) : r.metadata) : {};
        return {
            id: r.id,
            fromUsername: r.fromUsername,
            toSocketId: r.toSocketId,
            type: r.type,
            message: r.content,
            timestamp: new Date(r.created_at).getTime(),
            ...m
        };
    });
}

function markPrivateRead(chatId, username) {
    if (!chatId || !username) return;
    fire('UPDATE private_messages SET is_read = 1 WHERE chat_id = ? AND to_user = ?', [chatId, username]);
}

// ---- 禁言（按 username 持久化，跨重启保留）----
function muteUser(username, endTime, reason, mutedBy) {
    if (!username) return;
    fire('INSERT INTO muted_users (username, end_time, reason, muted_by, created_at, updated_at) VALUES (?,?,?,?,NOW(),NOW()) ON DUPLICATE KEY UPDATE end_time=VALUES(end_time), reason=VALUES(reason), muted_by=VALUES(muted_by), updated_at=NOW()',
        [username, endTime && endTime !== -1 ? new Date(endTime) : null, reason || null, mutedBy || null]);
}

function unmuteUser(username) {
    if (!username) return;
    fire('DELETE FROM muted_users WHERE username = ?', [username]);
}

// 返回 { username, endTime(ms|-1|null), reason } 或 null
async function getMute(username) {
    const rows = await query('SELECT username, end_time, reason FROM muted_users WHERE username = ?', [username]);
    if (!rows || rows.length === 0) return null;
    const r = rows[0];
    let endTime = null;
    if (r.end_time === null) endTime = -1; // 永久
    else endTime = new Date(r.end_time).getTime();
    return { username: r.username, endTime, reason: r.reason };
}

// ---- 黑名单 IP（按 ip 持久化，跨重启保留）----
function banIp(ip, reason, bannedBy) {
    if (!ip) return;
    fire('INSERT INTO banned_ips (ip, reason, banned_by, created_at) VALUES (?,?,?,NOW()) ON DUPLICATE KEY UPDATE reason=VALUES(reason), banned_by=VALUES(banned_by)',
        [ip, reason || null, bannedBy || null]);
}

function unbanIp(ip) {
    if (!ip) return;
    fire('DELETE FROM banned_ips WHERE ip = ?', [ip]);
}

async function isIpBanned(ip) {
    const rows = await query('SELECT ip FROM banned_ips WHERE ip = ?', [ip]);
    return !!(rows && rows.length > 0);
}

async function loadBannedIps(set) {
    const rows = await query('SELECT ip FROM banned_ips');
    if (!rows) return 0;
    set.clear?.();
    rows.forEach(r => set.add(r.ip));
    return rows.length;
}

module.exports = {
    init, query, execute, fire, isEnabled,
    // users
    upsertUser, touchUserLastSeen, saveUserSettings, saveUserAiSettings,
    // rooms
    loadAllRooms, saveRoom, deleteRoom, touchRoomActivity,
    // messages
    insertMessage, getRecentMessages, deleteMessage,
    // social
    addFriendship, removeFriendship, setForcedFriendship, getFriendUsernames,
    insertPrivateMessage, getPrivateMessages, markPrivateRead,
    muteUser, unmuteUser, getMute,
    banIp, unbanIp, isIpBanned, loadBannedIps
};
