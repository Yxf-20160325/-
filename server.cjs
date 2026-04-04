const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

// ── 配置常量 ────────────────────────────────────────────────
const CONFIG = {
    // 文件大小限制
    FILE_SIZE_LIMITS: {
        MAX_UPLOAD_SIZE: 30 * 1024 * 1024,  // 30MB
        MAX_IMAGE_SIZE: 5 * 1024 * 1024,    // 5MB
        MAX_AUDIO_SIZE: 10 * 1024 * 1024    // 10MB
    },
    // 输入长度限制
    INPUT_LIMITS: {
        USERNAME: 50,
        ROOM_NAME: 100,
        PASSWORD: 128,
        MESSAGE: 5000,
        FILENAME: 255,
        PATH: 255,
        EMAIL: 255,
        BIO: 500,
        WEBSITE: 255
    },
    // 病毒文件清理周期（天）
    VIRUS_FILE_RETENTION_DAYS: 7,
    // 病毒文件清理间隔（毫秒）
    VIRUS_CLEANUP_INTERVAL: 24 * 60 * 60 * 1000  // 每天一次
};

// ── 日志配置 ────────────────────────────────────────────────
const LOG_LEVELS = {
    ERROR: 0,
    WARN: 1,
    INFO: 2,
    DEBUG: 3
};

// 根据环境设置日志级别
const currentLogLevel = process.env.NODE_ENV === 'production'
    ? LOG_LEVELS.INFO
    : LOG_LEVELS.DEBUG;

function log(level, message, data) {
    if (level <= currentLogLevel) {
        const timestamp = new Date().toISOString();
        const prefix = {
            [LOG_LEVELS.ERROR]: '[ERROR]',
            [LOG_LEVELS.WARN]: '[WARN]',
            [LOG_LEVELS.INFO]: '[INFO]',
            [LOG_LEVELS.DEBUG]: '[DEBUG]'
        }[level];

        console.log(`${timestamp} ${prefix}`, message, data || '');
    }
}

// 导出日志函数供全局使用
global.log = log;
global.LOG_LEVELS = LOG_LEVELS;

// 病毒检测配置（提前声明，避免 TDZ 问题）
let virusScanEnabled = false;

// 导入病毒扫描器（添加错误处理）
let virusScanner = null;
try {
    virusScanner = require('./utils/virus-scanner.js');
    console.log('[病毒扫描器] 模块加载成功');
} catch (error) {
    console.warn('[病毒扫描器] 模块加载失败,病毒检测功能已禁用:', error.message);
    virusScanEnabled = false;
}

// 全局变量
const rooms = new Map();
const users = new Map();
const games = new Map(); // 存储游戏: Map<gameId, game>（全局共享，所有连接可见）

// 默认权限（提前声明，避免 TDZ 问题）
let defaultPermissions = {
    allowAudio: true,
    allowImage: true,
    allowFile: true,
    allowSendMessages: true,
    allowViewMessages: true,
    allowCall: false, // 默认禁用通话功能，需通过权限申请获取
    allowAddFriends: true,
    allowViewUsers: true,
    allowPrivateChat: true,
    allowOpenFriendsPage: true,
    allowRecallMessage: true,
    allowAIChat: false // 默认禁用AI聊天功能，需要管理员同意
};

// IP 封禁和连接管理（提前声明，避免 TDZ 问题）
const bannedIPs = new Set(); // 存储被封禁的IP
const ipConnections = new Map(); // 存储IP连接数: Map<ip, Set<socketId>>
const mutedUsers = new Map(); // 存储被禁言用户: Map<socketId, { username, endTime, reason }>
const MAX_CONNECTIONS_PER_IP = 5; // 每个IP最大连接数

const app = express();
app.use(cors({
    origin: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'X-Content-Type-Options', 'X-Requested-With'],
    credentials: true,
    exposedHeaders: ['Content-Type', 'X-Content-Type-Options']
}));

// ── 安全响应头 ────────────────────────────────────────────────
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // 【安全】禁止在 <iframe> / <frame> / <embed> 中嵌入，防点击劫持
    res.setHeader('X-Frame-Options', 'DENY');
    // 【安全】不向第三方泄露完整 Referer URL
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    // 【安全】限制浏览器功能（摄像头/麦克风仅限同源，地理位置允许同源使用）
    res.setHeader('Permissions-Policy', 'camera=(self), microphone=(self), geolocation=(self)');
    // 【安全】启用旧版 XSS Filter（部分老浏览器）
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});
app.use(express.static(path.join(__dirname, 'public')));

// 为文件上传API单独配置raw解析器
app.post('/api/files/upload', express.raw({ type: '*/*', limit: '30mb' }), async (req, res) => {
    try {
        // 验证请求头
        if (!req.headers['content-type']) {
            return res.status(400).json({ error: '缺少Content-Type请求头' });
        }
        
        // 验证相对路径（改进的安全检查）
        let relativePath = req.headers['x-path'] || '';
        if (relativePath) {
            // 先检查原始路径类型和长度
            if (typeof relativePath !== 'string') {
                return res.status(400).json({ error: '路径格式错误' });
            }
            if (relativePath.length > 255) {
                return res.status(400).json({ error: '路径过长' });
            }

            // 解码路径
            try {
                relativePath = decodeURIComponent(relativePath);
            } catch (error) {
                return res.status(400).json({ error: '路径编码错误' });
            }

            // 检查危险字符（包括 null 字节）
            const dangerousChars = ['..', '\\', '/', '\0', '\n', '\r', '\t'];
            for (const char of dangerousChars) {
                if (relativePath.includes(char)) {
                    return res.status(403).json({ error: '路径包含非法字符' });
                }
            }

            // 规范化路径
            relativePath = path.normalize(relativePath);

            // 最终安全检查
            if (relativePath !== '.' && relativePath !== '') {
                if (relativePath.startsWith('.') || relativePath.startsWith('/') || relativePath.startsWith('\\')) {
                    return res.status(403).json({ error: '路径包含非法字符' });
                }
            }
        }
        
        // 验证文件名
        let filename = req.headers['x-filename'] || Date.now() + '-' + Math.round(Math.random() * 1E9);
        if (filename) {
            // 解码文件名，处理中文等非ASCII字符
            filename = decodeURIComponent(filename);
            // 检查文件名长度
            if (filename.length > CONFIG.INPUT_LIMITS.FILENAME) {
                return res.status(400).json({ error: `文件名过长,最大${CONFIG.INPUT_LIMITS.FILENAME}个字符` });
            }
            // 检查文件名中是否包含危险字符
            if (filename.includes('..') || filename.includes('\\') || filename.includes('/') || filename.includes(':')) {
                return res.status(403).json({ error: '文件名包含非法字符' });
            }
        }
        
        // 检查是否为PHP文件
        if (filename.toLowerCase().endsWith('.php')) {
            return res.status(403).json({ error: '不允许上传PHP文件' });
        }
        
        // 检查是否为其他危险文件类型
        const dangerousExtensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.jsp', '.asp', '.aspx', '.shtml', '.cgi', '.pl', '.sh', '.vbs'];
        const fileExtension = path.extname(filename).toLowerCase();
        if (dangerousExtensions.includes(fileExtension)) {
            return res.status(403).json({ error: '不允许上传该类型的文件' });
        }
        
        // 检查文件大小
        if (req.body.length > CONFIG.FILE_SIZE_LIMITS.MAX_UPLOAD_SIZE) {
            return res.status(413).json({
                error: `文件大小超过限制（最大${CONFIG.FILE_SIZE_LIMITS.MAX_UPLOAD_SIZE / 1024 / 1024}MB）`
            });
        }
        
        // 构建文件路径
        const uploadsDir = path.join(__dirname, 'uploads');
        const filePath = path.join(uploadsDir, relativePath, filename);

        // 验证文件路径是否在uploads目录内
        const normalizedFilePath = path.normalize(filePath);
        const normalizedUploadsDir = path.normalize(uploadsDir);
        if (!normalizedFilePath.startsWith(normalizedUploadsDir)) {
            return res.status(403).json({ error: '无权访问该路径' });
        }

        // 确保目录存在
        const dirPath = path.dirname(filePath);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
        }

        // 病毒扫描
        let scanResult = { safe: true, scanned: false, message: '病毒检测已禁用' };

        if (virusScanEnabled && virusScanner) {
            console.log('开始病毒扫描:', filename);
            scanResult = await virusScanner.scanBuffer(req.body, filename);

            if (!scanResult.safe) {
                console.log('文件被检测到病毒:', filename);

                // 将病毒文件保存到隔离区
                const virusPath = path.join(virusesDir, filename);
                fs.writeFileSync(virusPath, req.body);

                // 记录病毒文件信息
                const virusFile = {
                    id: Date.now().toString() + Math.random().toString(36).substring(2, 11),
                    filename: filename,
                    size: req.body.length,
                    uploaderIp: req.ip,
                    uploadTime: new Date().toISOString(),
                    scanResult: scanResult
                };

                // 使用 Map 存储而不是数组
                virusFiles.set(virusFile.id, virusFile);

                return res.status(403).json({
                    error: '不允许上传病毒',
                    viruses: scanResult.viruses,
                    virusId: virusFile.id
                });
            }
            
            console.log('病毒扫描完成:', filename, '结果:', scanResult.message);
        } else {
            console.log('病毒检测已禁用，跳过扫描:', filename);
        }
        
        // 写入文件
        fs.writeFileSync(filePath, req.body);
        const stats = fs.statSync(filePath);
        
        // 构建响应URL
        const fileUrl = `/uploads/${relativePath ? relativePath + '/' + filename : filename}`;
        
        // 更新用户统计数据（如果能获取到用户信息）
        const userIP = req.ip;
        const user = Array.from(users.values()).find(u => u.ip === userIP);
        if (user) {
            user.stats.filesUploaded++;
            user.experience += 5; // 上传文件获得更多经验值
            
            // 检查是否升级
            const oldLevel = user.level;
            const newLevel = Math.floor(user.experience / 100) + 1;
            if (newLevel > oldLevel) {
                user.level = newLevel;
                // 通知用户升级
                if (user.socketId) {
                    io.to(user.socketId).emit('level-up', { oldLevel, newLevel, experience: user.experience });
                }
                console.log(`${user.username} 升级到 ${newLevel} 级`);
            }
            

        }
        
        res.json({
            name: filename,
            size: stats.size,
            createdAt: stats.birthtime,
            modifiedAt: stats.mtime,
            url: fileUrl,
            scanResult: scanResult // 包含扫描结果
        });
    } catch (error) {
        console.error('上传文件失败:', error);
        res.status(500).json({ error: '上传文件失败' });
    }
});

// 其他路由使用json解析器
app.use(express.json({ limit: '30mb' }));

// 应用API速率限制中间件到所有API端点
app.use('/api/', apiRateLimitMiddleware);



// 确保 uploads 目录存在
if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
    fs.mkdirSync(path.join(__dirname, 'uploads'));
}

// 确保 viruses 目录存在（用于隔离病毒文件）
const virusesDir = path.join(__dirname, 'viruses');
if (!fs.existsSync(virusesDir)) {
    fs.mkdirSync(virusesDir, { recursive: true });
}

// 病毒文件记录（使用 Map 以便管理）
let virusFiles = new Map();

// 定期清理旧病毒文件记录（保留最近 7 天的记录）
setInterval(() => {
    const now = Date.now();
    const sevenDaysAgo = now - (7 * 24 * 60 * 60 * 1000);

    let cleanedCount = 0;
    for (const [id, virusFile] of virusFiles.entries()) {
        const uploadTime = new Date(virusFile.uploadTime).getTime();
        if (uploadTime < sevenDaysAgo) {
            virusFiles.delete(id);

            // 删除隔离文件
            const virusPath = path.join(virusesDir, virusFile.filename);
            try {
                if (fs.existsSync(virusPath)) {
                    fs.unlinkSync(virusPath);
                }
                cleanedCount++;
            } catch (error) {
                console.warn('删除病毒文件失败:', error.message);
            }
        }
    }

    if (cleanedCount > 0) {
        console.log(`[病毒扫描器] 已清理 ${cleanedCount} 条旧记录,当前记录数: ${virusFiles.size}`);
    }
}, 24 * 60 * 60 * 1000); // 每天清理一次

// 本地存储配置


// 推送通知系统
const pushSubscriptions = new Map(); // 存储用户的推送订阅

// 注册推送订阅
app.post('/api/push/subscribe', express.json(), (req, res) => {
    try {
        const { socketId, subscription } = req.body;
        if (!socketId || !subscription) {
            return res.status(400).json({ error: '缺少必要参数' });
        }
        
        pushSubscriptions.set(socketId, subscription);
        console.log(`用户 ${socketId} 注册了推送订阅`);
        res.json({ success: true, message: '推送订阅成功' });
    } catch (error) {
        console.error('推送订阅失败:', error);
        res.status(500).json({ error: '推送订阅失败' });
    }
});

// 取消推送订阅
app.post('/api/push/unsubscribe', express.json(), (req, res) => {
    try {
        const { socketId } = req.body;
        if (!socketId) {
            return res.status(400).json({ error: '缺少必要参数' });
        }
        
        pushSubscriptions.delete(socketId);
        console.log(`用户 ${socketId} 取消了推送订阅`);
        res.json({ success: true, message: '推送订阅已取消' });
    } catch (error) {
        console.error('取消推送订阅失败:', error);
        res.status(500).json({ error: '取消推送订阅失败' });
    }
});

// 发送推送通知
function sendPushNotification(socketId, title, body, data = {}) {
    const subscription = pushSubscriptions.get(socketId);
    if (subscription) {
        // 这里可以集成实际的推送服务，如 Firebase Cloud Messaging 或 Web Push
        console.log(`发送推送通知给 ${socketId}: ${title} - ${body}`);
        // 实际的推送逻辑
    }
}

// 移动应用接口

// 移动应用登录
app.post('/api/mobile/login', express.json(), (req, res) => {
    try {
        const { username, roomName = 'main', password = null } = req.body;
        
        if (!username) {
            return res.status(400).json({ error: '用户名不能为空' });
        }
        
        // 检查房间是否存在
        const room = rooms.get(roomName);
        if (!room) {
            return res.status(404).json({ error: '房间不存在' });
        }
        
        // 检查密码是否正确
        if (room.password && room.password !== password) {
            return res.status(401).json({ error: '密码错误' });
        }
        
        // 检查用户名是否已存在
        const existingUser = Array.from(users.values()).find(user => user.username === username);
        if (existingUser) {
            return res.status(400).json({ error: '用户名已存在' });
        }
        
        // 生成临时socketId（移动应用使用）
        const mobileSocketId = 'mobile-' + Date.now() + '-' + Math.random().toString(36).substring(2, 11);
        
        // 创建用户对象
        const user = {
            username: username,
            color: getRandomColor(),
            socketId: mobileSocketId,
            ip: req.ip,
            roomName: roomName,
            role: 'user',
            permissions: { ...defaultPermissions },
            status: 'online',
            lastSeen: new Date().toISOString(),
            profile: {
                avatar: null,
                bio: '',
                age: null,
                location: '',
                website: ''
            },
            level: 1,
            experience: 0,
            achievements: [],
            stats: {
                messagesSent: 0,
                filesUploaded: 0,
                callsMade: 0,
                friendsAdded: 0,
                timeSpent: 0
            },
            settings: { locked: false, lockMessage: '设置已被管理员锁定' },
            userSettings: {
                targetLanguage: 'zh',
                autoTranslate: false,
                soundNotification: true,
                mentionNotification: true,
                theme: 'light',
                fontSize: 'medium',
                notifications: {
                    messages: true,
                    calls: true,
                    friendRequests: true,
                    mentions: true
                }
            },
            aiSettings: {
                enable: false,
                model: 'glm4',
                glm4: {
                    apiKey: ''
                },
                deepseek: {
                    modelName: '',
                    apiKey: ''
                },
                siliconflow: {
                    modelName: '',
                    apiKey: ''
                },
                custom: {
                    apiUrl: '',
                    apiKey: '',
                    modelName: ''
                }
            }
        };
        
        // 保存用户
        users.set(mobileSocketId, user);
        
        // 将用户添加到房间
        room.users.push(mobileSocketId);
        
        // 更新房间统计数据
        room.stats.totalUsers++;
        room.stats.currentUsers = room.users.length;
        if (room.users.length > room.stats.peakUsers) {
            room.stats.peakUsers = room.users.length;
        }
        room.stats.lastActivity = new Date();
        
        // 生成认证令牌
        const token = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        
        res.json({
            success: true,
            token: token,
            user: {
                username: user.username,
                color: user.color,
                socketId: user.socketId,
                roomName: user.roomName,
                status: user.status,
                profile: user.profile,
                level: user.level,
                experience: user.experience
            },
            room: {
                roomName: room.roomName,
                userCount: room.users.length,
                settings: room.settings
            }
        });
        
    } catch (error) {
        console.error('移动应用登录失败:', error);
        res.status(500).json({ error: '登录失败' });
    }
});

// 移动应用获取消息
app.get('/api/mobile/messages', (req, res) => {
    try {
        const { token, roomName, limit = 50, offset = 0 } = req.query;
        
        if (!token || !roomName) {
            return res.status(400).json({ error: '缺少必要参数' });
        }
        
        const room = rooms.get(roomName);
        if (!room) {
            return res.status(404).json({ error: '房间不存在' });
        }
        
        // 优先从缓存获取消息
        let messages = getMessagesFromCache(roomName, limit, offset);
        
        // 如果缓存中没有足够的消息，从房间消息中获取
        if (messages.length < limit) {
            messages = room.messages
                .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
                .slice(offset, offset + limit);
            
            // 更新缓存
            messages.forEach(message => {
                addMessageToCache(roomName, message);
            });
        }
        
        res.json({
            success: true,
            messages: messages,
            total: room.messages.length
        });
        
    } catch (error) {
        console.error('获取消息失败:', error);
        res.status(500).json({ error: '获取消息失败' });
    }
});

// 移动应用发送消息
app.post('/api/mobile/send-message', express.json(), (req, res) => {
    try {
        const { token, roomName, message, type = 'text', fileName, fileSize, contentType } = req.body;
        
        if (!token || !roomName || !message) {
            return res.status(400).json({ error: '缺少必要参数' });
        }
        
        // 查找用户（这里简化处理，实际应该验证token）
        const user = Array.from(users.values()).find(u => u.socketId.includes('mobile-'));
        if (!user) {
            return res.status(401).json({ error: '用户未登录' });
        }
        
        const room = rooms.get(roomName);
        if (!room) {
            return res.status(404).json({ error: '房间不存在' });
        }
        
        // 生成消息ID
        const messageId = Date.now() + '-' + Math.random().toString(36).substring(2, 11);
        
        // 创建消息数据
        const messageData = {
            id: messageId,
            username: user.username,
            color: user.color,
            message: message,
            type: type,
            timestamp: new Date().toLocaleTimeString(),
            senderSocketId: user.socketId,
            readBy: [user.socketId],
            pinned: false,
            pinnedBy: null,
            pinnedAt: null,
            fileName: fileName,
            fileSize: fileSize,
            contentType: contentType
        };
        
        // 添加消息到房间
        room.messages.push(messageData);
        if (room.messages.length > 100) {
            room.messages.shift();
        }
        
        // 更新用户统计数据
        user.stats.messagesSent++;
        user.experience += 1;
        
        // 检查是否升级
        const oldLevel = user.level;
        const newLevel = Math.floor(user.experience / 100) + 1;
        if (newLevel > oldLevel) {
            user.level = newLevel;
        }
        
        // 广播消息
        room.users.forEach(userId => {
            const roomUser = users.get(userId);
            if (roomUser && roomUser.permissions.allowViewMessages) {
                // 使用批量发送消息
                sendBatchMessage(userId, messageData);
                
                // 发送推送通知给离线用户
                if (roomUser.status === 'offline') {
                    sendPushNotification(userId, `来自 ${user.username} 的消息`, message.substring(0, 50) + (message.length > 50 ? '...' : ''), {
                        type: 'message',
                        roomName: room.roomName,
                        messageId: messageId
                    });
                }
            }
        });
        
        // 发送给管理员
        if (adminSocketId) {
            sendBatchMessage(adminSocketId, messageData);
        }
        
        res.json({
            success: true,
            message: messageData
        });
        
    } catch (error) {
        console.error('发送消息失败:', error);
        res.status(500).json({ error: '发送消息失败' });
    }
});

// 插件系统
const plugins = new Map();
const pluginDir = path.join(__dirname, 'plugins');

// 确保插件目录存在
if (!fs.existsSync(pluginDir)) {
    fs.mkdirSync(pluginDir, { recursive: true });
}

// 加载插件
function loadPlugins() {
    try {
        const pluginFiles = fs.readdirSync(pluginDir).filter(file => file.endsWith('.js'));

        pluginFiles.forEach(file => {
            try {
                const pluginPath = path.join(pluginDir, file);

                // 清除 Node.js require 缓存，确保每次都能加载最新文件内容
                // （不清除缓存时，修改/新建插件后 require 会返回旧的缓存模块）
                if (require.cache[require.resolve(pluginPath)]) {
                    delete require.cache[require.resolve(pluginPath)];
                }

                const plugin = require(pluginPath);

                if (plugin.name && plugin.init) {
                    // 创建一个模拟的 socket 对象,让插件能够注册消息处理函数
                    const mockSocket = {
                        on: (event, handler) => {
                            if (event === 'message') {
                                // 将消息处理函数保存到插件对象中
                                plugin.messageHandler = handler;
                                console.log(`插件 ${plugin.name} 注册了消息处理函数`);
                            }
                        },
                        emit: (event, data) => {
                            // 模拟 socket.emit,让插件可以发送消息
                            console.log(`插件 ${plugin.name} 尝试发送事件: ${event}`, data);
                        }
                    };

                    // 将 io 对象修改,让插件的 io.on('connection') 能够注册消息监听器
                    const originalIoOn = io.on;
                    io.on = (event, handler) => {
                        if (event === 'connection') {
                            // 模拟一个连接事件,让插件能够注册 socket 监听器
                            handler(mockSocket);
                        }
                        return originalIoOn.call(io, event, handler);
                    };

                    // 调用插件的 init 函数
                    plugin.init(app, io, { users, rooms, messages });

                    // 恢复原始的 io.on
                    io.on = originalIoOn;

                    plugins.set(plugin.name, plugin);
                    console.log(`插件加载成功: ${plugin.name}`);
                }
            } catch (error) {
                console.error(`加载插件 ${file} 失败:`, error);
            }
        });

        console.log(`共加载 ${plugins.size} 个插件`);
    } catch (error) {
        console.error('加载插件失败:', error);
    }
}

// 卸载插件
function unloadPlugin(pluginName) {
    try {
        const plugin = plugins.get(pluginName);
        if (plugin && plugin.destroy) {
            plugin.destroy();
        }
        plugins.delete(pluginName);
        console.log(`插件卸载成功: ${pluginName}`);
    } catch (error) {
        console.error(`卸载插件 ${pluginName} 失败:`, error);
    }
}

// 插件管理API
app.get('/api/plugins', (req, res) => {
    try {
        // 定义自带插件列表
        const builtinPlugins = ['weather'];
        
        const pluginList = Array.from(plugins.values()).map(plugin => ({
            name: plugin.name,
            version: plugin.version || '1.0.0',
            description: plugin.description || '',
            isBuiltin: builtinPlugins.includes(plugin.name)
        }));
        res.json({ plugins: pluginList });
    } catch (error) {
        console.error('获取插件列表失败:', error);
        res.status(500).json({ error: '获取插件列表失败' });
    }
});

app.post('/api/plugins/reload', (req, res) => {
    try {
        // 卸载所有插件
        plugins.forEach((plugin, name) => {
            unloadPlugin(name);
        });
        
        // 重新加载插件
        loadPlugins();
        
        res.json({ success: true, message: '插件已重新加载' });
    } catch (error) {
        console.error('重新加载插件失败:', error);
        res.status(500).json({ error: '重新加载插件失败' });
    }
});

// 上传/创建插件API
app.post('/api/plugins', express.json(), (req, res) => {
    try {
        const { name, description, code } = req.body;
        
        if (!name || !code) {
            return res.status(400).json({ error: '缺少必要参数' });
        }
        
        // 验证插件名称
        const validName = name.replace(/[^a-zA-Z0-9_-]/g, '');
        if (!validName) {
            return res.status(400).json({ error: '无效的插件名称' });
        }
        
        // 验证代码安全性（简单的安全检查）
        const unsafePatterns = [
            'require("child_process")',
            'require("fs")',
            'require("net")',
            'exec(',
            'spawn(',
            'fork(',
            'fs.readFile',
            'fs.writeFile',
            'fs.unlink',
            'process.exit'
        ];
        
        for (const pattern of unsafePatterns) {
            if (code.includes(pattern)) {
                return res.status(400).json({ error: '插件代码包含不安全的操作' });
            }
        }
        
        // 生成插件文件内容
        // 注意：用户代码本身应包含 const { users, rooms, messages } = context; 这行，不在模板里重复注入
        const indentedCode = code.split('\n').map(line => line ? '        ' + line : '').join('\n');
        const pluginContent = `// ${description || '用户自定义插件'}
module.exports = {
    name: "${validName}",
    description: "${description || ''}",
    version: "1.0.0",
    init: function(app, io, context) {
${indentedCode}
    },
    destroy: function() {
        // 插件销毁代码
    }
};
`;
        
        // 写入插件文件
        const pluginPath = path.join(pluginDir, `${validName}.js`);
        fs.writeFileSync(pluginPath, pluginContent);
        
        // 重新加载插件
        loadPlugins();
        
        res.json({ success: true, message: '插件创建成功', pluginName: validName });
    } catch (error) {
        console.error('创建插件失败:', error);
        res.status(500).json({ error: '创建插件失败' });
    }
});

// 删除插件API
app.delete('/api/plugins/:name', (req, res) => {
    try {
        const { name } = req.params;
        
        // 检查是否为自带插件
        const builtinPlugins = ['weather'];
        if (builtinPlugins.includes(name)) {
            return res.status(403).json({ error: '自带插件禁止删除' });
        }
        
        // 卸载插件
        unloadPlugin(name);
        
        // 删除插件文件
        const pluginPath = path.join(pluginDir, `${name}.js`);
        if (fs.existsSync(pluginPath)) {
            fs.unlinkSync(pluginPath);
        }
        
        res.json({ success: true, message: '插件删除成功' });
    } catch (error) {
        console.error('删除插件失败:', error);
        res.status(500).json({ error: '删除插件失败' });
    }
});

// 获取插件代码API
app.get('/api/plugins/:name/code', (req, res) => {
    try {
        const { name } = req.params;
        
        // 检查是否为自带插件
        const builtinPlugins = ['weather'];
        if (builtinPlugins.includes(name)) {
            return res.status(403).json({ error: '自带插件禁止编辑' });
        }
        
        // 读取插件文件
        const pluginPath = path.join(pluginDir, `${name}.js`);
        if (!fs.existsSync(pluginPath)) {
            return res.status(404).json({ error: '插件不存在' });
        }
        
        const code = fs.readFileSync(pluginPath, 'utf8');
        
        // 提取插件代码（去除模块包装）
        const codeMatch = code.match(/init: function\(app, io, context\) \{[\s\S]*?\n    \},/);
        let pluginCode = '';
        if (codeMatch) {
            pluginCode = codeMatch[0].replace('init: function(app, io, context) {', '').replace('    },', '').trim();
        }
        
        // 提取插件描述
        const descMatch = code.match(/description: "([^"]*)"/);
        const description = descMatch ? descMatch[1] : '';
        
        res.json({ success: true, name, description, code: pluginCode });
    } catch (error) {
        console.error('获取插件代码失败:', error);
        res.status(500).json({ error: '获取插件代码失败' });
    }
});

// 导出插件API
app.get('/api/plugins/:name/export', (req, res) => {
    try {
        const { name } = req.params;

        // 自带插件不允许导出（可选：按需去掉此限制）
        const builtinPlugins = ['weather'];
        if (builtinPlugins.includes(name)) {
            return res.status(403).json({ error: '自带插件不支持导出' });
        }

        const pluginPath = path.join(pluginDir, `${name}.js`);
        if (!fs.existsSync(pluginPath)) {
            return res.status(404).json({ error: '插件不存在' });
        }

        const code = fs.readFileSync(pluginPath, 'utf8');

        // 提取用户代码段（init 内容）
        // 用括号计数法精确找到 init 函数体，避免正则终止符对缩进的敏感性
        let pluginCode = '';
        const initStart = code.indexOf('init: function(app, io, context) {');
        if (initStart !== -1) {
            let braceCount = 0;
            let bodyStart = -1;
            let bodyEnd = -1;
            for (let i = initStart; i < code.length; i++) {
                if (code[i] === '{') {
                    if (braceCount === 0) bodyStart = i + 1;
                    braceCount++;
                } else if (code[i] === '}') {
                    braceCount--;
                    if (braceCount === 0) {
                        bodyEnd = i;
                        break;
                    }
                }
            }
            if (bodyStart !== -1 && bodyEnd !== -1) {
                let rawBody = code.slice(bodyStart, bodyEnd);
                // 去掉模板自动生成的第一行（context 解构）和注释行
                rawBody = rawBody
                    .replace(/^\s*\n/, '')                          // 去掉开头空行
                    .replace(/^[ \t]*const \{ users, rooms, messages \} = context;\s*\n/, '') // 去掉模板解构行
                    .replace(/^[ \t]*\/\/ 插件初始化代码\s*\n/, '') // 去掉模板注释行
                    .trimEnd();
                // 统一去除最多8个空格的公共缩进
                const lines = rawBody.split('\n');
                const indent = lines
                    .filter(l => l.trim())
                    .reduce((min, l) => Math.min(min, l.match(/^(\s*)/)[1].length), 8);
                pluginCode = lines.map(l => l.slice(indent)).join('\n').trim();
            }
        }

        // 提取描述
        const descMatch = code.match(/description: "([^"]*)"/);
        const description = descMatch ? descMatch[1] : '';

        // 提取版本
        const verMatch = code.match(/version: "([^"]*)"/);
        const version = verMatch ? verMatch[1] : '1.0.0';

        const exportData = {
            name,
            description,
            version,
            code: pluginCode,
            exportedAt: new Date().toISOString(),
            exportedBy: 'chatroom-plugin-system'
        };

        res.setHeader('Content-Disposition', `attachment; filename="${name}.plugin.json"`);
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.json(exportData);
    } catch (error) {
        console.error('导出插件失败:', error);
        res.status(500).json({ error: '导出插件失败' });
    }
});

// 导入插件API
app.post('/api/plugins/import', express.json(), (req, res) => {
    try {
        const { name, description, code } = req.body;

        if (!name || !code) {
            return res.status(400).json({ error: '缺少必要参数' });
        }

        // 验证插件名称
        const validName = name.replace(/[^a-zA-Z0-9_-]/g, '');
        if (!validName) {
            return res.status(400).json({ error: '无效的插件名称' });
        }

        // 自带插件名称保护
        const builtinPlugins = ['weather'];
        if (builtinPlugins.includes(validName)) {
            return res.status(403).json({ error: '不能使用内置插件名称' });
        }

        // 安全检查（与创建插件相同）
        const unsafePatterns = [
            'require("child_process")',
            'require("fs")',
            'require("net")',
            'exec(',
            'spawn(',
            'fork(',
            'fs.readFile',
            'fs.writeFile',
            'fs.unlink',
            'process.exit'
        ];

        for (const pattern of unsafePatterns) {
            if (code.includes(pattern)) {
                return res.status(400).json({ error: '插件代码包含不安全的操作' });
            }
        }

        // 缩进用户代码（每行加8个空格），保持文件格式整洁
        const indentedCode = code.split('\n').map(line => line ? '        ' + line : '').join('\n');

        // 生成插件文件内容（不再重复注入 context 解构，避免 "already declared" 错误）
        const pluginContent = `// ${description || '导入的用户自定义插件'}
module.exports = {
    name: "${validName}",
    description: "${description || ''}",
    version: "1.0.0",
    init: function(app, io, context) {
        const { users, rooms, messages } = context;
${indentedCode}
    },
    destroy: function() {
        // 插件销毁代码
    }
};
`;

        const pluginPath = path.join(pluginDir, `${validName}.js`);
        const isOverwrite = fs.existsSync(pluginPath);

        fs.writeFileSync(pluginPath, pluginContent);
        loadPlugins();

        res.json({
            success: true,
            message: isOverwrite ? `插件 ${validName} 已覆盖导入` : `插件 ${validName} 导入成功`,
            pluginName: validName,
            overwritten: isOverwrite
        });
    } catch (error) {
        console.error('导入插件失败:', error);
        res.status(500).json({ error: '导入插件失败' });
    }
});

// 加载插件
// loadPlugins(); // 移到io创建之后

// API文档生成
app.get('/api/docs', (req, res) => {
    try {
        const docs = {
            version: '1.0.0',
            endpoints: [
                {
                    method: 'GET',
                    path: '/api/users',
                    description: '获取用户列表'
                },
                {
                    method: 'GET',
                    path: '/api/rooms',
                    description: '获取房间列表'
                },
                {
                    method: 'POST',
                    path: '/api/files/upload',
                    description: '上传文件'
                },
                {
                    method: 'POST',
                    path: '/api/mobile/login',
                    description: '移动应用登录'
                },
                {
                    method: 'GET',
                    path: '/api/mobile/messages',
                    description: '移动应用获取消息'
                },
                {
                    method: 'POST',
                    path: '/api/mobile/send-message',
                    description: '移动应用发送消息'
                },
                {
                    method: 'POST',
                    path: '/api/push/subscribe',
                    description: '注册推送订阅'
                },
                {
                    method: 'POST',
                    path: '/api/push/unsubscribe',
                    description: '取消推送订阅'
                },
                {
                    method: 'GET',
                    path: '/api/plugins',
                    description: '获取插件列表'
                },
                {
                    method: 'POST',
                    path: '/api/plugins/reload',
                    description: '重新加载插件'
                }
            ]
        };
        res.json(docs);
    } catch (error) {
        console.error('生成API文档失败:', error);
        res.status(500).json({ error: '生成API文档失败' });
    }
});

// 第三方集成
// 社交媒体登录接口（示例）
app.post('/api/auth/social', express.json(), (req, res) => {
    try {
        const { provider, token } = req.body;
        
        if (!provider || !token) {
            return res.status(400).json({ error: '缺少必要参数' });
        }
        
        // 这里可以集成实际的社交媒体登录验证
        // 例如：Google、Facebook、WeChat等
        
        // 模拟登录成功
        const username = `social_${provider}_${Date.now()}`;
        const socialSocketId = `social-${provider}-${Date.now()}`;
        
        // 创建用户对象
        const user = {
            username: username,
            color: getRandomColor(),
            socketId: socialSocketId,
            ip: req.ip,
            roomName: 'main',
            role: 'user',
            permissions: { ...defaultPermissions },
            status: 'online',
            lastSeen: new Date().toISOString(),
            profile: {
                avatar: null,
                bio: `通过${provider}登录`,
                age: null,
                location: '',
                website: ''
            },
            level: 1,
            experience: 0,
            achievements: [],
            stats: {
                messagesSent: 0,
                filesUploaded: 0,
                callsMade: 0,
                friendsAdded: 0,
                timeSpent: 0
            },
            settings: { locked: false, lockMessage: '设置已被管理员锁定' },
            userSettings: {
                targetLanguage: 'zh',
                autoTranslate: false,
                soundNotification: true,
                mentionNotification: true,
                theme: 'light',
                fontSize: 'medium',
                notifications: {
                    messages: true,
                    calls: true,
                    friendRequests: true,
                    mentions: true
                }
            },
            aiSettings: {
                enable: false,
                model: 'glm4',
                glm4: {
                    apiKey: ''
                },
                deepseek: {
                    modelName: '',
                    apiKey: ''
                },
                siliconflow: {
                    modelName: '',
                    apiKey: ''
                },
                custom: {
                    apiUrl: '',
                    apiKey: '',
                    modelName: ''
                }
            }
        };
        
        // 保存用户
        users.set(socialSocketId, user);
        
        // 将用户添加到默认房间
        const room = rooms.get('main');
        if (room) {
            room.users.push(socialSocketId);
        }
        
        res.json({
            success: true,
            user: {
                username: user.username,
                color: user.color,
                socketId: user.socketId,
                roomName: user.roomName,
                status: user.status
            }
        });
        
    } catch (error) {
        console.error('社交媒体登录失败:', error);
        res.status(500).json({ error: '社交媒体登录失败' });
    }
});

// 应用CSRF保护中间件到所有非GET请求的API端点
app.use('/api/', csrfProtectionMiddleware);

// 天气查询API
app.post('/api/weather', express.json(), async (req, res) => {
    try {
        const { city } = req.body;
        
        if (!city) {
            return res.status(400).json({ error: '缺少城市参数' });
        }
        
        // 调用天气API
        const weatherData = await getWeather(city);
        
        res.json({
            success: true,
            data: weatherData
        });
        
    } catch (error) {
        console.error('天气查询失败:', error);
        res.status(500).json({ error: '天气查询失败' });
    }
});

// 获取病毒文件列表
app.get('/api/viruses', (req, res) => {
    res.json(Array.from(virusFiles.values()));
});

// 允许病毒文件
app.post('/api/viruses/allow/:id', (req, res) => {
    const { id } = req.params;
    const virusFile = virusFiles.get(id);
    
    if (virusFile) {
        // 将文件从隔离区移回上传目录
        const originalPath = path.join(__dirname, 'uploads', virusFile.filename);
        const virusPath = path.join(virusesDir, virusFile.filename);
        
        if (fs.existsSync(virusPath)) {
            fs.copyFileSync(virusPath, originalPath);
            fs.unlinkSync(virusPath);
        }
        
        // 从病毒列表中移除
        virusFiles.delete(id);
        
        res.json({ success: true, message: '文件已允许并移回上传目录' });
    } else {
        res.status(404).json({ error: '病毒文件不存在' });
    }
});

// 隔离病毒文件
app.post('/api/viruses/quarantine/:id', (req, res) => {
    const { id } = req.params;
    const virusFile = virusFiles.get(id);
    
    if (virusFile) {
        // 确保文件在隔离区
        const virusPath = path.join(virusesDir, virusFile.filename);
        if (!fs.existsSync(virusPath) && fs.existsSync(path.join(__dirname, 'uploads', virusFile.filename))) {
            fs.copyFileSync(path.join(__dirname, 'uploads', virusFile.filename), virusPath);
            fs.unlinkSync(path.join(__dirname, 'uploads', virusFile.filename));
        }
        
        res.json({ success: true, message: '文件已隔离' });
    } else {
        res.status(404).json({ error: '病毒文件不存在' });
    }
});

// 删除病毒文件
app.delete('/api/viruses/:id', (req, res) => {
    const { id } = req.params;
    const virusFile = virusFiles.get(id);
    
    if (virusFile) {
        // 删除隔离区中的文件
        const virusPath = path.join(virusesDir, virusFile.filename);
        if (fs.existsSync(virusPath)) {
            fs.unlinkSync(virusPath);
        }
        
        // 删除上传目录中的文件（如果存在）
        const originalPath = path.join(__dirname, 'uploads', virusFile.filename);
        if (fs.existsSync(originalPath)) {
            fs.unlinkSync(originalPath);
        }
        
        // 从病毒列表中移除
        virusFiles.delete(id);
        
        res.json({ success: true, message: '病毒文件已删除' });
    } else {
        res.status(404).json({ error: '病毒文件不存在' });
    }
});

// 一键封禁用户（IP封禁）
app.post('/api/viruses/ban/:id', (req, res) => {
    const { id } = req.params;
    const virusFile = virusFiles.get(id);
    
    if (virusFile && virusFile.uploaderIp) {
        // 添加IP到封禁列表
        bannedIPs.add(virusFile.uploaderIp);
        
        // 断开该IP的所有连接
        if (ipConnections.has(virusFile.uploaderIp)) {
            ipConnections.get(virusFile.uploaderIp).forEach(sid => {
                const s = io.sockets.sockets.get(sid);
                if (s) {
                    s.emit('banned', { message: '您的IP已被封禁' });
                    s.disconnect(true);
                }
            });
        }
        
        res.json({ success: true, message: `用户IP ${virusFile.uploaderIp} 已封禁` });
    } else {
        res.status(404).json({ error: '病毒文件不存在或无上传者IP信息' });
    }
});

// 获取病毒检测状态
app.get('/api/viruses/status', (req, res) => {
    res.json({ enabled: virusScanEnabled });
});

// 设置病毒检测状态
app.post('/api/viruses/status', (req, res) => {
    const { enabled } = req.body;
    virusScanEnabled = Boolean(enabled);
    res.json({ success: true, enabled: virusScanEnabled, message: virusScanEnabled ? '病毒检测已启用' : '病毒检测已禁用' });
});

// 静态文件服务 - 提供上传的文件
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 图片上传接口 - 单独配置raw解析器
app.post('/upload-image', express.raw({ type: '*/*', limit: '30mb' }), async (req, res) => {
    try {
        // 验证请求头
        if (!req.headers['content-type']) {
            return res.status(400).json({ error: '缺少Content-Type请求头' });
        }
        
        // 检查文件大小
        if (req.body.length > 10 * 1024 * 1024) { // 10MB限制
            return res.status(413).json({ error: '图片大小超过限制（最大10MB）' });
        }
        
        // 验证Content-Type
        const contentType = req.headers['content-type'];
        const allowedImageTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'];
        if (contentType && !allowedImageTypes.includes(contentType)) {
            return res.status(403).json({ error: '不允许上传非图片文件' });
        }
        
        // 获取原始文件扩展名
        let extension = '.jpg';
        if (contentType) {
            const mimeToExt = {
                'image/jpeg': '.jpg',
                'image/png': '.png',
                'image/gif': '.gif',
                'image/webp': '.webp',
                'image/svg+xml': '.svg'
            };
            extension = mimeToExt[contentType] || extension;
        }
        
        // 生成安全的文件名
        const filename = Date.now() + '-' + Math.round(Math.random() * 1E9) + extension;

        // 检查是否为危险文件类型
        const dangerousExtensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.jsp', '.asp', '.aspx', '.shtml', '.cgi', '.pl', '.sh', '.js', '.vbs'];
        const fileExtension = path.extname(filename).toLowerCase();
        if (dangerousExtensions.includes(fileExtension)) {
            return res.status(403).json({ error: '不允许上传该类型的文件' });
        }

        // 构建文件路径
        const uploadsDir = path.join(__dirname, 'uploads');
        const filePath = path.join(uploadsDir, filename);

        // 验证文件路径是否在uploads目录内
        const normalizedFilePath = path.normalize(filePath);
        const normalizedUploadsDir = path.normalize(uploadsDir);
        if (!normalizedFilePath.startsWith(normalizedUploadsDir)) {
            return res.status(403).json({ error: '无权访问该路径' });
        }

        // 确保目录存在
        const dirPath = path.dirname(filePath);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
        }

        // 病毒扫描
        let scanResult = { safe: true, scanned: false, message: '病毒检测已禁用' };

        if (virusScanEnabled && virusScanner) {
            console.log('开始病毒扫描:', filename);
            scanResult = await virusScanner.scanBuffer(req.body, filename);

            if (!scanResult.safe) {
                console.log('文件被检测到病毒:', filename);

                // 将病毒文件保存到隔离区
                const virusPath = path.join(virusesDir, filename);
                fs.writeFileSync(virusPath, req.body);

                // 记录病毒文件信息
                const virusFile = {
                    id: Date.now().toString() + Math.random().toString(36).substring(2, 11),
                    filename: filename,
                    size: req.body.length,
                    uploaderIp: req.ip,
                    uploadTime: new Date().toISOString(),
                    scanResult: scanResult
                };

                // 使用 Map 存储而不是数组
                virusFiles.set(virusFile.id, virusFile);

                return res.status(403).json({
                    error: '不允许上传病毒',
                    viruses: scanResult.viruses,
                    virusId: virusFile.id
                });
            }
            
            console.log('病毒扫描完成:', filename, '结果:', scanResult.message);
        } else {
            console.log('病毒检测已禁用，跳过扫描:', filename);
        }
        
        // 写入文件
        fs.writeFileSync(filePath, req.body);
        
        // 构建响应URL
        const imageUrl = `/uploads/${filename}`;
        
        res.json({ 
            imageUrl: imageUrl,
            scanResult: scanResult // 包含扫描结果
        });
    } catch (error) {
        console.error('上传图片失败:', error);
        res.status(500).json({ error: '上传图片失败' });
    }
});

// 音频上传接口 - 单独配置raw解析器
app.post('/upload-audio', express.raw({ type: '*/*', limit: '30mb' }), async (req, res) => {
    try {
        // 验证请求头
        if (!req.headers['content-type']) {
            return res.status(400).json({ error: '缺少Content-Type请求头' });
        }
        
        // 检查文件大小
        if (req.body.length > 15 * 1024 * 1024) { // 15MB限制
            return res.status(413).json({ error: '音频大小超过限制（最大15MB）' });
        }
        
        // 验证Content-Type
        const contentType = req.headers['content-type'];
        const allowedAudioTypes = ['audio/webm', 'audio/mp3', 'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/flac'];
        if (contentType && !allowedAudioTypes.includes(contentType)) {
            return res.status(403).json({ error: '不允许上传非音频文件' });
        }
        
        // 根据Content-Type确定文件扩展名
        let extension = '.webm';
        if (contentType) {
            const mimeToExt = {
                'audio/webm': '.webm',
                'audio/mp3': '.mp3',
                'audio/mpeg': '.mp3',
                'audio/ogg': '.ogg',
                'audio/wav': '.wav',
                'audio/flac': '.flac'
            };
            extension = mimeToExt[contentType] || extension;
        }
        
        // 生成安全的文件名
        const filename = Date.now() + '-' + Math.round(Math.random() * 1E9) + extension;
        
        // 检查是否为危险文件类型
        const dangerousExtensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.jsp', '.asp', '.aspx', '.shtml', '.cgi', '.pl', '.sh', '.js', '.vbs'];
        const fileExtension = path.extname(filename).toLowerCase();
        if (dangerousExtensions.includes(fileExtension)) {
            return res.status(403).json({ error: '不允许上传该类型的文件' });
        }
        
        // 构建文件路径
        const uploadsDir = path.join(__dirname, 'uploads');
        const filePath = path.join(uploadsDir, filename);
        
        // 验证文件路径是否在uploads目录内
        const normalizedFilePath = path.normalize(filePath);
        const normalizedUploadsDir = path.normalize(uploadsDir);
        if (!normalizedFilePath.startsWith(normalizedUploadsDir)) {
            return res.status(403).json({ error: '无权访问该路径' });
        }
        
        // 确保目录存在
        const dirPath = path.dirname(filePath);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
        }
        
        // 语音文件跳过病毒扫描
        console.log('语音文件跳过病毒扫描:', filename);
        
        // 写入文件
        fs.writeFileSync(filePath, req.body);
        
        // 构建响应URL
        const audioUrl = `/uploads/${filename}`;
        
        res.json({ 
            audioUrl: audioUrl,
            contentType: contentType
        });
    } catch (error) {
        console.error('上传音频失败:', error);
        res.status(500).json({ error: '上传音频失败' });
    }
});

// 管理员获取威胁日志API
app.get('/api/admin/threat-log', (req, res) => {
    try {
        // 支持按类型过滤和数量限制
        const { type, limit: limitStr = '100' } = req.query;
        let logs = [...threatLog].reverse(); // 最新的排前面
        if (type) {
            logs = logs.filter(entry => entry.type === type);
        }
        const limit = Math.min(parseInt(limitStr) || 100, MAX_THREAT_LOG);
        res.json({ total: threatLog.length, logs: logs.slice(0, limit) });
    } catch (error) {
        console.error('获取威胁日志失败:', error);
        res.status(500).json({ error: '获取威胁日志失败' });
    }
});

// 管理员获取通话列表API
app.get('/api/admin/calls', (req, res) => {
    try {
        const calls = Array.from(ongoingCalls.values());
        res.json({ calls });
    } catch (error) {
        console.error('获取通话列表失败:', error);
        res.status(500).json({ error: '获取通话列表失败' });
    }
});

// 管理员结束通话API
app.post('/api/admin/calls/:callId/end', (req, res) => {
    try {
        const { callId } = req.params;
        const call = ongoingCalls.get(callId);
        if (call) {
            // 通知通话双方结束通话
            io.to(call.initiator).emit('call-ended', { from: 'admin', callId });
            io.to(call.recipient).emit('call-ended', { from: 'admin', callId });
            
            // 从通话列表中移除
            ongoingCalls.delete(callId);
            
            res.json({ success: true, message: '通话已结束' });
        } else {
            res.status(404).json({ error: '通话不存在' });
        }
    } catch (error) {
        console.error('结束通话失败:', error);
        res.status(500).json({ error: '结束通话失败' });
    }
});

// 管理员控制通话API
app.post('/api/admin/calls/:callId/control', (req, res) => {
    try {
        const { callId } = req.params;
        const { type, enabled } = req.body;
        const call = ongoingCalls.get(callId);
        
        if (call) {
            // 更新通话控制状态
            call.controls[type] = enabled;
            ongoingCalls.set(callId, call);
            
            // 通知通话双方控制状态变化
            io.to(call.initiator).emit('call-control-updated', { callId, type, enabled });
            io.to(call.recipient).emit('call-control-updated', { callId, type, enabled });
            
            res.json({ success: true, message: `通话${type}控制已更新`, call });
        } else {
            res.status(404).json({ error: '通话不存在' });
        }
    } catch (error) {
        console.error('控制通话失败:', error);
        res.status(500).json({ error: '控制通话失败' });
    }
});

// 管理员查看通话详情API
app.get('/api/admin/calls/:callId', (req, res) => {
    try {
        const { callId } = req.params;
        const call = ongoingCalls.get(callId);
        if (call) {
            res.json({ call });
        } else {
            res.status(404).json({ error: '通话不存在' });
        }
    } catch (error) {
        console.error('获取通话详情失败:', error);
        res.status(500).json({ error: '获取通话详情失败' });
    }
});

// 文件管理API - 获取文件列表（支持目录浏览）
app.get('/api/files', (req, res) => {
    try {
        // 验证路径参数
        let relativePath = req.query.path || '';
        if (relativePath) {
            if (typeof relativePath !== 'string') {
                return res.status(400).json({ error: '路径必须是字符串' });
            }
            // 检查路径中是否包含危险字符
            if (relativePath.includes('..') || relativePath.includes('\\')) {
                return res.status(403).json({ error: '路径包含非法字符' });
            }
            // 规范化路径
            relativePath = path.normalize(relativePath);
            // 再次检查路径安全性
            if (relativePath.includes('..')) {
                return res.status(403).json({ error: '路径包含非法字符' });
            }
        }
        
        // 构建目录路径
        const baseUploadsDir = path.join(__dirname, 'uploads');
        const targetDir = path.join(baseUploadsDir, relativePath);
        
        // 验证路径是否在uploads目录内
        const normalizedTargetDir = path.normalize(targetDir);
        const normalizedBaseDir = path.normalize(baseUploadsDir);
        if (!normalizedTargetDir.startsWith(normalizedBaseDir)) {
            return res.status(403).json({ error: '无权访问该路径' });
        }
        
        // 检查目录是否存在
        if (!fs.existsSync(targetDir)) {
            return res.json({ files: [], currentPath: relativePath });
        }
        
        // 读取目录内容
        const files = fs.readdirSync(targetDir).map(filename => {
            const filePath = path.join(targetDir, filename);
            const stats = fs.statSync(filePath);
            const isDirectory = stats.isDirectory();
            return {
                name: filename,
                size: isDirectory ? 0 : stats.size,
                createdAt: stats.birthtime,
                modifiedAt: stats.mtime,
                isDirectory: isDirectory,
                url: isDirectory ? null : `/uploads/${relativePath ? relativePath + '/' + filename : filename}`
            };
        });
        
        // 排序并返回结果
        res.json({ 
            files: files.sort((a, b) => {
                if (a.isDirectory && !b.isDirectory) return -1;
                if (!a.isDirectory && b.isDirectory) return 1;
                return b.createdAt - a.createdAt;
            }),
            currentPath: relativePath
        });
    } catch (error) {
        console.error('获取文件列表失败:', error);
        res.status(500).json({ error: '获取文件列表失败' });
    }
});

// 文件管理API - 创建目录
app.post('/api/files/create-directory', express.json(), (req, res) => {
    try {
        // 验证请求体
        if (!req.body) {
            return res.status(400).json({ error: '请求体不能为空' });
        }
        
        const { dirname, path: relativePath } = req.body;
        
        // 验证目录名
        if (!dirname || typeof dirname !== 'string') {
            return res.status(400).json({ error: '目录名不能为空且必须是字符串' });
        }
        
        // 检查目录名长度
        if (dirname.length > 255) {
            return res.status(400).json({ error: '目录名过长' });
        }
        
        // 检查目录名中是否包含危险字符
        if (dirname.includes('..') || dirname.includes('\\') || dirname.includes('/') || dirname.includes(':')) {
            return res.status(403).json({ error: '目录名包含非法字符' });
        }
        
        // 验证相对路径
        let safeRelativePath = relativePath || '';
        if (safeRelativePath) {
            if (typeof safeRelativePath !== 'string') {
                return res.status(400).json({ error: '路径必须是字符串' });
            }
            // 检查路径中是否包含危险字符
            if (safeRelativePath.includes('..') || safeRelativePath.includes('\\') || safeRelativePath.startsWith('/')) {
                return res.status(403).json({ error: '不允许使用相对路径或绝对路径' });
            }
            // 规范化路径
            safeRelativePath = path.normalize(safeRelativePath);
            // 再次检查路径安全性
            if (safeRelativePath.includes('..')) {
                return res.status(403).json({ error: '路径包含非法字符' });
            }
        }
        
        // 构建目录路径
        const uploadsDir = path.join(__dirname, 'uploads');
        const dirPath = path.join(uploadsDir, safeRelativePath, dirname);
        
        // 验证目录路径是否在uploads目录内
        const normalizedDirPath = path.normalize(dirPath);
        const normalizedUploadsDir = path.normalize(uploadsDir);
        if (!normalizedDirPath.startsWith(normalizedUploadsDir)) {
            return res.status(403).json({ error: '无权访问该路径' });
        }
        
        // 检查目录是否已存在
        if (fs.existsSync(dirPath)) {
            return res.status(400).json({ error: '目录已存在' });
        }
        
        // 创建目录
        fs.mkdirSync(dirPath, { recursive: true });
        res.json({ success: true });
    } catch (error) {
        console.error('创建目录失败:', error);
        res.status(500).json({ error: '创建目录失败' });
    }
});



// 文件管理API - 删除文件或目录
app.delete('/api/files/*', (req, res) => {
    try {
        // 验证路径参数
        const itemPath = req.params[0];
        if (!itemPath) {
            return res.status(400).json({ error: '路径不能为空' });
        }
        
        // 检查路径中是否包含危险字符
        if (itemPath.includes('..') || itemPath.includes('\\')) {
            return res.status(403).json({ error: '路径包含非法字符' });
        }
        
        // 规范化路径
        const normalizedItemPath = path.normalize(itemPath);
        // 再次检查路径安全性
        if (normalizedItemPath.includes('..')) {
            return res.status(403).json({ error: '路径包含非法字符' });
        }
        
        // 构建完整路径
        const uploadsDir = path.join(__dirname, 'uploads');
        const fullPath = path.join(uploadsDir, normalizedItemPath);
        
        // 验证路径是否在uploads目录内
        const normalizedFullPath = path.normalize(fullPath);
        const normalizedUploadsDir = path.normalize(uploadsDir);
        if (!normalizedFullPath.startsWith(normalizedUploadsDir)) {
            return res.status(403).json({ error: '无权访问该路径' });
        }
        
        // 检查文件或目录是否存在
        if (!fs.existsSync(fullPath)) {
            return res.status(404).json({ error: '文件或目录不存在' });
        }
        
        // 删除文件或目录
        const stats = fs.statSync(fullPath);
        if (stats.isDirectory()) {
            fs.rmSync(fullPath, { recursive: true, force: true });
        } else {
            fs.unlinkSync(fullPath);
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('删除失败:', error);
        res.status(500).json({ error: '删除失败' });
    }
});

// 文件管理API - 创建文本文件
app.post('/api/files/create', express.json(), (req, res) => {
    try {
        // 验证请求体
        if (!req.body) {
            return res.status(400).json({ error: '请求体不能为空' });
        }
        
        const { filename, content, path: relativePath } = req.body;
        
        // 验证文件名
        if (!filename || typeof filename !== 'string') {
            return res.status(400).json({ error: '文件名不能为空且必须是字符串' });
        }
        
        // 检查文件名长度
        if (filename.length > 255) {
            return res.status(400).json({ error: '文件名过长' });
        }
        
        // 检查文件名中是否包含危险字符
        if (filename.includes('..') || filename.includes('\\') || filename.includes('/') || filename.includes(':')) {
            return res.status(403).json({ error: '文件名包含非法字符' });
        }
        
        // 验证相对路径
        let safeRelativePath = relativePath || '';
        if (safeRelativePath) {
            if (typeof safeRelativePath !== 'string') {
                return res.status(400).json({ error: '路径必须是字符串' });
            }
            // 检查路径中是否包含危险字符
            if (safeRelativePath.includes('..') || safeRelativePath.includes('\\')) {
                return res.status(403).json({ error: '路径包含非法字符' });
            }
            // 规范化路径
            safeRelativePath = path.normalize(safeRelativePath);
            // 再次检查路径安全性
            if (safeRelativePath.includes('..')) {
                return res.status(403).json({ error: '路径包含非法字符' });
            }
        }
        
        // 验证内容
        const fileContent = content || '';
        if (typeof fileContent !== 'string') {
            return res.status(400).json({ error: '文件内容必须是字符串' });
        }
        
        // 构建文件路径
        const uploadsDir = path.join(__dirname, 'uploads');
        const filePath = path.join(uploadsDir, safeRelativePath, filename);
        
        // 验证文件路径是否在uploads目录内
        const normalizedFilePath = path.normalize(filePath);
        const normalizedUploadsDir = path.normalize(uploadsDir);
        if (!normalizedFilePath.startsWith(normalizedUploadsDir)) {
            return res.status(403).json({ error: '无权访问该路径' });
        }
        
        // 确保目录存在
        const dirPath = path.dirname(filePath);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
        }
        
        // 写入文件
        fs.writeFileSync(filePath, fileContent);
        const stats = fs.statSync(filePath);
        
        // 构建响应URL
        const fileUrl = `/uploads/${safeRelativePath ? safeRelativePath + '/' + filename : filename}`;
        
        res.json({
            name: filename,
            size: stats.size,
            createdAt: stats.birthtime,
            modifiedAt: stats.mtime,
            url: fileUrl
        });
    } catch (error) {
        console.error('创建文件失败:', error);
        res.status(500).json({ error: '创建文件失败' });
    }
});

// 文件管理API - 编辑文件内容
app.put('/api/files/*', express.json(), (req, res) => {
    try {
        // 验证路径参数
        const itemPath = req.params[0];
        if (!itemPath) {
            return res.status(400).json({ error: '路径不能为空' });
        }
        
        // 检查路径中是否包含危险字符
        if (itemPath.includes('..') || itemPath.includes('\\')) {
            return res.status(403).json({ error: '路径包含非法字符' });
        }
        
        // 规范化路径
        const normalizedItemPath = path.normalize(itemPath);
        // 再次检查路径安全性
        if (normalizedItemPath.includes('..')) {
            return res.status(403).json({ error: '路径包含非法字符' });
        }
        
        // 验证请求体
        if (!req.body) {
            return res.status(400).json({ error: '请求体不能为空' });
        }
        
        // 验证内容
        const { content } = req.body;
        const fileContent = content || '';
        if (typeof fileContent !== 'string') {
            return res.status(400).json({ error: '文件内容必须是字符串' });
        }
        
        // 构建文件路径
        const uploadsDir = path.join(__dirname, 'uploads');
        const filePath = path.join(uploadsDir, normalizedItemPath);
        
        // 验证文件路径是否在uploads目录内
        const normalizedFilePath = path.normalize(filePath);
        const normalizedUploadsDir = path.normalize(uploadsDir);
        if (!normalizedFilePath.startsWith(normalizedUploadsDir)) {
            return res.status(403).json({ error: '无权访问该路径' });
        }
        
        // 检查文件是否存在
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: '文件不存在' });
        }
        
        // 检查是否为目录
        const stats = fs.statSync(filePath);
        if (stats.isDirectory()) {
            return res.status(400).json({ error: '不能编辑目录' });
        }
        
        // 写入文件
        fs.writeFileSync(filePath, fileContent);
        const newStats = fs.statSync(filePath);
        
        // 构建响应数据
        const filename = path.basename(normalizedItemPath);
        const relativePath = path.dirname(normalizedItemPath);
        
        res.json({
            name: filename,
            size: newStats.size,
            createdAt: newStats.birthtime,
            modifiedAt: newStats.mtime,
            url: `/uploads/${normalizedItemPath}`
        });
    } catch (error) {
        console.error('编辑文件失败:', error);
        res.status(500).json({ error: '编辑文件失败' });
    }
});

// 文件管理API - 获取文件内容
app.get('/api/files/*/content', (req, res) => {
    try {
        // 验证路径参数
        const itemPath = req.params[0];
        if (!itemPath) {
            return res.status(400).json({ error: '路径不能为空' });
        }
        
        // 检查路径中是否包含危险字符
        if (itemPath.includes('..') || itemPath.includes('\\')) {
            return res.status(403).json({ error: '路径包含非法字符' });
        }
        
        // 规范化路径
        const normalizedItemPath = path.normalize(itemPath);
        // 再次检查路径安全性
        if (normalizedItemPath.includes('..')) {
            return res.status(403).json({ error: '路径包含非法字符' });
        }
        
        // 构建文件路径
        const uploadsDir = path.join(__dirname, 'uploads');
        const filePath = path.join(uploadsDir, normalizedItemPath);
        
        // 验证文件路径是否在uploads目录内
        const normalizedFilePath = path.normalize(filePath);
        const normalizedUploadsDir = path.normalize(uploadsDir);
        if (!normalizedFilePath.startsWith(normalizedUploadsDir)) {
            return res.status(403).json({ error: '无权访问该路径' });
        }
        
        // 检查文件是否存在
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: '文件不存在' });
        }
        
        // 检查是否为目录
        const stats = fs.statSync(filePath);
        if (stats.isDirectory()) {
            return res.status(400).json({ error: '不能读取目录内容' });
        }
        
        // 读取文件内容
        const content = fs.readFileSync(filePath, 'utf8');
        res.json({ content });
    } catch (error) {
        console.error('获取文件内容失败:', error);
        res.status(500).json({ error: '获取文件内容失败' });
    }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// 房间访问路由
app.get('/:roomName', (req, res) => {
    const roomName = req.params.roomName;
    // 检查房间是否存在
    if (rooms.has(roomName) || roomName === 'admin') {
        if (roomName === 'admin') {
            res.sendFile(path.join(__dirname, 'public', 'admin.html'));
        } else {
            res.sendFile(path.join(__dirname, 'public', 'index.html'));
        }
    } else {
        // 如果房间不存在，重定向到首页
        res.redirect('/');
    }
});

// 管理员密码（使用明文存储）
let ADMIN_PASSWORD = 'admin123';
let adminSocketId = null;

// 管理员 API 令牌系统（用于 HTTP API 验证）
let adminApiToken = null; // 当前有效的管理员 API 令牌
const ADMIN_API_TOKEN_EXPIRY = 60 * 60 * 1000; // 令牌有效期 1 小时

// 生成管理员 API 令牌
function generateAdminApiToken() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// 管理员 API 令牌验证中间件
function adminApiAuthMiddleware(req, res, next) {
    const token = req.headers['x-admin-token'];
    if (!token) {
        return res.status(401).json({ error: '缺少管理员令牌' });
    }
    if (token !== adminApiToken) {
        return res.status(401).json({ error: '无效的管理员令牌' });
    }
    next();
}

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: true,
        methods: ["GET", "POST"],
        credentials: true,
        allowedHeaders: ["Content-Type", "Authorization"]
    },
    
    // 传输方式配置
    transports: ['websocket', 'polling'],
    allowUpgrades: true,
    
    // 连接配置
    maxHttpBufferSize: 1e8,
    pingTimeout: 60000,
    pingInterval: 25000,
    connectTimeout: 45000,
    
    // 向下兼容
    allowEIO3: true,
    
    // 启用数据压缩
    perMessageDeflate: {
        zlibDeflateOptions: {
            level: 5
        },
        zlibInflateOptions: {
            chunkSize: 1024
        },
        threshold: 1024,
        concatenateFlush: true
    }
});

// 消息变量
const messages = new Map();

// 加载插件
loadPlugins();

// 消息批处理系统
const messageBatches = new Map(); // 存储每个客户端的消息批次
const BATCH_INTERVAL = 100; // 批处理间隔（毫秒）
const MAX_BATCH_SIZE = 50; // 最大批次大小

// 处理消息批处理
function processMessageBatch(socketId) {
    const batch = messageBatches.get(socketId);
    if (batch && batch.length > 0) {
        // 发送批次消息
        io.to(socketId).emit('message-batch', batch);
        // 清空批次
        messageBatches.set(socketId, []);
    }
}

// 批量发送消息
function sendBatchMessage(socketId, message) {
    if (!messageBatches.has(socketId)) {
        messageBatches.set(socketId, []);
    }
    
    const batch = messageBatches.get(socketId);
    batch.push(message);
    
    // 如果批次大小达到上限，立即处理
    if (batch.length >= MAX_BATCH_SIZE) {
        processMessageBatch(socketId);
    } else if (batch.length === 1) {
        // 只有当批次为空时才设置定时器，确保每次有新消息时都会处理
        setTimeout(() => processMessageBatch(socketId), BATCH_INTERVAL);
    }
}

// 消息缓存系统
const messageCache = new Map(); // 内存缓存
const CACHE_DIR = path.join(__dirname, 'cache');
const MAX_CACHE_SIZE = 1000; // 每个房间最大缓存消息数
const CACHE_EXPIRY = 30 * 60 * 60 * 1000; // 缓存过期时间（24小时）

// 确保缓存目录存在
if (!fs.existsSync(CACHE_DIR)) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
}

// 初始化房间消息缓存
function initRoomCache(roomName) {
    if (!messageCache.has(roomName)) {
        messageCache.set(roomName, {
            messages: [],
            lastUpdated: Date.now(),
            size: 0
        });
    }
}

// 添加消息到缓存
function addMessageToCache(roomName, message) {
    initRoomCache(roomName);
    const cache = messageCache.get(roomName);
    
    // 添加消息到缓存
    cache.messages.push(message);
    cache.size = cache.messages.length;
    cache.lastUpdated = Date.now();
    
    // 如果缓存超过最大大小，删除最旧的消息
    if (cache.size > MAX_CACHE_SIZE) {
        cache.messages = cache.messages.slice(-MAX_CACHE_SIZE);
        cache.size = cache.messages.length;
    }
    
    // 异步保存到文件
    saveCacheToFile(roomName);
}

// 从缓存获取消息
function getMessagesFromCache(roomName, limit = 50, offset = 0) {
    initRoomCache(roomName);
    const cache = messageCache.get(roomName);
    
    // 检查缓存是否过期
    if (Date.now() - cache.lastUpdated > CACHE_EXPIRY) {
        // 重新加载缓存
        loadCacheFromFile(roomName);
    }
    
    // 返回分页消息
    return cache.messages.slice(offset, offset + limit);
}

// 保存缓存到文件
function saveCacheToFile(roomName) {
    const cache = messageCache.get(roomName);
    if (cache) {
        const cachePath = path.join(CACHE_DIR, `${roomName}_messages.json`);
        try {
            fs.writeFileSync(cachePath, JSON.stringify({
                messages: cache.messages,
                lastUpdated: cache.lastUpdated
            }));
        } catch (error) {
            console.error(`保存缓存失败: ${roomName}`, error);
        }
    }
}

// 从文件加载缓存
function loadCacheFromFile(roomName) {
    const cachePath = path.join(CACHE_DIR, `${roomName}_messages.json`);
    try {
        if (fs.existsSync(cachePath)) {
            const data = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
            messageCache.set(roomName, {
                messages: data.messages || [],
                lastUpdated: data.lastUpdated || Date.now(),
                size: (data.messages || []).length
            });
        }
    } catch (error) {
        console.error(`加载缓存失败: ${roomName}`, error);
    }
}

// 清理过期缓存
function cleanExpiredCache() {
    const now = Date.now();
    messageCache.forEach((cache, roomName) => {
        if (now - cache.lastUpdated > CACHE_EXPIRY) {
            messageCache.delete(roomName);
            console.log(`清理过期缓存: ${roomName}`);
        }
    });
}

// 定期清理过期缓存（优化：从1小时改为15分钟）
setInterval(cleanExpiredCache, 15 * 60 * 1000);

// 天气API配置
const WEATHER_API_URL = 'https://api-proxy-juhe.jenius.cn/simpleWeather/query';
const WEATHER_API_KEY = 'cb9fc22848b739befe3f0b3d5e4e9248';

// 天气查询函数
async function getWeather(city) {
    try {
        const https = require('https');
        const querystring = require('querystring');
        
        const postData = querystring.stringify({
            key: WEATHER_API_KEY,
            city: city
        });
        
        const options = {
            hostname: 'api-proxy-juhe.jenius.cn',
            path: '/simpleWeather/query',
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(postData)
            }
        };
        
        return new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => {
                    data += chunk;
                });
                res.on('end', () => {
                    try {
                        const weatherData = JSON.parse(data);
                        
                        // 处理API响应，提取需要的字段
                        console.log('天气API返回的原始数据:', weatherData);
                        if (weatherData && weatherData.result) {
                            const result = weatherData.result;
                            console.log('天气API返回的result字段:', result);
                            
                            // 从realtime对象中提取实时天气数据
                            const realtime = result.realtime || {};
                            
                            resolve({
                                city: result.city || result.cityName || city,
                                temperature: realtime.temperature || result.temperature || result.temp || '未知',
                                weather: realtime.info || result.weather || result.weatherDesc || '未知',
                                wind: `${realtime.direct || ''} ${realtime.power || ''}`.trim() || result.wind || result.windDirection || result.windPower || '未知',
                                humidity: realtime.humidity || result.humidity || '未知',
                                updateTime: result.updateTime || result.date || new Date().toLocaleString()
                            });
                        } else {
                            // 如果API响应结构不符合预期，返回默认值
                            console.log('天气API返回的结构不符合预期');
                            resolve({
                                city: city,
                                temperature: '未知',
                                weather: '未知',
                                wind: '未知',
                                humidity: '未知',
                                updateTime: new Date().toLocaleString()
                            });
                        }
                    } catch (error) {
                        console.error('解析天气数据失败:', error);
                        // 解析失败时返回默认值
                        resolve({
                            city: city,
                            temperature: '未知',
                            weather: '未知',
                            wind: '未知',
                            humidity: '未知',
                            updateTime: new Date().toLocaleString()
                        });
                    }
                });
            });
            
            req.on('error', (error) => {
                console.error('天气查询请求失败:', error);
                // 请求失败时返回默认值
                resolve({
                    city: city,
                    temperature: '未知',
                    weather: '未知',
                    wind: '未知',
                    humidity: '未知',
                    updateTime: new Date().toLocaleString()
                });
            });
            
            req.write(postData);
            req.end();
        });
    } catch (error) {
        console.error('天气查询失败:', error);
        // 发生异常时返回默认值
        return {
            city: city,
            temperature: '未知',
            weather: '未知',
            wind: '未知',
            humidity: '未知',
            updateTime: new Date().toLocaleString()
        };
    }
}
const deletedMessages = new Map();

// 房间系统数据结构

// 好友系统数据结构
const friendships = new Map(); // 存储好友关系: Map<socketId, Set<friendSocketId>>
const adminForcedFriendships = new Map(); // 存储管理员强制添加的好友关系（不可被用户删除）: Map<userSocketId, Set<forcedFriendSocketId>>
const privateMessages = new Map(); // 存储私聊消息: Map<chatId, Array<message>>

// 白板系统数据结构
const whiteboards = new Map(); // 存储白板数据: Map<whiteboardId, { users: [], data: [] }>
let whiteboardIdCounter = 1;

// 文档编辑系统数据结构
const documents = new Map(); // 存储文档内容: Map<documentId, { content, users, lastModified }>

// 好友数量限制系统
const userMaxFriends = new Map(); // 存储用户的好友数量上限: Map<socketId, number>
const friendLimitRequests = new Map(); // 存储好友扩容申请: Map<requestId, request>
let requestIdCounter = 1; // 申请ID计数器

// 通话管理系统
const ongoingCalls = new Map(); // 存储正在进行的通话: Map<callId, callInfo>
let callIdCounter = 1; // 通话ID计数器

// 控制台日志系统
const userConsoleLogs = new Map(); // Map<socketId, Array<log>>

// 截屏通知日志
const screenshotLogs = []; // 全局截屏日志数组
const MAX_SCREENSHOT_LOGS = 500; // 最多保留500条记录

function logScreenshotNotice(user, roomName) {
    const entry = {
        username: user.username,
        roomName: roomName,
        ip: user.ip || 'unknown',
        timestamp: new Date().toISOString()
    };
    screenshotLogs.unshift(entry);
    if (screenshotLogs.length > MAX_SCREENSHOT_LOGS) {
        screenshotLogs.pop();
    }
    return entry;
}

// 投票系统数据结构
const activePolls = new Map(); // 存储当前活跃投票: Map<pollId, pollInfo>
let pollIdCounter = 1; // 投票ID计数器

// 游戏邀请系统数据结构
const gameInvitations = new Map(); // 存储游戏邀请: Map<invitationId, invitation>
const gameHistory = new Map(); // 存储游戏历史: Map<gameId, gameHistory>
let invitationIdCounter = 1;

// 消息速率限制系统
const messageRateLimits = new Map(); // 存储用户消息发送时间: Map<socketId, Array<timestamp>>
const MAX_MESSAGES_PER_MINUTE = 20; // 每分钟最大消息数
const RATE_LIMIT_WINDOW = 60 * 1000; // 速率限制窗口（毫秒）

// ── 刷屏防护系统 ───────────────────────────────────────────────
const spamMessageHistory = new Map(); // Map<socketId, Array<{ content, time }>>
const SPAM_SAME_MESSAGE_LIMIT = 5;    // 相同消息连续发送上限
const SPAM_MESSAGE_WINDOW = 10000;     // 10秒内检测刷屏
const SPAM_AUTO_MUTE_MINUTES = 5;      // 刷屏自动禁言时长（分钟）
const MAX_SPAM_VIOLATIONS = 3;         // 累计违规次数达到此值则永久封禁IP

const spamViolations = new Map(); // Map<ip, { count, lastTime }>

/**
 * 检测并处理刷屏行为
 * @returns {string|null} 如果触发刷屏返回错误信息，否则返回 null
 */
function checkAndHandleSpam(socketId, ip, messageContent) {
    if (!spamMessageHistory.has(socketId)) {
        spamMessageHistory.set(socketId, []);
    }
    const history = spamMessageHistory.get(socketId);
    const now = Date.now();

    // 清理 10 秒前的记录
    while (history.length > 0 && now - history[0].time > SPAM_MESSAGE_WINDOW) {
        history.shift();
    }

    // 检查是否发送相同消息（用于过滤无意义重复）
    const recentSameCount = history.filter(m => m.content === messageContent).length;
    
    // 记录当前消息
    history.push({ content: messageContent, time: now });

    // 超过相同消息上限
    if (recentSameCount >= SPAM_SAME_MESSAGE_LIMIT) {
        // 记录违规
        const violation = spamViolations.get(ip) || { count: 0, lastTime: now };
        violation.count++;
        violation.lastTime = now;
        spamViolations.set(ip, violation);

        // 超过累计上限，永久封禁
        if (violation.count >= MAX_SPAM_VIOLATIONS) {
            bannedIPs.add(ip);
            logThreat(ip, 'SPAM_BAN', `累计刷屏 ${violation.count} 次，IP 被永久封禁`);
            return '您的IP因刷屏已被永久封禁';
        }

        // 否则临时禁言
        const muteEndTime = Date.now() + SPAM_AUTO_MUTE_MINUTES * 60 * 1000;
        mutedUsers.set(socketId, {
            username: users.get(socketId)?.username || 'unknown',
            endTime: muteEndTime,
            reason: '刷屏（发送重复消息）'
        });
        logThreat(ip, 'SPAM_MUTE', `发送相同消息 ${recentSameCount + 1} 次，禁言 ${SPAM_AUTO_MUTE_MINUTES} 分钟`);
        return `检测到刷屏行为，已被禁言 ${SPAM_AUTO_MUTE_MINUTES} 分钟`;
    }

    return null;
}

// API请求速率限制系统
const apiRateLimits = new Map(); // 存储IP的API请求时间: Map<ip, Array<timestamp>>
const MAX_API_REQUESTS_PER_MINUTE = 100; // 每分钟最大API请求数
const MAX_SENSITIVE_REQUESTS_PER_MINUTE = 20; // 每分钟最大敏感操作请求数

// CSRF保护系统
const csrfTokens = new Map(); // 存储用户会话的CSRF令牌: Map<ip, { token: string, expires: number }>
const CSRF_TOKEN_EXPIRY = 24 * 60 * 60 * 1000; // 令牌过期时间（24小时）

// 生成CSRF令牌
function generateCsrfToken() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// CSRF令牌验证中间件
function csrfProtectionMiddleware(req, res, next) {
    // GET请求不需要CSRF令牌
    if (req.method === 'GET') {
        return next();
    }
    
    // 获取用户IP
    const userIP = req.ip || req.connection.remoteAddress;
    if (!userIP) {
        return res.status(403).json({ error: '无法验证请求来源' });
    }
    
    // 获取CSRF令牌
    const csrfToken = req.headers['x-csrf-token'] || req.body.csrfToken;
    if (!csrfToken) {
        return res.status(403).json({ error: '缺少CSRF令牌' });
    }
    
    // 验证令牌
    const tokenData = csrfTokens.get(userIP);
    if (!tokenData || tokenData.token !== csrfToken) {
        return res.status(403).json({ error: '无效的CSRF令牌' });
    }
    
    // 检查令牌是否过期
    if (Date.now() > tokenData.expires) {
        csrfTokens.delete(userIP);
        return res.status(403).json({ error: 'CSRF令牌已过期' });
    }
    
    next();
}

// 获取CSRF令牌的API
app.get('/api/csrf-token', (req, res) => {
    const userIP = req.ip || req.connection.remoteAddress;
    if (!userIP) {
        return res.status(400).json({ error: '无法生成CSRF令牌' });
    }
    
    // 生成新令牌
    const token = generateCsrfToken();
    const expires = Date.now() + CSRF_TOKEN_EXPIRY;
    
    // 存储令牌
    csrfTokens.set(userIP, { token, expires });
    
    res.json({ csrfToken: token, expires });
});

// 定期清理过期的CSRF令牌（优化：从默认改为10分钟）
setInterval(() => {
    const now = Date.now();
    let cleanedCount = 0;
    csrfTokens.forEach((tokenData, ip) => {
        if (now > tokenData.expires) {
            csrfTokens.delete(ip);
            cleanedCount++;
        }
    });
    if (cleanedCount > 0) {
        console.log(`[CSRF清理] 已清理 ${cleanedCount} 个过期令牌`);
    }
}, 10 * 60 * 1000); // 每10分钟清理一次

// 统一错误处理中间件
function errorHandlerMiddleware(err, req, res, next) {
    // 记录错误详情（包含请求信息）
    console.error('API错误:', {
        error: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method,
        ip: req.ip,
        query: req.query,
        body: req.body
    });
    
    // 确定错误状态码
    const statusCode = err.statusCode || 500;
    
    // 构建用户友好的错误消息
    let errorMessage = '服务器内部错误';
    switch (statusCode) {
        case 400:
            errorMessage = err.message || '请求参数错误';
            break;
        case 401:
            errorMessage = err.message || '未授权访问';
            break;
        case 403:
            errorMessage = err.message || '禁止访问';
            break;
        case 404:
            errorMessage = err.message || '资源不存在';
            break;
        case 429:
            errorMessage = err.message || '请求过于频繁，请稍后再试';
            break;
        default:
            // 对于500错误，不暴露详细信息
            errorMessage = '服务器内部错误';
    }
    
    // 返回错误响应
    res.status(statusCode).json({
        error: errorMessage,
        // 仅在开发环境返回详细错误信息
        ...(process.env.NODE_ENV === 'development' && { detail: err.message })
    });
}

// 404错误处理
app.use((req, res, next) => {
    const error = new Error('请求的资源不存在');
    error.statusCode = 404;
    next(error);
});

// 应用统一错误处理中间件
app.use(errorHandlerMiddleware);

// API速率限制中间件
function apiRateLimitMiddleware(req, res, next) {
    // 获取用户IP
    const userIP = req.ip || req.connection.remoteAddress;
    if (!userIP) {
        return next();
    }
    
    // 获取当前时间
    const now = Date.now();
    
    // 获取该IP的请求记录
    let requestTimes = apiRateLimits.get(userIP) || [];
    
    // 清理过期的请求记录
    requestTimes = requestTimes.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
    
    // 检查是否超过速率限制
    if (requestTimes.length >= MAX_API_REQUESTS_PER_MINUTE) {
        return res.status(429).json({ error: '请求过于频繁，请稍后再试' });
    }
    
    // 检查是否为敏感操作
    const sensitivePaths = ['/api/admin/', '/api/files/create', '/api/files/delete', '/api/files/upload'];
    const isSensitive = sensitivePaths.some(path => req.path.includes(path));
    
    if (isSensitive) {
        // 对敏感操作进行更严格的限制
        const sensitiveRequests = requestTimes.filter(timestamp => {
            const requestTime = timestamp;
            // 这里简化处理，实际应该存储请求类型
            return true;
        });
        
        if (sensitiveRequests.length >= MAX_SENSITIVE_REQUESTS_PER_MINUTE) {
            return res.status(429).json({ error: '敏感操作请求过于频繁，请稍后再试' });
        }
    }
    
    // 记录本次请求
    requestTimes.push(now);
    apiRateLimits.set(userIP, requestTimes);
    
    next();
}

// 主动触发清理函数（消息发送后调用）
function cleanupRateLimit(socketId) {
    const now = Date.now();
    const rateLimitData = messageRateLimits.get(socketId);
    if (rateLimitData && rateLimitData.messages) {
        rateLimitData.messages = rateLimitData.messages.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
        if (rateLimitData.messages.length === 0) {
            messageRateLimits.delete(socketId);
        }
    }
}

// 主动触发清理函数（API请求后调用）
function cleanupApiRateLimit(ip) {
    const now = Date.now();
    const times = apiRateLimits.get(ip);
    if (Array.isArray(times)) {
        const filteredTimes = times.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
        if (filteredTimes.length === 0) {
            apiRateLimits.delete(ip);
        } else {
            apiRateLimits.set(ip, filteredTimes);
        }
    }
}

// 定期清理过期的速率限制记录（优化：从30秒改为10秒）
setInterval(() => {
    const now = Date.now();
    let msgCleaned = 0, apiCleaned = 0;

    // 清理消息速率限制
    messageRateLimits.forEach((rateLimitData, socketId) => {
        if (rateLimitData && typeof rateLimitData === 'object' && Array.isArray(rateLimitData.messages)) {
            const beforeCount = rateLimitData.messages.length;
            const filteredMessages = rateLimitData.messages.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
            msgCleaned += beforeCount - filteredMessages.length;
            if (filteredMessages.length === 0) {
                messageRateLimits.delete(socketId);
            } else {
                rateLimitData.messages = filteredMessages;
                rateLimitData.lastCleanup = now;
                messageRateLimits.set(socketId, rateLimitData);
            }
        } else {
            messageRateLimits.delete(socketId);
        }
    });

    // 清理API速率限制
    apiRateLimits.forEach((times, ip) => {
        if (Array.isArray(times)) {
            const beforeCount = times.length;
            const filteredTimes = times.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
            apiCleaned += beforeCount - filteredTimes.length;
            if (filteredTimes.length === 0) {
                apiRateLimits.delete(ip);
            } else {
                apiRateLimits.set(ip, filteredTimes);
            }
        } else {
            apiRateLimits.delete(ip);
        }
    });

    if (msgCleaned > 0 || apiCleaned > 0) {
        console.log(`[速率限制清理] 消息: ${msgCleaned}, API: ${apiCleaned}, 当前: 消息${messageRateLimits.size}, API${apiRateLimits.size}`);
    }
}, 10000); // 每10秒清理一次

// ── 威胁日志系统 ──────────────────────────────────────────────
const threatLog = []; // 存储威胁事件: Array<{ time, ip, type, detail }>
const MAX_THREAT_LOG = 500; // 最多保留500条记录

function logThreat(ip, type, detail) {
    const entry = {
        time: new Date().toISOString(),
        ip: ip || 'unknown',
        type,
        detail
    };
    threatLog.push(entry);
    if (threatLog.length > MAX_THREAT_LOG) threatLog.shift(); // 超出则移除最旧的
    console.warn(`[威胁] [${type}] IP=${entry.ip} | ${detail}`);
}

// ── 输入验证工具 ───────────────────────────────────────────────
const INPUT_LIMITS = {
    username:  { min: 1, max: 30 },
    roomName:  { min: 1, max: 50 },
    roomPwd:   { min: 0, max: 64 },
    message:   { min: 1, max: 500 },
    reason:    { min: 0, max: 200 },
    bio:       { min: 0, max: 300 }
};

/**
 * 验证字符串字段
 * @param {*} value      待验证的值
 * @param {string} field 字段名（对应 INPUT_LIMITS 键）
 * @returns {string|null} 合法则返回 null，非法则返回错误描述
 */
function validateField(value, field) {
    if (value === undefined || value === null) return null; // 可选字段允许缺省
    if (typeof value !== 'string') return `${field} 类型错误（需要字符串）`;
    const limit = INPUT_LIMITS[field];
    if (!limit) return null;
    if (value.length < limit.min) return `${field} 过短（最少 ${limit.min} 个字符）`;
    if (value.length > limit.max) return `${field} 过长（最多 ${limit.max} 个字符）`;
    return null;
}

// ── 管理员登录暴力破解防护 ───────────────────────────────────
const adminLoginAttempts = new Map(); // Map<ip, { count, lockedUntil }>
const ADMIN_LOGIN_MAX_ATTEMPTS = 5;   // 连续失败 5 次
const ADMIN_LOGIN_LOCKOUT_MS   = 15 * 60 * 1000; // 锁定 15 分钟

function checkAdminLoginAllowed(ip) {
    const record = adminLoginAttempts.get(ip);
    if (!record) return { allowed: true };
    if (record.lockedUntil && Date.now() < record.lockedUntil) {
        const remainSec = Math.ceil((record.lockedUntil - Date.now()) / 1000);
        return { allowed: false, remainSec };
    }
    return { allowed: true };
}

function recordAdminLoginFail(ip) {
    let record = adminLoginAttempts.get(ip) || { count: 0, lockedUntil: null };
    record.count++;
    if (record.count >= ADMIN_LOGIN_MAX_ATTEMPTS) {
        record.lockedUntil = Date.now() + ADMIN_LOGIN_LOCKOUT_MS;
        logThreat(ip, 'ADMIN_BRUTE_FORCE', `管理员登录连续失败 ${record.count} 次，锁定 15 分钟`);
    }
    adminLoginAttempts.set(ip, record);
}

function resetAdminLoginRecord(ip) {
    adminLoginAttempts.delete(ip);
}

// ── Socket 事件通用速率限制 ───────────────────────────────────
// 防止客户端用非消息事件（join/create-room/private-msg等）洪水攻击
const socketEventRateLimits = new Map(); // Map<socketId, Map<event, Array<timestamp>>>
const SOCKET_EVENT_LIMITS = {
    'join':              { max: 5,  window: 10000  }, // 10秒内最多 5 次
    'admin-create-room': { max: 10, window: 60000  }, // 1分钟内最多 10 次
    'private-message':   { max: 30, window: 60000  }, // 1分钟内最多 30 条私聊
    'friend-request':    { max: 10, window: 60000  }, // 1分钟内最多 10 次好友申请
    'admin-login':       { max: 10, window: 60000  }, // 1分钟内最多 10 次（配合暴力破解防护）
    'whiteboard-draw':   { max: 120,window: 10000  }, // 10秒内最多 120 次画图
    'game-action':       { max: 60, window: 10000  }, // 10秒内最多 60 次游戏操作
};

/**
 * 检查 Socket 事件速率限制
 * @returns {boolean} 是否超限（true=超限，应拦截）
 */
function checkSocketEventRate(socketId, event, ip) {
    const limit = SOCKET_EVENT_LIMITS[event];
    if (!limit) return false; // 未配置限制的事件直接放行

    if (!socketEventRateLimits.has(socketId)) {
        socketEventRateLimits.set(socketId, new Map());
    }
    const eventsMap = socketEventRateLimits.get(socketId);

    const now = Date.now();
    let times = eventsMap.get(event) || [];
    // 清理窗口外的旧记录
    times = times.filter(t => now - t < limit.window);

    if (times.length >= limit.max) {
        logThreat(ip, 'SOCKET_FLOOD', `事件 "${event}" 速率超限 (${times.length}/${limit.max} / ${limit.window}ms)`);
        return true; // 超限
    }

    times.push(now);
    eventsMap.set(event, times);
    return false;
}

// IP封禁系统


// 默认好友数量上限
const DEFAULT_MAX_FRIENDS = 5;
const INFINITE_FRIENDS = -1; // 无限好友数量


// @功能开关
let allowMentions = true; // 默认开启@功能

// 脏话过滤系统
const badWords = [
    // 英文脏话
    'fuck', 'shit', 'asshole', 'bitch', 'dick', 'pussy', 'cunt', 'nigger', 'faggot', 'damn',
    // 中文脏话
    '傻逼', 'sb', '傻b', '煞笔', '操你妈', '去死', '垃圾', '废物', '脑残', '王八蛋', '滚蛋', '畜生', '贱人', '狗东西', '杂种',
    '草泥马', '妈蛋', '二货', '智障', '白痴', '混蛋', '恶棍', '禽兽', '畜生不如',
    '操蛋', '操你大爷', '你妈逼', '你妹', '你大爷', '草泥马'
];

// 注意：移除了单字脏话（如'草'、'日'、'靠'、'操'），因为它们会导致误判，例如"草莓"中的"草"字被错误识别为脏话

// 脏话计数系统
const swearWordCount = new Map(); // 存储用户脏话计数: Map<socketId, number>

// 默认房间
rooms.set('main', {
    roomName: 'main',
    password: null,
    creator: 'system(11)',
    createdAt: new Date(),
    updatedAt: new Date(),
    users: [],
    messages: [],
    announcements: [], // 房间公告
    theme: { // 房间主题
        background: 'default', // 默认背景
        colorScheme: 'light', // 配色方案：light, dark
        customCSS: '' // 自定义CSS
    },
    stats: { // 房间统计
        totalMessages: 0,
        totalUsers: 0,
        peakUsers: 0,
        createdAt: new Date(),
        lastActivity: new Date()
    },
    history: { // 历史记录
        messageHistory: [], // 消息历史
        userHistory: [], // 用户进出历史
        eventHistory: [] // 事件历史
    },
    settings: {
        maxUsers: 100,
        allowPublicAccess: true,
        allowMessages: true,
        allowFiles: true,
        allowAudio: true,
        allowVideo: true,
        allowCalls: true,
        allowWhiteboard: true,
        allowPolls: true,
        allowGames: true
    }
});

io.on('connection', (socket) => {
    // 获取用户IP
    const userIP = socket.handshake.address;
    
    // 添加调试日志
    console.log(`[连接] 用户连接: ${socket.id}`);
    console.log(`[连接] 客户端IP: ${userIP}`);
    console.log(`[连接] 传输方式: ${socket.conn.transport.name}`);
    console.log(`[连接] User-Agent: ${socket.handshake.headers['user-agent']}`);
    
    // 监听传输方式升级
    socket.conn.on('upgrade', () => {
        console.log(`[升级] ${socket.id} 传输方式从 polling 升级为 ${socket.conn.transport.name}`);
    });
    
    // 检查IP是否被封禁
    if (bannedIPs.has(userIP)) {
        console.log(`[封禁] 被封禁的IP ${userIP} 尝试连接`);
        socket.disconnect(true);
        return;
    }
    
    // 检查IP连接数限制
    if (!ipConnections.has(userIP)) {
        ipConnections.set(userIP, new Set());
    }
    
    const ipConnSet = ipConnections.get(userIP);
    if (ipConnSet.size >= MAX_CONNECTIONS_PER_IP) {
        console.log(`[连接限制] IP ${userIP} 连接数超过限制 (${ipConnSet.size}/${MAX_CONNECTIONS_PER_IP})`);
        socket.emit('connection-error', { message: '该IP连接数已达上限，请稍后再试' });
        socket.disconnect(true);
        return;
    }
    
    // 记录连接
    ipConnSet.add(socket.id);
    console.log(`用户连接: ${socket.id} (IP: ${userIP}), 当前IP连接数: ${ipConnSet.size}`);

    socket.on('join', (data) => {
        // 速率限制
        if (checkSocketEventRate(socket.id, 'join', userIP)) {
            socket.emit('join-error', { message: '操作过于频繁，请稍后再试' });
            return;
        }

        // 输入类型检查
        if (!data || (typeof data !== 'object' && typeof data !== 'string')) {
            logThreat(userIP, 'INVALID_INPUT', 'join 事件收到非法 data 类型');
            socket.emit('join-error', { message: '无效的请求数据' });
            return;
        }

        const { username, roomName = 'main', password = null } = typeof data === 'object' ? data : { username: data };

        // 字段长度/类型验证
        const usernameErr = validateField(username, 'username');
        if (usernameErr || !username) {
            logThreat(userIP, 'INVALID_INPUT', `join 用户名非法: ${usernameErr || '为空'}`);
            socket.emit('join-error', { message: usernameErr || '用户名不能为空' });
            return;
        }
        const roomNameErr = validateField(roomName, 'roomName');
        if (roomNameErr) {
            socket.emit('join-error', { message: roomNameErr });
            return;
        }
        if (password !== null) {
            const pwdErr = validateField(password, 'roomPwd');
            if (pwdErr) {
                socket.emit('join-error', { message: pwdErr });
                return;
            }
        }

        // 检查房间是否存在
        let room = rooms.get(roomName);
        if (!room) {
            // 房间不存在
            socket.emit('join-error', { message: '没有这个房间' });
            return;
        }
        
        // 检查密码是否正确
        if (room.password && room.password !== password) {
            socket.emit('join-error', { message: '密码错误' });
            return;
        }
        
        // 检查房间是否已满
        if (room.users.length >= room.settings.maxUsers) {
            socket.emit('join-error', { message: '房间已满' });
            return;
        }
        
        // 检查是否允许创建新房间（至少有一个房间存在）
        const allRooms = Array.from(rooms.values());
        if (allRooms.length === 0) {
            socket.emit('join-error', { message: '至少需要有一个房间才能加入' });
            return;
        }
        
        // 检查用户名是否已存在
        const existingUser = Array.from(users.values()).find(user => user.username === username);
        if (existingUser) {
            socket.emit('join-error', { message: '用户名已存在，请选择其他用户名' });
            return;
        }
        
        // 设置用户信息
            const user = {
                username: username,
                color: getRandomColor(),
                socketId: socket.id,
                ip: userIP, // 添加IP属性
                roomName: roomName,
                role: 'user', // 默认角色为user
                permissions: { ...defaultPermissions },
                status: 'online', // 在线状态：online, away, busy, offline
                lastSeen: new Date().toISOString(), // 最后在线时间
                profile: { // 用户资料
                    avatar: null, // 头像URL
                    bio: '', // 个人简介
                    age: null, // 年龄
                    location: '', // 位置
                    website: '' // 个人网站
                },
                level: 1, // 用户等级
                experience: 0, // 经验值
                achievements: [], // 成就列表
                stats: { // 统计数据
                    messagesSent: 0,
                    filesUploaded: 0,
                    callsMade: 0,
                    friendsAdded: 0,
                    timeSpent: 0 // 在线时间（分钟）
                },
                settings: { locked: false, lockMessage: '设置已被管理员锁定' },
                userSettings: { // 用户具体设置
                    targetLanguage: 'zh',
                    autoTranslate: false,
                    soundNotification: true,
                    mentionNotification: true,
                    theme: 'light', // 主题：light, dark
                    fontSize: 'medium', // 字体大小：small, medium, large
                    notifications: {
                        messages: true,
                        calls: true,
                        friendRequests: true,
                        mentions: true
                    }
                },
                aiSettings: { // AI设置
                    enable: false,
                    model: 'glm4',
                    glm4: {
                        apiKey: ''
                    },
                    deepseek: {
                        modelName: '',
                        apiKey: ''
                    },
                    siliconflow: {
                        modelName: '',
                        apiKey: ''
                    },
                    custom: {
                        apiUrl: '',
                        apiKey: '',
                        modelName: ''
                    }
                }
            };
        
        // 为新用户分配25%概率的通话权限
        if (Math.random() < 0.25) {
            user.permissions.allowCall = true;
        }
        
        // 保存用户对象
        users.set(socket.id, user);
        
        // 将用户添加到房间
        room.users.push(socket.id);
        
        // 让socket加入房间频道
        socket.join(roomName);
        
        // 发送房间内的用户列表和消息
        let roomUsers = room.users.map(userId => users.get(userId)).filter(user => user);
        // 确保room.messages存在，如果不存在就初始化它
        if (!room.messages) {
            room.messages = [];
        }
        const roomMessages = room.messages;
        
        // 检查用户是否有查看用户列表的权限
        if (!user.permissions.allowViewUsers) {
            roomUsers = [];
        }
        
        // 发送给当前用户
        socket.emit('user-joined', {
            username: username,
            userCount: room.users.length,
            users: roomUsers,
            roomName: roomName
        });
        
        // 发送给房间内其他用户（只发送有权限的用户）
        const otherUsers = roomUsers.filter(u => u.permissions.allowViewUsers);
        socket.to(roomName).emit('user-joined', {
            username: username,
            userCount: room.users.length,
            users: otherUsers,
            roomName: roomName
        });
        
        // 分批发送房间历史消息（每次5条）
        const batchSize = 5;
        const totalMessages = roomMessages.length;
        
        function sendBatch(startIndex) {
            const endIndex = Math.min(startIndex + batchSize, totalMessages);
            const batchMessages = roomMessages.slice(startIndex, endIndex);
            
            socket.emit('room-history', {
                messages: batchMessages,
                batch: true,
                startIndex: startIndex,
                endIndex: endIndex,
                total: totalMessages,
                done: endIndex >= totalMessages
            });
            
            if (endIndex < totalMessages) {
                // 延迟发送下一批，避免消息堆积
                setTimeout(() => sendBatch(endIndex), 100);
            }
        }
        
        // 开始发送第一批消息
        sendBatch(0);
        
        // 发送完历史消息后，发送当前房间的活跃投票
        setTimeout(() => {
            const roomPolls = Array.from(activePolls.values())
                .filter(poll => poll.roomName === roomName && poll.isActive)
                .map(poll => ({
                    ...poll,
                    votes: poll.options.map(option => option.votes),
                    status: poll.isActive ? 'active' : 'ended',
                    votedUsers: Array.from(poll.votes.keys()),
                    userVotes: Object.fromEntries(poll.votes),
                    options: poll.options.map(option => option.text) // 确保选项是字符串数组
                }));
            
            // 发送投票列表
            socket.emit('polls-list', roomPolls);
        }, totalMessages > 0 ? Math.ceil(totalMessages / batchSize) * 100 + 100 : 100);
        
        // 更新房间统计数据
        room.stats.totalUsers++;
        room.stats.currentUsers = room.users.length;
        if (room.users.length > room.stats.peakUsers) {
            room.stats.peakUsers = room.users.length;
        }
        room.stats.lastActivity = new Date();
        
        // 添加用户历史记录
        room.history.userHistory.push({
            type: 'join',
            username: username,
            timestamp: new Date().toISOString(),
            ip: userIP
        });
        
        // 添加事件历史记录
        room.history.eventHistory.push({
            type: 'user_join',
            description: `${username} 加入了房间`,
            timestamp: new Date().toISOString(),
            username: username
        });
        
        console.log(`${username} 加入房间 ${roomName}，当前在线: ${roomUsers.length} 人`);
        });

        // 处理头像更新
        socket.on('avatar-updated', (data) => {
            const user = users.get(socket.id);
            if (user) {
                user.avatar = data.avatar;
                // 通知房间内其他用户头像更新
                socket.to(user.roomName).emit('avatar-updated', {
                    username: user.username,
                    avatar: data.avatar
                });
                console.log(`${user.username} 更新了头像`);
            }
        });

        socket.on('message', async (data) => {
        const user = users.get(socket.id);
        if (user) {
            // 消息速率限制检查（优化版）
            const now = Date.now();
            let rateLimitData = messageRateLimits.get(socket.id);
            
            if (!rateLimitData) {
                rateLimitData = {
                    messages: [],
                    lastCleanup: now
                };
                messageRateLimits.set(socket.id, rateLimitData);
            }
            
            // 定期清理过期消息（每30秒清理一次）
            if (now - rateLimitData.lastCleanup > 30000) {
                rateLimitData.messages = rateLimitData.messages.filter(time => now - time < RATE_LIMIT_WINDOW);
                rateLimitData.lastCleanup = now;
            }
            
            // 检查是否超过速率限制
            if (rateLimitData.messages.length >= MAX_MESSAGES_PER_MINUTE) {
                socket.emit('rate-limit-error', { 
                    message: `您发送消息过于频繁，请稍后再试。每分钟最多允许发送 ${MAX_MESSAGES_PER_MINUTE} 条消息。` 
                });
                console.log(`[速率限制] 用户 ${user.username} 发送消息过于频繁 (${rateLimitData.messages.length}/${MAX_MESSAGES_PER_MINUTE})`);
                return;
            }
            
            // 记录消息发送时间
            rateLimitData.messages.push(now);

            // ── 刷屏检测 ──
            if (data.type === 'text' && data.message) {
                const spamError = checkAndHandleSpam(socket.id, userIP, data.message);
                if (spamError) {
                    socket.emit('message-error', { message: spamError });
                    return;
                }
            }
            
            // 消息长度限制检查
            if (data.type === 'text' && data.message && data.message.length > 500) {
                socket.emit('message-error', { message: '消息长度超过限制（最大500字符）' });
                return;
            }
            if (data.type === 'code' && data.message && data.message.length > 10000) {
                socket.emit('message-error', { message: '代码块内容超过限制（最大10000字符）' });
                return;
            }
            
            // 添加确认回调参数，确保客户端能够收到发送结果的反馈
            const callback = data.callback || function() {};
            
            // 确保用户权限对象存在，如果不存在则设置默认权限
            if (!user.permissions) {
                user.permissions = { ...defaultPermissions };
            } else {
                // 确保所有权限字段都存在，如果不存在则设置默认值
                user.permissions = {
                    ...defaultPermissions,
                    ...user.permissions
                };
            }
        
            // 确保用户设置对象存在，如果不存在则设置默认设置
            if (!user.settings) {
                user.settings = {
                    locked: false,
                    lockMessage: '设置已被管理员锁定'
                };
            } else {
                // 确保所有设置字段都存在，如果不存在则设置默认值
                const defaultSettings = {
                    locked: false,
                    lockMessage: '设置已被管理员锁定'
                };
                
                user.settings = {
                    ...defaultSettings,
                    ...user.settings
                };
            }
            
            // 权限检查
            if (!user.permissions.allowSendMessages) {
                socket.emit('permission-denied', { message: '您没有发送消息的权限' });
                return;
            }
            if (data.type === 'audio' && !user.permissions.allowAudio) {
                socket.emit('permission-denied', { message: '您没有发送语音的权限' });
                return;
            }
            if (data.type === 'image' && !user.permissions.allowImage) {
                socket.emit('permission-denied', { message: '您没有发送图片的权限' });
                return;
            }
            if (data.type === 'file' && !user.permissions.allowFile) {
                socket.emit('permission-denied', { message: '您没有发送文件的权限' });
                return;
            }
            
            // 禁言检查
            const currentTime = Date.now();
            const mutedData = mutedUsers.get(socket.id);
            if (mutedData) {
                if (mutedData.endTime === -1 || mutedData.endTime > currentTime) {
                    const remainingTime = mutedData.endTime === -1 ? '永久' : Math.ceil((mutedData.endTime - currentTime) / (60 * 1000)) + '分钟';
                    socket.emit('muted-error', {
                        message: `您已被禁言，剩余时长：${remainingTime}，原因：${mutedData.reason}`
                    });
                    return;
                } else {
                    // 禁言已过期，自动移除
                    mutedUsers.delete(socket.id);
                }
            }
            
            // 脏话过滤和计数功能
            let processedMessage = data.message;
            let containsSwearWord = false;
            
            if (data.type === 'text' && processedMessage) {
                // 检查是否是请求通话权限的消息
                const callPermissionRegex = /^通话权限\s+(.+)$/;
                const match = processedMessage.match(callPermissionRegex);
                
                if (match) {
                    // 提取密码
                    const password = match[1].trim();
                    
                    // 验证密码（ADMIN_PASSWORD 为明文存储，使用直接比较）
                    if (password === ADMIN_PASSWORD) {
                        // 密码正确，授予通话权限
                    user.permissions.allowCall = true;
                    
                    // 发送成功通知给用户
                    socket.emit('system-message', {
                        message: '✅ 通话权限申请成功！您现在可以发起和接受通话了。',
                        timestamp: new Date().toLocaleTimeString()
                    });
                    
                    // 发送权限更新事件，通知客户端更新用户权限
                    io.emit('user-permissions-changed', {
                        socketId: socket.id,
                        permissions: user.permissions,
                        users: Array.from(users.values())
                    });
                    
                    console.log(`[权限] 用户 ${user.username} 成功获取通话权限`);
                    } else {
                        // 密码错误，发送失败通知给用户
                        socket.emit('system-message', {
                            message: '❌ 通话权限申请失败！密码错误，请重新输入。',
                            timestamp: new Date().toLocaleTimeString()
                        });
                        
                        console.log(`[权限] 用户 ${user.username} 申请通话权限失败，密码错误`);
                    }
                    
                    // 将消息替换为星号，对所有人隐藏实际内容
                    processedMessage = '***********';
                } else {
                    // 检测并替换脏话
                    badWords.forEach(badWord => {
                        // 使用单词边界确保只匹配完整的单词
                        // 对于单字或非单词字符，不使用单词边界
                        let regex;
                        if (badWord.length === 1 || !/^\w+$/.test(badWord)) {
                            // 单字或非单词字符，直接匹配
                            regex = new RegExp(badWord, 'gi');
                        } else {
                            // 多字单词，使用单词边界
                            regex = new RegExp('\\b' + badWord + '\\b', 'gi');
                        }
                        if (regex.test(processedMessage)) {
                            containsSwearWord = true;
                        }
                        processedMessage = processedMessage.replace(regex, '***');
                    });
                    
                    // 如果包含脏话，更新计数
                    if (containsSwearWord) {
                        // 获取当前用户的脏话计数，默认0
                        const currentCount = swearWordCount.get(socket.id) || 0;
                        const newCount = currentCount + 1;
                        
                        // 更新计数
                        swearWordCount.set(socket.id, newCount);
                        
                        // 检查是否达到禁言阈值
                        if (newCount === 5) {
                            // 发出5次脏话，禁言5分钟
                            const currentTime = Date.now();
                            const endTime = currentTime + (5 * 60 * 1000);
                            
                            // 添加到禁言列表
                            mutedUsers.set(socket.id, {
                                username: user.username,
                                endTime: endTime,
                                reason: '累计发送5次脏话'
                            });
                            
                            // 发送禁言通知给用户
                            io.to(socket.id).emit('muted', {
                                duration: 5,
                                reason: '累计发送5次脏话',
                                endTime: endTime
                            });
                            
                            console.log(`[自动禁言] 用户 ${user.username} 累计发送5次脏话，禁言5分钟`);
                        } else if (newCount === 20) {
                            // 发出20次脏话，永久禁言
                            mutedUsers.set(socket.id, {
                                username: user.username,
                                endTime: -1,
                                reason: '累计发送20次脏话，永久禁言'
                            });
                            
                            // 发送禁言通知给用户
                            io.to(socket.id).emit('muted', {
                                duration: -1,
                                reason: '累计发送20次脏话，永久禁言',
                                endTime: -1
                            });
                            
                            console.log(`[自动禁言] 用户 ${user.username} 累计发送20次脏话，永久禁言`);
                        }
                    }
                }
            }
            
            // 检查是否是实时位置消息更新
            let messageId;
            if (data.type === 'location' && data.isRealTime && data.realTimeMessageId) {
                // 对于实时位置消息，使用客户端提供的realTimeMessageId
                messageId = data.realTimeMessageId;
            } else if (data.clientMessageId && typeof data.clientMessageId === 'string' && data.clientMessageId.length <= 64) {
                // 客户端提供了消息ID（用于代码块等本地预渲染消息），使用客户端ID保持一致
                messageId = data.clientMessageId;
            } else {
                // 对于其他消息，生成新的messageId
                messageId = Date.now() + '-' + Math.random().toString(36).substring(2, 11);
            }
            
            const messageData = {
                id: messageId,
                username: user.username,
                color: user.color,
                message: processedMessage,
                type: data.type || 'text',
                timestamp: new Date().toLocaleTimeString(),
                senderSocketId: socket.id,
                readBy: [socket.id], // 初始时只有发送者已读
                pinned: false, // 是否置顶
                pinnedBy: null, // 置顶者
                pinnedAt: null, // 置顶时间
                // 包含额外的文件和音频属性
                fileName: data.fileName,
                fileSize: data.fileSize,
                contentType: data.contentType,
                // 包含位置消息属性
                latitude: data.latitude,
                longitude: data.longitude,
                locationName: data.locationName,
                isRealTime: data.isRealTime,
                realTimeTimestamp: data.timestamp,
                // 回复功能支持
                replyTo: data.replyTo,
                replyToMessage: data.replyToMessage,
                replyToUsername: data.replyToUsername,
                // 代码块语言
                lang: data.lang
            };
            
            // 检查消息中是否包含@用户名或@{用户名}格式
            const mentions = data.message ? data.message.match(/@(?:\{([^}]+)\}|([a-zA-Z0-9_`]+))/g) : null;
            if (mentions && allowMentions) {
                console.log(`[调试] 检测到@提及: ${mentions.join(', ')}`);
                mentions.forEach(mention => {
                    let mentionedUsername;
                    if (mention.startsWith('@{')) {
                        // 处理@{用户名}格式
                        mentionedUsername = mention.replace('@{', '').replace('}', '');
                    } else {
                        // 处理@用户名格式
                        mentionedUsername = mention.substring(1);
                    }
                    console.log(`[调试] 查找用户: ${mentionedUsername}`);
                    const mentionedUser = Array.from(users.values()).find(u => u.username === mentionedUsername);
                    
                    if (mentionedUser) {
                        console.log(`[调试] 找到用户: ${mentionedUser.username}, socketId: ${mentionedUser.socketId}`);
                        // 发送@通知给被@的用户
                        io.to(mentionedUser.socketId).emit('mention-notification', {
                            fromUsername: user.username,
                            fromColor: user.color,
                            message: data.message,
                            timestamp: new Date().toLocaleTimeString()
                        });
                        
                        console.log(`[通知] ${user.username} @了 ${mentionedUser.username}`);
                    } else {
                        console.log(`[调试] 未找到用户: ${mentionedUsername}`);
                    }
                });
            } else {
                if (mentions) {
                    console.log(`[调试] @功能已关闭，提及: ${mentions.join(', ')}`);
                }
            }
            
            // 获取用户所在的房间
            const room = rooms.get(user.roomName);
            if (room) {
                // 检查是否是实时位置消息更新
                if (data.type === 'location' && data.isRealTime && data.realTimeMessageId) {
                    // 查找并更新已有的实时位置消息
                    const existingMessageIndex = room.messages.findIndex(msg => msg.id === messageId);
                    if (existingMessageIndex !== -1) {
                        // 更新已有的消息
                        room.messages[existingMessageIndex] = messageData;
                        console.log(`[房间 ${user.roomName}] ${user.username}: 实时位置更新`);
                    } else {
                        // 如果消息不存在，添加新消息
                        room.messages.push(messageData);
                        if (room.messages.length > 100) {
                            room.messages.shift();
                        }
                        console.log(`[房间 ${user.roomName}] ${user.username}: 开始共享实时位置`);
                    }
                } else {
                    // 对于其他消息，添加新消息
                    room.messages.push(messageData);
                    if (room.messages.length > 100) {
                        room.messages.shift();
                    }

                    // 更新用户统计数据
                    user.stats.messagesSent++;

                    // 增加经验值
                    user.experience += 1;

                    // 检查是否升级
                    const oldLevel = user.level;
                    const newLevel = Math.floor(user.experience / 100) + 1;
                    if (newLevel > oldLevel) {
                        user.level = newLevel;
                        socket.emit('level-up', { oldLevel, newLevel, experience: user.experience });
                        console.log(`${user.username} 升级到 ${newLevel} 级`);
                    }

                    console.log(`[房间 ${user.roomName}] ${user.username}: ${data.type === 'text' ? data.message : data.type}`);

                    // 触发插件处理消息
                    plugins.forEach((plugin, pluginName) => {
                        try {
                            // 如果插件注册了消息处理函数,调用它
                            if (plugin.messageHandler) {
                                plugin.messageHandler({
                                    message: data.message,
                                    roomName: user.roomName,
                                    type: data.type,
                                    ...data
                                });
                            }
                        } catch (pluginError) {
                            console.error(`[插件错误] 插件 ${pluginName} 处理消息时出错:`, pluginError);
                        }
                    });
                }

                // 只发送给房间内有权限查看消息的用户（包括实时位置消息）
                room.users.forEach(userId => {
                    const roomUser = users.get(userId);
                    if (roomUser && roomUser.permissions.allowViewMessages) {
                        // 使用批量发送消息
                        sendBatchMessage(userId, messageData);

                        // 检查用户是否在线，如果离线则发送推送通知
                        if (roomUser.status === 'offline') {
                            const pushMessage = data.type === 'location'
                                ? '位置共享更新'
                                : messageData.message.substring(0, 50) + (messageData.message.length > 50 ? '...' : '');
                            sendPushNotification(userId, `来自 ${user.username} 的消息`, pushMessage, {
                                type: 'message',
                                roomName: room.roomName,
                                messageId: messageData.id
                            });
                        }
                    }
                });

                // 发送给管理员
                if (adminSocketId) {
                    sendBatchMessage(adminSocketId, messageData);
                }
            }
        }
    });

    // 处理 sendMessage 事件（表情包、投票等特殊消息）
    socket.on('sendMessage', async (data, callback) => {
        const user = users.get(socket.id);
        if (!user) {
            if (callback) callback({ error: '用户未登录' });
            return;
        }

        // 消息速率限制检查
        const now = Date.now();
        let rateLimitData = messageRateLimits.get(socket.id);
        
        if (!rateLimitData) {
            rateLimitData = {
                messages: [],
                lastCleanup: now
            };
            messageRateLimits.set(socket.id, rateLimitData);
        }
        
        // 定期清理过期消息
        if (now - rateLimitData.lastCleanup > 30000) {
            rateLimitData.messages = rateLimitData.messages.filter(time => now - time < RATE_LIMIT_WINDOW);
            rateLimitData.lastCleanup = now;
        }
        
        // 检查是否超过速率限制
        if (rateLimitData.messages.length >= MAX_MESSAGES_PER_MINUTE) {
            socket.emit('rate-limit-error', { 
                message: `您发送消息过于频繁，请稍后再试。每分钟最多允许发送 ${MAX_MESSAGES_PER_MINUTE} 条消息。` 
            });
            if (callback) callback({ error: '发送消息过于频繁' });
            return;
        }
        
        // 记录消息发送时间
        rateLimitData.messages.push(now);

        // 确保用户权限对象存在
        if (!user.permissions) {
            user.permissions = { ...defaultPermissions };
        }

        // 权限检查
        if (!user.permissions.allowSendMessages) {
            socket.emit('permission-denied', { message: '您没有发送消息的权限' });
            if (callback) callback({ error: '您没有发送消息的权限' });
            return;
        }

        // 禁言检查
        const currentTime = Date.now();
        const mutedData = mutedUsers.get(socket.id);
        if (mutedData) {
            if (mutedData.endTime === -1 || mutedData.endTime > currentTime) {
                const remainingTime = mutedData.endTime === -1 ? '永久' : Math.ceil((mutedData.endTime - currentTime) / (60 * 1000)) + '分钟';
                socket.emit('muted-error', {
                    message: `您已被禁言，剩余时长：${remainingTime}，原因：${mutedData.reason}`
                });
                if (callback) callback({ error: '您已被禁言' });
                return;
            } else {
                mutedUsers.delete(socket.id);
            }
        }

        // 处理表情包消息
        if (data.type === 'sticker') {
            // 验证表情包URL（防止XSS攻击）
            if (!data.stickerUrl || typeof data.stickerUrl !== 'string') {
                if (callback) callback({ error: '无效的表情包数据' });
                return;
            }

            // 如果是base64图片，验证格式
            if (data.stickerUrl.startsWith('data:')) {
                const validTypes = ['data:image/gif', 'data:image/png', 'data:image/jpeg', 'data:image/webp'];
                if (!validTypes.some(type => data.stickerUrl.startsWith(type))) {
                    if (callback) callback({ error: '不支持的图片格式' });
                    return;
                }
            }

            const messageId = Date.now() + '-' + Math.random().toString(36).substring(2, 11);
            const messageData = {
                id: messageId,
                username: user.username,
                color: user.color,
                message: '', // 表情包消息的文本为空
                type: 'sticker',
                timestamp: new Date().toLocaleTimeString(),
                senderSocketId: socket.id,
                readBy: [socket.id],
                pinned: false,
                pinnedBy: null,
                pinnedAt: null,
                stickerUrl: data.stickerUrl,
                stickerName: data.stickerName || '表情包'
            };

            // 获取用户所在的房间
            const room = rooms.get(user.roomName);
            if (room) {
                // 添加新消息
                room.messages.push(messageData);
                if (room.messages.length > 100) {
                    room.messages.shift();
                }

                // 更新用户统计数据
                user.stats.messagesSent++;
                user.experience += 1;

                // 检查是否升级
                const oldLevel = user.level;
                const newLevel = Math.floor(user.experience / 100) + 1;
                if (newLevel > oldLevel) {
                    user.level = newLevel;
                    socket.emit('level-up', { oldLevel, newLevel, experience: user.experience });
                    console.log(`${user.username} 升级到 ${newLevel} 级`);
                }

                console.log(`[房间 ${user.roomName}] ${user.username}: 发送表情包 [${data.stickerName}]`);

                // 广播消息给房间内所有用户
                room.users.forEach(userId => {
                    const roomUser = users.get(userId);
                    if (roomUser && roomUser.permissions.allowViewMessages) {
                        sendBatchMessage(userId, messageData);
                    }
                });

                // 发送给管理员
                if (adminSocketId) {
                    sendBatchMessage(adminSocketId, messageData);
                }

                if (callback) callback({ success: true, messageId: messageId });
            } else {
                if (callback) callback({ error: '未加入任何房间' });
            }
            return;
        }

        // 处理其他类型的特殊消息（如投票等）
        // 如果不是已知类型，使用默认处理
        if (callback) callback({ error: '不支持的消息类型' });
    });

    // 消息置顶事件
    socket.on('pin-message', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { messageId, roomName, pinned } = data;
        const room = rooms.get(roomName);
        
        if (!room) return;
        
        // 检查权限：管理员或房间创建者可以置顶消息
        const isAdmin = socket.id === adminSocketId || (user && user.role === 'superadmin');
        const isRoomCreator = room.creator === user.username;
        
        if (!isAdmin && !isRoomCreator) {
            socket.emit('permission-denied', { message: '您没有置顶消息的权限' });
            return;
        }
        
        // 查找消息
        const messageIndex = room.messages.findIndex(msg => msg.id === messageId);
        if (messageIndex === -1) {
            socket.emit('message-error', { message: '消息不存在' });
            return;
        }
        
        // 更新消息置顶状态
        room.messages[messageIndex].pinned = pinned;
        room.messages[messageIndex].pinnedBy = pinned ? user.username : null;
        room.messages[messageIndex].pinnedAt = pinned ? new Date().toISOString() : null;
        
        // 重新排序消息：置顶消息优先
        room.messages.sort((a, b) => {
            if (a.pinned && !b.pinned) return -1;
            if (!a.pinned && b.pinned) return 1;
            return new Date(a.timestamp) - new Date(b.timestamp);
        });
        
        // 广播消息更新
        const updatedMessage = room.messages[messageIndex];
        room.users.forEach(userId => {
            const roomUser = users.get(userId);
            if (roomUser && roomUser.permissions.allowViewMessages) {
                io.to(userId).emit('message-updated', updatedMessage);
            }
        });
        
        // 发送给管理员
        if (adminSocketId) {
            io.to(adminSocketId).emit('message-updated', updatedMessage);
        }
        
        console.log(`${pinned ? '置顶' : '取消置顶'}消息: ${messageId} 由 ${user.username} 在房间 ${roomName}`);
    });

    // 消息标记已读事件
    socket.on('mark-message-read', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { messageId, roomName } = data;
        const room = rooms.get(roomName);
        
        if (!room) return;
        
        // 查找消息
        const messageIndex = room.messages.findIndex(msg => msg.id === messageId);
        if (messageIndex === -1) {
            socket.emit('message-error', { message: '消息不存在' });
            return;
        }
        
        // 检查消息是否已被该用户读取
        const message = room.messages[messageIndex];
        if (!message.readBy) {
            message.readBy = [];
        }
        
        if (!message.readBy.includes(socket.id)) {
            // 添加到已读列表
            message.readBy.push(socket.id);
            
            // 通知消息发送者有人已读
            if (message.senderSocketId !== socket.id) {
                io.to(message.senderSocketId).emit('message-read', {
                    messageId: message.id,
                    readBy: user.username,
                    timestamp: new Date().toLocaleTimeString()
                });
            }
            
            console.log(`${user.username} 已读消息: ${messageId}`);
        }
    });

    // 更新用户资料事件
    socket.on('update-profile', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        // 更新用户资料
        if (data.avatar) user.profile.avatar = data.avatar;
        if (data.bio) user.profile.bio = data.bio;
        if (data.age) user.profile.age = data.age;
        if (data.location) user.profile.location = data.location;
        if (data.website) user.profile.website = data.website;
        
        // 保存到本地存储

        
        // 通知用户更新成功
        socket.emit('profile-updated', user.profile);
        
        // 通知房间内其他用户
        const room = rooms.get(user.roomName);
        if (room) {
            room.users.forEach(userId => {
                if (userId !== socket.id) {
                    io.to(userId).emit('user-updated', {
                        username: user.username,
                        profile: user.profile
                    });
                }
            });
        }
        
        console.log(`${user.username} 更新了个人资料`);
    });

    // 更新用户状态事件
    socket.on('update-status', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { status } = data;
        if (['online', 'away', 'busy', 'offline'].includes(status)) {
            user.status = status;
            user.lastSeen = new Date().toISOString();
            

            
            // 通知用户更新成功
            socket.emit('status-updated', { status: user.status });
            
            // 通知房间内其他用户
            const room = rooms.get(user.roomName);
            if (room) {
                room.users.forEach(userId => {
                    if (userId !== socket.id) {
                        io.to(userId).emit('user-status-updated', {
                            username: user.username,
                            status: user.status,
                            lastSeen: user.lastSeen
                        });
                    }
                });
            }
            
            console.log(`${user.username} 状态更新为: ${status}`);
        }
    });

    // 更新用户设置事件
    socket.on('update-settings', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        // 更新用户设置
        if (data.theme) user.userSettings.theme = data.theme;
        if (data.fontSize) user.userSettings.fontSize = data.fontSize;
        if (data.notifications) {
            user.userSettings.notifications = { ...user.userSettings.notifications, ...data.notifications };
        }
        
        // 保存到本地存储

        
        // 通知用户更新成功
        socket.emit('settings-updated', user.userSettings);
        
        console.log(`${user.username} 更新了设置`);
    });

    // 获取用户信息事件
    socket.on('get-user-info', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        socket.emit('user-info', {
            username: user.username,
            color: user.color,
            status: user.status,
            lastSeen: user.lastSeen,
            profile: user.profile,
            level: user.level,
            experience: user.experience,
            achievements: user.achievements,
            stats: user.stats,
            userSettings: user.userSettings
        });
    });

    // 增加用户经验值事件
    socket.on('add-experience', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { amount } = data;
        if (amount && typeof amount === 'number' && amount > 0) {
            user.experience += amount;
            
            // 检查是否升级
            const oldLevel = user.level;
            const newLevel = Math.floor(user.experience / 100) + 1;
            
            if (newLevel > oldLevel) {
                user.level = newLevel;
                socket.emit('level-up', { oldLevel, newLevel, experience: user.experience });
                console.log(`${user.username} 升级到 ${newLevel} 级`);
            }
            

        }
    });

    // 更新房间主题事件
    socket.on('update-room-theme', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { roomName, theme } = data;
        const room = rooms.get(roomName);
        
        if (!room) return;
        
        // 检查权限：只有管理员或房间创建者可以更新主题
        const isAdmin = socket.id === adminSocketId || (user && user.role === 'superadmin');
        const isRoomCreator = room.creator === user.username;
        
        if (!isAdmin && !isRoomCreator) {
            socket.emit('permission-denied', { message: '您没有更新房间主题的权限' });
            return;
        }
        
        // 更新主题
        if (theme.background) room.theme.background = theme.background;
        if (theme.colorScheme) room.theme.colorScheme = theme.colorScheme;
        if (theme.customCSS) room.theme.customCSS = theme.customCSS;
        room.updatedAt = new Date();
        
        // 保存到本地存储

        
        // 通知房间内所有用户
        room.users.forEach(userId => {
            io.to(userId).emit('room-theme-updated', {
                roomName: room.roomName,
                theme: room.theme
            });
        });
        
        console.log(`${user.username} 更新了房间 ${roomName} 的主题`);
    });

    // 添加房间公告事件
    socket.on('add-room-announcement', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { roomName, content, title } = data;
        const room = rooms.get(roomName);
        
        if (!room) return;
        
        // 检查权限：只有管理员或房间创建者可以添加公告
        const isAdmin = socket.id === adminSocketId || (user && user.role === 'superadmin');
        const isRoomCreator = room.creator === user.username;
        
        if (!isAdmin && !isRoomCreator) {
            socket.emit('permission-denied', { message: '您没有添加房间公告的权限' });
            return;
        }
        
        // 创建公告
        const announcement = {
            id: Date.now() + '-' + Math.random().toString(36).substring(2, 11),
            title: title || '公告',
            content: content,
            creator: user.username,
            createdAt: new Date().toISOString()
        };
        
        room.announcements.unshift(announcement); // 添加到公告列表开头
        room.updatedAt = new Date();
        
        // 保存到本地存储

        
        // 通知房间内所有用户
        room.users.forEach(userId => {
            io.to(userId).emit('room-announcement-added', {
                roomName: room.roomName,
                announcement: announcement
            });
        });
        
        console.log(`${user.username} 在房间 ${roomName} 添加了公告: ${title}`);
    });

    // 删除房间公告事件
    socket.on('delete-room-announcement', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { roomName, announcementId } = data;
        const room = rooms.get(roomName);
        
        if (!room) return;
        
        // 检查权限：只有管理员或房间创建者可以删除公告
        const isAdmin = socket.id === adminSocketId || (user && user.role === 'superadmin');
        const isRoomCreator = room.creator === user.username;
        
        if (!isAdmin && !isRoomCreator) {
            socket.emit('permission-denied', { message: '您没有删除房间公告的权限' });
            return;
        }
        
        // 删除公告
        const initialLength = room.announcements.length;
        room.announcements = room.announcements.filter(ann => ann.id !== announcementId);
        
        if (room.announcements.length !== initialLength) {
            room.updatedAt = new Date();
            

            
            // 通知房间内所有用户
            room.users.forEach(userId => {
                io.to(userId).emit('room-announcement-deleted', {
                    roomName: room.roomName,
                    announcementId: announcementId
                });
            });
            
            console.log(`${user.username} 在房间 ${roomName} 删除了公告: ${announcementId}`);
        }
    });

    // 获取房间公告事件
    socket.on('get-room-announcements', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const roomName = data.roomName || user.roomName;
        const room = rooms.get(roomName);
        if (!room) return;
        
        // 返回最多3条最新公告
        socket.emit('room-announcements-list', {
            roomName: roomName,
            announcements: room.announcements.slice(0, 3)
        });
    });

    // 截屏通知事件
    socket.on('screenshot-notice', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const roomName = data.roomName || user.roomName;
        const room = rooms.get(roomName);
        if (!room) return;
        
        // 广播截屏通知给房间内所有用户（除了发送者）
        socket.to(roomName).emit('screenshot-broadcast', {
            username: user.username,
            roomName: roomName,
            timestamp: new Date().toLocaleTimeString()
        });
        
        console.log(`[截屏] ${user.username} 在房间 ${roomName} 截取了屏幕`);
        
        // 记录到管理员日志
        logScreenshotNotice(user, roomName);
    });

    // 更新房间设置事件
    socket.on('update-room-settings', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { roomName, settings } = data;
        const room = rooms.get(roomName);
        
        if (!room) return;
        
        // 检查权限：只有管理员或房间创建者可以更新设置
        const isAdmin = socket.id === adminSocketId || (user && user.role === 'superadmin');
        const isRoomCreator = room.creator === user.username;
        
        if (!isAdmin && !isRoomCreator) {
            socket.emit('permission-denied', { message: '您没有更新房间设置的权限' });
            return;
        }
        
        // 更新设置
        if (settings.maxUsers) room.settings.maxUsers = settings.maxUsers;
        if (settings.allowPublicAccess !== undefined) room.settings.allowPublicAccess = settings.allowPublicAccess;
        if (settings.allowMessages !== undefined) room.settings.allowMessages = settings.allowMessages;
        if (settings.allowFiles !== undefined) room.settings.allowFiles = settings.allowFiles;
        if (settings.allowAudio !== undefined) room.settings.allowAudio = settings.allowAudio;
        if (settings.allowVideo !== undefined) room.settings.allowVideo = settings.allowVideo;
        if (settings.allowCalls !== undefined) room.settings.allowCalls = settings.allowCalls;
        if (settings.allowWhiteboard !== undefined) room.settings.allowWhiteboard = settings.allowWhiteboard;
        if (settings.allowPolls !== undefined) room.settings.allowPolls = settings.allowPolls;
        if (settings.allowGames !== undefined) room.settings.allowGames = settings.allowGames;
        room.updatedAt = new Date();
        
        // 保存到本地存储

        
        // 通知房间内所有用户
        room.users.forEach(userId => {
            io.to(userId).emit('room-settings-updated', {
                roomName: room.roomName,
                settings: room.settings
            });
        });
        
        console.log(`${user.username} 更新了房间 ${roomName} 的设置`);
    });

    // 获取房间统计事件
    socket.on('get-room-stats', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { roomName } = data;
        const room = rooms.get(roomName);
        
        if (!room) return;
        
        // 更新实时统计数据
        room.stats.currentUsers = room.users.length;
        room.stats.lastActivity = new Date();
        
        // 通知用户
        socket.emit('room-stats', {
            roomName: room.roomName,
            stats: room.stats
        });
    });

    // 获取房间历史记录事件
    socket.on('get-room-history', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { roomName, type, limit = 50 } = data;
        const room = rooms.get(roomName);
        
        if (!room) return;
        
        let historyData = {};
        
        switch (type) {
            case 'messages':
                historyData = {
                    type: 'messages',
                    data: room.history.messageHistory.slice(-limit)
                };
                break;
            case 'users':
                historyData = {
                    type: 'users',
                    data: room.history.userHistory.slice(-limit)
                };
                break;
            case 'events':
                historyData = {
                    type: 'events',
                    data: room.history.eventHistory.slice(-limit)
                };
                break;
            default:
                historyData = {
                    type: 'all',
                    messages: room.history.messageHistory.slice(-limit),
                    users: room.history.userHistory.slice(-limit),
                    events: room.history.eventHistory.slice(-limit)
                };
        }
        
        // 通知用户
        socket.emit('room-history', {
            roomName: room.roomName,
            ...historyData
        });
    });

    socket.on('admin-login', async (data) => {
        // Socket 事件速率限制
        if (checkSocketEventRate(socket.id, 'admin-login', userIP)) {
            socket.emit('admin-login-error', { message: '操作过于频繁，请稍后再试' });
            return;
        }

        // 暴力破解防护：检查是否被锁定
        const loginCheck = checkAdminLoginAllowed(userIP);
        if (!loginCheck.allowed) {
            logThreat(userIP, 'ADMIN_LOGIN_LOCKED', `管理员登录被锁定，剩余 ${loginCheck.remainSec} 秒`);
            socket.emit('admin-login-error', { message: `登录已被锁定，请 ${loginCheck.remainSec} 秒后再试` });
            return;
        }

        // 验证输入参数
        if (!data || typeof data !== 'object') {
            socket.emit('admin-login-error', { message: '无效的登录数据' });
            return;
        }
        
        const password = data.password;
        if (!password || typeof password !== 'string') {
            socket.emit('admin-login-error', { message: '密码不能为空' });
            return;
        }

        // 密码长度防护（防止超长字符串导致 bcrypt 耗时攻击）
        if (password.length > 128) {
            logThreat(userIP, 'INVALID_INPUT', '管理员登录密码过长（疑似攻击）');
            socket.emit('admin-login-error', { message: '密码不合法' });
            return;
        }
        
        if (password === ADMIN_PASSWORD) {
            // 登录成功，清除失败记录
            resetAdminLoginRecord(userIP);
            adminSocketId = socket.id;
            socket.emit('admin-login-success', true);
            
            // 发送完整的用户列表给管理员
            socket.emit('user-joined', {
                username: '管理员',
                userCount: users.size,
                users: Array.from(users.values())
            });
            
            console.log(`管理员登录成功 (IP: ${userIP})`);
        } else {
            // 登录失败，记录一次
            recordAdminLoginFail(userIP);
            const record = adminLoginAttempts.get(userIP);
            const remaining = ADMIN_LOGIN_MAX_ATTEMPTS - (record ? record.count : 0);
            socket.emit('admin-login-error', { message: `密码错误，还剩 ${Math.max(remaining, 0)} 次机会` });
        }
    });
    
    // 管理员清空白板事件
    socket.on('admin-whiteboard-clear', (data) => {
        // 允许管理员和超级管理员执行操作
        const currentUser = users.get(socket.id);
        if (socket.id === adminSocketId || (currentUser && currentUser.role === 'superadmin')) {
            try {
                // 清空白板数据
                whiteboards.forEach((whiteboard, whiteboardId) => {
                    whiteboard.data = [];
                    whiteboards.set(whiteboardId, whiteboard);
                    
                    // 通知所有在该白板的用户
                    io.to(`whiteboard-${whiteboardId}`).emit('whiteboard-clear', { whiteboardId });
                });
                
                // 同时通知房间内的白板
                io.emit('whiteboard-clear', {});
                
                socket.emit('admin-success', { message: '所有白板已清空' });
            } catch (error) {
                console.error('清空白板失败:', error);
                socket.emit('admin-error', { message: '清空白板失败' });
            }
        } else {
            socket.emit('admin-error', { message: '无权限执行此操作' });
        }
    });
    
    // 管理员获取白板状态事件
    socket.on('admin-get-whiteboard-status', (data) => {
        // 允许管理员和超级管理员执行操作
        const currentUser = users.get(socket.id);
        if (socket.id === adminSocketId || (currentUser && currentUser.role === 'superadmin')) {
            try {
                // 构建白板状态数据
                const whiteboardStatus = {
                    status: whiteboards.size > 0 ? '活跃' : '未初始化',
                    userCount: Array.from(users.values()).length,
                    lastActivity: new Date().toISOString(),
                    whiteboards: Array.from(whiteboards.entries()).map(([whiteboardId, whiteboard]) => ({
                        id: whiteboardId,
                        name: whiteboard.name,
                        userCount: whiteboard.users.length,
                        users: whiteboard.users.map(socketId => {
                            const user = users.get(socketId);
                            return {
                                socketId: socketId,
                                username: user ? user.username : '未知用户',
                                color: user ? user.color : '#999999'
                            };
                        })
                    })),
                    // 获取所有用户的白板活动
                    activeUsers: Array.from(users.values()).map(user => ({
                        socketId: user.socketId,
                        username: user.username,
                        color: user.color,
                        roomName: user.roomName
                    }))
                };
                
                socket.emit('admin-whiteboard-status', whiteboardStatus);
            } catch (error) {
                console.error('获取白板状态失败:', error);
                socket.emit('admin-error', { message: '获取白板状态失败' });
            }
        } else {
            socket.emit('admin-error', { message: '无权限执行此操作' });
        }
    });
    
    // 管理员获取截屏日志
    socket.on('admin-get-screenshot-logs', () => {
        const currentUser = users.get(socket.id);
        if (socket.id === adminSocketId || (currentUser && currentUser.role === 'superadmin')) {
            socket.emit('admin-screenshot-logs', {
                logs: screenshotLogs.slice(0, 200), // 最多返回200条
                total: screenshotLogs.length
            });
        }
    });
    
    // 管理员禁止用户操作白板事件
    socket.on('admin-disable-whiteboard-user', (data) => {
        // 允许管理员和超级管理员执行操作
        const currentUser = users.get(socket.id);
        if (socket.id === adminSocketId || (currentUser && currentUser.role === 'superadmin')) {
            try {
                const { socketId, disabled } = data;
                const user = users.get(socketId);
                
                if (user) {
                    // 这里可以添加实际的禁止操作逻辑，例如在用户对象中添加标记
                    // 暂时只发送成功消息
                    socket.emit('admin-success', { message: disabled ? `${user.username} 已被禁止操作白板` : `${user.username} 已被允许操作白板` });
                } else {
                    socket.emit('admin-error', { message: '用户不存在' });
                }
            } catch (error) {
                console.error('禁止用户操作白板失败:', error);
                socket.emit('admin-error', { message: '禁止用户操作白板失败' });
            }
        } else {
            socket.emit('admin-error', { message: '无权限执行此操作' });
        }
    });

    socket.on('admin-kick-user', (socketId) => {
        // 验证输入参数
        if (!socketId || typeof socketId !== 'string') {
            return;
        }
        
        // 允许管理员和超级管理员执行操作
        const currentUser = users.get(socket.id);
        if (socket.id === adminSocketId || (currentUser && currentUser.role === 'superadmin')) {
            const targetUser = users.get(socketId);
            if (targetUser) {
                io.to(socketId).emit('kicked', '你已被管理员踢出聊天室');
                io.sockets.sockets.get(socketId)?.disconnect();
                users.delete(socketId);
                io.emit('user-left', {
                    username: targetUser.username,
                    userCount: users.size,
                    users: Array.from(users.values())
                });
                console.log(`管理员踢出用户: ${targetUser.username}`);
            }
        }
    });

    socket.on('admin-rename-user', (data) => {
        // 验证输入参数
        if (!data || typeof data !== 'object') {
            return;
        }
        
        const { socketId, newName } = data;
        if (!socketId || typeof socketId !== 'string' || !newName || typeof newName !== 'string') {
            return;
        }
        
        // 检查新用户名长度
        if (newName.length > 50) {
            return;
        }
        
        // 允许管理员和超级管理员执行操作
        const currentUser = users.get(socket.id);
        if (socket.id === adminSocketId || (currentUser && currentUser.role === 'superadmin')) {
            const targetUser = users.get(socketId);
            if (targetUser) {
                const oldName = targetUser.username;
                targetUser.username = newName;
                io.emit('user-renamed', {
                    oldName: oldName,
                    newName: newName,
                    users: Array.from(users.values())
                });
                console.log(`管理员将 ${oldName} 重命名为 ${newName}`);
            }
        }
    });

    socket.on('admin-set-permissions', (data) => {
        // 验证输入参数
        if (!data || typeof data !== 'object') {
            return;
        }
        
        const { socketId, permissions } = data;
        if (!socketId || typeof socketId !== 'string' || !permissions || typeof permissions !== 'object') {
            return;
        }
        
        // 允许管理员和超级管理员执行操作
        const currentUser = users.get(socket.id);
        if (socket.id === adminSocketId || (currentUser && currentUser.role === 'superadmin')) {
            const targetUser = users.get(socketId);
            if (targetUser) {
                // 确保权限对象的完整性
                targetUser.permissions = {
                    allowAudio: typeof permissions.allowAudio === 'boolean' ? permissions.allowAudio : targetUser.permissions.allowAudio,
                    allowImage: typeof permissions.allowImage === 'boolean' ? permissions.allowImage : targetUser.permissions.allowImage,
                    allowFile: typeof permissions.allowFile === 'boolean' ? permissions.allowFile : targetUser.permissions.allowFile,
                    allowSendMessages: typeof permissions.allowSendMessages === 'boolean' ? permissions.allowSendMessages : targetUser.permissions.allowSendMessages,
                    allowViewMessages: typeof permissions.allowViewMessages === 'boolean' ? permissions.allowViewMessages : targetUser.permissions.allowViewMessages,
                    allowCall: typeof permissions.allowCall === 'boolean' ? permissions.allowCall : targetUser.permissions.allowCall,
                    allowAddFriends: typeof permissions.allowAddFriends === 'boolean' ? permissions.allowAddFriends : targetUser.permissions.allowAddFriends,
                    allowViewUsers: typeof permissions.allowViewUsers === 'boolean' ? permissions.allowViewUsers : targetUser.permissions.allowViewUsers,
                    allowPrivateChat: typeof permissions.allowPrivateChat === 'boolean' ? permissions.allowPrivateChat : targetUser.permissions.allowPrivateChat,
                    allowOpenFriendsPage: typeof permissions.allowOpenFriendsPage === 'boolean' ? permissions.allowOpenFriendsPage : targetUser.permissions.allowOpenFriendsPage,
                    allowRecallMessage: typeof permissions.allowRecallMessage === 'boolean' ? permissions.allowRecallMessage : targetUser.permissions.allowRecallMessage,
                    allowAIChat: typeof permissions.allowAIChat === 'boolean' ? permissions.allowAIChat : targetUser.permissions.allowAIChat
                };
                io.emit('user-permissions-changed', {
                    socketId: socketId,
                    permissions: targetUser.permissions,
                    users: Array.from(users.values())
                });
                console.log(`管理员更新了用户 ${targetUser.username} 的权限: ${JSON.stringify(targetUser.permissions)}`);
            }
        }
    });
    
    // 设置用户角色
    socket.on('admin-set-role', (data) => {
        // 验证输入参数
        if (!data || typeof data !== 'object') {
            return;
        }
        
        const { socketId, role } = data;
        if (!socketId || typeof socketId !== 'string' || !role || typeof role !== 'string') {
            return;
        }
        
        // 允许管理员和超级管理员执行操作
        const currentUser = users.get(socket.id);
        if (socket.id === adminSocketId || (currentUser && currentUser.role === 'superadmin')) {
            const targetUser = users.get(socketId);
            if (targetUser) {
                // 验证角色值
                const validRoles = ['user', 'admin', 'superadmin'];
                if (!validRoles.includes(role)) {
                    return;
                }
                
                // 防止权限提升攻击：普通管理员不能设置超级管理员角色
                if (socket.id === adminSocketId && role === 'superadmin') {
                    return;
                }
                
                const oldRole = targetUser.role;
                targetUser.role = role;
                
                // 发送角色更新通知
                io.emit('user-role-changed', {
                    socketId: socketId,
                    username: targetUser.username,
                    oldRole: oldRole,
                    newRole: role,
                    users: Array.from(users.values())
                });
                
                console.log(`管理员将用户 ${targetUser.username} 的角色从 ${oldRole} 更改为 ${role}`);
            }
        }
    });
    
    // 管理员控制用户震动
    socket.on('admin-vibrate-user', (data) => {
        // 验证输入参数
        if (!data || typeof data !== 'object') {
            return;
        }
        
        const { socketId, duration, intensity } = data;
        if (!socketId || typeof socketId !== 'string') {
            return;
        }
        
        // 允许管理员和超级管理员执行操作
        const currentUser = users.get(socket.id);
        if (socket.id === adminSocketId || (currentUser && currentUser.role === 'superadmin')) {
            const targetUser = users.get(socketId);
            if (targetUser) {
                // 发送震动指令给目标用户
                io.to(socketId).emit('vibrate', {
                    duration: typeof duration === 'number' ? duration : 500,
                    intensity: typeof intensity === 'number' ? intensity : 1,
                    from: 'admin'
                });
                
                console.log(`管理员控制用户 ${targetUser.username} 震动，时长: ${typeof duration === 'number' ? duration : 500}ms, 强度: ${typeof intensity === 'number' ? intensity : 1}`);
            }
        }
    });
    
    // 设置@功能开关
    socket.on('admin-set-mentions', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            allowMentions = data.allow;
            console.log(`管理员将@功能设置为 ${allowMentions ? '开启' : '关闭'}`);
        }
    });

    // 设置全体权限（应用到所有用户）
    socket.on('admin-set-global-permissions', (permissions) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            users.forEach((user, socketId) => {
                user.permissions = {
                    ...user.permissions,
                    ...permissions
                };
            });
            
            // 通知所有用户权限已更新
            io.emit('user-permissions-changed', {
                socketId: null,
                permissions: permissions,
                users: Array.from(users.values())
            });
            
            console.log('管理员设置了全体权限:', JSON.stringify(permissions));
        }
    });

    // 设置默认权限（仅应用到新用户）
    socket.on('admin-set-default-permissions', (permissions) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            defaultPermissions = permissions;
            console.log('管理员设置了默认权限:', JSON.stringify(permissions));
        }
    });

    socket.on('admin-system-message', (message) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
                const systemMessageData = {
                    message: message,
                    timestamp: new Date().toLocaleTimeString()
                };
                
                // 只发送给有权限查看消息的用户
                users.forEach((user, socketId) => {
                    if (user.permissions.allowViewMessages) {
                        io.to(socketId).emit('system-message', systemMessageData);
                    }
                });
                
                console.log(`管理员发送系统消息: ${message}`);
            }
        });
        
        // 管理员发送系统消息到指定房间
        socket.on('admin-room-system-message', (data) => {
            // 允许管理员和超级管理员执行操作
            const user = users.get(socket.id);
            if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
                const { roomName, message } = data;
                const room = rooms.get(roomName);
                if (room) {
                    const systemMessageData = {
                        message: message,
                        timestamp: new Date().toLocaleTimeString()
                    };
                    
                    // 只发送给房间内有权限查看消息的用户
                    room.users.forEach(userId => {
                        const user = users.get(userId);
                        if (user && user.permissions.allowViewMessages) {
                            io.to(userId).emit('system-message', systemMessageData);
                        }
                    });
                    
                    console.log(`[房间 ${roomName}] 管理员发送系统消息: ${message}`);
                }
            }
        });
        
        // 管理员在指定房间伪装发送消息
        socket.on('admin-room-send-message', (data) => {
            // 允许管理员和超级管理员执行操作
            const user = users.get(socket.id);
            if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
                const { roomName, username, message, color, type } = data;
                const room = rooms.get(roomName);
                if (room) {
                    const messageId = Date.now() + '-' + Math.random().toString(36).substring(2, 11);
                    const messageData = {
                        id: messageId,
                        username: username,
                        color: color || getRandomColor(),
                        message: message,
                        type: type || 'text',
                        timestamp: new Date().toLocaleTimeString(),
                        senderSocketId: socket.id
                    };
                    
                    // 将消息存储在房间的messages数组中
                    room.messages.push(messageData);
                    if (room.messages.length > 100) {
                        room.messages.shift();
                    }
                    
                    // 只发送给房间内有权限查看消息的用户
                    room.users.forEach(userId => {
                        const user = users.get(userId);
                        if (user && user.permissions.allowViewMessages) {
                            if (type === 'system') {
                                // 发送系统消息格式，但包含用户名和颜色信息
                                io.to(userId).emit('message', {
                                    id: messageId,
                                    username: username,
                                    color: color || getRandomColor(),
                                    message: message,
                                    type: 'system',
                                    timestamp: new Date().toLocaleTimeString(),
                                    senderSocketId: socket.id
                                });
                            } else {
                                io.to(userId).emit('message', messageData);
                            }
                        }
                    });
                    
                    console.log(`[房间 ${roomName}] 管理员伪装成 ${username} 发送消息: ${type === 'text' ? message : type}`);
                }
            }
        });

    socket.on('admin-send-message', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const messageId = Date.now() + '-' + Math.random().toString(36).substring(2, 11);
            const messageData = {
                id: messageId,
                username: data.username,
                color: data.color || getRandomColor(),
                message: data.message,
                type: data.type || 'text',
                timestamp: new Date().toLocaleTimeString(),
                senderSocketId: socket.id
            };
            
            messages.set(messageId, messageData);
            if (messages.size > 100) {
                const firstKey = messages.keys().next().value;
                messages.delete(firstKey);
            }
            
            // 根据消息类型发送不同的事件
            users.forEach((user, socketId) => {
                if (user.permissions.allowViewMessages) {
                    if (data.type === 'system') {
                        // 发送系统消息格式，但包含用户名和颜色信息
                        io.to(socketId).emit('message', {
                            id: messageId,
                            username: data.username,
                            color: data.color || getRandomColor(),
                            message: data.message,
                            type: 'system',
                            timestamp: new Date().toLocaleTimeString(),
                            senderSocketId: socket.id
                        });
                    } else {
                        io.to(socketId).emit('message', messageData);
                    }
                }
            });
            
            console.log(`管理员伪装成 ${data.username} 发送消息: ${data.type === 'text' ? data.message : data.type}`);
        }
    });

    socket.on('admin-get-users', () => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            socket.emit('user-joined', {
                username: '管理员',
                userCount: users.size,
                users: Array.from(users.values())
            });
        }
    });
    
    // 管理员获取好友扩容申请列表
    socket.on('admin-get-friend-limit-requests', () => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const requests = Array.from(friendLimitRequests.values());
            socket.emit('admin-friend-limit-requests', requests);
        }
    });

    // 管理员批准好友扩容申请
    socket.on('admin-approve-friend-limit-request', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const { requestId, newLimit } = data;
            const request = friendLimitRequests.get(requestId);
            
            if (request) {
                // 更新申请状态
                request.status = 'approved';
                request.newLimit = newLimit;
                request.updatedAt = new Date();
                friendLimitRequests.set(requestId, request);
                
                // 设置用户的好友数量上限
                userMaxFriends.set(request.userId, newLimit);
                
                // 通知用户申请已批准
                if (users.has(request.userId)) {
                    io.to(request.userId).emit('friend-limit-request-approved', {
                        message: `好友扩容申请已批准，好友数量上限已升级至${newLimit === INFINITE_FRIENDS ? '无限' : newLimit}个`,
                        newLimit: newLimit
                    });
                }
                
                // 通知管理员申请已处理
                socket.emit('admin-friend-limit-request-updated', request);
            }
        }
    });

    // 管理员拒绝好友扩容申请
    socket.on('admin-reject-friend-limit-request', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const { requestId, reason } = data;
            const request = friendLimitRequests.get(requestId);
            
            if (request) {
                // 更新申请状态
                request.status = 'rejected';
                request.updatedAt = new Date();
                request.rejectReason = reason;
                friendLimitRequests.set(requestId, request);
                
                // 通知用户申请已拒绝
                if (users.has(request.userId)) {
                    io.to(request.userId).emit('friend-limit-request-rejected', {
                        message: '好友扩容申请已拒绝' + (reason ? `，理由：${reason}` : '')
                    });
                }
                
                // 通知管理员申请已处理
                socket.emit('admin-friend-limit-request-updated', request);
            }
        }
    });
    
    // 禁言管理 - 获取禁言用户列表
    // 投票系统事件处理
    
    // 创建投票
    socket.on('create-poll', (data) => {
        const user = users.get(socket.id);
        if (user) {
            // 验证用户权限
            if (!user.permissions.allowSendMessages) {
                socket.emit('permission-denied', { message: '您没有发送消息的权限' });
                return;
            }
            
            const { question, options, duration = 5 } = data;
            
            // 验证投票数据
            if (!question || !options || options.length < 2) {
                socket.emit('poll-error', { message: '投票问题和选项不能为空，且至少需要两个选项' });
                return;
            }
            
            // 创建投票对象
            const pollId = `poll-${pollIdCounter++}`;
            const poll = {
                id: pollId,
                creator: user.username,
                creatorSocketId: socket.id,
                question: question,
                options: options.map((option, index) => ({
                    id: `option-${index}`,
                    text: option,
                    votes: 0
                })),
                votes: new Map(), // 存储用户投票: Map<socketId, optionId>
                createdAt: new Date(),
                endTime: duration > 0 ? Date.now() + (duration * 60 * 1000) : null, // 将分钟转换为毫秒
                isActive: true,
                roomName: user.roomName
            };
            
            // 存储投票
            activePolls.set(pollId, poll);
            
            // 广播投票创建事件（优化版）
            const room = rooms.get(user.roomName);
            if (room) {
                // 转换投票对象为客户端期望的格式
                const clientPoll = {
                    ...poll,
                    votes: poll.options.map(option => option.votes),
                    status: poll.isActive ? 'active' : 'ended',
                    votedUsers: [],
                    userVotes: {},
                    options: poll.options.map(option => option.text) // 确保选项是字符串数组
                };
                
                // 直接使用socket.to()广播给房间内所有用户
                socket.to(user.roomName).emit('poll-created', clientPoll);
                // 同时发送给创建者自己
                socket.emit('poll-created', clientPoll);
            }
            
            console.log(`[房间 ${user.roomName}] ${user.username} 创建了投票: ${question}`);
        }
    });
    
    // 提交投票
    socket.on('vote', (data) => {
        const user = users.get(socket.id);
        if (user) {
            const { pollId, optionIndex } = data;
            const poll = activePolls.get(pollId);
            
            // 验证投票是否存在且活跃
            if (!poll || !poll.isActive) {
                socket.emit('poll-error', { message: '投票不存在或已结束' });
                return;
            }
            
            // 验证用户是否在投票所在房间
            if (user.roomName !== poll.roomName) {
                socket.emit('poll-error', { message: '您不在投票所在的房间' });
                return;
            }
            
            // 防止重复投票
            if (poll.votes.has(socket.id)) {
                socket.emit('poll-error', { message: '您已经投过票了' });
                return;
            }
            
            // 验证选项是否有效
            const option = poll.options[optionIndex];
            if (!option) {
                socket.emit('poll-error', { message: '无效的投票选项' });
                return;
            }
            
            // 记录投票
            poll.votes.set(socket.id, optionIndex);
            option.votes++;
            
            // 广播投票更新事件
            const room = rooms.get(user.roomName);
            if (room) {
                // 转换投票对象为客户端期望的格式
                const clientPoll = {
                    ...poll,
                    votes: poll.options.map(option => option.votes),
                    status: poll.isActive ? 'active' : 'ended',
                    votedUsers: Array.from(poll.votes.keys()),
                    userVotes: Object.fromEntries(poll.votes),
                    options: poll.options.map(option => option.text) // 确保选项是字符串数组
                };
                
                // 直接使用socket.to()广播给房间内所有用户
                socket.to(user.roomName).emit('poll-updated', clientPoll);
                // 同时发送给投票者自己
                socket.emit('poll-updated', clientPoll);
            }
            
            console.log(`[房间 ${user.roomName}] ${user.username} 对投票 "${poll.question}" 投了 ${option.text}`);
        }
    });
    
    // 结束投票
    socket.on('end-poll', (data) => {
        const user = users.get(socket.id);
        if (user) {
            const poll = activePolls.get(data.pollId);
            
            // 验证投票是否存在
            if (!poll) {
                socket.emit('poll-error', { message: '投票不存在' });
                return;
            }
            
            // 验证用户权限（只有创建者或管理员可以结束投票）
            if (socket.id !== poll.creatorSocketId && socket.id !== adminSocketId) {
                const userObj = users.get(socket.id);
                if (!userObj || userObj.role !== 'superadmin') {
                    socket.emit('permission-denied', { message: '您没有结束投票的权限' });
                    return;
                }
            }
            
            // 结束投票
            poll.isActive = false;
            poll.endTime = Date.now();
            
            // 广播投票结束事件
            const room = rooms.get(poll.roomName);
            if (room) {
                // 转换投票对象为客户端期望的格式
                const clientPoll = {
                    ...poll,
                    votes: poll.options.map(option => option.votes),
                    status: 'ended',
                    votedUsers: Array.from(poll.votes.keys()),
                    userVotes: Object.fromEntries(poll.votes),
                    options: poll.options.map(option => option.text) // 确保选项是字符串数组
                };
                
                // 直接使用socket.to()广播给房间内所有用户
                socket.to(poll.roomName).emit('poll-ended', clientPoll);
                // 同时发送给结束投票的用户
                socket.emit('poll-ended', clientPoll);
            }
            
            console.log(`[房间 ${poll.roomName}] ${user.username} 结束了投票: ${poll.question}`);
        }
    });
    
    // 获取投票状态
    socket.on('get-polls', () => {
        const user = users.get(socket.id);
        if (user) {
            const roomPolls = Array.from(activePolls.values())
                .filter(poll => poll.roomName === user.roomName && poll.isActive)
                .map(poll => ({
                    ...poll,
                    votes: poll.options.map(option => option.votes),
                    status: poll.isActive ? 'active' : 'ended',
                    votedUsers: Array.from(poll.votes.keys()),
                    userVotes: Object.fromEntries(poll.votes),
                    options: poll.options.map(option => option.text) // 确保选项是字符串数组
                }));
            
            socket.emit('polls-list', roomPolls);
        }
    });
    
    // 白板相关事件
    socket.on('create-whiteboard', (data) => {
        try {
            const whiteboardId = whiteboardIdCounter++;
            const whiteboard = {
                id: whiteboardId,
                name: data.name || `白板 ${whiteboardId}`,
                creator: socket.id,
                users: [socket.id],
                data: [],
                createdAt: new Date().toISOString()
            };
            whiteboards.set(whiteboardId, whiteboard);
            
            socket.join(`whiteboard-${whiteboardId}`);
            socket.emit('whiteboard-created', whiteboard);
            console.log(`创建白板: ${whiteboardId}, 创建者: ${socket.id}`);
        } catch (error) {
            console.error('创建白板失败:', error);
            socket.emit('whiteboard-error', { message: '创建白板失败' });
        }
    });
    
    socket.on('join-whiteboard', (data) => {
        try {
            const { whiteboardId } = data;
            const whiteboard = whiteboards.get(whiteboardId);
            
            if (!whiteboard) {
                socket.emit('whiteboard-error', { message: '白板不存在' });
                return;
            }
            
            if (!whiteboard.users.includes(socket.id)) {
                whiteboard.users.push(socket.id);
                whiteboards.set(whiteboardId, whiteboard);
            }
            
            socket.join(`whiteboard-${whiteboardId}`);
            socket.emit('whiteboard-joined', whiteboard);
            socket.emit('whiteboard-data', { whiteboardId, data: whiteboard.data });
            
            // 通知其他用户有新用户加入
            socket.to(`whiteboard-${whiteboardId}`).emit('whiteboard-user-joined', {
                whiteboardId,
                userId: socket.id,
                username: Array.from(users.values()).find(u => u.socketId === socket.id)?.username
            });
            
            console.log(`用户加入白板: ${socket.id} -> ${whiteboardId}`);
        } catch (error) {
            console.error('加入白板失败:', error);
            socket.emit('whiteboard-error', { message: '加入白板失败' });
        }
    });
    
    socket.on('leave-whiteboard', (data) => {
        try {
            const { whiteboardId } = data;
            const whiteboard = whiteboards.get(whiteboardId);
            
            if (whiteboard) {
                whiteboard.users = whiteboard.users.filter(id => id !== socket.id);
                whiteboards.set(whiteboardId, whiteboard);
                
                socket.leave(`whiteboard-${whiteboardId}`);
                
                // 通知其他用户有用户离开
                socket.to(`whiteboard-${whiteboardId}`).emit('whiteboard-user-left', {
                    whiteboardId,
                    userId: socket.id
                });
                
                console.log(`用户离开白板: ${socket.id} -> ${whiteboardId}`);
            }
        } catch (error) {
            console.error('离开白板失败:', error);
        }
    });
    
    socket.on('draw', (data) => {
        try {
            const { whiteboardId, drawData } = data;
            const whiteboard = whiteboards.get(whiteboardId);
            
            if (whiteboard) {
                // 保存绘制数据
                whiteboard.data.push(drawData);
                whiteboards.set(whiteboardId, whiteboard);
                
                // 广播给其他用户
                socket.to(`whiteboard-${whiteboardId}`).emit('whiteboard-draw', {
                    whiteboardId,
                    x1: drawData.points[0][0],
                    y1: drawData.points[0][1],
                    x2: drawData.points[1][0],
                    y2: drawData.points[1][1],
                    color: drawData.color,
                    size: drawData.size,
                    tool: drawData.tool,
                    userId: socket.id
                });
            }
        } catch (error) {
            console.error('绘制事件处理失败:', error);
        }
    });
    
    socket.on('clear-whiteboard', (data) => {
        try {
            const { whiteboardId } = data;
            const whiteboard = whiteboards.get(whiteboardId);
            
            if (whiteboard) {
                whiteboard.data = [];
                whiteboards.set(whiteboardId, whiteboard);
                
                // 广播给所有用户
                io.to(`whiteboard-${whiteboardId}`).emit('whiteboard-clear', { whiteboardId });
                console.log(`清空白板: ${whiteboardId}`);
            }
        } catch (error) {
            console.error('清空白板失败:', error);
            socket.emit('whiteboard-error', { message: '清空白板失败' });
        }
    });
    
    socket.on('get-whiteboards', () => {
        try {
            const userWhiteboards = Array.from(whiteboards.values()).filter(wb => 
                wb.users.includes(socket.id)
            );
            socket.emit('whiteboards-list', { whiteboards: userWhiteboards });
        } catch (error) {
            console.error('获取白板列表失败:', error);
            socket.emit('whiteboard-error', { message: '获取白板列表失败' });
        }
    });

    // 断开连接事件
    socket.on('disconnect', () => {
        const user = users.get(socket.id);
        if (user) {
            console.log(`用户断开连接: ${user.username} (${socket.id})`);
            
            // 从房间中移除用户
            const room = rooms.get(user.roomName);
            if (room) {
                room.users = room.users.filter(id => id !== socket.id);
                
                // 更新房间统计数据
                room.stats.currentUsers = room.users.length;
                room.stats.lastActivity = new Date();
                
                // 添加用户历史记录
                room.history.userHistory.push({
                    type: 'leave',
                    username: user.username,
                    timestamp: new Date().toISOString()
                });
                
                // 添加事件历史记录
                room.history.eventHistory.push({
                    type: 'user_leave',
                    description: `${user.username} 离开了房间`,
                    timestamp: new Date().toISOString(),
                    username: user.username
                });
            }
            
            // 从所有白板中移除用户
            whiteboards.forEach((whiteboard, whiteboardId) => {
                if (whiteboard.users.includes(socket.id)) {
                    whiteboard.users = whiteboard.users.filter(id => id !== socket.id);
                    whiteboards.set(whiteboardId, whiteboard);
                    
                    // 通知其他用户有用户离开
                    io.to(`whiteboard-${whiteboardId}`).emit('whiteboard-user-left', {
                        whiteboardId,
                        userId: socket.id
                    });
                }
            });
            
            // 从所有文档中移除用户
            documents.forEach((document, documentId) => {
                if (document.users.includes(socket.id)) {
                    document.users = document.users.filter(id => id !== socket.id);
                    documents.set(documentId, document);
                    
                    // 通知其他用户有用户离开
                    socket.to(document.roomName).emit('document-user-left', {
                        documentId: document.id,
                        username: user.username
                    });
                }
            });
            
            // 清理用户数据
            users.delete(socket.id);
            friendships.delete(socket.id);
            adminForcedFriendships.delete(socket.id);
            swearWordCount.delete(socket.id);
            mutedUsers.delete(socket.id);
            userMaxFriends.delete(socket.id);
            messageRateLimits.delete(socket.id);
            socketEventRateLimits.delete(socket.id); // 清理 Socket 事件速率限制记录
            spamMessageHistory.delete(socket.id);    // 清理刷屏历史记录
            userConsoleLogs.delete(socket.id);
            
            // 清理IP连接数
            const userIP = socket.handshake.address;
            const ipConnSet = ipConnections.get(userIP);
            if (ipConnSet) {
                ipConnSet.delete(socket.id);
                if (ipConnSet.size === 0) {
                    ipConnections.delete(userIP);
                } else {
                    console.log(`[连接清理] IP ${userIP} 连接数: ${ipConnSet.size}`);
                }
            }
            
            // 广播用户离开事件
            io.emit('user-left', {
                username: user.username,
                userCount: users.size,
                users: Array.from(users.values())
            });

            // 清理该用户参与的游戏：如果所有玩家都离开了，删除游戏
            for (const [gameId, game] of games.entries()) {
                if (game.players && game.players.includes(socket.id)) {
                    // 从游戏中移除该玩家
                    game.players = game.players.filter(p => p !== socket.id);
                    // 如果所有玩家都离开了，删除游戏
                    if (game.players.length === 0) {
                        games.delete(gameId);
                        console.log(`[游戏清理] 游戏 ${gameId} (${game.type}) 所有玩家已离开，已删除`);
                    } else {
                        games.set(gameId, game);
                        // 通知仍在游戏中的玩家对手已离开
                        game.players.forEach(pid => {
                            io.to(pid).emit('opponent-left', {
                                gameId: gameId,
                                gameType: game.type
                            });
                        });
                    }
                }
            }
        } else {
            // 清理未登录用户的IP连接数
            const userIP = socket.handshake.address;
            const ipConnSet = ipConnections.get(userIP);
            if (ipConnSet) {
                ipConnSet.delete(socket.id);
                if (ipConnSet.size === 0) {
                    ipConnections.delete(userIP);
                } else {
                    console.log(`[连接清理] IP ${userIP} 连接数: ${ipConnSet.size}`);
                }
            }
            console.log(`未登录用户断开连接: ${socket.id}`);
        }
    });
    
    // IP管理功能（管理员）
    
    // 获取当前连接的IP列表
    socket.on('admin-get-ip-list', () => {
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const ipList = [];
            ipConnections.forEach((connSet, ip) => {
                ipList.push({
                    ip: ip,
                    connectionCount: connSet.size,
                    isBanned: bannedIPs.has(ip)
                });
            });
            
            socket.emit('admin-ip-list', ipList);
        }
    });
    
    // 获取被封禁的IP列表
    socket.on('admin-get-banned-ips', () => {
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const bannedList = Array.from(bannedIPs);
            socket.emit('admin-banned-ips', bannedList);
        }
    });
    
    // 封禁IP
    socket.on('admin-ban-ip', (ip) => {
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            bannedIPs.add(ip);
            
            // 断开该IP的所有连接
            const connSet = ipConnections.get(ip);
            if (connSet) {
                connSet.forEach(socketId => {
                    const socket = io.sockets.sockets.get(socketId);
                    if (socket) {
                        socket.emit('banned', { message: '您的IP已被管理员封禁' });
                        socket.disconnect(true);
                    }
                });
                ipConnections.delete(ip);
            }
            
            socket.emit('admin-ban-success', { ip: ip });
            console.log(`[管理员] ${user.username} 封禁了IP: ${ip}`);
        }
    });
    
    // 解除IP封禁
    socket.on('admin-unban-ip', (ip) => {
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            bannedIPs.delete(ip);
            socket.emit('admin-unban-success', { ip: ip });
            console.log(`[管理员] ${user.username} 解除了对IP的封禁: ${ip}`);
        }
    });
    
    socket.on('admin-get-muted-users', () => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            // 过滤掉已过期的禁言记录
            const now = Date.now();
            const validMutedUsers = [];
            
            mutedUsers.forEach((mutedData, socketId) => {
                if (mutedData.endTime === -1 || mutedData.endTime > now) {
                    validMutedUsers.push({
                        socketId: socketId,
                        username: mutedData.username,
                        endTime: mutedData.endTime,
                        reason: mutedData.reason
                    });
                } else {
                    // 移除过期的禁言记录
                    mutedUsers.delete(socketId);
                }
            });
            
            socket.emit('admin-muted-users', validMutedUsers);
        }
    });
    
    // 禁言管理 - 禁言用户
    socket.on('admin-mute-user', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const { socketId, duration, reason } = data;
            const user = users.get(socketId);
            
            if (user) {
                const now = Date.now();
                const endTime = duration === -1 ? -1 : now + (duration * 60 * 1000);
                
                // 添加到禁言列表
                mutedUsers.set(socketId, {
                    username: user.username,
                    endTime: endTime,
                    reason: reason
                });
                
                // 发送禁言通知给用户
                io.to(socketId).emit('muted', {
                    duration: duration,
                    reason: reason,
                    endTime: endTime
                });
                
                // 更新管理员的禁言列表
                socket.emit('admin-muted-users', Array.from(mutedUsers.entries()).map(([socketId, data]) => ({
                    socketId: socketId,
                    username: data.username,
                    endTime: data.endTime,
                    reason: data.reason
                })));
                
                console.log(`管理员禁言了用户: ${user.username}，时长: ${duration}分钟，原因: ${reason}`);
            }
        }
    });
    
    // 禁言管理 - 解除禁言
    socket.on('admin-unmute-user', (socketId) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const mutedData = mutedUsers.get(socketId);
            
            if (mutedData) {
                // 从禁言列表中移除
                mutedUsers.delete(socketId);
                
                // 重置该用户的脏话计数
                swearWordCount.delete(socketId);
                
                // 发送解除禁言通知给用户
                io.to(socketId).emit('unmuted');
                
                // 更新管理员的禁言列表
                socket.emit('admin-muted-users', Array.from(mutedUsers.entries()).map(([socketId, data]) => ({
                    socketId: socketId,
                    username: data.username,
                    endTime: data.endTime,
                    reason: data.reason
                })));
                
                console.log(`管理员解除了对用户: ${mutedData.username} 的禁言，重置了脏话计数`);
            }
        }
    });
    
    // 用户设置管理 - 获取用户设置
    socket.on('admin-get-user-settings', (socketId) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const user = users.get(socketId);
            if (user) {
                // 确保用户设置对象存在
                if (!user.settings) {
                    user.settings = {
                        locked: false,
                        lockMessage: '设置已被管理员锁定'
                    };
                }
                
                // 确保用户具体设置对象存在
                if (!user.userSettings) {
                    user.userSettings = {
                        targetLanguage: 'zh',
                        autoTranslate: false,
                        soundNotification: true,
                        mentionNotification: true,
                        developerMode: false,
                        mirrorVideo: true,
                        remoteMirrorVideo: false,
                        autoAdjustVolume: true,
                        enableSubtitles: false,
                        speakingThreshold: 40,
                        volumeReduction: 30,
                        subtitlesFontSize: 16,
                        enableAIChat: false,
                        aiModel: 'glm4'
                    };
                }
                
                socket.emit('admin-user-settings', {
                    socketId: socketId,
                    settings: user.settings,
                    userSettings: user.userSettings
                });
            }
        }
    });
    
    // 用户设置管理 - 设置用户设置
    socket.on('admin-set-user-settings', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const { socketId, settings, userSettings } = data;
            const user = users.get(socketId);
            
            if (user) {
                // 更新用户设置（锁定状态等）
                user.settings = {
                    ...user.settings,
                    ...settings
                };
                
                // 更新用户具体设置值
                if (userSettings) {
                    user.userSettings = {
                        ...user.userSettings,
                        ...userSettings
                    };
                }
                
                // 发送设置更新通知给用户，包含所有设置信息
                io.to(socketId).emit('user-settings-updated', {
                    ...user.settings,
                    userSettings: user.userSettings
                });
                
                console.log(`管理员更新了用户 ${user.username} 的设置: ${JSON.stringify(user.settings)}，具体设置: ${JSON.stringify(user.userSettings)}`);
            }
        }
    });

    // 管理员直接设置用户好友数量上限
    socket.on('admin-set-user-max-friends', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const { userId, maxFriends } = data;
            
            // 设置用户的好友数量上限
            userMaxFriends.set(userId, maxFriends);
            
            // 通知用户好友数量上限已更新
            if (users.has(userId)) {
                io.to(userId).emit('max-friends-updated', {
                    message: `管理员已将您的好友数量上限调整为${maxFriends === INFINITE_FRIENDS ? '无限' : maxFriends}个`,
                    maxFriends: maxFriends
                });
            }
            
            // 通知管理员操作成功
            socket.emit('admin-set-max-friends-success', { userId, maxFriends });
        }
    });
    
    // 管理员设置用户AI聊天配置
    socket.on('admin-set-ai-settings', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const { socketId, aiSettings } = data;
            const targetUser = users.get(socketId);
            
            if (targetUser) {
                // 更新用户的AI设置
                targetUser.aiSettings = {
                    ...targetUser.aiSettings,
                    ...aiSettings
                };
                
                // 通知用户AI设置已更新
                io.to(socketId).emit('ai-settings-updated', {
                    ...targetUser.aiSettings,
                    message: '管理员已更新您的AI聊天设置'
                });
                
                // 通知管理员操作成功
                socket.emit('admin-ai-settings-success', {
                    socketId: socketId,
                    username: targetUser.username,
                    aiSettings: targetUser.aiSettings
                });
                
                console.log(`管理员更新了用户 ${targetUser.username} 的AI设置: ${JSON.stringify(targetUser.aiSettings)}`);
            }
        }
    });

    socket.on('admin-get-friends', () => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            console.log('管理员请求获取好友列表');
            const allFriendships = [];
            friendships.forEach((friendSet, userSocketId) => {
                const user = users.get(userSocketId);
                if (user) {
                    friendSet.forEach(friendSocketId => {
                        const friend = users.get(friendSocketId);
                        if (friend) {
                            allFriendships.push({
                                userSocketId: userSocketId,
                                username: user.username,
                                userColor: user.color,
                                friendSocketId: friendSocketId,
                                friendUsername: friend.username,
                                friendColor: friend.color
                            });
                        }
                    });
                }
            });
            console.log('发送好友列表给管理员，共', allFriendships.length, '条');
            socket.emit('admin-friends-list', allFriendships);
        } else {
            console.log('非管理员请求获取好友列表，socket.id:', socket.id, 'adminSocketId:', adminSocketId);
        }
    });

    socket.on('admin-delete-friendship', (data) => {
        // 允许管理员和超级管理员执行操作
        const adminUser = users.get(socket.id);
        if (socket.id === adminSocketId || (adminUser && adminUser.role === 'superadmin')) {
            const { userSocketId, friendSocketId } = data;
            
            const user = users.get(userSocketId);
            const friend = users.get(friendSocketId);
            
            // 删除好友关系（双向删除）
            if (friendships.has(userSocketId)) {
                friendships.get(userSocketId).delete(friendSocketId);
            }
            if (friendships.has(friendSocketId)) {
                friendships.get(friendSocketId).delete(userSocketId);
            }
            
            // 同时清理强制好友记录
            if (adminForcedFriendships.has(userSocketId)) {
                adminForcedFriendships.get(userSocketId).delete(friendSocketId);
            }
            if (adminForcedFriendships.has(friendSocketId)) {
                adminForcedFriendships.get(friendSocketId).delete(userSocketId);
            }
            
            console.log(`管理员删除了好友关系: ${userSocketId} <-> ${friendSocketId}`);
            
            // 通知双方用户
            io.to(userSocketId).emit('friend-removed', {
                friendSocketId: friendSocketId,
                friendUsername: friend?.username
            });
            io.to(friendSocketId).emit('friend-removed', {
                friendSocketId: userSocketId,
                friendUsername: user?.username
            });
            
            // 重新发送好友列表
            socket.emit('admin-get-friends');
        }
    });

    socket.on('admin-add-friendship', (data) => {
        // 允许管理员和超级管理员执行操作
        const adminUser = users.get(socket.id);
        if (socket.id === adminSocketId || (adminUser && adminUser.role === 'superadmin')) {
            const { userSocketId, friendSocketId } = data;
            
            const user = users.get(userSocketId);
            const friend = users.get(friendSocketId);
            
            if (!user || !friend) {
                socket.emit('friend-error', { message: '用户不存在' });
                return;
            }
            
            // 初始化好友集合
            if (!friendships.has(userSocketId)) {
                friendships.set(userSocketId, new Set());
            }
            if (!friendships.has(friendSocketId)) {
                friendships.set(friendSocketId, new Set());
            }
            
            // 检查是否已经是好友
            if (friendships.get(userSocketId).has(friendSocketId)) {
                socket.emit('friend-error', { message: '已经是好友了' });
                return;
            }
            
            // 双向添加好友关系
            friendships.get(userSocketId).add(friendSocketId);
            friendships.get(friendSocketId).add(userSocketId);
            
            // 记录管理员强制添加的好友关系（双方都无法删除）
            if (!adminForcedFriendships.has(userSocketId)) {
                adminForcedFriendships.set(userSocketId, new Set());
            }
            if (!adminForcedFriendships.has(friendSocketId)) {
                adminForcedFriendships.set(friendSocketId, new Set());
            }
            adminForcedFriendships.get(userSocketId).add(friendSocketId);
            adminForcedFriendships.get(friendSocketId).add(userSocketId);
            
            console.log(`管理员强制添加了好友关系: ${user.username} <-> ${friend.username}`);
            
            // 通知双方用户（标记为管理员强制添加）
            io.to(userSocketId).emit('friend-added', {
                friendSocketId: friendSocketId,
                friendUsername: friend.username,
                friendColor: friend.color,
                forcedByAdmin: true
            });
            io.to(friendSocketId).emit('friend-added', {
                friendSocketId: userSocketId,
                friendUsername: user.username,
                friendColor: user.color,
                forcedByAdmin: true
            });
            
            // 重新发送好友列表
            socket.emit('admin-get-friends');
        }
    });

    socket.on('admin-clear-messages', () => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            // 清空全局消息Map
            messages.clear();
            
            // 清空所有房间的消息数组
            rooms.forEach(room => {
                room.messages = [];
            });
            
            // 通知所有用户消息已清空
            io.emit('messages-cleared');
            
            console.log('管理员清空了所有消息（包括所有房间的消息历史）');
        }
    });
    
    // 管理员创建房间
    socket.on('admin-create-room', (data) => {
        // 速率限制
        if (checkSocketEventRate(socket.id, 'admin-create-room', userIP)) {
            socket.emit('admin-room-error', { message: '操作过于频繁，请稍后再试' });
            return;
        }

        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const { roomName, password, settings } = data;

            // 房间名输入验证
            const roomNameErr = validateField(roomName, 'roomName');
            if (roomNameErr || !roomName) {
                socket.emit('admin-room-error', { message: roomNameErr || '房间名不能为空' });
                return;
            }
            
            // 检查房间名是否已存在
            if (rooms.has(roomName)) {
                socket.emit('admin-room-error', { message: '房间名已存在' });
                return;
            }
            
            // 验证maxUsers参数是否为有效数字
            if (settings?.maxUsers && (typeof settings.maxUsers !== 'number' || settings.maxUsers <= 0)) {
                socket.emit('admin-room-error', { message: 'maxUsers必须是一个大于0的数字' });
                return;
            }
            
            // 创建新房间
            const newRoom = {
                roomName: roomName,
                password: password,
                creator: socket.id,
                createdAt: new Date(),
                updatedAt: new Date(),
                users: [],
                messages: [],
                settings: {
                    maxUsers: settings?.maxUsers || 100,
                    allowPublicAccess: true,
                    ...settings
                }
            };
            
            rooms.set(roomName, newRoom);
            
            // 发送房间列表给管理员
            socket.emit('admin-rooms', Array.from(rooms.values()));
            console.log(`管理员创建了新房间: ${roomName}`);
        }
    });
    
    // 管理员删除房间
    socket.on('admin-delete-room', (roomName) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            // 不允许删除默认房间
            if (roomName === 'main') {
                socket.emit('admin-room-error', { message: '不能删除默认房间' });
                return;
            }
            
            // 检查是否至少有一个房间存在
            const allRooms = Array.from(rooms.values());
            if (allRooms.length <= 1) {
                socket.emit('admin-room-error', { message: '至少需要有一个房间，不能删除最后一个房间' });
                return;
            }
            
            const room = rooms.get(roomName);
            if (room) {
                // 将房间内的用户移动到默认房间
                room.users.forEach(userId => {
                    const user = users.get(userId);
                    if (user) {
                        // 从当前房间移除
                        user.roomName = 'main';
                        const mainRoom = rooms.get('main');
                        mainRoom.users.push(userId);
                        
                        // 发送房间变更通知
                        io.to(userId).emit('room-changed', {
                            roomName: 'main',
                            message: '您所在的房间已被管理员删除，已自动转移到默认房间'
                        });
                    }
                });
                
                // 删除房间
                rooms.delete(roomName);
                
                // 发送房间列表给管理员
                socket.emit('admin-rooms', Array.from(rooms.values()));
                console.log(`管理员删除了房间: ${roomName}`);
            }
        }
    });
    
    // 管理员修改房间设置
    socket.on('admin-update-room', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const { roomName, updates } = data;
            
            const room = rooms.get(roomName);
            if (room) {
                // 更新房间信息
                room.updatedAt = new Date();
                if (updates.password !== undefined) {
                    room.password = updates.password;
                }
                if (updates.settings) {
                    room.settings = { ...room.settings, ...updates.settings };
                }
                
                // 发送房间列表给管理员
                socket.emit('admin-rooms', Array.from(rooms.values()));
                console.log(`管理员更新了房间 ${roomName} 的设置`);
            }
        }
    });

    // 管理员修改管理员密码
    socket.on('admin-change-password', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
                const { oldPassword, newPassword } = data;
                
                // 验证旧密码
                if (oldPassword !== ADMIN_PASSWORD) {
                    socket.emit('admin-password-error', { message: '旧密码错误' });
                    return;
                }
                
                // 直接存储新密码（明文）
                ADMIN_PASSWORD = newPassword;
                
                socket.emit('admin-password-success', { message: '管理员密码已修改' });
                console.log('管理员修改了密码');
            }
        });
        
        // 管理员发送弹窗消息给指定用户
        socket.on('admin-popup', (data) => {
            if (socket.id === adminSocketId) {
                const { socketId, message } = data;
                io.to(socketId).emit('popup-message', { message });
                console.log(`管理员向 ${socketId} 发送弹窗: ${message}`);
            }
        });
        
        // 管理员更改用户页面标题
        socket.on('admin-change-title', (data) => {
            if (socket.id === adminSocketId) {
                const { socketId, title } = data;
                io.to(socketId).emit('change-title', { title });
                console.log(`管理员将 ${socketId} 的页面标题更改为: ${title}`);
            }
        });
    
    // 系统管理 - 获取服务器信息
    socket.on('admin-get-server-info', () => {
        if (socket.id === adminSocketId) {
            const serverInfo = {
                nodeVersion: process.version,
                platform: process.platform,
                arch: process.arch,
                uptime: process.uptime(),
                memoryUsage: process.memoryUsage(),
                pid: process.pid,
                cwd: process.cwd(),
                isRunning: true
            };
            socket.emit('admin-server-info', serverInfo);
        }
    });
    
    // 系统管理 - 关闭服务器
    socket.on('admin-shutdown-server', () => {
        if (socket.id === adminSocketId) {
            console.log('管理员正在关闭服务器...');
            io.emit('server-shutting-down', { message: '服务器正在关闭，请稍后刷新页面' });
            setTimeout(() => {
                process.exit(0);
            }, 2000);
        }
    });
    
    // 系统管理 - 执行命令
    socket.on('admin-exec-command', (data) => {
        if (socket.id === adminSocketId) {
            const { command } = data;

            const { spawn } = require('child_process');
            
            // 获取当前操作系统类型
            const platform = process.platform;

            
            let cmd, args, options;
            
            // 根据不同的操作系统使用不同的命令执行方式
            if (platform === 'win32') {
                // Windows系统
                cmd = 'cmd.exe';
                args = ['/c', command];
                options = {
                    timeout: 10000,
                    encoding: 'buffer' // 先以buffer形式获取，再转码
                };
            } else if (platform === 'linux' || platform === 'darwin') {
                // Linux或Mac系统
                cmd = '/bin/sh';
                args = ['-c', command];
                options = {
                    timeout: 10000,
                    encoding: 'utf8' // Linux/Mac默认使用UTF-8编码
                };
            } else {
                // 其他系统，默认使用UTF-8
                cmd = '/bin/sh';
                args = ['-c', command];
                options = {
                    timeout: 10000,
                    encoding: 'utf8'
                };
            }
            


            
            // 使用spawn方法执行命令
            const child = spawn(cmd, args, options);
            
            let stdout = [];
            let stderr = [];
            
            // 收集stdout
            child.stdout.on('data', (data) => {

                if (Buffer.isBuffer(data)) {
                    stdout.push(data);
                } else {
                    stdout.push(Buffer.from(data, 'utf8'));
                }
            });
            
            // 收集stderr
            child.stderr.on('data', (data) => {

                if (Buffer.isBuffer(data)) {
                    stderr.push(data);
                } else {
                    stderr.push(Buffer.from(data, 'utf8'));
                }
            });
            
            // 命令执行完成
            child.on('close', (code) => {

                
                let stdoutStr, stderrStr;
                
                // 合并Buffer
                const stdoutBuffer = Buffer.concat(stdout);
                const stderrBuffer = Buffer.concat(stderr);
                
                // 根据操作系统选择正确的编码解码
                if (platform === 'win32') {
                    // Windows系统：尝试使用GBK解码，失败则使用UTF-8
                    try {
                        stdoutStr = stdoutBuffer.toString('gbk');
                        stderrStr = stderrBuffer.toString('gbk');

                    } catch (e) {

                        stdoutStr = stdoutBuffer.toString('utf8');
                        stderrStr = stderrBuffer.toString('utf8');
                    }
                } else {
                    // Linux/Mac系统：直接使用UTF-8解码
                    stdoutStr = stdoutBuffer.toString('utf8');
                    stderrStr = stderrBuffer.toString('utf8');
                }
                


                
                if (code !== 0) {
                    // 处理执行错误
                    const errorMessage = stderrStr || `命令执行失败，退出码: ${code}`;

                    socket.emit('admin-command-result', { success: false, error: errorMessage });
                } else {

                    socket.emit('admin-command-result', { success: true, output: stdoutStr });
                }
            });
            
            // 处理超时
            child.on('timeout', () => {

                child.kill();
                socket.emit('admin-command-result', { success: false, error: '命令执行超时' });
            });
            
            // 处理错误
            child.on('error', (error) => {

                socket.emit('admin-command-result', { success: false, error: error.message });
            });
        }
    });
    
    // 获取房间列表
    socket.on('admin-get-rooms', () => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            socket.emit('admin-rooms', Array.from(rooms.values()));
        }
    });
    
    // 获取房间内用户列表
    socket.on('admin-get-room-users', (roomName) => {
        if (socket.id === adminSocketId) {
            const room = rooms.get(roomName);
            if (room) {
                const roomUsers = room.users.map(userId => users.get(userId)).filter(user => user);
                socket.emit('admin-room-users', {
                    roomName: roomName,
                    users: roomUsers
                });
            }
        }
    });
    
    // 在房间内踢人
    socket.on('admin-room-kick-user', (data) => {
        if (socket.id === adminSocketId) {
            const { roomName, socketId } = data;
            const room = rooms.get(roomName);
            if (room) {
                // 从房间用户列表中移除
                room.users = room.users.filter(userId => userId !== socketId);
                
                // 获取用户信息
                const user = users.get(socketId);
                if (user) {
                    // 发送踢人通知
                    io.to(socketId).emit('kicked', '你已被管理员踢出房间');
                    
                    // 断开用户连接
                    io.sockets.sockets.get(socketId)?.disconnect();
                    
                    // 删除用户信息
                    users.delete(socketId);
                    
                    console.log(`[房间 ${roomName}] 管理员踢出了用户: ${user.username}`);
                }
            }
        }
    });
    
    // 白板系统事件处理
    socket.on('whiteboard-draw', (data) => {
        const user = users.get(socket.id);
        if (user) {
            // 广播绘制事件给房间内所有用户
            socket.to(user.roomName).emit('whiteboard-draw', {
                ...data,
                username: user.username
                // 不要覆盖客户端发送的color，保持用户选择的颜色
            });
            // 移除日志输出，避免服务端日志过多
            // console.log(`[房间 ${user.roomName}] ${user.username} 在白板上绘制`);
        }
    });
    
    socket.on('whiteboard-clear', (data) => {
        const user = users.get(socket.id);
        if (user) {
            // 广播清屏事件给房间内所有用户
            socket.to(user.roomName).emit('whiteboard-clear', {
                username: user.username
            });
            // 移除日志输出，避免服务端日志过多
            // console.log(`[房间 ${user.roomName}] ${user.username} 清空了白板`);
        }
    });
    
    socket.on('whiteboard-text', (data) => {
        const user = users.get(socket.id);
        if (user) {
            // 广播文本绘制事件给房间内所有用户
            socket.to(user.roomName).emit('whiteboard-text', {
                ...data,
                username: user.username
            });
            // 移除日志输出，避免服务端日志过多
            // console.log(`[房间 ${user.roomName}] ${user.username} 在白板上添加了文本: ${data.text}`);
        }
    });
    
    socket.on('whiteboard-undo', (data) => {
        const user = users.get(socket.id);
        if (user) {
            // 广播撤销事件给房间内所有用户
            socket.to(user.roomName).emit('whiteboard-undo', {
                username: user.username
            });
            // 移除日志输出，避免服务端日志过多
            // console.log(`[房间 ${user.roomName}] ${user.username} 撤销了操作`);
        }
    });
    
    socket.on('whiteboard-redo', (data) => {
        const user = users.get(socket.id);
        if (user) {
            // 广播重做事件给房间内所有用户
            socket.to(user.roomName).emit('whiteboard-redo', {
                username: user.username
            });
        }
    });
    
    socket.on('whiteboard-save', (data) => {
        const user = users.get(socket.id);
        if (user) {
            console.log(`[房间 ${user.roomName}] ${user.username} 保存了白板内容`);
            // 可以在这里添加保存白板内容到服务器的逻辑
        }
    });
    
    // 文档编辑系统事件处理

    // 文档安全工具函数
    const DOC_TITLE_MAX_LEN = 60;
    const DOC_CONTENT_MAX_LEN = 200 * 1024; // 200KB
    const DOC_PER_ROOM_LIMIT = 30;
    function sanitizeDocTitle(title) {
        if (typeof title !== 'string') return '新文档';
        // 去除 HTML 标签和危险字符，限制长度
        return title.replace(/<[^>]*>/g, '').replace(/[<>"'&]/g, '').trim().slice(0, DOC_TITLE_MAX_LEN) || '新文档';
    }
    
    socket.on('document-create', (data) => {
        console.log(`[文档] 收到 document-create 事件，socketId: ${socket.id}，标题: ${data?.title}`);
        const user = users.get(socket.id);
        if (!user) {
            socket.emit('document-error', { message: '用户未登录，请先加入房间' });
            return;
        }
        // 验证输入
        if (!data || typeof data !== 'object') {
            socket.emit('document-error', { message: '无效的请求数据' });
            return;
        }
        // 限制每个房间的文档数量
        const roomDocCount = Array.from(documents.values()).filter(d => d.roomName === user.roomName).length;
        if (roomDocCount >= DOC_PER_ROOM_LIMIT) {
            socket.emit('document-error', { message: `房间文档数量已达上限（${DOC_PER_ROOM_LIMIT} 个），请删除旧文档后再创建` });
            return;
        }
        const safeTitle = sanitizeDocTitle(data.title);
        const documentId = `doc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const document = {
            id: documentId,
            title: safeTitle,
            content: '',   // 创建时内容始终为空，不接受客户端传入
            creator: user.username,
            roomName: user.roomName,
            users: [socket.id],
            lastModified: new Date().toISOString()
        };
        
        documents.set(documentId, document);
        console.log(`[文档] ${user.username} 创建了文档: ${document.title} (${documentId})`);
        
        // 发送创建成功事件给创建者
        socket.emit('document-create-success', document);
        
        // 广播文档创建事件给房间内所有用户（改用 io.to 确保可靠广播）
        const room = rooms.get(user.roomName);
        const roomUserCount = room ? room.users.length : 0;
        console.log(`[文档] 广播 document-created 到房间 "${user.roomName}"，房间人数: ${roomUserCount}`);
        io.to(user.roomName).emit('document-created', {
            id: document.id,
            title: document.title,
            creator: document.creator,
            roomName: document.roomName,
            lastModified: document.lastModified
        });
    });
    
    socket.on('document-join', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        if (!data || typeof data.documentId !== 'string') return;
        const document = documents.get(data.documentId);
        if (!document) return;
        // 安全校验：文档必须属于当前用户所在的房间
        if (document.roomName !== user.roomName) {
            socket.emit('document-error', { message: '无权访问该文档' });
            return;
        }
        // 添加用户到文档用户列表
        if (!document.users.includes(socket.id)) {
            document.users.push(socket.id);
        }
        
        // 发送文档内容给用户
        socket.emit('document-joined', document);
        
        // 广播用户加入事件给其他用户
        socket.to(document.roomName).emit('document-user-joined', {
            documentId: document.id,
            username: user.username,
            color: user.color
        });
        console.log(`[房间 ${document.roomName}] ${user.username} 加入了文档: ${document.title}`);
    });
    
    socket.on('document-edit', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        if (!data || typeof data.documentId !== 'string' || typeof data.content !== 'string') return;
        const document = documents.get(data.documentId);
        if (!document) return;
        // 安全校验：文档必须属于当前用户所在的房间
        if (document.roomName !== user.roomName) {
            socket.emit('document-error', { message: '无权编辑该文档' });
            return;
        }
        // 安全校验：用户必须已加入文档（document-join 过）
        if (!document.users.includes(socket.id)) {
            socket.emit('document-error', { message: '请先加入文档再编辑' });
            return;
        }
        // 限制内容长度，防止超大数据攻击
        if (data.content.length > DOC_CONTENT_MAX_LEN) {
            socket.emit('document-error', { message: `文档内容超出限制（最大 ${DOC_CONTENT_MAX_LEN / 1024}KB）` });
            return;
        }
        // 更新文档内容
        document.content = data.content;
        document.lastModified = new Date().toISOString();
        documents.set(data.documentId, document);
        
        console.log(`[文档] ${user.username} 编辑了文档: ${document.title} (${data.documentId})`);
        
        // 广播编辑事件给所有文档用户
        document.users.forEach(userId => {
            if (userId !== socket.id) {
                io.to(userId).emit('document-edited', {
                    documentId: document.id,
                    content: data.content,
                    username: user.username
                });
            }
        });
    });
    
    socket.on('document-save', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        if (!data || typeof data.documentId !== 'string') return;
        const document = documents.get(data.documentId);
        if (!document) return;
        // 安全校验：文档必须属于当前用户所在的房间
        if (document.roomName !== user.roomName) {
            socket.emit('document-error', { message: '无权保存该文档' });
            return;
        }
        console.log(`[房间 ${document.roomName}] ${user.username} 保存了文档: ${document.title}`);
        
        // 发送保存成功事件给用户
        socket.emit('document-save-success', {
            documentId: document.id,
            timestamp: new Date()
        });
    });
    
    socket.on('document-leave', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        if (!data || typeof data.documentId !== 'string') return;
        const document = documents.get(data.documentId);
        if (!document) return;
        document.users = document.users.filter(userId => userId !== socket.id);
        socket.to(document.roomName).emit('document-user-left', {
            documentId: document.id,
            username: user.username
        });
        console.log(`[房间 ${document.roomName}] ${user.username} 离开了文档: ${document.title}`);
    });

    // 删除文档
    socket.on('document-delete', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        if (!data || typeof data.documentId !== 'string') return;
        const document = documents.get(data.documentId);
        if (!document) return;
        // 安全校验：文档必须属于当前用户所在的房间
        if (document.roomName !== user.roomName) {
            socket.emit('document-error', { message: '无权删除该文档' });
            return;
        }
        // 权限校验：只有文档创建者或管理员/房间创建者可以删除
        const isAdmin = socket.id === adminSocketId || (user && user.role === 'superadmin');
        const room = rooms.get(user.roomName);
        const isRoomCreator = room && room.creator === user.username;
        const isDocCreator = document.creator === user.username;
        if (!isDocCreator && !isAdmin && !isRoomCreator) {
            socket.emit('document-error', { message: '只有文档创建者或管理员才能删除文档' });
            return;
        }
        documents.delete(data.documentId);
        io.to(user.roomName).emit('document-deleted', {
            documentId: data.documentId,
            title: document.title
        });
        console.log(`[文档] ${user.username} 删除了文档: ${document.title}`);
    });

    // 重命名文档
    socket.on('document-rename', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        if (!data || typeof data.documentId !== 'string' || data.title === undefined) return;
        const document = documents.get(data.documentId);
        if (!document) return;
        // 安全校验：文档必须属于当前用户所在的房间
        if (document.roomName !== user.roomName) {
            socket.emit('document-error', { message: '无权重命名该文档' });
            return;
        }
        // 权限校验：只有文档创建者或管理员/房间创建者可以改名
        const isAdmin = socket.id === adminSocketId || (user && user.role === 'superadmin');
        const room = rooms.get(user.roomName);
        const isRoomCreator = room && room.creator === user.username;
        const isDocCreator = document.creator === user.username;
        if (!isDocCreator && !isAdmin && !isRoomCreator) {
            socket.emit('document-error', { message: '只有文档创建者或管理员才能重命名文档' });
            return;
        }
        const safeTitle = sanitizeDocTitle(data.title);
        document.title = safeTitle;
        document.lastModified = new Date().toISOString();
        io.to(user.roomName).emit('document-renamed', {
            documentId: data.documentId,
            title: safeTitle
        });
    });

    // 获取文档在线用户列表（返回用户名）
    socket.on('document-users', (data) => {
        const user = users.get(socket.id);
        if (user && data.documentId) {
            const document = documents.get(data.documentId);
            if (document) {
                const usernames = document.users
                    .map(uid => {
                        const u = users.get(uid);
                        return u ? u.username : null;
                    })
                    .filter(Boolean);
                socket.emit('document-users', {
                    documentId: data.documentId,
                    usernames
                });
            }
        }
    });

    socket.on('document-list', (data) => {
        const user = users.get(socket.id);
        if (user) {
            const roomDocuments = Array.from(documents.values()).filter(doc => doc.roomName === user.roomName);
            socket.emit('document-list', roomDocuments);
        } else {
            socket.emit('document-error', { message: '用户未登录，请先加入房间' });
        }
    });
    
    // 插件系统架构
    const plugins = new Map(); // 存储插件: Map<pluginId, plugin>
    const pluginInstances = new Map(); // 存储插件实例: Map<pluginId, instance>
    
    // 初始化插件系统
    function initPlugins() {
        // 内置插件
        const builtinPlugins = [
            {
                id: 'weather',
                name: '天气查询',
                description: '查询城市天气信息',
                version: '1.0.0',
                author: 'system',
                enabled: true,
                commands: ['weather', '天气']
            },
            {
                id: 'translator',
                name: '翻译器',
                description: '翻译文本',
                version: '1.0.0',
                author: 'system',
                enabled: true,
                commands: ['translate', '翻译']
            },
            {
                id: 'games',
                name: '小游戏',
                description: '内置小游戏',
                version: '1.0.0',
                author: 'system',
                enabled: true,
                commands: ['game', '游戏']
            },
            {
                id: 'vote',
                name: '投票系统',
                description: '创建和管理投票',
                version: '1.0.0',
                author: 'system',
                enabled: true,
                commands: ['vote', '投票']
            }
        ];
        
        // 注册内置插件
        builtinPlugins.forEach(plugin => {
            plugins.set(plugin.id, plugin);
        });
        
        console.log('插件系统初始化完成，加载了', builtinPlugins.length, '个内置插件');
    }
    
    // 初始化插件系统
    initPlugins();
    
    // 插件系统事件处理
    socket.on('plugin-list', () => {
        const user = users.get(socket.id);
        if (user) {
            const pluginList = Array.from(plugins.values());
            socket.emit('plugin-list', pluginList);
        }
    });
    
    socket.on('plugin-execute', async (data) => {
        const user = users.get(socket.id);
        if (user && data.pluginId && data.command && data.args) {
            const plugin = plugins.get(data.pluginId);
            if (plugin && plugin.enabled) {
                // 执行插件命令
                await executePluginCommand(plugin, data.command, data.args, user);
            }
        }
    });
    
    socket.on('plugin-toggle', (data) => {
        const user = users.get(socket.id);
        if (user && data.pluginId) {
            const plugin = plugins.get(data.pluginId);
            if (plugin) {
                plugin.enabled = !plugin.enabled;
                socket.emit('plugin-toggled', {
                    pluginId: plugin.id,
                    enabled: plugin.enabled
                });
                console.log(`[房间 ${user.roomName}] ${user.username} ${plugin.enabled ? '启用' : '禁用'}了插件: ${plugin.name}`);
            }
        }
    });
    
    // 游戏系统事件处理
    socket.on('game-join', (data) => {
        const user = users.get(socket.id);
        if (user && data.gameId) {
            const game = games.get(data.gameId);
            if (game) {
                if (game.type === 'gomoku' && game.status === 'waiting' && game.players.length < 2) {
                    const updatedGame = joinGomokuGame(data.gameId, socket.id, user.username);
                    if (updatedGame) {
                        // 通知所有玩家游戏开始
                        updatedGame.players.forEach(playerSocketId => {
                            io.to(playerSocketId).emit('game-start', {
                                gameId: updatedGame.id,
                                gameType: 'gomoku',
                                players: updatedGame.players.map(pid => ({
                                    socketId: pid,
                                    username: users.get(pid)?.username || '未知'
                                })),
                                board: updatedGame.board,
                                currentPlayer: updatedGame.currentPlayer
                            });
                        });
                        
                        // 广播游戏开始事件给房间内其他用户
                        socket.to(user.roomName).emit('game-started', {
                            gameId: updatedGame.id,
                            gameType: updatedGame.type,
                            players: updatedGame.players.map(pid => users.get(pid)?.username || '未知')
                        });
                        
                        console.log(`[房间 ${user.roomName}] ${user.username} 加入了五子棋游戏 ${updatedGame.id}`);
                    }
                } else if (game.type === 'pictionary' && game.status === 'waiting') {
                    const updatedGame = joinPictionaryGame(data.gameId, socket.id, user.username);
                    if (updatedGame) {
                        // 通知所有玩家游戏状态
                        updatedGame.players.forEach(playerSocketId => {
                            const isDrawer = playerSocketId === updatedGame.currentDrawer;
                            io.to(playerSocketId).emit('game-start', {
                                gameId: updatedGame.id,
                                gameType: 'pictionary',
                                players: updatedGame.players.map(pid => ({
                                    socketId: pid,
                                    username: users.get(pid)?.username || '未知'
                                })),
                                currentDrawer: updatedGame.currentDrawer,
                                currentDrawerName: users.get(updatedGame.currentDrawer)?.username || '未知',
                                currentWord: isDrawer ? updatedGame.currentWord : null,
                                wordHint: updatedGame.currentWord ? (updatedGame.currentWord.length + '个字') : '',
                                scores: Object.fromEntries(updatedGame.scores),
                                currentRound: updatedGame.currentRound,
                                maxRounds: updatedGame.maxRounds,
                                status: updatedGame.status
                            });
                        });
                        
                        // 广播游戏开始事件给房间内其他用户
                        socket.to(user.roomName).emit('game-started', {
                            gameId: updatedGame.id,
                            gameType: updatedGame.type,
                            players: updatedGame.players.map(pid => users.get(pid)?.username || '未知')
                        });
                        
                        console.log(`[房间 ${user.roomName}] ${user.username} 加入了你画我猜游戏 ${updatedGame.id}`);
                    }
                } else if (game.type === 'guess-number' && game.status === 'waiting' && game.players.length < 2) {
                    const updatedGame = joinGuessNumberGame(data.gameId, socket.id);
                    if (updatedGame) {
                        [updatedGame.players[0], socket.id].forEach(playerSocketId => {
                            io.to(playerSocketId).emit('guess-number-start', {
                                gameId: updatedGame.id,
                                gameType: 'guess-number',
                                players: updatedGame.players.map(pid => ({
                                    socketId: pid,
                                    username: users.get(pid)?.username || game.playerNames?.[pid] || '未知'
                                })),
                                currentGuesser: updatedGame.currentGuesser,
                                status: updatedGame.status
                            });
                        });
                        socket.to(user.roomName).emit('game-started', {
                            gameId: updatedGame.id,
                            gameType: 'guess-number',
                            players: updatedGame.players.map(pid => users.get(pid)?.username || '未知')
                        });
                        console.log(`[房间 ${user.roomName}] ${user.username} 加入了猜数字游戏 ${updatedGame.id}`);
                    }
                } else if (game.type === 'rps' && game.status === 'waiting' && game.players.length < 2) {
                    const updatedGame = joinRPSGame(data.gameId, socket.id, user.username);
                    if (updatedGame) {
                        updatedGame.players.forEach(pid => {
                            io.to(pid).emit('rps-start', {
                                gameId: updatedGame.id,
                                gameType: 'rps',
                                players: updatedGame.players.map(p => ({
                                    socketId: p,
                                    username: updatedGame.playerNames[p]
                                })),
                                wins: { ...updatedGame.wins },
                                maxWins: updatedGame.maxWins,
                                round: updatedGame.round
                            });
                        });
                        socket.to(user.roomName).emit('game-started', {
                            gameId: updatedGame.id,
                            gameType: 'rps',
                            players: updatedGame.players.map(p => updatedGame.playerNames[p])
                        });
                        console.log(`[房间 ${user.roomName}] ${user.username} 加入了剪刀石头布游戏 ${updatedGame.id}`);
                    }
                } else if (game.type === 'bomb' && game.status === 'waiting' && game.players.length < 2) {
                    const updatedGame = joinBombGame(data.gameId, socket.id, user.username);
                    if (updatedGame) {
                        updatedGame.players.forEach(pid => {
                            io.to(pid).emit('bomb-start', {
                                gameId: updatedGame.id,
                                gameType: 'bomb',
                                players: updatedGame.players.map(p => ({
                                    socketId: p,
                                    username: updatedGame.playerNames[p]
                                })),
                                maxStep: updatedGame.maxStep,
                                current: 0,
                                currentPlayer: updatedGame.players[0]
                            });
                        });
                        socket.to(user.roomName).emit('game-started', {
                            gameId: updatedGame.id,
                            gameType: 'bomb',
                            players: updatedGame.players.map(p => updatedGame.playerNames[p])
                        });
                        console.log(`[房间 ${user.roomName}] ${user.username} 加入了数字炸弹游戏 ${updatedGame.id}`);
                    }
                } else if (game.type === 'typing' && game.status === 'waiting' && game.players.length < 2) {
                    const updatedGame = joinTypingGame(data.gameId, socket.id, user.username);
                    if (updatedGame) {
                        updatedGame.players.forEach(pid => {
                            io.to(pid).emit('typing-start', {
                                gameId: updatedGame.id,
                                gameType: 'typing',
                                players: updatedGame.players.map(p => ({
                                    socketId: p,
                                    username: updatedGame.playerNames[p]
                                })),
                                text: updatedGame.text
                            });
                        });
                        socket.to(user.roomName).emit('game-started', {
                            gameId: updatedGame.id,
                            gameType: 'typing',
                            players: updatedGame.players.map(p => updatedGame.playerNames[p])
                        });
                        console.log(`[房间 ${user.roomName}] ${user.username} 加入了打字对战 ${updatedGame.id}`);
                    }
                }
            }
        }
    });
    
    socket.on('game-move', (data) => {
        console.log('收到游戏移动请求:', data);
        const user = users.get(socket.id);
        console.log('用户信息:', user);
        
        if (!user) {
            console.log('用户不存在');
            return;
        }
        
        if (!data.gameId) {
            console.log('缺少游戏ID');
            return;
        }
        
        if (data.x === undefined || data.y === undefined) {
            console.log('缺少落子位置');
            return;
        }
        
        const game = games.get(data.gameId);
        console.log('游戏信息:', game);
        
        if (!game) {
            console.log('游戏不存在:', data.gameId);
            return;
        }
        
        if (game.type !== 'gomoku') {
            console.log('游戏类型不是五子棋:', game.type);
            return;
        }
        
        if (game.status !== 'playing') {
            console.log('游戏状态不是playing:', game.status);
            return;
        }
        
        if (game.currentPlayer !== socket.id) {
            console.log('不是当前玩家的回合:', game.currentPlayer, 'vs', socket.id);
            return;
        }
        
        if (game.board[data.x][data.y] !== null) {
            console.log('该位置已经有棋子:', data.x, data.y);
            return;
        }
        
        console.log('处理五子棋移动');
        const updatedGame = makeGomokuMove(data.gameId, socket.id, data.x, data.y);
        console.log('更新后的游戏:', updatedGame);
        
        if (updatedGame) {
            // 从map中获取最新的游戏状态
            const latestGame = games.get(data.gameId);
            console.log('从map中获取的最新游戏:', latestGame);
            
            if (!latestGame) {
                console.log('无法获取最新游戏状态');
                return;
            }
            
            // 通知所有玩家移动结果
            console.log('通知玩家:', latestGame.players);
            latestGame.players.forEach(playerSocketId => {
                io.to(playerSocketId).emit('game-update', {
                    gameId: latestGame.id,
                    gameType: 'gomoku',
                    board: latestGame.board,
                    currentPlayer: latestGame.currentPlayer,
                    lastMove: { x: data.x, y: data.y, player: socket.id },
                    status: latestGame.status,
                    winner: latestGame.winner,
                    players: latestGame.players.map(pid => ({
                        socketId: pid,
                        username: users.get(pid)?.username || '未知'
                    }))
                });
                console.log('已向玩家发送游戏更新:', playerSocketId);
            });
            
            // 通知观战者
            console.log('通知观战者:', latestGame.spectators);
            latestGame.spectators.forEach(spectatorSocketId => {
                io.to(spectatorSocketId).emit('game-update', {
                    gameId: latestGame.id,
                    gameType: 'gomoku',
                    board: latestGame.board,
                    currentPlayer: latestGame.currentPlayer,
                    lastMove: { x: data.x, y: data.y, player: socket.id },
                    status: latestGame.status,
                    winner: latestGame.winner,
                    players: latestGame.players.map(pid => ({
                        socketId: pid,
                        username: users.get(pid)?.username || '未知'
                    }))
                });
                console.log('已向观战者发送游戏更新:', spectatorSocketId);
            });
            
            if (latestGame.status === 'ended') {
                const winnerUser = users.get(latestGame.winner);
                console.log(`[房间 ${user.roomName}] 五子棋游戏 ${latestGame.id} 结束，赢家: ${winnerUser?.username || '未知'}`);
            }
        } else {
            console.log('makeGomokuMove返回null');
        }
    });
    
    // 你画我猜游戏猜词事件
    socket.on('game-guess', (data) => {
        const user = users.get(socket.id);
        if (user && data.gameId && data.guess) {
            const game = games.get(data.gameId);
            if (game && game.type === 'pictionary' && game.status === 'playing') {
                const updatedGame = makePictionaryGuess(data.gameId, socket.id, data.guess);
                if (updatedGame) {
                    // 通知所有玩家猜测结果
                    updatedGame.players.forEach(playerSocketId => {
                        const isDrawer = playerSocketId === updatedGame.currentDrawer;
                        io.to(playerSocketId).emit('game-update', {
                            gameId: updatedGame.id,
                            gameType: 'pictionary',
                            currentDrawer: updatedGame.currentDrawer,
                            currentDrawerName: users.get(updatedGame.currentDrawer)?.username || '未知',
                            currentWord: isDrawer ? updatedGame.currentWord : null,
                            wordHint: updatedGame.currentWord.length + '个字',
                            scores: Object.fromEntries(updatedGame.scores),
                            currentRound: updatedGame.currentRound,
                            maxRounds: updatedGame.maxRounds,
                            guesses: updatedGame.guesses.map(guess => ({
                                ...guess,
                                username: users.get(guess.playerSocketId)?.username || '未知'
                            })),
                            status: updatedGame.status,
                            winner: updatedGame.winner,
                            lastGuess: {
                                player: socket.id,
                                username: user.username,
                                guess: data.guess,
                                isCorrect: updatedGame.guesses[updatedGame.guesses.length - 1]?.isCorrect || false
                            }
                        });
                    });
                    
                    // 通知观战者
                    updatedGame.spectators.forEach(spectatorSocketId => {
                        io.to(spectatorSocketId).emit('game-update', {
                            gameId: updatedGame.id,
                            gameType: 'pictionary',
                            currentDrawer: updatedGame.currentDrawer,
                            currentDrawerName: users.get(updatedGame.currentDrawer)?.username || '未知',
                            scores: Object.fromEntries(updatedGame.scores),
                            currentRound: updatedGame.currentRound,
                            maxRounds: updatedGame.maxRounds,
                            guesses: updatedGame.guesses.map(guess => ({
                                ...guess,
                                username: users.get(guess.playerSocketId)?.username || '未知'
                            })),
                            status: updatedGame.status,
                            winner: updatedGame.winner,
                            lastGuess: {
                                player: socket.id,
                                username: user.username,
                                guess: data.guess,
                                isCorrect: updatedGame.guesses[updatedGame.guesses.length - 1]?.isCorrect || false
                            }
                        });
                    });
                    
                    if (updatedGame.status === 'ended') {
                        const winnerUser = users.get(updatedGame.winner);
                        console.log(`[房间 ${user.roomName}] 你画我猜游戏 ${updatedGame.id} 结束，赢家: ${winnerUser?.username || '未知'}`);
                    }
                }
            }
        }
    });
    
    // 你画我猜游戏：画者主动宣告画完，切换下一轮
    socket.on('game-finish-drawing', (data) => {
        const user = users.get(socket.id);
        if (!user || !data.gameId) return;
        const game = games.get(data.gameId);
        if (!game || game.type !== 'pictionary' || game.status !== 'playing' || game.currentDrawer !== socket.id) return;

        // 本轮无人猜对，直接推进到下一轮
        game.currentRound++;
        if (game.currentRound < game.maxRounds) {
            const nextDrawerIndex = (game.players.indexOf(game.currentDrawer) + 1) % game.players.length;
            game.currentDrawer = game.players[nextDrawerIndex];
            game.currentWord = game.words[Math.floor(Math.random() * game.words.length)];
            game.roundStartTime = new Date();
            game.guesses = [];
        } else {
            game.status = 'ended';
            game.endTime = new Date();
            let maxScore = 0, winnerSocketId = null;
            game.scores.forEach((score, sid) => { if (score > maxScore) { maxScore = score; winnerSocketId = sid; } });
            game.winner = winnerSocketId;
        }
        games.set(data.gameId, game);

        // 广播给所有玩家
        game.players.forEach(playerSocketId => {
            const isDrawer = playerSocketId === game.currentDrawer;
            io.to(playerSocketId).emit('game-update', {
                gameId: game.id,
                gameType: 'pictionary',
                currentDrawer: game.currentDrawer,
                currentDrawerName: users.get(game.currentDrawer)?.username || '未知',
                currentWord: isDrawer ? game.currentWord : null,
                wordHint: game.currentWord ? (game.currentWord.length + '个字') : '',
                scores: Object.fromEntries(game.scores),
                currentRound: game.currentRound,
                maxRounds: game.maxRounds,
                guesses: [],
                status: game.status,
                winner: game.winner,
                finishedByDrawer: true   // 前端用于提示"画者宣告结束"
            });
        });
        game.spectators.forEach(sid => {
            io.to(sid).emit('game-update', {
                gameId: game.id,
                gameType: 'pictionary',
                currentDrawer: game.currentDrawer,
                currentDrawerName: users.get(game.currentDrawer)?.username || '未知',
                scores: Object.fromEntries(game.scores),
                currentRound: game.currentRound,
                maxRounds: game.maxRounds,
                guesses: [],
                status: game.status,
                winner: game.winner,
                finishedByDrawer: true
            });
        });

        if (game.status === 'ended') {
            recordGameHistory(game);
            console.log(`[房间 ${user.roomName}] 你画我猜游戏 ${game.id} 结束`);
        } else {
            console.log(`[房间 ${user.roomName}] ${user.username} 画完了，进入第 ${game.currentRound + 1} 轮`);
        }
    });

    // 你画我猜游戏跳过词汇事件
    socket.on('game-skip-word', (data) => {
        const user = users.get(socket.id);
        if (user && data.gameId) {
            const game = games.get(data.gameId);
            if (game && game.type === 'pictionary' && game.status === 'playing' && game.currentDrawer === socket.id) {
                const updatedGame = skipWord(data.gameId);
                if (updatedGame) {
                    // 通知所有玩家词汇已跳过
                    updatedGame.players.forEach(playerSocketId => {
                        const isDrawer = playerSocketId === updatedGame.currentDrawer;
                        io.to(playerSocketId).emit('game-update', {
                            gameId: updatedGame.id,
                            gameType: 'pictionary',
                            currentDrawer: updatedGame.currentDrawer,
                            currentDrawerName: users.get(updatedGame.currentDrawer)?.username || '未知',
                            currentWord: isDrawer ? updatedGame.currentWord : '???',
                            scores: Object.fromEntries(updatedGame.scores),
                            currentRound: updatedGame.currentRound,
                            maxRounds: updatedGame.maxRounds,
                            guesses: [],
                            status: updatedGame.status
                        });
                    });
                    
                    console.log(`[房间 ${user.roomName}] ${user.username} 跳过了词汇，新词汇: ${updatedGame.currentWord}`);
                }
            }
        }
    });
    
    // 你画我猜游戏绘画事件
    socket.on('game-draw', (data) => {
        const user = users.get(socket.id);
        if (user && data.gameId && data.drawingData) {
            const game = games.get(data.gameId);
            if (game && game.type === 'pictionary' && game.status === 'playing' && game.currentDrawer === socket.id) {
                // 广播绘画数据给其他玩家
                game.players.forEach(playerSocketId => {
                    if (playerSocketId !== socket.id) {
                        io.to(playerSocketId).emit('game-draw', {
                            gameId: game.id,
                            drawingData: data.drawingData
                        });
                    }
                });
                
                // 广播绘画数据给观战者
                game.spectators.forEach(spectatorSocketId => {
                    io.to(spectatorSocketId).emit('game-draw', {
                        gameId: game.id,
                        drawingData: data.drawingData
                    });
                });
            }
        }
    });
    
    // 你画我猜游戏清空画布事件
    socket.on('game-clear-canvas', (data) => {
        const user = users.get(socket.id);
        if (user && data.gameId) {
            const game = games.get(data.gameId);
            if (game && game.type === 'pictionary' && game.status === 'playing' && game.currentDrawer === socket.id) {
                // 广播清空画布事件给其他玩家
                game.players.forEach(playerSocketId => {
                    if (playerSocketId !== socket.id) {
                        io.to(playerSocketId).emit('game-clear-canvas', {
                            gameId: game.id
                        });
                    }
                });
                
                // 广播清空画布事件给观战者
                game.spectators.forEach(spectatorSocketId => {
                    io.to(spectatorSocketId).emit('game-clear-canvas', {
                        gameId: game.id
                    });
                });
            }
        }
    });
    
    // 猜数字游戏：玩家提交猜测
    socket.on('guess-number-guess', (data) => {
        const user = users.get(socket.id);
        if (!user || !data.gameId || data.guess === undefined) return;

        const guessValue = parseInt(data.guess, 10);
        if (isNaN(guessValue) || guessValue < 1 || guessValue > 100) {
            socket.emit('guess-number-error', { message: '请输入 1~100 之间的整数' });
            return;
        }

        const res = makeGuessNumberGuess(data.gameId, socket.id, guessValue);
        if (!res) {
            socket.emit('guess-number-error', { message: '操作无效，请检查游戏状态' });
            return;
        }

        const { game, result } = res;

        // 通知所有玩家和观战者最新游戏状态
        const payload = {
            gameId: game.id,
            guesserSocketId: socket.id,
            guesserUsername: user.username,
            guess: guessValue,
            result,           // 'low' | 'high' | 'correct'
            guessCounts: game.guessCounts,
            currentGuesser: game.currentGuesser,
            status: game.status,
            winner: game.winner,
            winnerName: game.winner ? (users.get(game.winner)?.username || '未知') : null
        };

        [...game.players, ...game.spectators].forEach(pid => {
            io.to(pid).emit('guess-number-update', payload);
        });

        // 游戏结束时记录历史
        if (game.status === 'ended') {
            recordGameHistory(game);
            console.log(`[房间 ${user.roomName}] 猜数字游戏 ${game.id} 结束，胜者: ${users.get(game.winner)?.username}`);
        }
    });

    socket.on('game-spectate', (data) => {
        const user = users.get(socket.id);
        if (user && data.gameId) {
            const game = games.get(data.gameId);
            if (game) {
                if (!game.spectators.includes(socket.id)) {
                    game.spectators.push(socket.id);
                }
                
                if (game.type === 'gomoku') {
                    // 发送五子棋游戏状态给观战者
                    socket.emit('game-spectate-success', {
                        gameId: game.id,
                        gameType: 'gomoku',
                        board: game.board,
                        currentPlayer: game.currentPlayer,
                        status: game.status,
                        players: game.players.map(pid => ({
                            socketId: pid,
                            username: users.get(pid)?.username || '未知'
                        })),
                        winner: game.winner
                    });
                } else if (game.type === 'pictionary') {
                    // 发送你画我猜游戏状态给观战者
                    socket.emit('game-spectate-success', {
                        gameId: game.id,
                        gameType: 'pictionary',
                        players: game.players.map(pid => ({
                            socketId: pid,
                            username: users.get(pid)?.username || '未知'
                        })),
                        currentDrawer: game.currentDrawer,
                        currentDrawerName: users.get(game.currentDrawer)?.username || '未知',
                        scores: Object.fromEntries(game.scores),
                        currentRound: game.currentRound,
                        maxRounds: game.maxRounds,
                        guesses: game.guesses.map(guess => ({
                            ...guess,
                            username: users.get(guess.playerSocketId)?.username || '未知'
                        })),
                        status: game.status,
                        winner: game.winner
                    });
                } else if (game.type === 'guess-number') {
                    socket.emit('game-spectate-success', {
                        gameId: game.id,
                        gameType: 'guess-number',
                        players: game.players.map(pid => ({
                            socketId: pid,
                            username: users.get(pid)?.username || game.playerNames?.[pid] || '未知'
                        })),
                        currentGuesser: game.currentGuesser,
                        status: game.status,
                        winner: game.winner
                    });
                } else if (game.type === 'rps') {
                    socket.emit('game-spectate-success', {
                        gameId: game.id,
                        gameType: 'rps',
                        players: game.players.map(p => ({
                            socketId: p,
                            username: game.playerNames[p]
                        })),
                        wins: { ...game.wins },
                        maxWins: game.maxWins,
                        round: game.round,
                        status: game.status,
                        champion: game.champion || null
                    });
                } else if (game.type === 'bomb') {
                    socket.emit('game-spectate-success', {
                        gameId: game.id,
                        gameType: 'bomb',
                        players: game.players.map(p => ({
                            socketId: p,
                            username: game.playerNames[p]
                        })),
                        maxStep: game.maxStep,
                        current: game.current,
                        currentPlayer: game.players[game.currentPlayerIdx] || null,
                        history: game.history || [],
                        status: game.status,
                        loser: game.loser || null
                    });
                }
                
                console.log(`[房间 ${user.roomName}] ${user.username} 开始观战游戏 ${game.id}`);
            }
        }
    });
    
    socket.on('game-leave', (data) => {
        const user = users.get(socket.id);
        if (user && data.gameId) {
            const game = games.get(data.gameId);
            if (game) {
                // 从玩家列表移除
                game.players = game.players.filter(pid => pid !== socket.id);
                // 从观战者列表移除
                game.spectators = game.spectators.filter(sid => sid !== socket.id);
                
                if (game.players.length === 0) {
                    // 所有人都走了，删除游戏
                    games.delete(data.gameId);
                } else if (game.status === 'playing') {
                    // 对手中途离开，游戏结束（离开者判负）
                    game.status = 'ended';
                    game.winner = game.players[0]; // 留下来的玩家获胜
                    game.endTime = new Date();
                    games.set(data.gameId, game);
                    
                    // 通知剩余玩家和观战者
                    const notifyList = [...game.players, ...game.spectators];
                    notifyList.forEach(sid => {
                        io.to(sid).emit('game-update', {
                            gameId: game.id,
                            gameType: game.type,
                            board: game.board,
                            currentPlayer: null,
                            status: 'ended',
                            winner: game.winner,
                            players: game.players.map(pid => ({
                                socketId: pid,
                                username: users.get(pid)?.username || '未知'
                            })),
                            leaveMessage: `${user.username} 已离开游戏`
                        });
                    });
                } else {
                    // 等待阶段有人离开，更新状态
                    games.set(data.gameId, game);
                }
                
                console.log(`[房间 ${user.roomName}] ${user.username} 离开了游戏 ${game.id}`);
            }
        }
    });
    
    // 执行插件命令
    async function executePluginCommand(plugin, command, args, user) {
        switch (plugin.id) {
            case 'weather':
                await executeWeatherPlugin(command, args, user);
                break;
            case 'translator':
                executeTranslatorPlugin(command, args, user);
                break;
            case 'games':
                executeGamesPlugin(command, args, user);
                break;
            case 'vote':
                executeVotePlugin(command, args, user);
                break;
            default:
                // 处理自定义插件
                break;
        }
    }
    
    // 天气插件
    async function executeWeatherPlugin(command, args, user) {
        const city = args.join(' ');
        if (!city) {
            socket.emit('plugin-response', {
                pluginId: 'weather',
                success: false,
                message: '请输入城市名称，例如: /weather 北京'
            });
            return;
        }
        
        try {
            // 使用实际的天气API获取数据
            const weatherData = await getWeather(city);
            
            socket.emit('plugin-response', {
                pluginId: 'weather',
                success: true,
                data: weatherData,
                message: `🌤️ ${city} 的天气：${weatherData.weather}，温度 ${weatherData.temperature}，湿度 ${weatherData.humidity}%，风力 ${weatherData.wind}`
            });
            
            // 广播天气信息给房间内所有用户
            socket.to(user.roomName).emit('plugin-broadcast', {
                pluginId: 'weather',
                username: user.username,
                message: `🌤️ ${user.username} 查询了 ${city} 的天气：${weatherData.weather}，温度 ${weatherData.temperature}`
            });
        } catch (error) {
            console.error('天气查询失败:', error);
            socket.emit('plugin-response', {
                pluginId: 'weather',
                success: false,
                message: '天气查询失败，请稍后重试'
            });
        }
    }
    
    // 翻译插件
    function executeTranslatorPlugin(command, args, user) {
        const text = args.join(' ');
        if (!text) {
            socket.emit('plugin-response', {
                pluginId: 'translator',
                success: false,
                message: '请输入要翻译的文本，例如: /translate Hello world'
            });
            return;
        }
        
        // 模拟翻译（实际项目中可以使用真实的翻译API）
        const translations = {
            'hello': '你好',
            'world': '世界',
            'hello world': '你好世界',
            'how are you': '你好吗',
            'thank you': '谢谢',
            'goodbye': '再见'
        };
        
        const translatedText = translations[text.toLowerCase()] || `[翻译] ${text}`;
        
        socket.emit('plugin-response', {
            pluginId: 'translator',
            success: true,
            data: {
                original: text,
                translated: translatedText
            },
            message: `🌍 翻译结果：${translatedText}`
        });
    }
    
    // 游戏管理系统（使用全局 games Map）
    
    // 五子棋游戏逻辑
    function createGomokuGame(creator, roomName) {
        const gameId = `gomoku-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
        const game = {
            id: gameId,
            type: 'gomoku',
            creator: creator.username,
            creatorSocketId: creator.socketId,
            roomName: roomName,
            players: [creator.socketId],
            board: Array(15).fill().map(() => Array(15).fill(null)),
            currentPlayer: creator.socketId,
            status: 'waiting', // waiting, playing, ended
            startTime: null,
            endTime: null,
            winner: null,
            spectators: []
        };
        
        games.set(gameId, game);
        return game;
    }
    
    function joinGomokuGame(gameId, playerSocketId, playerUsername) {
        const game = games.get(gameId);
        if (game && game.status === 'waiting' && game.players.length < 2) {
            game.players.push(playerSocketId);
            game.status = 'playing';
            game.startTime = new Date();
            games.set(gameId, game); // 更新游戏状态到map
            return game;
        }
        return null;
    }
    
    function makeGomokuMove(gameId, playerSocketId, x, y) {
        const game = games.get(gameId);
        if (!game || game.status !== 'playing') return null;
        
        if (game.currentPlayer !== playerSocketId) return null;
        if (game.board[x][y] !== null) return null;
        
        // 落子
        game.board[x][y] = playerSocketId;
        
        // 检查胜负
        if (checkGomokuWin(game.board, x, y, playerSocketId)) {
            game.status = 'ended';
            game.endTime = new Date();
            game.winner = playerSocketId;
        } else {
            // 切换玩家
            game.currentPlayer = game.players[0] === playerSocketId ? game.players[1] : game.players[0];
        }
        
        games.set(gameId, game); // 更新游戏状态到map
        return game;
    }
    
    function checkGomokuWin(board, x, y, player) {
        const directions = [
            [1, 0], // 水平
            [0, 1], // 垂直
            [1, 1], // 对角线
            [1, -1] // 反对角线
        ];
        
        for (const [dx, dy] of directions) {
            let count = 1;
            
            // 正向检查
            for (let i = 1; i < 5; i++) {
                const nx = x + i * dx;
                const ny = y + i * dy;
                if (nx >= 0 && nx < 15 && ny >= 0 && ny < 15 && board[nx][ny] === player) {
                    count++;
                } else {
                    break;
                }
            }
            
            // 反向检查
            for (let i = 1; i < 5; i++) {
                const nx = x - i * dx;
                const ny = y - i * dy;
                if (nx >= 0 && nx < 15 && ny >= 0 && ny < 15 && board[nx][ny] === player) {
                    count++;
                } else {
                    break;
                }
            }
            
            if (count >= 5) {
                return true;
            }
        }
        
        return false;
    }
    
    // 猜数字游戏逻辑（1-100，双方轮流猜同一个数，猜对者赢）
    function createGuessNumberGame(creator, roomName) {
        const gameId = `guess-number-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
        const secret = Math.floor(Math.random() * 100) + 1; // 服务端随机生成的唯一秘密数字，双方轮流猜它
        const game = {
            id: gameId,
            type: 'guess-number',
            creator: creator.username,
            creatorSocketId: creator.socketId,
            roomName: roomName,
            players: [creator.socketId],
            spectators: [],
            status: 'waiting',       // waiting → playing → ended
            secret: secret,
            guesses: {},             // Map<socketId, [{guess, result, timestamp}]>
            guessCounts: {},         // Map<socketId, number>
            currentGuesser: null,    // 当前该谁猜
            startTime: null,
            endTime: null,
            winner: null
        };
        games.set(gameId, game);
        console.log(`[猜数字游戏] 游戏 ${gameId} 创建，秘密数字：${secret}`);
        return game;
    }

    function joinGuessNumberGame(gameId, playerSocketId) {
        const game = games.get(gameId);
        if (!game || game.status !== 'waiting' || game.players.length >= 2) return null;

        game.players.push(playerSocketId);
        // 秘密数字已经在创建游戏时生成
        game.players.forEach(pid => {
            game.guesses[pid] = [];
            game.guessCounts[pid] = 0;
        });
        // 邀请发起者先猜
        game.currentGuesser = game.players[0];
        game.status = 'playing';
        game.startTime = new Date();
        games.set(gameId, game);
        return game;
    }

    // 双方轮流猜同一个秘密数字，猜对者赢
    function makeGuessNumberGuess(gameId, guesserSocketId, guessValue) {
        const game = games.get(gameId);
        if (!game || game.status !== 'playing') return null;
        if (!game.players.includes(guesserSocketId)) return null;
        // 非当前轮次，拒绝
        if (game.currentGuesser !== guesserSocketId) return null;

        const secret = game.secret;
        let result;
        if (guessValue < secret)       result = 'low';
        else if (guessValue > secret)  result = 'high';
        else                           result = 'correct';

        game.guesses[guesserSocketId].push({
            guess: guessValue,
            result,
            timestamp: new Date().toISOString()
        });
        game.guessCounts[guesserSocketId]++;

        if (result === 'correct') {
            // 猜对则游戏结束
            game.status = 'ended';
            game.endTime = new Date();
            game.winner = guesserSocketId;
        } else {
            // 猜错则切换给对方
            game.currentGuesser = game.players.find(pid => pid !== guesserSocketId);
        }

        games.set(gameId, game);
        return { game, result };
    }

    // 你画我猜游戏逻辑
    function createPictionaryGame(creator, roomName) {
        const gameId = `pictionary-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
        
        // 游戏词汇库
        const words = [
            // 🍎 水果蔬菜
            '苹果', '香蕉', '葡萄', '西瓜', '草莓', '菠萝', '橙子', '樱桃', '芒果', '柠檬',
            '白菜', '番茄', '黄瓜', '玉米', '蘑菇', '南瓜', '胡萝卜', '辣椒', '大蒜', '洋葱',
            // 🐶 动物
            '猫', '狗', '鱼', '鸟', '兔子', '熊猫', '老虎', '大象', '长颈鹿', '企鹅',
            '鳄鱼', '猴子', '斑马', '骆驼', '蜗牛', '蝴蝶', '乌龟', '螃蟹', '蜜蜂', '鲨鱼',
            // ✈️ 交通工具
            '飞机', '汽车', '自行车', '摩托车', '轮船', '火车', '地铁', '直升机', '潜水艇', '热气球',
            // ⚽ 运动
            '足球', '篮球', '乒乓球', '羽毛球', '网球', '游泳', '滑板', '跳绳', '钓鱼', '爬山',
            // 🏠 家居物品
            '电视', '冰箱', '电脑', '手机', '雨伞', '手表', '眼镜', '帽子', '鞋子', '书包',
            '枕头', '镜子', '蜡烛', '钥匙', '剪刀', '台灯', '风扇', '锁头', '毛巾', '牙刷',
            // 🍔 食物
            '蛋糕', '汉堡', '披萨', '寿司', '火锅', '冰淇淋', '面条', '饺子', '包子', '炒饭',
            '薯条', '爆米花', '糖果', '巧克力', '奶茶', '咖啡', '面包', '鸡腿', '烤鸭', '螺蛳粉',
            // 🌲 自然景物
            '山', '海', '树', '花', '太阳', '月亮', '星星', '彩虹', '云朵', '瀑布',
            '沙漠', '火山', '闪电', '雪花', '彩霞', '河流', '草地', '森林', '洞穴', '岛屿',
            // 🏫 场所
            '学校', '医院', '公园', '超市', '餐厅', '电影院', '动物园', '图书馆', '游乐场', '加油站',
            '机场', '地铁站', '海滩', '操场', '教室',
            // 🎭 职业与人物
            '厨师', '警察', '护士', '老师', '消防员', '宇航员', '魔法师', '海盗', '忍者', '超人',
            // 🎮 娱乐
            '吉他', '钢琴', '麦克风', '魔方', '风筝', '扑克', '棋盘', '玩偶', '气球', '烟花',
            // 😀 表情与动作
            '跑步', '跳舞', '睡觉', '哭泣', '大笑', '拥抱', '飞翔', '游泳', '打架', '变魔术'
        ];
        
        const game = {
            id: gameId,
            type: 'pictionary',
            creator: creator.username,
            creatorSocketId: creator.socketId,
            roomName: roomName,
            players: [creator.socketId],
            spectators: [],
            status: 'waiting', // waiting, playing, ended
            currentRound: 0,
            maxRounds: 5,
            currentDrawer: creator.socketId,
            currentWord: words[Math.floor(Math.random() * words.length)],
            words: words,
            scores: new Map(), // Map<socketId, score>
            startTime: null,
            endTime: null,
            winner: null,
            roundStartTime: null,
            roundTimeLimit: 60, // 每轮60秒
            guesses: [] // 存储猜测记录
        };
        
        // 初始化分数
        game.players.forEach(playerSocketId => {
            game.scores.set(playerSocketId, 0);
        });
        
        games.set(gameId, game);
        return game;
    }
    
    function joinPictionaryGame(gameId, playerSocketId, playerUsername) {
        const game = games.get(gameId);
        if (game && game.status === 'waiting') {
            game.players.push(playerSocketId);
            game.scores.set(playerSocketId, 0);
            
            if (game.players.length >= 2) {
                game.status = 'playing';
                game.startTime = new Date();
                game.roundStartTime = new Date();
            }
            games.set(gameId, game); // 更新游戏状态到map
            return game;
        }
        return null;
    }
    
    function makePictionaryGuess(gameId, playerSocketId, guess) {
        const game = games.get(gameId);
        if (!game || game.status !== 'playing') return null;
        
        if (game.currentDrawer === playerSocketId) return null;
        
        const normalizedGuess = guess.toLowerCase().trim();
        const normalizedWord = game.currentWord.toLowerCase().trim();
        
        // 检查猜测是否正确
        const isCorrect = normalizedGuess === normalizedWord;
        
        // 记录猜测
        game.guesses.push({
            playerSocketId: playerSocketId,
            guess: guess,
            isCorrect: isCorrect,
            timestamp: new Date()
        });
        
        if (isCorrect) {
            // 加分
            const currentScore = game.scores.get(playerSocketId) || 0;
            game.scores.set(playerSocketId, currentScore + 10);
            
            // 切换到下一轮
            game.currentRound++;
            if (game.currentRound < game.maxRounds) {
                // 更换 drawer
                const nextDrawerIndex = (game.players.indexOf(game.currentDrawer) + 1) % game.players.length;
                game.currentDrawer = game.players[nextDrawerIndex];
                // 更换词汇
                game.currentWord = game.words[Math.floor(Math.random() * game.words.length)];
                game.roundStartTime = new Date();
                game.guesses = [];
            } else {
                // 游戏结束
                game.status = 'ended';
                game.endTime = new Date();
                
                // 计算赢家
                let maxScore = 0;
                let winnerSocketId = null;
                game.scores.forEach((score, socketId) => {
                    if (score > maxScore) {
                        maxScore = score;
                        winnerSocketId = socketId;
                    }
                });
                game.winner = winnerSocketId;
            }
        }
        
        return game;
    }
    
    function skipWord(gameId) {
        const game = games.get(gameId);
        if (game && game.status === 'playing') {
            game.currentWord = game.words[Math.floor(Math.random() * game.words.length)];
            game.roundStartTime = new Date();
            game.guesses = [];
            return game;
        }
        return null;
    }
    
    // ============================================================
    // 剪刀石头布游戏逻辑（先赢3局胜出）
    // ============================================================
    function createRPSGame(creator, roomName) {
        const gameId = `rps-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
        const game = {
            id: gameId,
            type: 'rps',
            status: 'waiting',
            roomName: roomName,
            players: [creator.socketId],
            playerNames: { [creator.socketId]: creator.username },
            wins: { [creator.socketId]: 0 },
            choices: {},   // 当前局双方出招
            round: 1,
            maxWins: 3,
            roundResult: null,
            spectators: [],
            createdAt: new Date()
        };
        games.set(gameId, game);
        return game;
    }

    function joinRPSGame(gameId, playerSocketId, playerUsername) {
        const game = games.get(gameId);
        if (game && game.status === 'waiting' && game.players.length < 2) {
            game.players.push(playerSocketId);
            game.playerNames[playerSocketId] = playerUsername;
            game.wins[playerSocketId] = 0;
            game.status = 'playing';
            games.set(gameId, game);
            return game;
        }
        return null;
    }

    // 出招：choice = 'rock'|'paper'|'scissors'
    function makeRPSMove(gameId, playerSocketId, choice) {
        const game = games.get(gameId);
        if (!game || game.type !== 'rps' || game.status !== 'playing') return null;
        if (!game.players.includes(playerSocketId)) return null;
        if (game.choices[playerSocketId]) return null; // 已出招

        game.choices[playerSocketId] = choice;

        // 双方都出招了，结算
        if (Object.keys(game.choices).length === 2) {
            const [p1, p2] = game.players;
            const c1 = game.choices[p1];
            const c2 = game.choices[p2];
            let winner = null;
            const beats = { rock: 'scissors', scissors: 'paper', paper: 'rock' };
            if (c1 === c2) {
                winner = 'draw';
            } else if (beats[c1] === c2) {
                winner = p1;
            } else {
                winner = p2;
            }
            game.roundResult = { winner, choices: { ...game.choices }, round: game.round };
            if (winner !== 'draw') game.wins[winner] = (game.wins[winner] || 0) + 1;

            // 判断是否有人赢得整场比赛
            const champion = game.players.find(p => game.wins[p] >= game.maxWins);
            if (champion) {
                game.status = 'finished';
                game.champion = champion;
            } else {
                game.round++;
                game.choices = {};
            }
        }
        games.set(gameId, game);
        return game;
    }

    // ============================================================
    // 数字炸弹游戏逻辑（轮流报数，随机炸弹数，超过者输）
    // ============================================================
    function createBombGame(creator, roomName) {
        const gameId = `bomb-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
        const bombNumber = Math.floor(Math.random() * 50) + 10; // 炸弹数范围 10-59
        const maxStep = Math.floor(Math.random() * 3) + 1;      // 每轮可报1~maxStep个数
        const game = {
            id: gameId,
            type: 'bomb',
            status: 'waiting',
            roomName: roomName,
            players: [creator.socketId],
            playerNames: { [creator.socketId]: creator.username },
            bombNumber,
            maxStep,
            current: 0,          // 当前已报到的数
            currentPlayerIdx: 0, // 当前轮到哪位玩家
            history: [],         // [{player, from, to}]
            loser: null,
            spectators: [],
            createdAt: new Date()
        };
        games.set(gameId, game);
        return game;
    }

    function joinBombGame(gameId, playerSocketId, playerUsername) {
        const game = games.get(gameId);
        if (game && game.status === 'waiting' && game.players.length < 2) {
            game.players.push(playerSocketId);
            game.playerNames[playerSocketId] = playerUsername;
            game.status = 'playing';
            games.set(gameId, game);
            return game;
        }
        return null;
    }

    // count: 本次报的数字个数 (1~maxStep)
    function makeBombMove(gameId, playerSocketId, count) {
        const game = games.get(gameId);
        if (!game || game.type !== 'bomb' || game.status !== 'playing') return null;
        if (game.players[game.currentPlayerIdx] !== playerSocketId) return null;
        if (count < 1 || count > game.maxStep) return null;

        const from = game.current + 1;
        const to = game.current + count;

        game.history.push({ player: playerSocketId, from, to, count });
        game.current = to;

        if (to >= game.bombNumber) {
            // 报到或超过炸弹数，这个玩家输
            game.status = 'finished';
            game.loser = playerSocketId;
        } else {
            // 换人
            game.currentPlayerIdx = (game.currentPlayerIdx + 1) % game.players.length;
        }
        games.set(gameId, game);
        return game;
    }

    // ============================================================
    // 打字对战游戏逻辑
    // ============================================================
    const TYPING_TEXTS = [
        '青山依旧在，几度夕阳红。白发渔樵江渚上，惯看秋月春风。',
        '落霞与孤鹜齐飞，秋水共长天一色。渔舟唱晚，响穷彭蠡之滨。',
        '人生若只如初见，何事秋风悲画扇。等闲变却故人心，却道故人心易变。',
        '春风得意马蹄疾，一日看尽长安花。天生我材必有用，千金散尽还复来。',
        '明月几时有？把酒问青天。不知天上宫阙，今夕是何年。',
        '会当凌绝顶，一览众山小。烽火连三月，家书抵万金。',
        '桃花潭水深千尺，不及汪伦送我情。孤帆远影碧空尽，唯见长江天际流。',
        '床前明月光，疑是地上霜。举头望明月，低头思故乡。',
        '欲穷千里目，更上一层楼。野旷天低树，江清月近人。'
    ];

    function createTypingGame(creator, roomName) {
        const gameId = 'typing_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
        const text = TYPING_TEXTS[Math.floor(Math.random() * TYPING_TEXTS.length)];
        const game = {
            id: gameId,
            type: 'typing',
            roomName,
            players: [creator.socketId],
            playerNames: { [creator.socketId]: creator.username },
            text,
            progress: { [creator.socketId]: 0 },   // 已正确打完的字符数
            errors: { [creator.socketId]: 0 },
            finishTime: {},
            status: 'waiting',
            startTime: null,
            endTime: null,
            spectators: [],
            createdAt: new Date()
        };
        games.set(gameId, game);
        return game;
    }

    function joinTypingGame(gameId, playerSocketId, playerUsername) {
        const game = games.get(gameId);
        if (game && game.type === 'typing' && game.status === 'waiting' && game.players.length < 2) {
            game.players.push(playerSocketId);
            game.playerNames[playerSocketId] = playerUsername;
            game.progress[playerSocketId] = 0;
            game.errors[playerSocketId] = 0;
            game.status = 'playing';
            game.startTime = new Date();
            games.set(gameId, game);
            return game;
        }
        return null;
    }

    // 注册打字对战 Socket 事件
    socket.on('typing-update', (data) => {
        const user = users.get(socket.id);
        if (!user || !data.gameId) return;
        const game = games.get(data.gameId);
        if (!game || game.type !== 'typing' || game.status !== 'playing') return;
        if (!game.players.includes(socket.id)) return;

        // 更新进度和错误数
        if (typeof data.progress === 'number') game.progress[socket.id] = data.progress;
        if (typeof data.errors === 'number')   game.errors[socket.id]   = data.errors;

        // 广播进度给对手
        const opponent = game.players.find(p => p !== socket.id);
        if (opponent) {
            io.to(opponent).emit('typing-opponent-update', {
                gameId: game.id,
                progress: data.progress,
                errors: data.errors,
                total: game.text.length
            });
        }

        // 检测完成
        if (data.progress >= game.text.length && !game.finishTime[socket.id]) {
            game.finishTime[socket.id] = Date.now();
            games.set(data.gameId, game);

            // 两人都完成，或先完成者直接获胜
            const allDone = game.players.every(p => game.finishTime[p]);
            if (allDone || true) {
                // 先完成者获胜（第一个触发的就算赢）
                const winner = socket.id;
                const timeCost = ((game.finishTime[socket.id] - game.startTime.getTime()) / 1000).toFixed(1);
                game.status = 'finished';
                game.endTime = new Date();
                game.winner = winner;
                games.set(data.gameId, game);

                game.players.forEach(pid => {
                    io.to(pid).emit('typing-finish', {
                        gameId: game.id,
                        winner,
                        winnerName: game.playerNames[winner],
                        timeCost,
                        progress: { ...game.progress },
                        errors: { ...game.errors },
                        playerNames: { ...game.playerNames }
                    });
                });

                console.log(`[房间 ${game.roomName}] 打字对战 ${game.id} 结束，${game.playerNames[winner]} 获胜`);
            }
        } else {
            games.set(data.gameId, game);
        }
    });

    // ============================================================
    // 俄罗斯方块对战游戏逻辑
    // ============================================================
    function createTetrisGame(creator, roomName) {
        const gameId = 'tetris_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
        const game = {
            id: gameId,
            type: 'tetris',
            roomName,
            players: [creator.socketId],
            playerNames: { [creator.socketId]: creator.username },
            status: 'waiting',
            createdAt: new Date(),
            spectators: [],
            boards: {}
        };
        games.set(gameId, game);
        return game;
    }

    function joinTetrisGame(gameId, playerSocketId, playerUsername) {
        const game = games.get(gameId);
        if (game && game.type === 'tetris' && game.status === 'waiting' && game.players.length < 2) {
            game.players.push(playerSocketId);
            game.playerNames[playerSocketId] = playerUsername;
            game.status = 'ready';
            game.startTime = new Date();
            games.set(gameId, game);
            return game;
        }
        return null;
    }

    // 注册俄罗斯方块 Socket 事件
    socket.on('tetris-start', (data) => {
        const user = users.get(socket.id);
        if (!user || !data.gameId) return;
        const game = games.get(data.gameId);
        if (!game || game.type !== 'tetris' || game.status !== 'ready') return;
        if (!game.players.includes(socket.id)) return;

        // 初始化每个玩家的游戏状态
        game.players.forEach(pid => {
            game.scores = game.scores || {};
            game.scores[pid] = 0;
            game.lines = game.lines || {};
            game.lines[pid] = 0;
        });
        game.status = 'playing';
        game.startTime = new Date();
        games.set(data.gameId, game);

        // 通知双方游戏开始
        game.players.forEach(pid => {
            io.to(pid).emit('tetris-started', {
                gameId: game.id,
                gameType: 'tetris',
                players: game.players.map(p => ({
                    socketId: p,
                    username: game.playerNames[p]
                }))
            });
        });

        socket.to(user.roomName).emit('game-started', {
            gameId: game.id,
            gameType: 'tetris',
            players: game.players.map(p => game.playerNames[p])
        });

        console.log(`[房间 ${game.roomName}] 俄罗斯方块对战 ${game.id} 开始`);
    });

    socket.on('tetris-update', (data) => {
        const user = users.get(socket.id);
        if (!user || !data.gameId) return;
        const game = games.get(data.gameId);
        if (!game || game.type !== 'tetris' || game.status !== 'playing') return;
        if (!game.players.includes(socket.id)) return;

        // 更新分数和消行
        if (typeof data.score === 'number') game.scores[socket.id] = data.score;
        if (typeof data.lines === 'number') game.lines[socket.id] = data.lines;

        // 同步棋盘状态给对手
        const opponent = game.players.find(p => p !== socket.id);
        if (opponent && data.board) {
            game.boards = game.boards || {};
            game.boards[socket.id] = data.board;
        }

        // 广播对手状态更新
        if (opponent) {
            io.to(opponent).emit('tetris-opponent-update', {
                gameId: game.id,
                score: data.score,
                lines: data.lines,
                board: data.board || null
            });
        }

        // 检测游戏结束（对手堆满）
        if (data.gameOver) {
            game.status = 'finished';
            game.endTime = new Date();
            game.winner = opponent;
            game.loser = socket.id;
            games.set(data.gameId, game);

            game.players.forEach(pid => {
                io.to(pid).emit('tetris-finish', {
                    gameId: game.id,
                    winner: opponent,
                    winnerName: game.playerNames[opponent],
                    scores: { ...game.scores },
                    lines: { ...game.lines },
                    playerNames: { ...game.playerNames }
                });
            });

            recordGameHistory(game);
            console.log(`[房间 ${game.roomName}] 俄罗斯方块对战 ${game.id} 结束，${game.playerNames[opponent]} 获胜`);
        } else {
            games.set(data.gameId, game);
        }
    });

    // 游戏插件
    function executeGamesPlugin(command, args, user) {
        const gameType = args[0] || 'help';
        
        switch (gameType) {
            case 'help':
                socket.emit('plugin-response', {
                    pluginId: 'games',
                    success: true,
                    message: '🎮 游戏列表：\n/游戏 gomoku - 五子棋\n/游戏 pictionary - 你画我猜\n/游戏 tic-tac-toe - 井字棋'
                });
                break;
            case 'gomoku':
                const gomokuGame = createGomokuGame(user, user.roomName);
                socket.emit('plugin-response', {
                    pluginId: 'games',
                    success: true,
                    message: '🎮 五子棋游戏创建成功，等待其他玩家加入...',
                    data: {
                        gameType: 'gomoku',
                        gameId: gomokuGame.id,
                        roomName: user.roomName
                    }
                });
                
                // 广播游戏创建事件
                socket.to(user.roomName).emit('game-created', {
                    gameType: 'gomoku',
                    gameId: gomokuGame.id,
                    creator: user.username,
                    roomName: user.roomName
                });
                break;
            case 'pictionary':
                const pictionaryGame = createPictionaryGame(user, user.roomName);
                socket.emit('plugin-response', {
                    pluginId: 'games',
                    success: true,
                    message: '🎮 你画我猜游戏创建成功，等待其他玩家加入...',
                    data: {
                        gameType: 'pictionary',
                        gameId: pictionaryGame.id,
                        roomName: user.roomName
                    }
                });
                
                // 广播游戏创建事件
                socket.to(user.roomName).emit('game-created', {
                    gameType: 'pictionary',
                    gameId: pictionaryGame.id,
                    creator: user.username,
                    roomName: user.roomName
                });
                break;
            default:
                socket.emit('plugin-response', {
                    pluginId: 'games',
                    success: false,
                    message: '未知的游戏类型，请输入 /游戏 help 查看游戏列表'
                });
        }
    }
    
    // 投票插件
    function executeVotePlugin(command, args, user) {
        const action = args[0] || 'help';
        
        switch (action) {
            case 'help':
                socket.emit('plugin-response', {
                    pluginId: 'vote',
                    success: true,
                    message: '🗳️ 投票系统：\n/投票 create 问题 选项1 选项2... - 创建投票\n/投票 list - 查看投票列表\n/投票 vote 投票ID 选项索引 - 投票'
                });
                break;
            case 'create':
                const question = args[1];
                const options = args.slice(2);
                if (!question || options.length < 2) {
                    socket.emit('plugin-response', {
                        pluginId: 'vote',
                        success: false,
                        message: '请输入问题和至少两个选项，例如: /投票 create 你喜欢什么颜色 红色 蓝色 绿色'
                    });
                    return;
                }
                
                // 创建投票（复用现有的投票系统）
                const pollId = `poll-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
                const poll = {
                    id: pollId,
                    creator: user.username,
                    question: question,
                    options: options.map((option, index) => ({
                        id: `option-${index}`,
                        text: option,
                        votes: 0
                    })),
                    votes: new Map(),
                    createdAt: new Date(),
                    endTime: null,
                    isActive: true,
                    roomName: user.roomName
                };
                
                activePolls.set(pollId, poll);
                
                socket.emit('plugin-response', {
                    pluginId: 'vote',
                    success: true,
                    message: `🗳️ 投票创建成功：${question}`
                });
                
                // 广播投票创建事件
                const room = rooms.get(user.roomName);
                if (room) {
                    const clientPoll = {
                        ...poll,
                        votes: poll.options.map(option => option.votes),
                        status: poll.isActive ? 'active' : 'ended',
                        votedUsers: [],
                        userVotes: {},
                        options: poll.options.map(option => option.text)
                    };
                    
                    socket.to(user.roomName).emit('poll-created', clientPoll);
                    socket.emit('poll-created', clientPoll);
                }
                break;
            default:
                socket.emit('plugin-response', {
                    pluginId: 'vote',
                    success: false,
                    message: '未知的投票命令，请输入 /投票 help 查看帮助'
                });
        }
    }
    
    // 在房间内修改用户权限
    socket.on('admin-room-set-permissions', (data) => {
        if (socket.id === adminSocketId) {
            const { roomName, socketId, permissions } = data;
            const room = rooms.get(roomName);
            if (room) {
                // 检查用户是否在该房间内
                if (room.users.includes(socketId)) {
                    const user = users.get(socketId);
                    if (user) {
                        user.permissions = {
                            ...user.permissions,
                            ...permissions
                        };
                        
                        // 发送权限更新通知
                        socket.emit('user-permissions-changed', {
                            socketId: socketId,
                            permissions: user.permissions,
                            users: room.users.map(userId => users.get(userId)).filter(user => user)
                        });
                        
                        console.log(`[房间 ${roomName}] 管理员更新了用户 ${user.username} 的权限: ${JSON.stringify(user.permissions)}`);
                    }
                }
            }
        }
    });
    
    // 在房间内重命名用户
    socket.on('admin-room-rename-user', (data) => {
        if (socket.id === adminSocketId) {
            const { roomName, socketId, newName } = data;
            const room = rooms.get(roomName);
            if (room) {
                // 检查用户是否在该房间内
                if (room.users.includes(socketId)) {
                    const user = users.get(socketId);
                    if (user) {
                        const oldName = user.username;
                        user.username = newName;
                        
                        // 发送重命名通知给房间内所有用户
                        room.users.forEach(userId => {
                            io.to(userId).emit('user-renamed', {
                                oldName: oldName,
                                newName: newName,
                                users: room.users.map(userId => users.get(userId)).filter(user => user)
                            });
                        });
                        
                        console.log(`[房间 ${roomName}] 管理员将 ${oldName} 重命名为 ${newName}`);
                    }
                }
            }
        }
    });

    socket.on('message-recall', (messageId) => {
        const user = users.get(socket.id);
        if (!user) {
            socket.emit('recall-failed', { message: '用户未登录，无法撤回消息' });
            return;
        }
        
        // 检查撤回消息权限
        if (!user.permissions.allowRecallMessage) {
            socket.emit('permission-denied', { message: '您没有撤回消息的权限' });
            return;
        }
        
        const room = rooms.get(user.roomName);
        if (!room) {
            socket.emit('recall-failed', { message: '房间不存在' });
            return;
        }
        
        // 查找要撤回的消息
        const messageIndex = room.messages.findIndex(msg => msg.id === messageId);
        if (messageIndex === -1) {
            socket.emit('recall-failed', { message: '消息不存在或已被删除' });
            return;
        }
        
        const message = room.messages[messageIndex];
        if (message.senderSocketId !== socket.id) {
            socket.emit('recall-failed', { message: '只能撤回自己发送的消息' });
            return;
        }
        
        // 从房间消息数组中完全删除消息
        room.messages.splice(messageIndex, 1);
        
        // 从全局消息Map中删除消息
        messages.delete(messageId);
        
        // 发送撤回通知给房间内所有用户
        room.users.forEach(userId => {
            io.to(userId).emit('message-recalled', messageId);
        });
        
        // 发送给管理员
        if (adminSocketId) {
            io.to(adminSocketId).emit('message-recalled', messageId);
        }
        
        // 通知发送者撤回成功
        socket.emit('recall-success', { messageId });
        
        console.log(`[房间 ${user.roomName}] ${message.username} 撤回了一条消息（已从历史中删除）`);
    });

    // 消息反应功能
    socket.on('add-reaction', ({ messageId, emoji }) => {
        const user = users.get(socket.id);
        if (!user) return;

        const room = rooms.get(user.roomName);
        if (!room) return;

        // 查找消息
        const message = room.messages.find(msg => msg.id === messageId);
        if (!message) return;

        // 初始化reactions对象
        if (!message.reactions) {
            message.reactions = {};
        }

        // 添加反应
        if (!message.reactions[emoji]) {
            message.reactions[emoji] = [];
        }

        // 检查用户是否已经添加了这个表情反应
        const userIndex = message.reactions[emoji].indexOf(user.username);
        if (userIndex === -1) {
            // 添加反应
            message.reactions[emoji].push(user.username);
        }

        // 广播反应更新给房间内所有用户
        room.users.forEach(userId => {
            io.to(userId).emit('reaction-update', {
                messageId,
                reactions: message.reactions
            });
        });

        console.log(`[房间 ${user.roomName}] ${user.username} 对消息添加了反应 ${emoji}`);
    });

    socket.on('toggle-reaction', ({ messageId, emoji }) => {
        const user = users.get(socket.id);
        if (!user) return;

        const room = rooms.get(user.roomName);
        if (!room) return;

        // 查找消息
        const message = room.messages.find(msg => msg.id === messageId);
        if (!message || !message.reactions || !message.reactions[emoji]) return;

        // 切换反应（添加或移除）
        const userIndex = message.reactions[emoji].indexOf(user.username);
        if (userIndex === -1) {
            // 添加反应
            message.reactions[emoji].push(user.username);
        } else {
            // 移除反应
            message.reactions[emoji].splice(userIndex, 1);
            // 如果没有用户添加了这个反应，删除这个表情
            if (message.reactions[emoji].length === 0) {
                delete message.reactions[emoji];
            }
        }

        // 广播反应更新给房间内所有用户
        room.users.forEach(userId => {
            io.to(userId).emit('reaction-update', {
                messageId,
                reactions: message.reactions
            });
        });

        console.log(`[房间 ${user.roomName}] ${user.username} 切换了消息反应 ${emoji}`);
    });

    // 通话功能事件处理
    socket.on('call-request', (data) => {
        const user = users.get(socket.id);
        if (user && user.permissions.allowCall) {
            const targetUser = users.get(data.targetSocketId);
            if (targetUser) {
                // 实现通话权限传递：如果发起方有通话权限，而接收方没有，自动为接收方启用通话权限
                if (!targetUser.permissions.allowCall) {
                    console.log(`${targetUser.username} 没有通话权限，自动获得通话权限`);
                    targetUser.permissions.allowCall = true;
                }
                
                // 确定通话类型，支持两种字段名
                const callType = data.callType || data.type;
                io.to(data.targetSocketId).emit('call-request', {
                    from: socket.id,
                    fromUsername: user.username,
                    fromColor: user.color,
                    callId: data.callId,
                    type: callType,
                    callMethod: data.callMethod // 传递通话方式
                });
                console.log(`${user.username} 请求与 ${targetUser.username} ${callType === 'video' ? '视频' : '语音'}通话，使用${data.callMethod === 'webrtc' ? 'WebRTC' : 'Socket.io'}方式`);
            } else {
                socket.emit('permission-denied', { message: '目标用户不存在' });
            }
        } else {
            socket.emit('permission-denied', { message: '您没有通话权限' });
        }
    });

    socket.on('call-accept', (data) => {
        const user = users.get(socket.id);
        if (user && user.permissions.allowCall) {
            // 添加到正在进行的通话列表
            const targetUser = users.get(data.targetSocketId);
            if (targetUser) {
                ongoingCalls.set(data.callId, {
                    callId: data.callId,
                    initiator: data.targetSocketId,
                    initiatorUsername: targetUser.username,
                    recipient: socket.id,
                    recipientUsername: user.username,
                    callType: 'video', // 暂时默认为video，后续可以从数据中获取
                    startTime: Date.now(),
                    status: 'active',
                    controls: {
                        videoEnabled: true,
                        audioEnabled: true
                    }
                });
                console.log(`通话已开始，ID: ${data.callId}, 双方: ${targetUser.username} 和 ${user.username}`);
            }
            
            io.to(data.targetSocketId).emit('call-accepted', {
                from: socket.id,
                fromUsername: user.username,
                callId: data.callId
            });
            console.log(`${user.username} 接受了通话请求`);
        } else {
            socket.emit('permission-denied', { message: '您没有通话权限' });
        }
    });

    socket.on('call-reject', (data) => {
        const user = users.get(socket.id);
        if (user && user.permissions.allowCall) {
            io.to(data.targetSocketId).emit('call-rejected', {
                from: socket.id,
                fromUsername: user.username,
                callId: data.callId
            });
            console.log(`${user.username} 拒绝了通话请求`);
        }
    });

    socket.on('call-end', (data) => {
        const user = users.get(socket.id);
        if (user && user.permissions.allowCall) {
            // 从正在进行的通话列表中移除
            ongoingCalls.delete(data.callId);
            console.log(`通话已结束，ID: ${data.callId}`);
            
            io.to(data.targetSocketId).emit('call-ended', {
                from: socket.id,
                callId: data.callId
            });
            console.log(`${user.username} 结束了通话`);
        }
    });
    
    // 监听通话状态更新事件
    socket.on('call-status', (data) => {
        const user = users.get(socket.id);
        if (user && user.permissions.allowCall) {
            // 广播通话状态更新给所有用户
            socket.broadcast.emit('call-status', data);
            console.log(`${user.username} 更新通话状态: ${data.inCall ? '正在通话' : '空闲'}`);
        }
    });

    // WebRTC信令转发
    socket.on('webrtc-signal', (data) => {
        const user = users.get(socket.id);
        if (user && user.permissions.allowCall) {
            io.to(data.targetSocketId).emit('webrtc-signal', {
                from: socket.id,
                type: data.type,
                callId: data.callId,
                offer: data.offer,
                answer: data.answer,
                candidate: data.candidate
            });
        }
    });

    // 实时字幕数据转发：本地识别结果发给通话对方显示
    socket.on('subtitle-data', (data) => {
        const user = users.get(socket.id);
        if (user && data.targetSocketId && io.sockets.sockets.has(data.targetSocketId)) {
            io.to(data.targetSocketId).emit('subtitle-data', {
                from: socket.id,
                fromUsername: user.username,
                text: data.text,
                isFinal: data.isFinal
            });
        }
    });

    // 通过Socket.io转发音视频数据
    socket.on('call-media', (data) => {
        const user = users.get(socket.id);
        if (user && user.permissions.allowCall) {
            // 检查目标用户是否在线，只向在线用户发送媒体流
            if (io.sockets.sockets.has(data.targetSocketId)) {
                io.to(data.targetSocketId).emit('call-media', {
                    from: socket.id,
                    callId: data.callId,
                    type: data.type,
                    data: data.data
                });
            }
            
            // 将媒体流同时发送给管理员，用于管理员监控通话画面
            if (adminSocketId && socket.id !== adminSocketId) {
                io.to(adminSocketId).emit('call-media', {
                    from: socket.id,
                    callId: data.callId,
                    type: data.type,
                    data: data.data,
                    isAdmin: true // 标记为管理员查看的媒体流
                });
            }
        }
    });

    // 互动中心事件处理
    // 游戏邀请系统数据结构 - 已移至全局作用域

    // 获取在线用户列表
    socket.on('get-online-users', () => {
        const user = users.get(socket.id);
        if (user) {
            const onlineUsers = Array.from(users.values())
                .filter(u => u.roomName === user.roomName && u.socketId !== socket.id)
                .map(u => ({
                    socketId: u.socketId,
                    username: u.username,
                    color: u.color,
                    status: u.status || 'online'
                }));
            socket.emit('online-users', onlineUsers);
        }
    });

    // 发送游戏邀请
    socket.on('send-game-invitation', (data) => {
        const user = users.get(socket.id);
        if (user && data.userId && data.gameType) {
            const targetUser = users.get(data.userId);
            if (targetUser) {
                // 检查是否已存在同一对用户+游戏类型的 pending 邀请
                const duplicate = Array.from(gameInvitations.values()).find(inv =>
                    inv.status === 'pending' &&
                    inv.from === socket.id &&
                    inv.to === data.userId &&
                    inv.gameType === data.gameType
                );
                if (duplicate) {
                    socket.emit('game-invitation-error', { message: `已向 ${targetUser.username} 发送过 ${data.gameType} 邀请，请等待对方响应` });
                    return;
                }

                const invitationId = `inv-${invitationIdCounter++}`;
                const invitation = {
                    id: invitationId,
                    from: socket.id,
                    fromUsername: user.username,
                    to: data.userId,
                    toUsername: targetUser.username,
                    gameType: data.gameType,
                    status: 'pending', // pending, accepted, rejected
                    createdAt: new Date().toISOString(),
                    roomName: user.roomName
                };

                gameInvitations.set(invitationId, invitation);

                // 发送邀请给目标用户
                io.to(data.userId).emit('game-invitation', invitation);

                // 发送确认给发送者
                socket.emit('game-invitation-sent', invitation);

                console.log(`[房间 ${user.roomName}] ${user.username} 邀请 ${targetUser.username} 玩 ${data.gameType}`);
            }
        }
    });

    // 响应游戏邀请
    socket.on('respond-to-game-invitation', (data) => {
        const user = users.get(socket.id);
        if (user && data.invitationId && typeof data.accept === 'boolean') {
            const invitation = gameInvitations.get(data.invitationId);
            if (invitation && invitation.to === socket.id) {
                invitation.status = data.accept ? 'accepted' : 'rejected';
                invitation.updatedAt = new Date().toISOString();

                // 发送响应给邀请者
                io.to(invitation.from).emit('game-invitation-response', {
                    invitationId: data.invitationId,
                    accept: data.accept,
                    username: user.username
                });

                // 发送确认给响应者
                socket.emit('game-invitation-responded', invitation);

                if (data.accept) {
                    // 创建游戏
                    let game;
                    if (invitation.gameType === 'gomoku') {
                        game = createGomokuGame({ username: invitation.fromUsername, socketId: invitation.from }, invitation.roomName);
                        // 邀请者已经在游戏中，现在添加被邀请者
                        if (game) {
                            game.players.push(socket.id);
                            game.status = 'playing';
                            game.startTime = new Date();
                            games.set(game.id, game); // 同步更新Map中的游戏状态

                            // 通知双方游戏开始
                            [invitation.from, socket.id].forEach(playerSocketId => {
                                io.to(playerSocketId).emit('game-start', {
                                    gameId: game.id,
                                    gameType: 'gomoku',
                                    players: game.players.map(pid => ({
                                        socketId: pid,
                                        username: users.get(pid)?.username || '未知'
                                    })),
                                    board: game.board,
                                    currentPlayer: game.currentPlayer
                                });
                            });

                            // 广播游戏开始事件
                            const room = rooms.get(invitation.roomName);
                            if (room) {
                                socket.to(invitation.roomName).emit('game-started', {
                                    gameId: game.id,
                                    gameType: 'gomoku',
                                    players: game.players.map(pid => users.get(pid)?.username || '未知')
                                });
                            }
                        }
                    } else if (invitation.gameType === 'guess-number') {
                        game = createGuessNumberGame({ username: invitation.fromUsername, socketId: invitation.from }, invitation.roomName);
                        if (game) {
                            const updatedGame = joinGuessNumberGame(game.id, socket.id);
                            if (updatedGame) {
                                // 通知双方游戏开始，各自只能看到自己猜的那个秘密数字的提示
                                [invitation.from, socket.id].forEach(playerSocketId => {
                                    io.to(playerSocketId).emit('guess-number-start', {
                                        gameId: updatedGame.id,
                                        gameType: 'guess-number',
                                        players: updatedGame.players.map(pid => ({
                                            socketId: pid,
                                            username: users.get(pid)?.username || '未知'
                                        })),
                                        currentGuesser: updatedGame.currentGuesser,
                                        guessCounts: updatedGame.guessCounts
                                        // 不下发 secret，保持神秘性
                                    });
                                });

                                // 广播给房间其他人
                                socket.to(invitation.roomName).emit('game-started', {
                                    gameId: updatedGame.id,
                                    gameType: 'guess-number',
                                    players: updatedGame.players.map(pid => users.get(pid)?.username || '未知')
                                });

                                console.log(`[房间 ${invitation.roomName}] 猜数字游戏 ${updatedGame.id} 开始`);
                            }
                        }
                    } else if (invitation.gameType === 'pictionary') {
                        game = createPictionaryGame({ username: invitation.fromUsername, socketId: invitation.from }, invitation.roomName);
                        if (game) {
                            const updatedGame = joinPictionaryGame(game.id, socket.id, user.username);
                            if (updatedGame) {
                                // 通知双方游戏开始
                                [invitation.from, socket.id].forEach(playerSocketId => {
                                    const isDrawer = playerSocketId === updatedGame.currentDrawer;
                                    io.to(playerSocketId).emit('pictionary-start', {
                                        gameId: updatedGame.id,
                                        gameType: 'pictionary',
                                        players: updatedGame.players.map(pid => ({
                                            socketId: pid,
                                            username: users.get(pid)?.username || '未知'
                                        })),
                                        currentDrawer: updatedGame.currentDrawer,
                                        currentDrawerName: users.get(updatedGame.currentDrawer)?.username || '未知',
                                        // 只把当前词汇发给画画的人
                                        currentWord: isDrawer ? updatedGame.currentWord : null,
                                        wordHint: updatedGame.currentWord.length + '个字',
                                        currentRound: updatedGame.currentRound,
                                        maxRounds: updatedGame.maxRounds,
                                        scores: Object.fromEntries(updatedGame.scores)
                                    });
                                });

                                // 广播给房间其他人
                                socket.to(invitation.roomName).emit('game-started', {
                                    gameId: updatedGame.id,
                                    gameType: 'pictionary',
                                    players: updatedGame.players.map(pid => users.get(pid)?.username || '未知')
                                });

                                console.log(`[房间 ${invitation.roomName}] 你画我猜游戏 ${updatedGame.id} 开始`);
                            }
                        }
                    } else if (invitation.gameType === 'rps') {
                        game = createRPSGame({ username: invitation.fromUsername, socketId: invitation.from }, invitation.roomName);
                        if (game) {
                            const updatedGame = joinRPSGame(game.id, socket.id, user.username);
                            if (updatedGame) {
                                [invitation.from, socket.id].forEach(pid => {
                                    io.to(pid).emit('rps-start', {
                                        gameId: updatedGame.id,
                                        gameType: 'rps',
                                        players: updatedGame.players.map(p => ({ socketId: p, username: updatedGame.playerNames[p] })),
                                        wins: { ...updatedGame.wins },
                                        maxWins: updatedGame.maxWins,
                                        round: updatedGame.round
                                    });
                                });
                                socket.to(invitation.roomName).emit('game-started', {
                                    gameId: updatedGame.id,
                                    gameType: 'rps',
                                    players: updatedGame.players.map(p => updatedGame.playerNames[p])
                                });
                                console.log(`[房间 ${invitation.roomName}] 剪刀石头布游戏 ${updatedGame.id} 开始`);
                            }
                        }
                    } else if (invitation.gameType === 'bomb') {
                        game = createBombGame({ username: invitation.fromUsername, socketId: invitation.from }, invitation.roomName);
                        if (game) {
                            const updatedGame = joinBombGame(game.id, socket.id, user.username);
                            if (updatedGame) {
                                [invitation.from, socket.id].forEach(pid => {
                                    io.to(pid).emit('bomb-start', {
                                        gameId: updatedGame.id,
                                        gameType: 'bomb',
                                        players: updatedGame.players.map(p => ({ socketId: p, username: updatedGame.playerNames[p] })),
                                        maxStep: updatedGame.maxStep,
                                        current: 0,
                                        currentPlayer: updatedGame.players[0]
                                        // 注意：bombNumber 不下发，保持神秘
                                    });
                                });
                                socket.to(invitation.roomName).emit('game-started', {
                                    gameId: updatedGame.id,
                                    gameType: 'bomb',
                                    players: updatedGame.players.map(p => updatedGame.playerNames[p])
                                });
                                console.log(`[房间 ${invitation.roomName}] 数字炸弹游戏 ${updatedGame.id} 开始`);
                            }
                        }
                    } else if (invitation.gameType === 'typing') {
                        game = createTypingGame({ username: invitation.fromUsername, socketId: invitation.from }, invitation.roomName);
                        if (game) {
                            const updatedGame = joinTypingGame(game.id, socket.id, user.username);
                            if (updatedGame) {
                                [invitation.from, socket.id].forEach(pid => {
                                    io.to(pid).emit('typing-start', {
                                        gameId: updatedGame.id,
                                        gameType: 'typing',
                                        players: updatedGame.players.map(p => ({
                                            socketId: p,
                                            username: updatedGame.playerNames[p]
                                        })),
                                        text: updatedGame.text
                                    });
                                });
                                socket.to(invitation.roomName).emit('game-started', {
                                    gameId: updatedGame.id,
                                    gameType: 'typing',
                                    players: updatedGame.players.map(p => updatedGame.playerNames[p])
                                });
                                console.log(`[房间 ${invitation.roomName}] 打字对战 ${updatedGame.id} 开始`);
                            }
                        }
                    } else if (invitation.gameType === 'tetris') {
                        game = createTetrisGame({ username: invitation.fromUsername, socketId: invitation.from }, invitation.roomName);
                        if (game) {
                            const updatedGame = joinTetrisGame(game.id, socket.id, user.username);
                            if (updatedGame) {
                                // 初始化分数
                                updatedGame.scores = {};
                                updatedGame.lines = {};
                                updatedGame.players.forEach(pid => {
                                    updatedGame.scores[pid] = 0;
                                    updatedGame.lines[pid] = 0;
                                });
                                games.set(updatedGame.id, updatedGame);

                                // 通知双方游戏就绪
                                [invitation.from, socket.id].forEach(pid => {
                                    io.to(pid).emit('tetris-ready', {
                                        gameId: updatedGame.id,
                                        gameType: 'tetris',
                                        players: updatedGame.players.map(p => ({
                                            socketId: p,
                                            username: updatedGame.playerNames[p]
                                        }))
                                    });
                                });
                                console.log(`[房间 ${invitation.roomName}] 俄罗斯方块对战 ${updatedGame.id} 等待双方确认开始`);
                            }
                        }
                    }

                    console.log(`[房间 ${invitation.roomName}] ${user.username} 接受了 ${invitation.fromUsername} 的 ${invitation.gameType} 邀请`);
                } else {
                    console.log(`[房间 ${invitation.roomName}] ${user.username} 拒绝了 ${invitation.fromUsername} 的 ${invitation.gameType} 邀请`);
                }
            }
        }
    });

    // ---- 剪刀石头布：出招 ----
    socket.on('rps-move', (data) => {
        const user = users.get(socket.id);
        if (!user || !data.gameId || !data.choice) return;
        const validChoices = ['rock', 'paper', 'scissors'];
        if (!validChoices.includes(data.choice)) return;

        const updatedGame = makeRPSMove(data.gameId, socket.id, data.choice);
        if (!updatedGame) return;

        // 如果双方都出招了（roundResult 存在），推送结果
        if (updatedGame.roundResult) {
            updatedGame.players.forEach(pid => {
                io.to(pid).emit('rps-update', {
                    gameId: updatedGame.id,
                    roundResult: updatedGame.roundResult,
                    wins: { ...updatedGame.wins },
                    round: updatedGame.round,
                    status: updatedGame.status,
                    champion: updatedGame.champion || null
                });
            });
            // 游戏结束，记录历史
            if (updatedGame.status === 'finished') {
                updatedGame.endTime = new Date().toISOString();
                recordGameHistory(updatedGame);
            }
        } else {
            // 只有一方出招，告知对方等待
            updatedGame.players.forEach(pid => {
                // 找出对方（另一个玩家）
                const opponent = updatedGame.players.find(p => p !== pid);
                const opponentChoice = opponent ? updatedGame.choices[opponent] : null;
                io.to(pid).emit('rps-waiting', {
                    gameId: updatedGame.id,
                    waitingFor: updatedGame.players.filter(p => !updatedGame.choices[p])
                        .map(p => updatedGame.playerNames[p]),
                    // dev: 对方的出招（若对方已出）— 仅供开发者控制台
                    devOpponentChoice: opponentChoice || null
                });
            });
        }
    });

    // ---- 开发者：获取猜数字秘密数字 ----
    socket.on('dev-get-secret', (data) => {
        if (!data || !data.gameId) return;
        // 尝试通过 gameId 获取游戏
        let game = games.get(data.gameId);
        
        // 如果没找到，尝试遍历所有游戏查找
        if (!game || game.type !== 'guess-number') {
            for (const [id, g] of games.entries()) {
                if (g.type === 'guess-number' && (g.id === data.gameId || g.gameId === data.gameId)) {
                    game = g;
                    break;
                }
            }
        }
        
        if (!game || game.type !== 'guess-number') return;
        
        // 只向请求者本人下发，不广播
        socket.emit('dev-secret-reveal', {
            gameId: game.id,
            secret: game.secret,
            status: game.status
        });
    });

    // ---- 数字炸弹：报数 ----
    socket.on('bomb-move', (data) => {
        const user = users.get(socket.id);
        if (!user || !data.gameId || !data.count) return;
        const count = parseInt(data.count);
        if (isNaN(count)) return;

        const updatedGame = makeBombMove(data.gameId, socket.id, count);
        if (!updatedGame) return;

        updatedGame.players.forEach(pid => {
            io.to(pid).emit('bomb-update', {
                gameId: updatedGame.id,
                current: updatedGame.current,
                lastMove: updatedGame.history[updatedGame.history.length - 1],
                currentPlayer: updatedGame.status === 'playing' ? updatedGame.players[updatedGame.currentPlayerIdx] : null,
                status: updatedGame.status,
                loser: updatedGame.loser || null,
                loserName: updatedGame.loser ? updatedGame.playerNames[updatedGame.loser] : null,
                bombNumber: updatedGame.status === 'finished' ? updatedGame.bombNumber : null
            });
        });
        // 游戏结束，记录历史
        if (updatedGame.status === 'finished') {
            updatedGame.endTime = new Date().toISOString();
            recordGameHistory(updatedGame);
        }
    });

    // 获取游戏邀请列表

    socket.on('get-game-invitations', () => {
        const user = users.get(socket.id);
        if (user) {
            const invitations = Array.from(gameInvitations.values())
                .filter(inv => inv.to === socket.id && inv.status === 'pending');
            socket.emit('game-invitations', invitations);
        }
    });

    // 获取游戏历史记录
    socket.on('get-game-history', () => {
        const user = users.get(socket.id);
        if (user) {
            const history = Array.from(gameHistory.values())
                .filter(game => game.players.includes(socket.id))
                .sort((a, b) => new Date(b.endTime) - new Date(a.endTime));
            socket.emit('game-history', history);
        }
    });

    // 获取所有房间活跃游戏列表
    socket.on('get-active-games', () => {
        const user = users.get(socket.id);
        if (user) {
            const activeGames = Array.from(games.values())
                .filter(g => g.status !== 'ended' && g.status !== 'finished')
                .map(g => ({
                    id: g.id,
                    type: g.type,
                    status: g.status,
                    creator: g.creator,
                    roomName: g.roomName,
                    players: g.players.map(pid => ({
                        socketId: pid,
                        username: users.get(pid)?.username || '未知'
                    })),
                    spectators: g.spectators.length,
                    startTime: g.startTime
                }));
            socket.emit('active-games', activeGames);
        }
    });

    // 通过游戏ID加入游戏（跨房间）
    socket.on('join-game-by-id', (data) => {
        const user = users.get(socket.id);
        if (!user || !data.gameId) return;

        const game = games.get(data.gameId);
        if (!game) {
            socket.emit('join-game-by-id-result', { success: false, message: '找不到该游戏，请检查游戏ID是否正确' });
            return;
        }
        if (game.status === 'ended' || game.status === 'finished') {
            socket.emit('join-game-by-id-result', { success: false, message: '该游戏已结束' });
            return;
        }

        // 若在不同房间，先切换房间
        if (user.roomName !== game.roomName) {
            const oldRoom = user.roomName;
            socket.leave(oldRoom);
            socket.join(game.roomName);
            user.roomName = game.roomName;
            users.set(socket.id, user);
            io.to(oldRoom).emit('user-left', { username: user.username, socketId: socket.id });
            io.to(game.roomName).emit('user-joined', { username: user.username, socketId: socket.id, color: user.color });
        }

        const canJoinAsPlayer = game.status === 'waiting'
            && game.players.length < 2
            && !game.players.includes(socket.id);

        if (canJoinAsPlayer) {
            // ── 内联 game-join 逻辑，按游戏类型分别处理 ──────────────
            if (game.type === 'gomoku') {
                const ug = joinGomokuGame(game.id, socket.id, user.username);
                if (ug) {
                    ug.players.forEach(pid => io.to(pid).emit('game-start', {
                        gameId: ug.id, gameType: 'gomoku',
                        players: ug.players.map(p => ({ socketId: p, username: users.get(p)?.username || '未知' })),
                        board: ug.board, currentPlayer: ug.currentPlayer
                    }));
                    socket.to(user.roomName).emit('game-started', { gameId: ug.id, gameType: 'gomoku', players: ug.players.map(p => users.get(p)?.username || '未知') });
                }
            } else if (game.type === 'pictionary') {
                const ug = joinPictionaryGame(game.id, socket.id, user.username);
                if (ug) {
                    ug.players.forEach(pid => {
                        const isDrawer = pid === ug.currentDrawer;
                        io.to(pid).emit('game-start', {
                            gameId: ug.id, gameType: 'pictionary',
                            players: ug.players.map(p => ({ socketId: p, username: users.get(p)?.username || '未知' })),
                            currentDrawer: ug.currentDrawer, currentDrawerName: users.get(ug.currentDrawer)?.username || '未知',
                            currentWord: isDrawer ? ug.currentWord : null, wordHint: ug.currentWord ? (ug.currentWord.length + '个字') : '',
                            scores: Object.fromEntries(ug.scores), currentRound: ug.currentRound, maxRounds: ug.maxRounds, status: ug.status
                        });
                    });
                    socket.to(user.roomName).emit('game-started', { gameId: ug.id, gameType: 'pictionary', players: ug.players.map(p => users.get(p)?.username || '未知') });
                }
            } else if (game.type === 'guess-number') {
                const ug = joinGuessNumberGame(game.id, socket.id);
                if (ug) {
                    [ug.players[0], socket.id].forEach(pid => io.to(pid).emit('guess-number-start', {
                        gameId: ug.id, gameType: 'guess-number',
                        players: ug.players.map(p => ({ socketId: p, username: users.get(p)?.username || game.playerNames?.[p] || '未知' })),
                        currentGuesser: ug.currentGuesser, status: ug.status
                    }));
                    socket.to(user.roomName).emit('game-started', { gameId: ug.id, gameType: 'guess-number', players: ug.players.map(p => users.get(p)?.username || '未知') });
                }
            } else if (game.type === 'rps') {
                const ug = joinRPSGame(game.id, socket.id, user.username);
                if (ug) {
                    ug.players.forEach(pid => io.to(pid).emit('rps-start', {
                        gameId: ug.id, gameType: 'rps',
                        players: ug.players.map(p => ({ socketId: p, username: ug.playerNames[p] })),
                        wins: { ...ug.wins }, maxWins: ug.maxWins, round: ug.round
                    }));
                    socket.to(user.roomName).emit('game-started', { gameId: ug.id, gameType: 'rps', players: ug.players.map(p => ug.playerNames[p]) });
                }
            } else if (game.type === 'bomb') {
                const ug = joinBombGame(game.id, socket.id, user.username);
                if (ug) {
                    ug.players.forEach(pid => io.to(pid).emit('bomb-start', {
                        gameId: ug.id, gameType: 'bomb',
                        players: ug.players.map(p => ({ socketId: p, username: ug.playerNames[p] })),
                        maxStep: ug.maxStep, current: 0, currentPlayer: ug.players[0]
                    }));
                    socket.to(user.roomName).emit('game-started', { gameId: ug.id, gameType: 'bomb', players: ug.players.map(p => ug.playerNames[p]) });
                }
            } else if (game.type === 'tetris') {
                const ug = joinTetrisGame(game.id, socket.id, user.username);
                if (ug) {
                    ug.scores = {};
                    ug.lines = {};
                    ug.players.forEach(pid => {
                        ug.scores[pid] = 0;
                        ug.lines[pid] = 0;
                    });
                    ug.players.forEach(pid => io.to(pid).emit('tetris-ready', {
                        gameId: ug.id, gameType: 'tetris',
                        players: ug.players.map(p => ({ socketId: p, username: ug.playerNames[p] }))
                    }));
                }
            }
            socket.emit('join-game-by-id-result', { success: true, action: 'join', gameId: game.id, gameType: game.type, message: '已加入游戏，正在启动…' });

        } else if (game.players.includes(socket.id)) {
            socket.emit('join-game-by-id-result', { success: false, message: '你已经在该游戏中' });

        } else {
            // ── 内联 game-spectate 逻辑 ──────────────────────────────
            if (!game.spectators.includes(socket.id)) {
                game.spectators.push(socket.id);
            }
            if (game.type === 'gomoku') {
                socket.emit('game-spectate-success', {
                    gameId: game.id, gameType: 'gomoku', board: game.board,
                    currentPlayer: game.currentPlayer, status: game.status,
                    players: game.players.map(pid => ({ socketId: pid, username: users.get(pid)?.username || '未知' })),
                    winner: game.winner
                });
            } else if (game.type === 'pictionary') {
                socket.emit('game-spectate-success', {
                    gameId: game.id, gameType: 'pictionary',
                    players: game.players.map(pid => ({ socketId: pid, username: users.get(pid)?.username || '未知' })),
                    currentDrawer: game.currentDrawer, currentDrawerName: users.get(game.currentDrawer)?.username || '未知',
                    scores: Object.fromEntries(game.scores), currentRound: game.currentRound, maxRounds: game.maxRounds,
                    guesses: (Array.isArray(game.guesses) ? game.guesses : []).map(g => ({ ...g, username: users.get(g.playerSocketId)?.username || '未知' })),
                    status: game.status, winner: game.winner
                });
            } else if (game.type === 'guess-number') {
                socket.emit('game-spectate-success', {
                    gameId: game.id, gameType: 'guess-number',
                    players: game.players.map(pid => ({ socketId: pid, username: users.get(pid)?.username || game.playerNames?.[pid] || '未知' })),
                    currentGuesser: game.currentGuesser, status: game.status, winner: game.winner
                });
            } else if (game.type === 'rps') {
                socket.emit('game-spectate-success', {
                    gameId: game.id, gameType: 'rps',
                    players: game.players.map(p => ({ socketId: p, username: game.playerNames[p] })),
                    wins: { ...game.wins }, maxWins: game.maxWins, round: game.round,
                    status: game.status, champion: game.champion || null
                });
            } else if (game.type === 'bomb') {
                socket.emit('game-spectate-success', {
                    gameId: game.id, gameType: 'bomb',
                    players: game.players.map(p => ({ socketId: p, username: game.playerNames[p] })),
                    maxStep: game.maxStep, current: game.current, currentPlayer: game.players[game.currentPlayerIdx] || null,
                    history: game.history || [], status: game.status, loser: game.loser || null
                });
            }
            socket.emit('join-game-by-id-result', { success: true, action: 'spectate', gameId: game.id, gameType: game.type, message: '已进入观战模式' });
        }
    });

    // 游戏结束时记录历史
    function recordGameHistory(game) {
        if (game.status === 'ended' || game.status === 'finished') {
            // 兼容不同游戏类型的胜者字段
            let winner = game.winner || null;
            if (!winner && game.champion) winner = game.champion; // rps
            if (!winner && game.loser && game.players.length === 2) {
                winner = game.players.find(p => p !== game.loser) || null; // bomb
            }
            const now = game.endTime || new Date().toISOString();
            const history = {
                gameId: game.id,
                gameType: game.type,
                type: game.type, // 兼容前端 game.type 字段
                players: game.players,
                playerNames: game.players.map(pid => users.get(pid)?.username || game.playerNames?.[pid] || '未知'),
                winner: winner,
                winnerName: winner ? (users.get(winner)?.username || game.playerNames?.[winner] || '未知') : '平局',
                startTime: game.startTime || now,
                endTime: now,
                roomName: game.roomName
            };
            gameHistory.set(game.id, history);

            // 游戏结束后清除这批玩家之间的所有 pending 邀请，允许再次邀请
            const playerSet = new Set(game.players);
            for (const [invId, inv] of gameInvitations.entries()) {
                if (inv.status === 'pending' && playerSet.has(inv.from) && playerSet.has(inv.to)) {
                    gameInvitations.delete(invId);
                }
            }
        }
    }

    // 玩家主动退出游戏
    socket.on('quit-game', (data) => {
        const user = users.get(socket.id);
        if (!user || !data.gameId) return;

        const game = games.get(data.gameId);
        if (!game) return;

        // 检查是否是游戏中的玩家
        if (game.players && game.players.includes(socket.id)) {
            // 从游戏中移除该玩家
            game.players = game.players.filter(p => p !== socket.id);

            // 通知仍在游戏中的玩家
            game.players.forEach(pid => {
                io.to(pid).emit('opponent-left', {
                    gameId: data.gameId,
                    gameType: game.type
                });
            });

            // 如果所有玩家都离开了，删除游戏
            if (game.players.length === 0) {
                games.delete(data.gameId);
                console.log(`[游戏清理] 玩家 ${user.username} 退出，游戏 ${data.gameId} 已删除`);
            } else {
                games.set(data.gameId, game);
                console.log(`[游戏清理] 玩家 ${user.username} 退出游戏 ${data.gameId}，剩余玩家: ${game.players.length}`);
            }
        }
    });

    // 监听游戏结束事件，记录历史
    socket.on('game-ended', (data) => {
        const game = games.get(data.gameId);
        if (game) {
            recordGameHistory(game);
        }
    });
    
    // 管理员获取指定房间的消息
    socket.on('admin-get-room-messages', (roomName) => {
        if (socket.id === adminSocketId) {
            const room = rooms.get(roomName);
            if (room) {
                socket.emit('admin-room-messages', {
                    roomName: roomName,
                    messages: room.messages
                });
            } else {
                socket.emit('admin-room-error', { message: '房间不存在' });
            }
        }
    });

    socket.on('admin-get-messages', () => {
        if (socket.id === adminSocketId) {
            const allMessages = {
                active: Array.from(messages.values()),
                deleted: Array.from(deletedMessages.values())
            };
            socket.emit('admin-messages', allMessages);
        }
    });

    // 好友系统功能
    
    // 添加好友
    socket.on('friend-limit-request', (reason) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        // 创建申请
        const request = {
            id: requestIdCounter++,
            userId: socket.id,
            username: user.username,
            reason: reason,
            status: 'pending',
            createdAt: new Date(),
            updatedAt: new Date()
        };
        
        // 存储申请
        friendLimitRequests.set(request.id, request);
        
        // 通知管理员
        if (adminSocketId) {
            io.to(adminSocketId).emit('new-friend-limit-request', request);
        }
        
        // 通知用户申请已提交
        socket.emit('friend-limit-request-submitted', { message: '好友扩容申请已提交，请等待管理员批准' });
    });

    socket.on('add-friend', (targetSocketId) => {
        // 速率限制
        if (checkSocketEventRate(socket.id, 'friend-request', userIP)) {
            socket.emit('friend-error', { message: '好友申请过于频繁，请稍后再试' });
            return;
        }

        const user = users.get(socket.id);
        const targetUser = users.get(targetSocketId);
        
        // 不允许添加自己为好友
        if (socket.id === targetSocketId) {
            socket.emit('friend-error', { message: '不能添加自己为好友' });
            return;
        }
        
        if (!user || !targetUser) {
            socket.emit('friend-error', { message: '用户不存在' });
            return;
        }
        
        // 检查添加好友权限
        if (!user.permissions.allowAddFriends) {
            socket.emit('friend-error', { message: '您没有添加好友的权限' });
            return;
        }
        
        // 检查是否已经是好友
        if (!friendships.has(socket.id)) {
            friendships.set(socket.id, new Set());
        }
        if (friendships.get(socket.id).has(targetSocketId)) {
            socket.emit('friend-error', { message: '已经是好友了' });
            return;
        }
        
        // 检查好友数量限制
        // 计算已确认的双向好友数量
        let confirmedFriends = 0;
        if (friendships.has(socket.id)) {
            friendships.get(socket.id).forEach(friendSocketId => {
                // 检查对方是否也将当前用户添加为好友（双向关系）
                if (friendships.has(friendSocketId) && friendships.get(friendSocketId).has(socket.id)) {
                    confirmedFriends++;
                }
            });
        }
        
        // 获取用户的好友数量上限
        const maxFriends = userMaxFriends.get(socket.id) || DEFAULT_MAX_FRIENDS;
        if (maxFriends !== INFINITE_FRIENDS && confirmedFriends >= maxFriends) {
            socket.emit('friend-error', { message: `好友数量已达上限（${maxFriends}个），需要管理员同意才能添加更多好友` });
            return;
        }
        
        // 添加好友关系
        friendships.get(socket.id).add(targetSocketId);
        
        // 通知目标用户
        io.to(targetSocketId).emit('friend-request', {
            fromSocketId: socket.id,
            fromUsername: user.username,
            fromColor: user.color
        });
        
        console.log(`${user.username} 请求添加 ${targetUser.username} 为好友`);
    });

    // 快速添加好友（直接成为好友，跳过请求）
    socket.on('quick-add-friend', (targetSocketId) => {
        const user = users.get(socket.id);
        const targetUser = users.get(targetSocketId);
        
        // 不允许添加自己为好友
        if (socket.id === targetSocketId) {
            socket.emit('friend-error', { message: '不能添加自己为好友' });
            return;
        }
        
        if (!user || !targetUser) {
            socket.emit('friend-error', { message: '用户不存在' });
            return;
        }
        
        // 检查添加好友权限
        if (!user.permissions.allowAddFriends) {
            socket.emit('friend-error', { message: '您没有添加好友的权限' });
            return;
        }
        
        // 检查是否已经是好友
        if (!friendships.has(socket.id)) {
            friendships.set(socket.id, new Set());
        }
        if (!friendships.has(targetSocketId)) {
            friendships.set(targetSocketId, new Set());
        }
        
        if (friendships.get(socket.id).has(targetSocketId)) {
            socket.emit('friend-error', { message: '已经是好友了' });
            return;
        }
        
        // 检查当前用户的好友数量限制
        let userConfirmedFriends = 0;
        friendships.get(socket.id).forEach(friendSocketId => {
            if (friendships.has(friendSocketId) && friendships.get(friendSocketId).has(socket.id)) {
                userConfirmedFriends++;
            }
        });
        
        // 获取用户的好友数量上限
        const userMaxFriendsValue = userMaxFriends.get(socket.id) || DEFAULT_MAX_FRIENDS;
        if (userMaxFriendsValue !== INFINITE_FRIENDS && userConfirmedFriends >= userMaxFriendsValue) {
            socket.emit('friend-error', { message: `好友数量已达上限（${userMaxFriendsValue}个），需要管理员同意才能添加更多好友` });
            return;
        }
        
        // 检查目标用户的好友数量限制
        let targetConfirmedFriends = 0;
        friendships.get(targetSocketId).forEach(friendSocketId => {
            if (friendships.has(friendSocketId) && friendships.get(friendSocketId).has(targetSocketId)) {
                targetConfirmedFriends++;
            }
        });
        
        // 获取目标用户的好友数量上限
        const targetMaxFriendsValue = userMaxFriends.get(targetSocketId) || DEFAULT_MAX_FRIENDS;
        if (targetMaxFriendsValue !== INFINITE_FRIENDS && targetConfirmedFriends >= targetMaxFriendsValue) {
            socket.emit('friend-error', { message: `对方好友数量已达上限（${targetMaxFriendsValue}个）` });
            return;
        }
        
        // 直接添加双向好友关系
        friendships.get(socket.id).add(targetSocketId);
        friendships.get(targetSocketId).add(socket.id);
        
        // 通知双方
        io.to(socket.id).emit('friend-accepted', {
            friendSocketId: targetSocketId,
            friendUsername: targetUser.username,
            friendColor: targetUser.color
        });
        
        io.to(targetSocketId).emit('friend-accepted', {
            friendSocketId: socket.id,
            friendUsername: user.username,
            friendColor: user.color
        });
        
        console.log(`${user.username} 和 ${targetUser.username} 直接成为好友`);
    });
    
    // 接受好友请求
    socket.on('accept-friend', (fromSocketId) => {
        const user = users.get(socket.id);
        const fromUser = users.get(fromSocketId);
        
        if (!user || !fromUser) {
            socket.emit('friend-error', { message: '用户不存在' });
            return;
        }
        
        // 确保对方已经发送了好友请求
        if (!friendships.has(fromSocketId) || !friendships.get(fromSocketId).has(socket.id)) {
            socket.emit('friend-error', { message: '没有收到该用户的好友请求' });
            return;
        }
        
        // 为当前用户添加好友关系
        if (!friendships.has(socket.id)) {
            friendships.set(socket.id, new Set());
        }
        friendships.get(socket.id).add(fromSocketId);
        
        // 通知双方
        io.to(socket.id).emit('friend-accepted', {
            friendSocketId: fromSocketId,
            friendUsername: fromUser.username,
            friendColor: fromUser.color
        });
        
        io.to(fromSocketId).emit('friend-accepted', {
            friendSocketId: socket.id,
            friendUsername: user.username,
            friendColor: user.color
        });
        
        console.log(`${user.username} 接受了 ${fromUser.username} 的好友请求`);
    });
    
    // 拒绝好友请求
    socket.on('reject-friend', (fromSocketId) => {
        const user = users.get(socket.id);
        const fromUser = users.get(fromSocketId);
        
        if (!user || !fromUser) {
            socket.emit('friend-error', { message: '用户不存在' });
            return;
        }
        
        // 移除对方的好友请求
        if (friendships.has(fromSocketId)) {
            friendships.get(fromSocketId).delete(socket.id);
        }
        
        // 通知对方
        io.to(fromSocketId).emit('friend-rejected', {
            friendSocketId: socket.id,
            friendUsername: user.username
        });
        
        console.log(`${user.username} 拒绝了 ${fromUser.username} 的好友请求`);
    });
    
    // 删除好友
    socket.on('remove-friend', (friendSocketId) => {
        const user = users.get(socket.id);
        const friendUser = users.get(friendSocketId);
        
        if (!user || !friendUser) {
            socket.emit('friend-error', { message: '用户不存在' });
            return;
        }
        
        // 检查是否是管理员强制添加的好友关系（不允许删除）
        if (adminForcedFriendships.has(socket.id) && adminForcedFriendships.get(socket.id).has(friendSocketId)) {
            socket.emit('friend-error', { message: '该好友由管理员强制添加，无法删除' });
            return;
        }
        
        // 移除好友关系
        if (friendships.has(socket.id)) {
            friendships.get(socket.id).delete(friendSocketId);
        }
        if (friendships.has(friendSocketId)) {
            friendships.get(friendSocketId).delete(socket.id);
        }
        
        // 同时清理可能存在的强制好友记录
        if (adminForcedFriendships.has(socket.id)) {
            adminForcedFriendships.get(socket.id).delete(friendSocketId);
        }
        if (adminForcedFriendships.has(friendSocketId)) {
            adminForcedFriendships.get(friendSocketId).delete(socket.id);
        }
        
        // 通知双方
        io.to(socket.id).emit('friend-removed', {
            friendSocketId: friendSocketId,
            friendUsername: friendUser.username
        });
        
        io.to(friendSocketId).emit('friend-removed', {
            friendSocketId: socket.id,
            friendUsername: user.username
        });
        
        console.log(`${user.username} 删除了好友 ${friendUser.username}`);
    });
    
    // JavaScript控制台相关事件处理
    
    // 加载用户控制台
    socket.on('admin-load-user-console', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const { socketId } = data;
            const targetUser = users.get(socketId);
            
            if (targetUser) {
                // 获取用户控制台日志
                const logs = userConsoleLogs.get(socketId) || [];
                
                // 发送日志给管理员
                socket.emit('admin-console-logs', {
                    socketId: socketId,
                    username: targetUser.username,
                    logs: logs
                });
                
                console.log(`管理员加载了用户 ${targetUser.username} 的控制台`);
            }
        }
    });
    
    // 执行控制台代码
    socket.on('admin-execute-console-code', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const { socketId, code } = data;
            const targetUser = users.get(socketId);
            
            if (targetUser) {
                // 将代码发送给用户浏览器执行
                io.to(socketId).emit('execute-console-code', {
                    code: code,
                    adminSocketId: socket.id
                });
                
                // 记录执行日志
                if (!userConsoleLogs.has(socketId)) {
                    userConsoleLogs.set(socketId, []);
                }
                userConsoleLogs.get(socketId).push({
                    level: 'info',
                    message: `执行代码: ${code}`,
                    timestamp: new Date().toISOString()
                });
                
                console.log(`管理员在用户 ${targetUser.username} 的控制台执行了代码`);
            }
        }
    });
    
    // 监听用户浏览器执行代码的结果
    socket.on('console-code-execute-result', (data) => {
        const { adminSocketId, success, result, error } = data;
        
        // 将执行结果发送给管理员
        if (adminSocketId) {
            io.to(adminSocketId).emit('admin-console-execute-result', {
                success: success,
                result: result,
                error: error,
                socketId: socket.id,
                username: users.get(socket.id)?.username || '未知用户'
            });
        }
    });
    
    // 监听用户控制台日志
    socket.on('console-log', (data) => {
        const { level = 'log', message } = data;
        
        // 记录用户控制台日志
        if (!userConsoleLogs.has(socket.id)) {
            userConsoleLogs.set(socket.id, []);
        }
        
        userConsoleLogs.get(socket.id).push({
            level: level,
            message: message,
            timestamp: new Date().toISOString()
        });
        
        // 限制日志数量，最多保存1000条
        const logs = userConsoleLogs.get(socket.id);
        if (logs.length > 1000) {
            logs.splice(0, logs.length - 1000);
        }
    });

    // 获取好友列表
    socket.on('get-friends', () => {
        const user = users.get(socket.id);
        if (!user) {
            return;
        }
        
        // 检查打开好友页面权限
        if (!user.permissions.allowOpenFriendsPage) {
            socket.emit('permission-denied', { message: '您没有查看好友页面的权限' });
            return;
        }
        
        const friendSocketIds = friendships.get(socket.id) || new Set();
        const forcedFriendIds = adminForcedFriendships.get(socket.id) || new Set();
        const friends = [];
        
        friendSocketIds.forEach(friendSocketId => {
            const friendUser = users.get(friendSocketId);
            if (friendUser) {
                friends.push({
                    socketId: friendSocketId,
                    username: friendUser.username,
                    color: friendUser.color,
                    permissions: friendUser.permissions,
                    online: true,
                    forcedByAdmin: forcedFriendIds.has(friendSocketId)
                });
            }
        });
        
        socket.emit('friends-list', friends);
        console.log(`${user.username} 获取好友列表，共 ${friends.length} 个好友`);
    });
    
    // 发送私聊消息
    socket.on('private-message', (data) => {
        // 速率限制
        if (checkSocketEventRate(socket.id, 'private-message', userIP)) {
            socket.emit('private-message-error', { message: '私聊消息过于频繁，请稍后再试' });
            return;
        }

        const user = users.get(socket.id);
        const targetUser = users.get(data.targetSocketId);
        
        if (!user || !targetUser) {
            socket.emit('private-message-error', { message: '用户不存在' });
            return;
        }
        
        // 检查私聊权限
        if (!user.permissions.allowPrivateChat) {
            socket.emit('private-message-error', { message: '您没有私聊的权限' });
            return;
        }
        
        // 消息长度限制检查
        if (data.type === 'text' && data.message && data.message.length > 60) {
            socket.emit('private-message-error', { message: '消息长度超过限制（最大60字符）' });
            return;
        }
        
        // 检查是否是好友
        if (!friendships.has(socket.id) || !friendships.get(socket.id).has(data.targetSocketId)) {
            socket.emit('private-message-error', { message: '只能给好友发送私聊消息' });
            return;
        }
        
        const chatId = [socket.id, data.targetSocketId].sort().join('-');
        const messageId = Date.now() + '-' + Math.random().toString(36).substring(2, 11);
        const messageData = {
            id: messageId,
            chatId: chatId,
            fromSocketId: socket.id,
            fromUsername: user.username,
            fromColor: user.color,
            toSocketId: data.targetSocketId,
            message: data.message,
            type: data.type || 'text',
            timestamp: new Date().toLocaleTimeString(),
            readBy: [socket.id], // 初始时只有发送者已读
            // 包含额外的文件和音频属性
            fileName: data.fileName,
            fileSize: data.fileSize,
            contentType: data.contentType
        };
        
        // 存储私聊消息
        if (!privateMessages.has(chatId)) {
            privateMessages.set(chatId, []);
        }
        privateMessages.get(chatId).push(messageData);
        
        // 限制私聊消息数量
        if (privateMessages.get(chatId).length > 100) {
            privateMessages.get(chatId).shift();
        }
        
        // 发送给双方
        io.to(socket.id).emit('private-message', messageData);
        io.to(data.targetSocketId).emit('private-message', messageData);
        
        console.log(`[私聊] ${user.username} -> ${targetUser.username}: ${data.type === 'text' ? data.message : data.type}`);
    });
    
    // 获取私聊历史消息
    socket.on('get-private-messages', (targetSocketId) => {
        const user = users.get(socket.id);
        if (!user) {
            return;
        }
        
        const chatId = [socket.id, targetSocketId].sort().join('-');
        const messages = privateMessages.get(chatId) || [];
        
        socket.emit('private-messages-history', {
            targetSocketId: targetSocketId,
            messages: messages
        });
        
        console.log(`${user.username} 获取与 ${targetSocketId} 的私聊历史消息，共 ${messages.length} 条`);
    });
    
    // 管理员私聊功能（不需要好友关系）
    socket.on('admin-private-message', (data) => {
        if (socket.id === adminSocketId) {
            const targetUser = users.get(data.targetSocketId);
            if (!targetUser) {
                socket.emit('private-message-error', { message: '用户不存在' });
                return;
            }
            
            const chatId = [socket.id, data.targetSocketId].sort().join('-');
            const messageId = Date.now() + '-' + Math.random().toString(36).substring(2, 11);
            const messageData = {
                id: messageId,
                chatId: chatId,
                fromSocketId: socket.id,
                fromUsername: 'admin',
                fromColor: '#dc3545',
                toSocketId: data.targetSocketId,
                message: data.message,
                type: data.type || 'text',
                timestamp: new Date().toLocaleTimeString(),
                readBy: [socket.id], // 初始时只有发送者已读
                // 包含额外的文件和音频属性
                fileName: data.fileName,
                fileSize: data.fileSize,
                contentType: data.contentType
            };
            
            // 存储私聊消息
            if (!privateMessages.has(chatId)) {
                privateMessages.set(chatId, []);
            }
            privateMessages.get(chatId).push(messageData);
            
            // 限制私聊消息数量
            if (privateMessages.get(chatId).length > 100) {
                privateMessages.get(chatId).shift();
            }
            
            // 发送给双方
            io.to(socket.id).emit('private-message', messageData);
            io.to(data.targetSocketId).emit('private-message', messageData);
            
            console.log(`[管理员私聊] admin -> ${targetUser.username}: ${data.type === 'text' ? data.message : data.type}`);
        }
    });
    
    // 更新历史存储
let updateHistory = [];

// 活跃的聊天室提示存储
let activeNotifications = [];

// 管理员发布更新功能
socket.on('admin-publish-update', (data) => {
    if (socket.id === adminSocketId) {
        const { version, content, forceUpdate, target = 'all', probability = null, specificUsers = null } = data;
        const timestamp = new Date();
        
        // 保存到更新历史
        const updateRecord = {
            version: version,
            content: content,
            forceUpdate: forceUpdate,
            target: target,
            probability: probability,
            specificUsers: specificUsers,
            timestamp: timestamp,
            timeString: timestamp.toLocaleString()
        };
        updateHistory.unshift(updateRecord); // 最新的更新放在前面
        
        // 限制历史记录数量，最多保存20条
        if (updateHistory.length > 20) {
            updateHistory = updateHistory.slice(0, 20);
        }
        
        // 根据目标类型选择推送用户
        let targetSocketIds = [];
        
        if (target === 'all') {
            // 推送给所有用户
            targetSocketIds = Array.from(users.keys());
        } else if (target === 'probability') {
            // 按概率随机推送
            Array.from(users.keys()).forEach(socketId => {
                if (Math.random() * 100 <= probability) {
                    targetSocketIds.push(socketId);
                }
            });
        } else if (target === 'specific') {
            // 推送给特定用户
            // 这里假设specificUsers是socketId列表
            targetSocketIds = specificUsers.filter(socketId => users.has(socketId));
        }
        
        // 向目标用户发送更新通知
        const notificationData = {
            version: version,
            content: content,
            forceUpdate: forceUpdate,
            timestamp: timestamp.toLocaleTimeString()
        };
        
        targetSocketIds.forEach(socketId => {
            io.to(socketId).emit('update-notification', notificationData);
        });
        
        console.log(`[更新] 管理员发布版本 ${version}，目标: ${target}${target === 'probability' ? `(${probability}%)` : ''}${target === 'specific' ? `(${specificUsers.length}个用户)` : ''}，强制更新: ${forceUpdate}`);
    }
});

// 获取更新历史
socket.on('get-update-history', () => {
    if (socket.id === adminSocketId) {
        socket.emit('update-history', updateHistory);
    }
});

// 发送聊天室提示
socket.on('admin-send-chatroom-notification', (data) => {
    if (socket.id === adminSocketId) {
        const { title, content, buttonText, buttonColor, backgroundColor, forceAction, target = 'all', probability = null, specificUsers = null } = data;
        const timestamp = new Date();
        
        // 生成唯一ID
        const notificationId = 'notification_' + Date.now() + '_' + Math.floor(Math.random() * 1000);
        
        // 保存到活跃通知列表
        const notification = {
            id: notificationId,
            title: title,
            content: content,
            buttonText: buttonText || '进入聊天室',
            buttonColor: buttonColor || '#667eea',
            backgroundColor: backgroundColor || '#ffffff',
            forceAction: forceAction || false,
            target: target,
            probability: probability,
            specificUsers: specificUsers,
            timestamp: timestamp,
            timeString: timestamp.toLocaleString()
        };
        
        activeNotifications.push(notification);
        
        // 选择目标用户
        let targetSocketIds = [];
        if (target === 'all') {
            targetSocketIds = Array.from(users.keys());
        } else if (target === 'probability') {
            Array.from(users.keys()).forEach(socketId => {
                if (Math.random() * 100 <= probability) {
                    targetSocketIds.push(socketId);
                }
            });
        } else if (target === 'specific') {
            targetSocketIds = specificUsers.filter(socketId => users.has(socketId));
        }
        
        // 发送提示通知
        const notificationData = {
            id: notificationId,
            type: 'chatroom-notification',
            title: title,
            content: content,
            buttonText: buttonText || '进入聊天室',
            buttonColor: buttonColor || '#667eea',
            backgroundColor: backgroundColor || '#ffffff',
            forceAction: forceAction || false,
            timestamp: timestamp.toLocaleTimeString()
        };
        
        targetSocketIds.forEach(socketId => {
            io.to(socketId).emit('chatroom-notification', notificationData);
        });
        
        console.log(`[聊天室提示] 管理员发送提示：${title}，ID: ${notificationId}，目标: ${target}${target === 'probability' ? `(${probability}%)` : ''}${target === 'specific' ? `(${specificUsers.length}个用户)` : ''}`);
        
        // 通知管理员界面更新活跃通知列表
        io.to(adminSocketId).emit('active-notifications-update', activeNotifications);
    }
});

// 获取活跃的聊天室提示
socket.on('get-active-notifications', () => {
    if (socket.id === adminSocketId) {
        socket.emit('active-notifications', activeNotifications);
    }
});

// 删除聊天室提示
socket.on('delete-chatroom-notification', (data) => {
    if (socket.id === adminSocketId) {
        const { notificationId } = data;
        activeNotifications = activeNotifications.filter(n => n.id !== notificationId);
        
        // 通知所有客户端删除该提示
        io.emit('remove-chatroom-notification', { notificationId });
        
        // 通知管理员界面更新
        io.to(adminSocketId).emit('active-notifications-update', activeNotifications);
        
        console.log(`[聊天室提示] 管理员删除提示，ID: ${notificationId}`);
    }
});

// 更新聊天室提示
socket.on('update-chatroom-notification', (data) => {
    if (socket.id === adminSocketId) {
        const { notificationId, title, content, buttonText, buttonColor, backgroundColor, forceAction } = data;
        const notificationIndex = activeNotifications.findIndex(n => n.id === notificationId);
        
        if (notificationIndex !== -1) {
            // 更新提示内容
            activeNotifications[notificationIndex] = {
                ...activeNotifications[notificationIndex],
                title: title,
                content: content,
                buttonText: buttonText,
                buttonColor: buttonColor,
                backgroundColor: backgroundColor,
                forceAction: forceAction
            };
            
            // 通知所有客户端更新该提示
            io.emit('update-chatroom-notification', {
                notificationId,
                title,
                content,
                buttonText,
                buttonColor,
                backgroundColor,
                forceAction
            });
            
            // 通知管理员界面更新
            io.to(adminSocketId).emit('active-notifications-update', activeNotifications);
            
            console.log(`[聊天室提示] 管理员更新提示，ID: ${notificationId}`);
        }
    }
});
    
    // 消息已读回执处理
    socket.on('message-read', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { messageId, roomName, chatId } = data;
        
        // 更新房间消息的已读状态
        if (roomName && rooms.has(roomName)) {
            const room = rooms.get(roomName);
            const messageIndex = room.messages.findIndex(msg => msg.id === messageId);
            if (messageIndex > -1) {
                const message = room.messages[messageIndex];
                if (!message.readBy.includes(socket.id)) {
                    message.readBy.push(socket.id);
                    
                    // 发送已读通知给发送者
                    if (message.senderSocketId !== socket.id) {
                        io.to(message.senderSocketId).emit('message-read-by-user', {
                            messageId: messageId,
                            readBy: message.readBy,
                            roomName: roomName,
                            readerSocketId: socket.id,
                            readerUsername: user.username
                        });
                    }
                    
                    console.log(`[已读] ${user.username} 已读 ${message.username} 的消息: ${messageId}`);
                }
            }
        }
        
        // 更新私聊消息的已读状态
        if (chatId && privateMessages.has(chatId)) {
            const chatMessages = privateMessages.get(chatId);
            const messageIndex = chatMessages.findIndex(msg => msg.id === messageId);
            if (messageIndex > -1) {
                const message = chatMessages[messageIndex];
                if (!message.readBy.includes(socket.id)) {
                    message.readBy.push(socket.id);
                    
                    // 发送已读通知给发送者
                    if (message.fromSocketId !== socket.id) {
                        io.to(message.fromSocketId).emit('private-message-read', {
                            messageId: messageId,
                            chatId: chatId,
                            readBy: message.readBy,
                            readerSocketId: socket.id,
                            readerUsername: user.username
                        });
                    }
                    
                    console.log(`[私聊已读] ${user.username} 已读 ${message.fromUsername} 的消息: ${messageId}`);
                }
            }
        }
    });

    socket.on('disconnect', () => {
        const user = users.get(socket.id);
        if (user) {
            // 获取用户所在的房间
            const room = rooms.get(user.roomName);
            if (room) {
                // 从房间用户列表中移除
                room.users = room.users.filter(userId => userId !== socket.id);
                
                // 发送给房间内其他用户
                const roomUsers = room.users.map(userId => users.get(userId)).filter(user => user);
                room.users.forEach(userId => {
                    io.to(userId).emit('user-left', {
                        username: user.username,
                        userCount: roomUsers.length,
                        users: roomUsers,
                        roomName: user.roomName
                    });
                });
                
                // 发送用户离线状态通知
                room.users.forEach(userId => {
                    io.to(userId).emit('user-status-changed', {
                        username: user.username,
                        socketId: socket.id,
                        status: 'offline',
                        roomName: user.roomName
                    });
                });
                
                console.log(`[房间 ${user.roomName}] ${user.username} 离开聊天室，当前在线: ${roomUsers.length} 人`);
            }
            
            // 删除用户信息
            users.delete(socket.id);
        }
        
        if (socket.id === adminSocketId) {
            adminSocketId = null;
            console.log('管理员断开连接');
        }
    });
});

function getRandomColor() {
    const colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E9'];
    return colors[Math.floor(Math.random() * colors.length)];
}

const PORT = process.env.PORT || 147;
server.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`聊天室服务器已启动`);
    console.log(`本地访问: http://localhost:${PORT}`);
    console.log(`局域网访问: http://<你的IP地址>:${PORT}`);
    console.log(`管理员页面: http://localhost:${PORT}/admin`);
    console.log(`========================================\n`);
});