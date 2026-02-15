const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'X-Content-Type-Options'],
    credentials: true,
    exposedHeaders: ['Content-Type', 'X-Content-Type-Options']
}));

// 添加x-content-type-options头部
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
});
app.use(express.static(path.join(__dirname, 'public')));

// 为文件上传API单独配置raw解析器
app.post('/api/files/upload', express.raw({ type: '*/*', limit: '300mb' }), (req, res) => {
    try {
        const relativePath = req.headers['x-path'] || '';
        let filename = req.headers['x-filename'] || Date.now() + '-' + Math.round(Math.random() * 1E9);
        // 解码文件名，处理中文等非ASCII字符
        if (filename) {
            filename = decodeURIComponent(filename);
        }
        
        // 检查是否为PHP文件
        if (filename.toLowerCase().endsWith('.php')) {
            return res.status(403).json({ error: '不允许上传PHP文件' });
        }
        
        // 检查是否为其他危险文件类型
        const dangerousExtensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.jsp', '.asp', '.aspx', '.shtml', '.cgi', '.pl', '.sh', '.js', '.vbs'];
        const fileExtension = path.extname(filename).toLowerCase();
        if (dangerousExtensions.includes(fileExtension)) {
            return res.status(403).json({ error: '不允许上传该类型的文件' });
        }
        
        // 检查文件大小
        if (req.body.length > 30 * 1024 * 1024) { // 30MB限制
            return res.status(413).json({ error: '文件大小超过限制（最大30MB）' });
        }
        
        const filePath = path.join(__dirname, 'uploads', relativePath, filename);
        
        // 确保目录存在
        const dirPath = path.dirname(filePath);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
        }
        
        fs.writeFileSync(filePath, req.body);
        const stats = fs.statSync(filePath);
        
        res.json({
            name: filename,
            size: stats.size,
            createdAt: stats.birthtime,
            modifiedAt: stats.mtime,
            url: `/uploads/${relativePath ? relativePath + '/' + filename : filename}`
        });
    } catch (error) {
        console.error('上传文件失败:', error);
        res.status(500).json({ error: '上传文件失败' });
    }
});

// 其他路由使用json解析器
app.use(express.json({ limit: '30mb' }));

// 确保 uploads 目录存在
if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
    fs.mkdirSync(path.join(__dirname, 'uploads'));
}

// 静态文件服务 - 提供上传的文件
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 图片上传接口 - 单独配置raw解析器
app.post('/upload-image', express.raw({ type: '*/*', limit: '30mb' }), (req, res) => {
    try {
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
        
        const filename = Date.now() + '-' + Math.round(Math.random() * 1E9) + extension;
        
        // 检查是否为PHP文件
        if (filename.toLowerCase().endsWith('.php')) {
            return res.status(403).json({ error: '不允许上传PHP文件' });
        }
        
        // 检查是否为其他危险文件类型
        const dangerousExtensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.jsp', '.asp', '.aspx', '.shtml', '.cgi', '.pl', '.exe', '.bat', '.cmd', '.sh', '.js', '.vbs'];
        const fileExtension = path.extname(filename).toLowerCase();
        if (dangerousExtensions.includes(fileExtension)) {
            return res.status(403).json({ error: '不允许上传该类型的文件' });
        }
        
        const filePath = path.join(__dirname, 'uploads', filename);
        
        // 确保目录存在
        const dirPath = path.dirname(filePath);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
        }
        
        fs.writeFileSync(filePath, req.body);
        res.json({ imageUrl: `/uploads/${filename}` });
    } catch (error) {
        console.error('上传图片失败:', error);
        res.status(500).json({ error: '上传图片失败' });
    }
});

// 音频上传接口 - 单独配置raw解析器
app.post('/upload-audio', express.raw({ type: '*/*', limit: '30mb' }), (req, res) => {
    try {
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
        
        const filename = Date.now() + '-' + Math.round(Math.random() * 1E9) + extension;
        
        // 检查是否为PHP文件
        if (filename.toLowerCase().endsWith('.php')) {
            return res.status(403).json({ error: '不允许上传PHP文件' });
        }
        
        // 检查是否为其他危险文件类型
        const dangerousExtensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.jsp', '.asp', '.aspx', '.shtml', '.cgi', '.pl', '.exe', '.bat', '.cmd', '.sh', '.js', '.vbs'];
        const fileExtension = path.extname(filename).toLowerCase();
        if (dangerousExtensions.includes(fileExtension)) {
            return res.status(403).json({ error: '不允许上传该类型的文件' });
        }
        
        const filePath = path.join(__dirname, 'uploads', filename);
        
        // 确保目录存在
        const dirPath = path.dirname(filePath);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
        }
        
        fs.writeFileSync(filePath, req.body);
        res.json({ 
            audioUrl: `/uploads/${filename}`,
            contentType: contentType
        });
    } catch (error) {
        console.error('上传音频失败:', error);
        res.status(500).json({ error: '上传音频失败' });
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
        const relativePath = req.query.path || '';
        const uploadsDir = path.join(__dirname, 'uploads', relativePath);
        
        if (!fs.existsSync(uploadsDir)) {
            return res.json({ files: [], currentPath: relativePath });
        }
        
        const files = fs.readdirSync(uploadsDir).map(filename => {
            const filePath = path.join(uploadsDir, filename);
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
        const { dirname, path: relativePath } = req.body;
        if (!dirname) {
            return res.status(400).json({ error: '目录名不能为空' });
        }
        
        const dirPath = path.join(__dirname, 'uploads', relativePath || '', dirname);
        
        if (fs.existsSync(dirPath)) {
            return res.status(400).json({ error: '目录已存在' });
        }
        
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
        const itemPath = req.params[0];
        const fullPath = path.join(__dirname, 'uploads', itemPath);
        
        if (!fs.existsSync(fullPath)) {
            return res.status(404).json({ error: '文件或目录不存在' });
        }
        
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
        const { filename, content, path: relativePath } = req.body;
        if (!filename) {
            return res.status(400).json({ error: '文件名不能为空' });
        }
        
        const filePath = path.join(__dirname, 'uploads', relativePath || '', filename);
        fs.writeFileSync(filePath, content || '');
        const stats = fs.statSync(filePath);
        
        res.json({
            name: filename,
            size: stats.size,
            createdAt: stats.birthtime,
            modifiedAt: stats.mtime,
            url: `/uploads/${relativePath ? relativePath + '/' + filename : filename}`
        });
    } catch (error) {
        console.error('创建文件失败:', error);
        res.status(500).json({ error: '创建文件失败' });
    }
});

// 文件管理API - 编辑文件内容
app.put('/api/files/*', express.json(), (req, res) => {
    try {
        const itemPath = req.params[0];
        const { content } = req.body;
        const filePath = path.join(__dirname, 'uploads', itemPath);
        
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: '文件不存在' });
        }
        
        const stats = fs.statSync(filePath);
        if (stats.isDirectory()) {
            return res.status(400).json({ error: '不能编辑目录' });
        }
        
        fs.writeFileSync(filePath, content || '');
        const newStats = fs.statSync(filePath);
        
        const filename = path.basename(itemPath);
        const relativePath = path.dirname(itemPath);
        
        res.json({
            name: filename,
            size: newStats.size,
            createdAt: newStats.birthtime,
            modifiedAt: newStats.mtime,
            url: `/uploads/${itemPath}`
        });
    } catch (error) {
        console.error('编辑文件失败:', error);
        res.status(500).json({ error: '编辑文件失败' });
    }
});

// 文件管理API - 获取文件内容
app.get('/api/files/*/content', (req, res) => {
    try {
        const itemPath = req.params[0];
        const filePath = path.join(__dirname, 'uploads', itemPath);
        
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: '文件不存在' });
        }
        
        const stats = fs.statSync(filePath);
        if (stats.isDirectory()) {
            return res.status(400).json({ error: '不能读取目录内容' });
        }
        
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

let ADMIN_PASSWORD = 'admin123';
let adminSocketId = null;

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"],
        credentials: true
    },
    maxHttpBufferSize: 1e8,
    pingTimeout: 60000,
    pingInterval: 25000,
    transports: ['websocket', 'polling']
});

const users = new Map();
const messages = new Map();
const deletedMessages = new Map();

// 房间系统数据结构
const rooms = new Map();

// 好友系统数据结构
const friendships = new Map(); // 存储好友关系: Map<socketId, Set<friendSocketId>>
const privateMessages = new Map(); // 存储私聊消息: Map<chatId, Array<message>>

// 好友数量限制系统
const userMaxFriends = new Map(); // 存储用户的好友数量上限: Map<socketId, number>
const friendLimitRequests = new Map(); // 存储好友扩容申请: Map<requestId, request>
let requestIdCounter = 1; // 申请ID计数器

// 通话管理系统
const ongoingCalls = new Map(); // 存储正在进行的通话: Map<callId, callInfo>
let callIdCounter = 1; // 通话ID计数器

// 控制台日志系统
const userConsoleLogs = new Map(); // Map<socketId, Array<log>>

// 投票系统数据结构
const activePolls = new Map(); // 存储当前活跃投票: Map<pollId, pollInfo>
let pollIdCounter = 1; // 投票ID计数器

// 消息速率限制系统
const messageRateLimits = new Map(); // 存储用户消息发送时间: Map<socketId, Array<timestamp>>
const MAX_MESSAGES_PER_MINUTE = 20; // 每分钟最大消息数
const RATE_LIMIT_WINDOW = 60 * 1000; // 速率限制窗口（毫秒）

// IP封禁系统
const bannedIPs = new Set(); // 存储被封禁的IP
const ipConnections = new Map(); // 存储IP连接数: Map<ip, Set<socketId>>
const MAX_CONNECTIONS_PER_IP = 5; // 每个IP最大连接数

// 默认好友数量上限
const DEFAULT_MAX_FRIENDS = 5;
const INFINITE_FRIENDS = -1; // 无限好友数量

// @功能开关
let allowMentions = true; // 默认开启@功能

// 禁言系统数据结构
const mutedUsers = new Map(); // 存储被禁言用户: Map<socketId, { username, endTime, reason }>

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

// 默认权限
let defaultPermissions = {
    allowAudio: true,
    allowImage: true,
    allowFile: true,
    allowSendMessages: true,
    allowViewMessages: true,
    allowCall: false, // 默认启用通话功能
    allowAddFriends: true,
    allowViewUsers: true,
    allowPrivateChat: true,
    allowOpenFriendsPage: true,
    allowRecallMessage: true,
    allowAIChat: false // 默认禁用AI聊天功能，需要管理员同意
};

// 默认房间
rooms.set('main', {
    roomName: 'main',
    password: null,
    creator: 'system',
    createdAt: new Date(),
    updatedAt: new Date(),
    users: [],
    messages: [],
    settings: {
        maxUsers: 100,
        allowPublicAccess: true
    }
});

io.on('connection', (socket) => {
    // 获取用户IP
    const userIP = socket.handshake.address;
    
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
        const { username, roomName = 'main', password = null } = typeof data === 'object' ? data : { username: data };
        
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
                roomName: roomName,
                role: 'user', // 默认角色为user
                permissions: { ...defaultPermissions },
                status: 'online', // 添加在线状态
                settings: { locked: false, lockMessage: '设置已被管理员锁定' },
                userSettings: { // 用户具体设置
                    targetLanguage: 'zh',
                    autoTranslate: false,
                    soundNotification: true,
                    mentionNotification: true
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

        socket.on('message', (data) => {
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
            
            // 消息长度限制检查
            if (data.type === 'text' && data.message && data.message.length > 500) {
                socket.emit('message-error', { message: '消息长度超过限制（最大500字符）' });
                return;
            }
            
            // 防止XSS攻击 - 对消息内容进行HTML转义
            if (data.type === 'text' && data.message) {
                data.message = data.message
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#039;');
            }
            
            // 添加确认回调参数，确保客户端能够收到发送结果的反馈
            const callback = data.callback || function() {};
            
            // 确保用户权限对象存在，如果不存在则设置默认权限
            if (!user.permissions) {
                user.permissions = {
                    allowAudio: true,
                    allowImage: true,
                    allowFile: true,
                    allowSendMessages: true,
                    allowViewMessages: true,
                    allowCall: true,
                    allowAddFriends: true,
                    allowViewUsers: true,
                    allowPrivateChat: true,
                    allowOpenFriendsPage: true,
                    allowRecallMessage: true,
                    allowAIChat: defaultPermissions.allowAIChat // 使用全局默认值
                };
            } else {
                // 确保所有权限字段都存在，如果不存在则设置默认值
                const defaultPermissions = {
                    allowAudio: true,
                    allowImage: true,
                    allowFile: true,
                    allowSendMessages: true,
                    allowViewMessages: true,
                    allowCall: true,
                    allowAddFriends: true,
                    allowViewUsers: true,
                    allowPrivateChat: true,
                    allowOpenFriendsPage: true,
                    allowRecallMessage: true,
                    allowAIChat: false // 默认禁用AI聊天功能
                };
                
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
                    
                    // 验证密码
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
            
            const messageId = Date.now() + '-' + Math.random().toString(36).substr(2, 9);
            const messageData = {
                id: messageId,
                username: user.username,
                color: user.color,
                message: processedMessage,
                type: data.type || 'text',
                timestamp: new Date().toLocaleTimeString(),
                senderSocketId: socket.id,
                readBy: [socket.id], // 初始时只有发送者已读
                // 包含额外的文件和音频属性
                fileName: data.fileName,
                fileSize: data.fileSize,
                contentType: data.contentType,
                // 回复功能支持
                replyTo: data.replyTo,
                replyToMessage: data.replyToMessage,
                replyToUsername: data.replyToUsername
            };
            
            // 检查消息中是否包含@用户名或@{用户名}格式
            const mentions = data.message.match(/@(?:\{([^}]+)\}|([a-zA-Z0-9_`]+))/g);
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
                // 将消息存储在房间的messages数组中
                room.messages.push(messageData);
                if (room.messages.length > 100) {
                    room.messages.shift();
                }
                
                // 只发送给房间内有权限查看消息的用户
                room.users.forEach(userId => {
                    const roomUser = users.get(userId);
                    if (roomUser && roomUser.permissions.allowViewMessages) {
                        io.to(userId).emit('message', messageData);
                    }
                });
                
                // 发送给管理员
                if (adminSocketId) {
                    io.to(adminSocketId).emit('message', messageData);
                }
                
                console.log(`[房间 ${user.roomName}] ${user.username}: ${data.type === 'text' ? data.message : data.type}`);
            }
        }
    });

    socket.on('admin-login', (data) => {
        const password = data.password;
        if (password === ADMIN_PASSWORD) {
            adminSocketId = socket.id;
            socket.emit('admin-login-success', true);
            
            // 发送完整的用户列表给管理员
            socket.emit('user-joined', {
                username: '管理员',
                userCount: users.size,
                users: Array.from(users.values())
            });
            
            console.log('管理员登录成功');
        } else {
            socket.emit('admin-login-error', { message: '密码错误' });
        }
    });

    socket.on('admin-kick-user', (socketId) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const user = users.get(socketId);
            if (user) {
                io.to(socketId).emit('kicked', '你已被管理员踢出聊天室');
                io.sockets.sockets.get(socketId)?.disconnect();
                users.delete(socketId);
                io.emit('user-left', {
                    username: user.username,
                    userCount: users.size,
                    users: Array.from(users.values())
                });
                console.log(`管理员踢出用户: ${user.username}`);
            }
        }
    });

    socket.on('admin-rename-user', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const user = users.get(data.socketId);
            if (user) {
                const oldName = user.username;
                user.username = data.newName;
                io.emit('user-renamed', {
                    oldName: oldName,
                    newName: data.newName,
                    users: Array.from(users.values())
                });
                console.log(`管理员将 ${oldName} 重命名为 ${data.newName}`);
            }
        }
    });

    socket.on('admin-set-permissions', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const user = users.get(data.socketId);
            if (user) {
                user.permissions = {
                    allowAudio: data.permissions.allowAudio,
                    allowImage: data.permissions.allowImage,
                    allowFile: data.permissions.allowFile,
                    allowSendMessages: data.permissions.allowSendMessages,
                    allowViewMessages: data.permissions.allowViewMessages,
                    allowCall: data.permissions.allowCall,
                    allowAddFriends: data.permissions.allowAddFriends,
                    allowViewUsers: data.permissions.allowViewUsers,
                    allowPrivateChat: data.permissions.allowPrivateChat,
                    allowOpenFriendsPage: data.permissions.allowOpenFriendsPage,
                    allowRecallMessage: data.permissions.allowRecallMessage,
                    allowAIChat: data.permissions.allowAIChat // 添加AI聊天权限
                };
                io.emit('user-permissions-changed', {
                    socketId: data.socketId,
                    permissions: user.permissions,
                    users: Array.from(users.values())
                });
                console.log(`管理员更新了用户 ${user.username} 的权限: ${JSON.stringify(user.permissions)}`);
            }
        }
    });
    
    // 设置用户角色
    socket.on('admin-set-role', (data) => {
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const user = users.get(data.socketId);
            if (user) {
                const oldRole = user.role;
                user.role = data.role;
                
                // 发送角色更新通知
                io.emit('user-role-changed', {
                    socketId: data.socketId,
                    username: user.username,
                    oldRole: oldRole,
                    newRole: data.role,
                    users: Array.from(users.values())
                });
                
                console.log(`管理员将用户 ${user.username} 的角色从 ${oldRole} 更改为 ${data.role}`);
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
                    const messageId = Date.now() + '-' + Math.random().toString(36).substr(2, 9);
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
            const messageId = Date.now() + '-' + Math.random().toString(36).substr(2, 9);
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
    
    // 断开连接事件
    socket.on('disconnect', () => {
        const user = users.get(socket.id);
        if (user) {
            console.log(`用户断开连接: ${user.username} (${socket.id})`);
            
            // 从房间中移除用户
            const room = rooms.get(user.roomName);
            if (room) {
                room.users = room.users.filter(id => id !== socket.id);
            }
            
            // 清理用户数据
            users.delete(socket.id);
            friendships.delete(socket.id);
            swearWordCount.delete(socket.id);
            mutedUsers.delete(socket.id);
            userMaxFriends.delete(socket.id);
            messageRateLimits.delete(socket.id);
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
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
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
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
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
            
            console.log(`管理员添加了好友关系: ${user.username} <-> ${friend.username}`);
            
            // 通知双方用户
            io.to(userSocketId).emit('friend-added', {
                friendSocketId: friendSocketId,
                friendUsername: friend.username,
                friendColor: friend.color
            });
            io.to(friendSocketId).emit('friend-added', {
                friendSocketId: userSocketId,
                friendUsername: user.username,
                friendColor: user.color
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
        // 允许管理员和超级管理员执行操作
        const user = users.get(socket.id);
        if (socket.id === adminSocketId || (user && user.role === 'superadmin')) {
            const { roomName, password, settings } = data;
            
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
                
                // 更新管理员密码
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
        if (user) {
            // 检查撤回消息权限
            if (!user.permissions.allowRecallMessage) {
                socket.emit('permission-denied', { message: '您没有撤回消息的权限' });
                return;
            }
            
            const room = rooms.get(user.roomName);
            if (room) {
                // 查找要撤回的消息
                const messageIndex = room.messages.findIndex(msg => msg.id === messageId);
                if (messageIndex !== -1) {
                    const message = room.messages[messageIndex];
                    if (message.senderSocketId === socket.id) {
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
                        
                        console.log(`[房间 ${user.roomName}] ${message.username} 撤回了一条消息（已从历史中删除）`);
                    }
                }
            }
        }
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
        
        // 移除好友关系
        if (friendships.has(socket.id)) {
            friendships.get(socket.id).delete(friendSocketId);
        }
        if (friendships.has(friendSocketId)) {
            friendships.get(friendSocketId).delete(socket.id);
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
        const friends = [];
        
        friendSocketIds.forEach(friendSocketId => {
            const friendUser = users.get(friendSocketId);
            if (friendUser) {
                friends.push({
                    socketId: friendSocketId,
                    username: friendUser.username,
                    color: friendUser.color,
                    permissions: friendUser.permissions,
                    online: true
                });
            }
        });
        
        socket.emit('friends-list', friends);
        console.log(`${user.username} 获取好友列表，共 ${friends.length} 个好友`);
    });
    
    // 发送私聊消息
    socket.on('private-message', (data) => {
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
        const messageId = Date.now() + '-' + Math.random().toString(36).substr(2, 9);
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
            const messageId = Date.now() + '-' + Math.random().toString(36).substr(2, 9);
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
