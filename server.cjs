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
app.use(express.json({ limit: '30mb' }));
app.use(express.raw({ type: ['image/*', 'audio/*'], limit: '30mb' }));

// 确保 uploads 目录存在
if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
    fs.mkdirSync(path.join(__dirname, 'uploads'));
}

// 静态文件服务 - 提供上传的文件
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 图片上传接口
app.post('/upload-image', (req, res) => {
    try {
        const filename = Date.now() + '-' + Math.round(Math.random() * 1E9) + '.jpg';
        const filePath = path.join(__dirname, 'uploads', filename);
        fs.writeFileSync(filePath, req.body);
        res.json({ imageUrl: `/uploads/${filename}` });
    } catch (error) {
        console.error('上传图片失败:', error);
        res.status(500).json({ error: '上传图片失败' });
    }
});

// 音频上传接口
app.post('/upload-audio', (req, res) => {
    try {
        const filename = Date.now() + '-' + Math.round(Math.random() * 1E9) + '.webm';
        const filePath = path.join(__dirname, 'uploads', filename);
        fs.writeFileSync(filePath, req.body);
        res.json({ audioUrl: `/uploads/${filename}` });
    } catch (error) {
        console.error('上传音频失败:', error);
        res.status(500).json({ error: '上传音频失败' });
    }
});

// 视频上传接口
app.post('/upload-video', (req, res) => {
    try {
        const filename = Date.now() + '-' + Math.round(Math.random() * 1E9) + '.webm';
        const filePath = path.join(__dirname, 'uploads', filename);
        fs.writeFileSync(filePath, req.body);
        res.json({ videoUrl: `/uploads/${filename}` });
    } catch (error) {
        console.error('上传视频失败:', error);
        res.status(500).json({ error: '上传视频失败' });
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

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST']
    }
});

// 存储在线用户
const users = new Map();

// 存储房间信息
const rooms = new Map();

// 存储好友关系
const friends = new Map();

// 存储私聊消息
const privateMessages = new Map();

// 存储好友请求
const friendRequests = new Map();

// 存储用户活动数据
const userActivity = new Map();

// 存储系统日志
const systemLogs = [];

// 存储管理员socket ID
let adminSocketId = null;

// 存储活跃的聊天室提示
const activeNotifications = [];

// 存储用户消息历史（用于刷屏检测）
const userMessageHistory = new Map();

// 存储用户禁言状态
const mutedUsers = new Map();

// 创建用户活动数据结构
function createUserActivityData() {
    return {
        socketId: '',
        username: '',
        joinTime: new Date(),
        messages: 0,
        filesUploaded: 0,
        audioSent: 0,
        videoSent: 0,
        imagesSent: 0,
        privateMessages: 0,
        friendRequests: 0,
        friendsAdded: 0,
        callsInitiated: 0,
        callsReceived: 0,
        swears: 0,
        lastActive: new Date(),
        activityHistory: [],
        messageLengths: []
    };
}

// 计算两个字符串的相似度（基于Levenshtein距离）
function calculateSimilarity(str1, str2) {
    if (!str1 || !str2) return 0;
    if (str1 === str2) return 1;
    
    const matrix = [];
    const n = str1.length;
    const m = str2.length;
    
    // 初始化矩阵
    for (let i = 0; i <= n; i++) {
        matrix[i] = [i];
    }
    for (let j = 0; j <= m; j++) {
        matrix[0][j] = j;
    }
    
    // 计算编辑距离
    for (let i = 1; i <= n; i++) {
        for (let j = 1; j <= m; j++) {
            const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
            matrix[i][j] = Math.min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            );
        }
    }
    
    // 计算相似度
    const maxLength = Math.max(n, m);
    const similarity = 1 - (matrix[n][m] / maxLength);
    return similarity;
}

// 检测用户是否在刷屏
function detectSpamming(socketId, message) {
    // 获取用户的消息历史
    let messageHistory = userMessageHistory.get(socketId);
    if (!messageHistory) {
        messageHistory = [];
        userMessageHistory.set(socketId, messageHistory);
    }
    
    // 添加当前消息到历史记录
    messageHistory.push({
        message: message,
        timestamp: new Date()
    });
    
    // 只保留最近的20条消息
    if (messageHistory.length > 20) {
        messageHistory.shift();
    }
    
    // 检测重复消息
    const recentMessages = messageHistory.slice(-10); // 最近10条消息
    const uniqueMessages = new Set(recentMessages.map(msg => msg.message));
    
    // 如果最近10条消息中有8条以上是重复的，则认为是刷屏
    if (recentMessages.length >= 8 && uniqueMessages.size <= 2) {
        return true;
    }
    
    // 检测相似度高的消息
    if (recentMessages.length >= 10) {
        let highSimilarityCount = 0;
        
        for (let i = 0; i < recentMessages.length - 1; i++) {
            const similarity = calculateSimilarity(recentMessages[i].message, recentMessages[i + 1].message);
            if (similarity >= 0.9) {
                highSimilarityCount++;
            }
        }
        
        // 如果最近10条消息中有8对以上相似度高于90%，则认为是刷屏
        if (highSimilarityCount >= 8) {
            return true;
        }
    }
    
    return false;
}

// 禁言用户
function muteUser(socketId, reason, duration = 5 * 60 * 1000) { // 默认禁言5分钟
    const user = users.get(socketId);
    if (!user) return;
    
    const muteEndTime = Date.now() + duration;
    
    // 设置禁言状态
    mutedUsers.set(socketId, {
        username: user.username,
        reason: reason,
        muteEndTime: muteEndTime,
        roomName: user.roomName
    });
    
    console.log(`[禁言] ${user.username} 被禁言 ${duration / 1000 / 60} 分钟，理由: ${reason}`);
    
    // 广播禁言信息给所有用户
    io.emit('user-muted', {
        username: user.username,
        reason: reason,
        duration: duration / 1000 / 60, // 转换为分钟
        roomName: user.roomName
    });
    
    // 记录系统事件
    logSystemEvent('user-muted', `${user.username} 被禁言，理由: ${reason}，时长: ${duration / 1000 / 60} 分钟`, socketId, user.roomName);
    
    // 禁言时间到后自动解除禁言
    setTimeout(() => {
        if (mutedUsers.has(socketId)) {
            mutedUsers.delete(socketId);
            
            // 广播解禁信息给所有用户
            io.emit('user-unmuted', {
                username: user.username,
                roomName: user.roomName
            });
            
            // 记录系统事件
            logSystemEvent('user-unmuted', `${user.username} 禁言解除`, socketId, user.roomName);
        }
    }, duration);
}

// 检查用户是否被禁言
function isUserMuted(socketId) {
    const muteInfo = mutedUsers.get(socketId);
    if (!muteInfo) return false;
    
    // 检查禁言是否过期
    if (Date.now() > muteInfo.muteEndTime) {
        mutedUsers.delete(socketId);
        return false;
    }
    
    return true;
}

// 记录系统事件
function logSystemEvent(eventType, description, userId = null, roomId = null) {
    const logEntry = {
        id: Date.now().toString(),
        timestamp: new Date(),
        eventType,
        description,
        userId,
        roomId
    };
    systemLogs.push(logEntry);
    
    // 限制日志数量，最多保留1000条
    if (systemLogs.length > 1000) {
        systemLogs.shift();
    }
    
    return logEntry;
}

// 处理用户连接
io.on('connection', (socket) => {
    console.log(`用户连接: ${socket.id}`);
    
    // 处理用户加入
    socket.on('join', (data) => {
        const { username, roomName = 'main', password = null } = data;
        
        // 检查用户名是否已存在
        let usernameExists = false;
        users.forEach(user => {
            if (user.username === username && user.roomName === roomName) {
                usernameExists = true;
            }
        });
        
        if (usernameExists) {
            socket.emit('join-error', { message: '用户名已存在，请选择其他昵称' });
            return;
        }
        
        // 检查房间密码
        if (rooms.has(roomName)) {
            const room = rooms.get(roomName);
            if (room.password && room.password !== password) {
                socket.emit('join-error', { message: '密码错误' });
                return;
            }
        } else {
            // 创建新房间
            rooms.set(roomName, {
                name: roomName,
                password: password,
                users: [],
                messages: [],
                createdAt: new Date()
            });
        }
        
        // 创建用户信息
        // 随机分配权限（25%概率有通话权限）
        const hasCallPermission = Math.random() < 0.25;
        
        const user = {
            id: socket.id,
            username,
            roomName,
            socketId: socket.id,
            color: getRandomColor(),
            status: 'online',
            joinedAt: new Date(),
            permissions: {
                admin: false,
                canKick: false,
                canMute: false,
                canChangeSettings: false,
                allowAudio: true,
                allowImage: true,
                allowFile: true,
                allowSendMessages: true,
                allowViewMessages: true,
                allowCall: hasCallPermission,
                allowAIChat: false
            }
        };
        
        // 存储用户信息
        users.set(socket.id, user);
        
        // 将用户加入房间
        const room = rooms.get(roomName);
        room.users.push(socket.id);
        
        // 加入Socket.IO房间
        socket.join(roomName);
        
        // 创建用户活动数据
        const activityData = createUserActivityData();
        activityData.socketId = socket.id;
        activityData.username = username;
        userActivity.set(socket.id, activityData);
        
        // 发送用户列表给新用户
        const roomUsers = Array.from(users.values()).filter(u => u.roomName === roomName);
        socket.emit('users', roomUsers);
        
        // 发送房间历史消息
        const roomMessages = room.messages.slice(-50); // 只发送最近50条消息
        socket.emit('room-history', { messages: roomMessages, roomName });
        
        // 广播用户加入消息给房间内其他用户
    socket.to(roomName).emit('user-joined', {
        username,
        userCount: roomUsers.length,
        users: roomUsers,
        roomName
    });
    
    // 发送用户加入消息给当前用户
    socket.emit('user-joined', {
        username,
        userCount: roomUsers.length,
        users: roomUsers,
        roomName
    });
        
        // 发送用户上线状态通知
        socket.to(roomName).emit('user-status-changed', {
            username,
            socketId: socket.id,
            status: 'online',
            roomName
        });
        
        console.log(`[房间 ${roomName}] ${username} 加入聊天室，当前在线: ${roomUsers.length} 人`);
        
        // 记录系统事件
        logSystemEvent('user-join', `${username} 加入房间 ${roomName}`, socket.id, roomName);
    });
    
    // 处理消息
    socket.on('message', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        // 检查用户是否被禁言
        if (isUserMuted(socket.id)) {
            const muteInfo = mutedUsers.get(socket.id);
            socket.emit('muted', {
                reason: muteInfo.reason,
                duration: Math.ceil((muteInfo.muteEndTime - Date.now()) / 1000 / 60) // 剩余禁言时间（分钟）
            });
            return;
        }
        
        const { message, type = 'text', replyTo = null } = data;
        
        // 检测用户是否在刷屏
        if (type === 'text' && message && message.length > 0) {
            if (detectSpamming(socket.id, message)) {
                // 禁言用户，理由：刷屏
                muteUser(socket.id, '刷屏');
                return;
            }
        }
        
        // 创建消息对象
        const newMessage = {
            id: Date.now().toString(),
            username: user.username,
            socketId: socket.id,
            senderSocketId: socket.id,
            message,
            type,
            timestamp: new Date(),
            roomName: user.roomName,
            replyTo,
            readBy: [socket.id]
        };
        
        // 存储消息到房间
        const room = rooms.get(user.roomName);
        if (room) {
            room.messages.push(newMessage);
            
            // 限制房间消息数量，每个房间最多保留1000条消息
            if (room.messages.length > 1000) {
                room.messages.shift();
            }
        }
        
        // 广播消息给房间内所有用户
        io.to(user.roomName).emit('message', newMessage);
        
        // 更新用户活动数据
        if (userActivity.has(socket.id)) {
            const activity = userActivity.get(socket.id);
            activity.messages++;
            activity.lastActive = new Date();
            activity.activityHistory.push({
                type: 'message',
                timestamp: new Date(),
                messageLength: message.length
            });
            if (message.length > 0) {
                activity.messageLengths.push(message.length);
            }
        }
        
        // 记录系统事件
        logSystemEvent('message', `${user.username} 发送消息`, socket.id, user.roomName);
    });
    
    // 处理用户离开
    socket.on('disconnect', () => {
        const user = users.get(socket.id);
        if (user) {
            // 从房间中移除用户
            const room = rooms.get(user.roomName);
            if (room) {
                room.users = room.users.filter(userId => userId !== socket.id);
                
                // 广播用户离开消息
                const roomUsers = Array.from(users.values()).filter(u => u.roomName === user.roomName);
                io.to(user.roomName).emit('user-left', {
                    username: user.username,
                    userCount: roomUsers.length,
                    users: roomUsers,
                    roomName: user.roomName
                });
                
                // 发送用户离线状态通知
                io.to(user.roomName).emit('user-status-changed', {
                    username: user.username,
                    socketId: socket.id,
                    status: 'offline',
                    roomName: user.roomName
                });
                
                console.log(`[房间 ${user.roomName}] ${user.username} 离开聊天室，当前在线: ${roomUsers.length} 人`);
            }
            
            // 删除用户信息
            users.delete(socket.id);
            
            // 删除用户活动数据
            userActivity.delete(socket.id);
            
            // 记录系统事件
            logSystemEvent('user-leave', `${user.username} 离开聊天室`, socket.id, user.roomName);
        }
        
        if (socket.id === adminSocketId) {
            adminSocketId = null;
            console.log('管理员断开连接');
        }
        
        console.log(`用户断开连接: ${socket.id}`);
    });
    
    // 处理私聊消息
    socket.on('private-message', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { receiverId, message, type = 'text' } = data;
        
        // 创建私聊消息
        const privateMessage = {
            id: Date.now().toString(),
            senderId: socket.id,
            senderUsername: user.username,
            receiverId,
            message,
            type,
            timestamp: new Date(),
            read: false
        };
        
        // 存储私聊消息
        const chatId = [socket.id, receiverId].sort().join('-');
        if (!privateMessages.has(chatId)) {
            privateMessages.set(chatId, []);
        }
        privateMessages.get(chatId).push(privateMessage);
        
        // 限制私聊消息数量，每对用户最多保留500条消息
        if (privateMessages.get(chatId).length > 500) {
            privateMessages.get(chatId).shift();
        }
        
        // 发送私聊消息给接收者
        io.to(receiverId).emit('private-message', privateMessage);
        
        // 发送确认给发送者
        socket.emit('private-message-sent', privateMessage);
        
        // 更新用户活动数据
        if (userActivity.has(socket.id)) {
            const activity = userActivity.get(socket.id);
            activity.privateMessages++;
            activity.lastActive = new Date();
        }
        
        // 记录系统事件
        logSystemEvent('private-message', `${user.username} 发送私聊消息`, socket.id);
    });
    
    // 处理好友请求
    socket.on('friend-request', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { receiverId } = data;
        
        // 检查是否已经是好友
        const friendKey = [socket.id, receiverId].sort().join('-');
        if (friends.has(friendKey)) {
            socket.emit('friend-error', { message: '已经是好友了' });
            return;
        }
        
        // 检查是否已经发送过请求
        if (friendRequests.has(`${socket.id}-${receiverId}`)) {
            socket.emit('friend-error', { message: '已经发送过好友请求了' });
            return;
        }
        
        // 创建好友请求
        const request = {
            id: Date.now().toString(),
            senderId: socket.id,
            senderUsername: user.username,
            receiverId,
            status: 'pending',
            createdAt: new Date()
        };
        
        // 存储好友请求
        friendRequests.set(`${socket.id}-${receiverId}`, request);
        
        // 发送好友请求给接收者
        io.to(receiverId).emit('friend-request', request);
        
        // 发送确认给发送者
        socket.emit('friend-request-sent', request);
        
        // 更新用户活动数据
        if (userActivity.has(socket.id)) {
            const activity = userActivity.get(socket.id);
            activity.friendRequests++;
            activity.lastActive = new Date();
        }
        
        // 记录系统事件
        logSystemEvent('friend-request', `${user.username} 发送好友请求`, socket.id);
    });
    
    // 处理好友请求接受
    socket.on('accept-friend-request', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { requestId, senderId } = data;
        
        // 查找好友请求
        const request = friendRequests.get(`${senderId}-${socket.id}`);
        if (!request) return;
        
        // 创建好友关系
        const friendKey = [socket.id, senderId].sort().join('-');
        friends.set(friendKey, {
            id: friendKey,
            user1Id: socket.id,
            user1Username: user.username,
            user2Id: senderId,
            user2Username: request.senderUsername,
            createdAt: new Date()
        });
        
        // 删除好友请求
        friendRequests.delete(`${senderId}-${socket.id}`);
        
        // 发送好友请求接受通知给发送者
        io.to(senderId).emit('friend-request-accepted', {
            friendId: friendKey,
            receiverId: socket.id,
            receiverUsername: user.username
        });
        
        // 发送确认给接收者
        socket.emit('friend-request-accepted', {
            friendId: friendKey,
            senderId,
            senderUsername: request.senderUsername
        });
        
        // 更新用户活动数据
        if (userActivity.has(socket.id)) {
            const activity = userActivity.get(socket.id);
            activity.friendsAdded++;
            activity.lastActive = new Date();
        }
        if (userActivity.has(senderId)) {
            const activity = userActivity.get(senderId);
            activity.friendsAdded++;
            activity.lastActive = new Date();
        }
        
        // 记录系统事件
        logSystemEvent('friend-accept', `${user.username} 接受好友请求`, socket.id);
    });
    
    // 处理好友请求拒绝
    socket.on('reject-friend-request', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { requestId, senderId } = data;
        
        // 删除好友请求
        friendRequests.delete(`${senderId}-${socket.id}`);
        
        // 发送好友请求拒绝通知给发送者
        io.to(senderId).emit('friend-request-rejected', {
            receiverId: socket.id,
            receiverUsername: user.username
        });
        
        // 记录系统事件
        logSystemEvent('friend-reject', `${user.username} 拒绝好友请求`, socket.id);
    });
    
    // 处理获取好友列表
    socket.on('get-friends', () => {
        const user = users.get(socket.id);
        if (!user) return;
        
        // 获取用户的好友列表
        const userFriends = [];
        friends.forEach(friend => {
            if (friend.user1Id === socket.id) {
                userFriends.push({
                    id: friend.user2Id,
                    username: friend.user2Username
                });
            } else if (friend.user2Id === socket.id) {
                userFriends.push({
                    id: friend.user1Id,
                    username: friend.user1Username
                });
            }
        });
        
        // 发送好友列表给用户
        socket.emit('friends-list', userFriends);
    });
    
    // 处理获取私聊消息历史
    socket.on('get-private-messages', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { friendId } = data;
        
        // 获取私聊消息历史
        const chatId = [socket.id, friendId].sort().join('-');
        const messages = privateMessages.get(chatId) || [];
        
        // 发送私聊消息历史给用户
        socket.emit('private-messages-history', {
            friendId,
            messages
        });
    });
    
    // 处理消息已读
    socket.on('message-read', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { messageId, roomName } = data;
        
        // 更新房间消息的已读状态
        if (roomName && rooms.has(roomName)) {
            const room = rooms.get(roomName);
            const message = room.messages.find(msg => msg.id === messageId);
            if (message && !message.readBy.includes(socket.id)) {
                message.readBy.push(socket.id);
                
                // 发送已读通知给发送者
                if (message.senderSocketId !== socket.id) {
                    io.to(message.senderSocketId).emit('message-read-by-user', {
                        messageId,
                        readerId: socket.id,
                        readerUsername: user.username
                    });
                }
            }
        }
    });
    
    // 处理私聊消息已读
    socket.on('private-message-read', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { messageId, friendId } = data;
        
        // 更新私聊消息的已读状态
        const chatId = [socket.id, friendId].sort().join('-');
        const messages = privateMessages.get(chatId) || [];
        const message = messages.find(msg => msg.id === messageId);
        if (message) {
            message.read = true;
            
            // 发送已读通知给发送者
            if (message.senderId !== socket.id) {
                io.to(message.senderId).emit('private-message-read', {
                    messageId,
                    readerId: socket.id
                });
            }
        }
    });
    
    // 处理用户正在输入
    socket.on('user-typing', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { roomName } = data;
        
        // 广播用户正在输入状态
        socket.to(roomName).emit('user-typing', {
            username: user.username,
            roomName
        });
    });
    
    // 处理用户停止输入
    socket.on('user-stop-typing', (data) => {
        const user = users.get(socket.id);
        if (!user) return;
        
        const { roomName } = data;
        
        // 广播用户停止输入状态
        socket.to(roomName).emit('user-stop-typing', {
            username: user.username,
            roomName
        });
    });
    
    // 管理员密码存储（实际应用中应该使用加密存储）
    let adminPassword = 'admin123';
    
    // 处理管理员登录
    socket.on('admin-login', (data) => {
        const { password } = data;
        
        // 密码验证
        if (password === adminPassword) {
            adminSocketId = socket.id;
            socket.emit('admin-login-success');
            
            // 发送系统信息给管理员
            socket.emit('admin-system-info', {
                onlineUsers: users.size,
                rooms: Array.from(rooms.entries()).map(([name, room]) => ({
                    name,
                    users: room.users.length,
                    messages: room.messages.length
                })),
                systemLogs: systemLogs.slice(-100), // 只发送最近100条日志
                activeNotifications,
                adminPassword: adminPassword
            });
            
            console.log('管理员登录成功');
            
            // 记录系统事件
            logSystemEvent('admin-login', '管理员登录', socket.id);
        } else {
            socket.emit('admin-login-error', { message: '密码错误' });
        }
    });
    
    // 处理管理员修改密码
    socket.on('admin-change-password', (data) => {
        if (socket.id !== adminSocketId) return;
        
        const { oldPassword, newPassword } = data;
        
        // 验证旧密码
        if (oldPassword === adminPassword) {
            // 更新密码
            adminPassword = newPassword;
            
            // 发送密码修改成功通知
            socket.emit('admin-password-changed', { message: '密码修改成功' });
            
            // 记录系统事件
            logSystemEvent('admin-change-password', '管理员修改密码', socket.id);
        } else {
            socket.emit('admin-password-error', { message: '旧密码错误' });
        }
    });
    
    // 处理管理员禁言用户
    socket.on('admin-mute-user', (data) => {
        if (socket.id !== adminSocketId) return;
        
        const { socketId, reason, duration } = data;
        
        // 调用禁言函数
        muteUser(socketId, reason, duration);
        
        // 通知管理员禁言成功
        socket.emit('admin-mute-success', { message: '用户禁言成功' });
    });
    
    // 处理管理员解禁用户
    socket.on('admin-unmute-user', (data) => {
        if (socket.id !== adminSocketId) return;
        
        const { socketId } = data;
        const user = users.get(socketId);
        if (!user) return;
        
        // 移除禁言状态
        if (mutedUsers.has(socketId)) {
            mutedUsers.delete(socketId);
            
            // 广播解禁信息给所有用户
            io.emit('user-unmuted', {
                username: user.username,
                roomName: user.roomName
            });
            
            // 记录系统事件
            logSystemEvent('user-unmuted', `${user.username} 禁言解除（管理员操作）`, socketId, user.roomName);
            
            // 通知管理员解禁成功
            socket.emit('admin-unmute-success', { message: '用户禁言解除成功' });
        }
    });
    
    // 处理管理员获取用户列表
    socket.on('admin-get-users', () => {
        if (socket.id === adminSocketId) {
            // 构建包含禁言状态的用户列表
            const usersWithMuteStatus = Array.from(users.values()).map(user => {
                const muteInfo = mutedUsers.get(user.socketId);
                let muted = false;
                let muteReason = '';
                let remainingMuteTime = 0;
                
                if (muteInfo) {
                    // 检查禁言是否过期
                    if (Date.now() <= muteInfo.muteEndTime) {
                        muted = true;
                        muteReason = muteInfo.reason;
                        remainingMuteTime = Math.ceil((muteInfo.muteEndTime - Date.now()) / 1000 / 60); // 剩余禁言时间（分钟）
                    } else {
                        // 禁言已过期，移除禁言状态
                        mutedUsers.delete(user.socketId);
                    }
                }
                
                return {
                    ...user,
                    muted: muted,
                    muteReason: muteReason,
                    remainingMuteTime: remainingMuteTime
                };
            });
            
            socket.emit('user-joined', {
                username: '管理员',
                userCount: users.size,
                users: usersWithMuteStatus
            });
        }
    });
    
    // 处理管理员获取用户活动数据
    socket.on('admin-get-user-activity', () => {
        if (socket.id !== adminSocketId) return;
        
        // 发送用户活动数据给管理员
        socket.emit('admin-user-activity-data', Array.from(userActivity.values()));
    });
    
    // 处理管理员获取系统日志
    socket.on('admin-get-system-logs', (data) => {
        if (socket.id !== adminSocketId) return;
        
        const { filter, startDate, endDate, limit = 100 } = data || {};
        
        // 过滤日志
        let filteredLogs = systemLogs;
        
        if (filter) {
            filteredLogs = filteredLogs.filter(log => 
                log.eventType.includes(filter) || 
                log.description.includes(filter)
            );
        }
    });
    
    // 处理管理员获取用户行为分析数据
    socket.on('admin-get-user-analytics', (data) => {
        if (socket.id !== adminSocketId) return;
        
        const { timeRange } = data || {};
        console.log('获取用户行为分析数据，时间范围:', timeRange);
        
        // 计算统计数据
        const userActivityArray = Array.from(userActivity.values());
        const totalUsers = users.size;
        const activeUsers = userActivityArray.length;
        const totalMessages = userActivityArray.reduce((sum, user) => sum + user.messages, 0);
        const totalFiles = userActivityArray.reduce((sum, user) => sum + user.filesUploaded, 0);
        
        // 计算平均消息长度
        let totalMessageLength = 0;
        let messageCount = 0;
        userActivityArray.forEach(user => {
            if (user.messageLengths.length > 0) {
                totalMessageLength += user.messageLengths.reduce((sum, length) => sum + length, 0);
                messageCount += user.messageLengths.length;
            }
        });
        const avgMessageLength = messageCount > 0 ? totalMessageLength / messageCount : 0;
        
        // 计算峰值时段
        const hourCounts = new Array(24).fill(0);
        userActivityArray.forEach(user => {
            if (user.activityHistory.length > 0) {
                user.activityHistory.forEach(activity => {
                    const hour = new Date(activity.timestamp).getHours();
                    hourCounts[hour]++;
                });
            }
        });
        const peakHour = hourCounts.indexOf(Math.max(...hourCounts));
        
        // 计算留存率（这里简单模拟，实际需要根据历史数据计算）
        const retentionRate = activeUsers / totalUsers;
        
        // 计算平均在线时间
        const now = new Date();
        let totalOnlineTime = 0;
        userActivityArray.forEach(user => {
            const joinTime = new Date(user.joinTime);
            totalOnlineTime += (now - joinTime) / (1000 * 60); // 转换为分钟
        });
        const avgOnlineTime = activeUsers > 0 ? Math.round(totalOnlineTime / activeUsers) : 0;
        
        // 计算回复率（这里简单模拟，实际需要根据消息交互计算）
        const responseRate = 0.3; // 假设30%的消息有回复
        
        // 计算用户增长率（这里简单模拟，实际需要根据历史数据计算）
        const userGrowthRate = 0.1; // 假设10%的增长率
        
        // 准备用户行为详情
        const behaviorDetails = userActivityArray.map(user => {
            // 计算活跃度分数
            const activityScore = (
                user.messages * 2 +
                user.filesUploaded * 5 +
                user.privateMessages * 3 +
                user.callsInitiated * 10 +
                user.callsReceived * 10
            );
            
            // 计算在线时长
            const joinTime = new Date(user.joinTime);
            const onlineTime = Math.round((now - joinTime) / (1000 * 60)); // 转换为分钟
            
            return {
                socketId: user.socketId,
                username: user.username,
                color: users.get(user.socketId)?.color || '#667eea',
                activityScore: activityScore,
                messageCount: user.messages,
                onlineTime: onlineTime,
                filesUploaded: user.filesUploaded,
                audioSent: user.audioSent,
                videoSent: user.videoSent,
                imagesSent: user.imagesSent,
                privateMessages: user.privateMessages,
                friendRequests: user.friendRequests,
                friendsAdded: user.friendsAdded,
                callsInitiated: user.callsInitiated,
                callsReceived: user.callsReceived,
                lastActive: user.lastActive
            };
        });
        
        // 发送用户行为分析数据到客户端
        socket.emit('admin-user-analytics', {
            stats: {
                activeUsers: activeUsers,
                totalUsers: totalUsers,
                totalMessages: totalMessages,
                totalFiles: totalFiles,
                avgMessageLength: avgMessageLength,
                peakHour: peakHour,
                retentionRate: retentionRate,
                avgOnlineTime: avgOnlineTime,
                responseRate: responseRate,
                userGrowthRate: userGrowthRate
            },
            behaviorDetails: behaviorDetails
        });
    });
    
    // 处理管理员获取系统日志
    socket.on('admin-get-system-logs', (data) => {
        if (socket.id !== adminSocketId) return;
        
        const { filter, startDate, endDate, limit = 100 } = data || {};
        
        // 过滤日志
        let filteredLogs = systemLogs;
        
        if (filter) {
            filteredLogs = filteredLogs.filter(log => 
                log.eventType.includes(filter) || 
                log.description.includes(filter)
            );
        }
        
        if (startDate) {
            const start = new Date(startDate);
            filteredLogs = filteredLogs.filter(log => new Date(log.timestamp) >= start);
        }
        
        if (endDate) {
            const end = new Date(endDate);
            filteredLogs = filteredLogs.filter(log => new Date(log.timestamp) <= end);
        }
        
        // 限制返回数量
        filteredLogs = filteredLogs.slice(-limit);
        
        // 转换日志格式以匹配客户端期望的格式
        const formattedLogs = filteredLogs.map(log => {
            const logDate = new Date(log.timestamp);
            const formattedDate = logDate.toLocaleString('zh-CN', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
            
            return {
                timestamp: formattedDate,
                level: log.eventType.toLowerCase(),
                message: log.description,
                details: {
                    userId: log.userId,
                    roomId: log.roomId
                }
            };
        });
        
        // 计算统计数据
        const stats = {
            loginCount: filteredLogs.filter(log => log.eventType.includes('login')).length,
            messageCount: filteredLogs.filter(log => log.eventType.includes('message')).length,
            fileUploadCount: filteredLogs.filter(log => log.eventType.includes('file')).length,
            errorCount: filteredLogs.filter(log => log.eventType === 'error').length
        };
        
        // 发送系统日志给管理员（使用客户端期望的事件名称和数据结构）
        socket.emit('admin-system-logs', {
            logs: formattedLogs,
            stats: stats
        });
    });
    
    // 处理管理员批量操作
    socket.on('admin-batch-action', (data) => {
        if (socket.id !== adminSocketId) return;
        
        const { action, userIds, roomName, reason } = data;
        
        // 执行批量操作
        userIds.forEach(userId => {
            const user = users.get(userId);
            if (user && user.roomName === roomName) {
                switch (action) {
                    case 'kick':
                        // 踢出用户
                        io.to(userId).emit('kicked', reason || '您被管理员踢出聊天室');
                        socket.to(roomName).emit('user-left', {
                            username: user.username,
                            userCount: Array.from(users.values()).filter(u => u.roomName === roomName).length - 1,
                            users: Array.from(users.values()).filter(u => u.roomName === roomName && u.id !== userId),
                            roomName
                        });
                        users.delete(userId);
                        break;
                    
                    case 'mute':
                        // 禁言用户
                        io.to(userId).emit('muted', reason || '您被管理员禁言');
                        break;
                    
                    case 'unmute':
                        // 解除禁言
                        io.to(userId).emit('unmuted');
                        break;
                    
                    case 'ban':
                        // 封禁用户
                        io.to(userId).emit('kicked', reason || '您被管理员永久封禁');
                        users.delete(userId);
                        break;
                }
            }
        });
        
        // 记录系统事件
        logSystemEvent('admin-batch-action', `${action} 操作执行`, socket.id, roomName);
    });
    
    // 处理管理员导出数据
    socket.on('admin-export-data', (data) => {
        if (socket.id !== adminSocketId) return;
        
        const { dataType, format = 'json' } = data;
        
        let exportData;
        
        switch (dataType) {
            case 'users':
                exportData = Array.from(users.values());
                break;
            
            case 'rooms':
                exportData = Array.from(rooms.entries()).map(([name, room]) => ({
                    name,
                    ...room
                }));
                break;
            
            case 'messages':
                exportData = [];
                rooms.forEach(room => {
                    room.messages.forEach(message => {
                        exportData.push({
                            ...message,
                            roomName: room.name
                        });
                    });
                });
                break;
            
            case 'activity':
                exportData = Array.from(userActivity.values());
                break;
            
            case 'logs':
                exportData = systemLogs;
                break;
        }
        
        // 发送导出数据给管理员
        socket.emit('admin-export-data-result', {
            data: exportData,
            format,
            timestamp: new Date()
        });
        
        // 记录系统事件
        logSystemEvent('admin-export-data', `导出 ${dataType} 数据`, socket.id);
    });
    
    // 处理管理员获取系统监控数据
    socket.on('admin-get-system-monitoring', () => {
        if (socket.id !== adminSocketId) return;
        
        // 获取系统监控数据
        const memoryUsage = process.memoryUsage();
        const cpuUsage = process.cpuUsage();
        const systemLoad = process.loadavg();
        
        // 计算内存使用率（百分比）
        const totalMemory = require('os').totalmem();
        const usedMemory = memoryUsage.rss;
        const memoryUsagePercent = Math.round((usedMemory / totalMemory) * 100);
        
        // 计算CPU使用率（百分比）
        const cpuUsagePercent = Math.round((cpuUsage.user + cpuUsage.system) / 1000);
        
        // 获取磁盘使用情况（模拟数据，实际应用中可以使用fs.statfs）
        const diskUsagePercent = Math.round(Math.random() * 30) + 20; // 模拟20-50%的磁盘使用率
        
        // 获取网络流量（模拟数据，实际应用中可以使用系统工具或第三方库）
        const networkTraffic = `${Math.round(Math.random() * 100) + 50} KB/s`; // 模拟50-150 KB/s的网络流量
        
        // 获取系统事件（最近的10条系统日志）
        const recentEvents = systemLogs.slice(-10).map(log => ({
            timestamp: new Date(log.timestamp).toLocaleString('zh-CN'),
            type: log.eventType === 'error' ? 'error' : log.eventType === 'warn' ? 'warn' : 'info',
            message: log.description,
            details: {
                userId: log.userId,
                roomId: log.roomId
            }
        }));
        
        // 构建客户端期望的系统监控数据
        const systemData = {
            cpuUsage: cpuUsagePercent,
            memoryUsage: memoryUsagePercent,
            diskUsage: diskUsagePercent,
            networkTraffic: networkTraffic,
            onlineUsers: users.size,
            websocketConnections: users.size, // 假设每个用户对应一个WebSocket连接
            events: recentEvents
        };
        
        // 发送系统监控数据给管理员（使用客户端期望的事件名称）
        socket.emit('admin-system-monitoring', systemData);
    });
    
    // 处理管理员添加聊天室提示
    socket.on('admin-add-notification', (data) => {
        if (socket.id !== adminSocketId) return;
        
        const { title, content, buttonText, buttonColor, backgroundColor, forceAction } = data;
        
        // 创建聊天室提示
        const notification = {
            id: Date.now().toString(),
            title,
            content,
            buttonText,
            buttonColor,
            backgroundColor,
            forceAction,
            createdAt: new Date()
        };
        
        // 存储聊天室提示
        activeNotifications.push(notification);
        
        // 广播聊天室提示给所有用户
        io.emit('chatroom-notification', notification);
        
        // 记录系统事件
        logSystemEvent('admin-add-notification', `添加聊天室提示: ${title}`, socket.id);
    });
    
    // 处理管理员更新聊天室提示
    socket.on('admin-update-notification', (data) => {
        if (socket.id !== adminSocketId) return;
        
        const { notificationId, title, content, buttonText, buttonColor, backgroundColor, forceAction } = data;
        
        // 查找聊天室提示
        const notificationIndex = activeNotifications.findIndex(n => n.id === notificationId);
        if (notificationIndex !== -1) {
            // 更新聊天室提示
            activeNotifications[notificationIndex] = {
                ...activeNotifications[notificationIndex],
                title,
                content,
                buttonText,
                buttonColor,
                backgroundColor,
                forceAction
            };
            
            // 广播更新后的聊天室提示给所有用户
            io.emit('update-chatroom-notification', {
                notificationId,
                title,
                content,
                buttonText,
                buttonColor,
                backgroundColor,
                forceAction
            });
            
            // 记录系统事件
            logSystemEvent('admin-update-notification', `更新聊天室提示: ${title}`, socket.id);
        }
    });
    
    // 处理管理员移除聊天室提示
    socket.on('admin-remove-notification', (data) => {
        if (socket.id !== adminSocketId) return;
        
        const { notificationId } = data;
        
        // 查找并移除聊天室提示
        const notificationIndex = activeNotifications.findIndex(n => n.id === notificationId);
        if (notificationIndex !== -1) {
            const notification = activeNotifications[notificationIndex];
            activeNotifications.splice(notificationIndex, 1);
            
            // 广播移除聊天室提示的通知给所有用户
            io.emit('remove-chatroom-notification', { notificationId });
            
            // 记录系统事件
            logSystemEvent('admin-remove-notification', `移除聊天室提示`, socket.id);
        }
    });
    
    // 处理管理员设置用户权限
    socket.on('admin-set-user-permissions', (data) => {
        if (socket.id !== adminSocketId) return;
        
        const { userId, permissions } = data;
        
        // 查找用户
        const user = users.get(userId);
        if (user) {
            // 更新用户权限
            user.permissions = {
                ...user.permissions,
                ...permissions
            };
            
            // 发送权限变更通知给所有用户
            const roomUsers = Array.from(users.values()).filter(u => u.roomName === user.roomName);
            io.to(user.roomName).emit('user-permissions-changed', {
                users: roomUsers
            });
            
            // 发送权限变更通知给被修改的用户
            io.to(userId).emit('permissions-updated', {
                permissions: user.permissions
            });
            
            // 记录系统事件
            logSystemEvent('admin-set-permissions', `设置用户 ${user.username} 的权限`, socket.id, user.roomName);
        }
    });
    
    // 处理管理员批量设置用户权限
    socket.on('admin-batch-set-permissions', (data) => {
        if (socket.id !== adminSocketId) return;
        
        const { userIds, permissions, roomName } = data;
        
        const updatedUsers = [];
        
        // 批量更新用户权限
        userIds.forEach(userId => {
            const user = users.get(userId);
            if (user && user.roomName === roomName) {
                user.permissions = {
                    ...user.permissions,
                    ...permissions
                };
                updatedUsers.push(user);
            }
        });
        
        if (updatedUsers.length > 0) {
            // 发送权限变更通知给所有用户
            const roomUsers = Array.from(users.values()).filter(u => u.roomName === roomName);
            io.to(roomName).emit('user-permissions-changed', {
                users: roomUsers
            });
            
            // 记录系统事件
            logSystemEvent('admin-batch-set-permissions', `批量设置 ${updatedUsers.length} 个用户的权限`, socket.id, roomName);
        }
    });
});

// 生成随机颜色
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
