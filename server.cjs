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
    allowedHeaders: ['Content-Type'],
    credentials: true
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.raw({ type: ['image/*', 'audio/*'], limit: '10mb' }));

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

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

const ADMIN_PASSWORD = 'admin123';
let adminSocketId = null;

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"],
        credentials: true
    }
});

const users = new Map();
const messages = new Map();
const deletedMessages = new Map();

io.on('connection', (socket) => {
    console.log(`用户连接: ${socket.id}`);

    socket.on('join', (username) => {
        users.set(socket.id, {
            username: username,
            color: getRandomColor(),
            socketId: socket.id,
            permissions: {
                allowAudio: true,
                allowImage: true,
                allowFile: true,
                allowSendMessages: true,
                allowViewMessages: true,
                allowCall: true
            }
        });
        
        io.emit('user-joined', {
            username: username,
            userCount: users.size,
            users: Array.from(users.values())
        });
        
        console.log(`${username} 加入聊天室，当前在线: ${users.size} 人`);
    });

    socket.on('message', (data) => {
        const user = users.get(socket.id);
        if (user) {
            // 确保用户权限对象存在，如果不存在则设置默认权限
            if (!user.permissions) {
                user.permissions = {
                    allowAudio: true,
                    allowImage: true,
                    allowFile: true,
                    allowSendMessages: true,
                    allowViewMessages: true,
                    allowCall: true
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
            
            const messageId = Date.now() + '-' + Math.random().toString(36).substr(2, 9);
            const messageData = {
                id: messageId,
                username: user.username,
                color: user.color,
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
            
            // 只发送给有权限查看消息的用户
            users.forEach((user, socketId) => {
                if (user.permissions.allowViewMessages) {
                    io.to(socketId).emit('message', messageData);
                }
            });
            
            console.log(`${user.username}: ${data.type === 'text' ? data.message : data.type}`);
        }
    });

    socket.on('admin-login', (password) => {
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
            socket.emit('admin-login-success', false);
        }
    });

    socket.on('admin-kick-user', (socketId) => {
        if (socket.id === adminSocketId) {
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
        if (socket.id === adminSocketId) {
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
        if (socket.id === adminSocketId) {
            const user = users.get(data.socketId);
            if (user) {
                user.permissions = {
                    allowAudio: data.permissions.allowAudio,
                    allowImage: data.permissions.allowImage,
                    allowFile: data.permissions.allowFile,
                    allowSendMessages: data.permissions.allowSendMessages,
                    allowViewMessages: data.permissions.allowViewMessages,
                    allowCall: data.permissions.allowCall
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

    socket.on('admin-system-message', (message) => {
        if (socket.id === adminSocketId) {
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

    socket.on('admin-send-message', (data) => {
        if (socket.id === adminSocketId) {
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
        if (socket.id === adminSocketId) {
            socket.emit('user-joined', {
                username: '管理员',
                userCount: users.size,
                users: Array.from(users.values())
            });
        }
    });

    socket.on('admin-clear-messages', () => {
        if (socket.id === adminSocketId) {
            messages.clear();
            io.emit('messages-cleared');
            console.log('管理员清空了所有消息');
        }
    });

    socket.on('message-recall', (messageId) => {
        const message = messages.get(messageId);
        if (message && message.senderSocketId === socket.id) {
            deletedMessages.set(messageId, { ...message, recalled: true, recallTime: new Date().toLocaleTimeString() });
            messages.delete(messageId);
            io.emit('message-recalled', messageId);
            console.log(`${message.username} 撤回了一条消息`);
        }
    });

    // 通话功能事件处理
    socket.on('call-request', (data) => {
        const user = users.get(socket.id);
        if (user && user.permissions.allowCall) {
            const targetUser = users.get(data.targetSocketId);
            if (targetUser && targetUser.permissions.allowCall) {
                io.to(data.targetSocketId).emit('call-request', {
                    from: socket.id,
                    fromUsername: user.username,
                    fromColor: user.color,
                    callId: data.callId
                });
                console.log(`${user.username} 请求与 ${targetUser.username} 通话`);
            } else {
                socket.emit('permission-denied', { message: '目标用户没有通话权限或不存在' });
            }
        } else {
            socket.emit('permission-denied', { message: '您没有通话权限' });
        }
    });

    socket.on('call-accept', (data) => {
        const user = users.get(socket.id);
        if (user && user.permissions.allowCall) {
            io.to(data.callerSocketId).emit('call-accepted', {
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
            io.to(data.callerSocketId).emit('call-rejected', {
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
            io.to(data.targetSocketId).emit('call-ended', {
                from: socket.id,
                callId: data.callId
            });
            console.log(`${user.username} 结束了通话`);
        }
    });

    // WebRTC事件处理
    socket.on('ice-candidate', (data) => {
        const user = users.get(socket.id);
        if (user && user.permissions.allowCall) {
            io.to(data.targetSocketId).emit('ice-candidate', {
                from: socket.id,
                candidate: data.candidate,
                callId: data.callId
            });
        }
    });

    socket.on('offer', (data) => {
        const user = users.get(socket.id);
        if (user && user.permissions.allowCall) {
            io.to(data.targetSocketId).emit('offer', {
                from: socket.id,
                offer: data.offer,
                callId: data.callId
            });
        }
    });

    socket.on('answer', (data) => {
        const user = users.get(socket.id);
        if (user && user.permissions.allowCall) {
            io.to(data.callerSocketId).emit('answer', {
                from: socket.id,
                answer: data.answer,
                callId: data.callId
            });
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

    socket.on('disconnect', () => {
        const user = users.get(socket.id);
        if (user) {
            users.delete(socket.id);
            io.emit('user-left', {
                username: user.username,
                userCount: users.size,
                users: Array.from(users.values())
            });
            console.log(`${user.username} 离开聊天室，当前在线: ${users.size} 人`);
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

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`聊天室服务器已启动`);
    console.log(`本地访问: http://localhost:${PORT}`);
    console.log(`局域网访问: http://<你的IP地址>:${PORT}`);
    console.log(`管理员页面: http://localhost:${PORT}/admin`);
    console.log(`========================================\n`);
});
