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

const ADMIN_PASSWORD = 'admin123';
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
    console.log(`用户连接: ${socket.id}`);

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
        
        // 设置用户信息
        users.set(socket.id, {
            username: username,
            color: getRandomColor(),
            socketId: socket.id,
            roomName: roomName,
            permissions: {
                allowAudio: true,
                allowImage: true,
                allowFile: true,
                allowSendMessages: true,
                allowViewMessages: true,
                allowCall: true
            }
        });
        
        // 将用户添加到房间
        room.users.push(socket.id);
        
        // 让socket加入房间频道
        socket.join(roomName);
        
        // 发送房间内的用户列表和消息
        const roomUsers = room.users.map(userId => users.get(userId)).filter(user => user);
        const roomMessages = room.messages;
        
        // 发送给当前用户
        socket.emit('user-joined', {
            username: username,
            userCount: roomUsers.length,
            users: roomUsers,
            roomName: roomName
        });
        
        // 发送给房间内其他用户
        socket.to(roomName).emit('user-joined', {
            username: username,
            userCount: roomUsers.length,
            users: roomUsers,
            roomName: roomName
        });
        
        // 发送房间历史消息
        socket.emit('room-history', {
            messages: roomMessages
        });
        
        console.log(`${username} 加入房间 ${roomName}，当前在线: ${roomUsers.length} 人`);
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
            } else {
                // 确保所有权限字段都存在，如果不存在则设置默认值
                const defaultPermissions = {
                    allowAudio: true,
                    allowImage: true,
                    allowFile: true,
                    allowSendMessages: true,
                    allowViewMessages: true,
                    allowCall: true
                };
                
                user.permissions = {
                    ...defaultPermissions,
                    ...user.permissions
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
                
                console.log(`[房间 ${user.roomName}] ${user.username}: ${data.type === 'text' ? data.message : data.type}`);
            }
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
        
        // 管理员发送系统消息到指定房间
        socket.on('admin-room-system-message', (data) => {
            if (socket.id === adminSocketId) {
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
            if (socket.id === adminSocketId) {
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
    
    // 管理员创建房间
    socket.on('admin-create-room', (data) => {
        if (socket.id === adminSocketId) {
            const { roomName, password, settings } = data;
            
            // 检查房间名是否已存在
            if (rooms.has(roomName)) {
                socket.emit('admin-room-error', { message: '房间名已存在' });
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
                    maxUsers: 100,
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
        if (socket.id === adminSocketId) {
            // 不允许删除默认房间
            if (roomName === 'main') {
                socket.emit('admin-room-error', { message: '不能删除默认房间' });
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
        if (socket.id === adminSocketId) {
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
    
    // 获取房间列表
    socket.on('admin-get-rooms', () => {
        if (socket.id === adminSocketId) {
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
            const room = rooms.get(user.roomName);
            if (room) {
                // 查找要撤回的消息
                const messageIndex = room.messages.findIndex(msg => msg.id === messageId);
                if (messageIndex !== -1) {
                    const message = room.messages[messageIndex];
                    if (message.senderSocketId === socket.id) {
                        // 标记消息为已撤回
                        message.recalled = true;
                        message.recallTime = new Date().toLocaleTimeString();
                        
                        // 发送撤回通知给房间内所有用户
                        room.users.forEach(userId => {
                            io.to(userId).emit('message-recalled', messageId);
                        });
                        
                        console.log(`[房间 ${user.roomName}] ${message.username} 撤回了一条消息`);
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
            if (targetUser && targetUser.permissions.allowCall) {
                io.to(data.targetSocketId).emit('call-request', {
                    from: socket.id,
                    fromUsername: user.username,
                    fromColor: user.color,
                    callId: data.callId,
                    type: data.type // 确保通话类型被正确传递
                });
                console.log(`${user.username} 请求与 ${targetUser.username} ${data.type === 'video' ? '视频' : '语音'}通话`);
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

    // 通过Socket.io转发音视频数据
    socket.on('call-media', (data) => {
        const user = users.get(socket.id);
        if (user && user.permissions.allowCall) {
            io.to(data.targetSocketId).emit('call-media', {
                from: socket.id,
                callId: data.callId,
                type: data.type,
                data: data.data
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

const PORT = process.env.PORT || 146;
server.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`聊天室服务器已启动`);
    console.log(`本地访问: http://localhost:${PORT}`);
    console.log(`局域网访问: http://<你的IP地址>:${PORT}`);
    console.log(`管理员页面: http://localhost:${PORT}/admin`);
    console.log(`========================================\n`);
});
