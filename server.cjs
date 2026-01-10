const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
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

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
    fs.mkdirSync(path.join(__dirname, 'uploads'));
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

app.post('/upload-image', upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: '没有上传文件' });
    }
    res.json({ imageUrl: `/uploads/${req.file.filename}` });
});

app.post('/upload-audio', upload.single('audio'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: '没有上传文件' });
    }
    res.json({ audioUrl: `/uploads/${req.file.filename}` });
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
const messages = [];

io.on('connection', (socket) => {
    console.log(`用户连接: ${socket.id}`);

    socket.on('join', (username) => {
        users.set(socket.id, {
            username: username,
            color: getRandomColor(),
            socketId: socket.id
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
            const messageData = {
                username: user.username,
                color: user.color,
                message: data.message,
                type: data.type || 'text',
                timestamp: new Date().toLocaleTimeString()
            };
            
            messages.push(messageData);
            if (messages.length > 100) {
                messages.shift();
            }
            
            io.emit('message', messageData);
            console.log(`${user.username}: ${data.type === 'text' ? data.message : data.type}`);
        }
    });

    socket.on('admin-login', (password) => {
        if (password === ADMIN_PASSWORD) {
            adminSocketId = socket.id;
            socket.emit('admin-login-success', true);
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

    socket.on('admin-system-message', (message) => {
        if (socket.id === adminSocketId) {
            io.emit('system-message', {
                message: message,
                timestamp: new Date().toLocaleTimeString()
            });
            console.log(`管理员发送系统消息: ${message}`);
        }
    });

    socket.on('admin-clear-messages', () => {
        if (socket.id === adminSocketId) {
            messages.length = 0;
            io.emit('messages-cleared');
            console.log('管理员清空了所有消息');
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
