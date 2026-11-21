// pages/chat/chat.js
const app = getApp()

const LOCATION_KEY = 'X9s@2k#M8p$5n%7q'

function base64Encode(bytes) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  let result = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const b1 = bytes[i]
    const b2 = i + 1 < bytes.length ? bytes[i + 1] : 0
    const b3 = i + 2 < bytes.length ? bytes[i + 2] : 0
    const triple = (b1 << 16) | (b2 << 8) | b3
    result += chars[(triple >> 18) & 0x3F]
    result += chars[(triple >> 12) & 0x3F]
    result += chars[(triple >> 6) & 0x3F]
    result += chars[triple & 0x3F]
  }
  const pad = bytes.length % 3
  if (pad === 1) {
    result = result.slice(0, -2) + '=='
  } else if (pad === 2) {
    result = result.slice(0, -1) + '='
  }
  return result
}

function base64Decode(base64) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  base64 = base64.replace(/=+$/, '')
  const bytes = []
  for (let i = 0; i < base64.length; i += 4) {
    const indexes = [0, 1, 2, 3].map(j => {
      const c = base64[i + j]
      return c ? chars.indexOf(c) : 0
    })
    const triple = (indexes[0] << 18) | (indexes[1] << 12) | (indexes[2] << 6) | indexes[3]
    bytes.push((triple >> 16) & 0xFF)
    if (i + 2 < base64.length) bytes.push((triple >> 8) & 0xFF)
    if (i + 3 < base64.length) bytes.push(triple & 0xFF)
  }
  return new Uint8Array(bytes)
}

function encryptLocation(lat, lng, address) {
  const data = lat + '|' + lng + '|' + address
  console.log('加密原始数据:', data)
  const bytes = new Uint8Array(data.length)
  for (let i = 0; i < data.length; i++) {
    bytes[i] = data.charCodeAt(i) ^ LOCATION_KEY.charCodeAt(i % LOCATION_KEY.length)
  }
  const base64 = base64Encode(bytes)
  const result = encodeURIComponent(base64)
  console.log('加密完成, base64:', base64)
  return result
}

function decryptLocation(encryptedData) {
  try {
    console.log('开始解密, 加密数据:', encryptedData)
    const base64 = decodeURIComponent(encryptedData)
    const bytes = base64Decode(base64)
    let decrypted = ''
    for (let i = 0; i < bytes.length; i++) {
      const charCode = bytes[i] ^ LOCATION_KEY.charCodeAt(i % LOCATION_KEY.length)
      decrypted += String.fromCharCode(charCode)
    }
    console.log('解密后字符串:', decrypted)
    const parts = decrypted.split('|')
    console.log('分割结果:', parts)
    const result = {
      latitude: parseFloat(parts[0]),
      longitude: parseFloat(parts[1]),
      address: parts[2] || '未知位置'
    }
    console.log('解密结果:', result)
    return result
  } catch (e) {
    console.error('位置解密失败:', e)
    wx.showModal({ title: '错误', content: '位置解析失败', showCancel: false })
    return null
  }
}

Page({
  data: {
    username: "",
    roomName: "",
    roomPassword: null,
    inputValue: "",
    messages: [],
    scrollTop: 0,
    connected: false,
    kicked: false,
    sending: false,
    reconnecting: false,
    users: [],
    currentPoll: null,
    showPoll: false,
    connecting: false,
    showCallMenu: false,
    isDevMode: false,
    devPasswordInput: "",
    showDevPasswordModal: false,
    requestingAdminHelp: false,
    userPermissions: {
      allowAccess: true,
      features: ['chat', 'file', 'image', 'audio', 'video', 'poll', 'location']
    },
    showInteractiveCenter: false,
    onlineUsers: [],
    avatarUrl: '',
    showOnlineUsers: false,
    showFileDownload: true,
    showImagePreview: true,
    showTimestamps: true,
    showAudioPlayer: false,
    notification: {
      show: false,
      senderName: '',
      content: '',
      avatarUrl: ''
    },
    showUploadModal: false,
    uploadingFilename: '',
    uploadProgress: 0,
    uploadStatus: '准备上传...',
    showDownloadModal: false,
    downloadingFilename: '',
    downloadProgress: 0,
    downloadStatus: '准备下载...',
    showPollDetail: false,
    selectedPoll: null,
    pollSelectedOptions: [],
    hasVoted: false,
    votedPolls: [],
    activeGames: [],
    gameInvitations: [],
    gameHistory: [],
    joinGameId: '',
    onlineUsersLoaded: false,
    devLogs: [],
    showLogsPanel: false,
    logsDisplay: [],
    downloadTask: null,
    uploadTask: null,
    notificationTimer: null,
    audioContexts: {},
    currentDownloadId: '',
    processedServerMsgIds: new Set(),
    reconnectAttempts: 0,
    isInitializingSocket: false,
    hasSentJoinRequest: false,
    hasJoinedRoom: false,
    maxReconnectAttempts: 5,
    lastSendTime: 0,
    sendInterval: 1000,
    trtcManager: null,
    callTimer: null,
    callStartTime: 0,
    recorderManager: null,
    recordingFilePath: null,
    useLocalServer: false,
    downloads: [],
    showUploadPanel: false,
    cancelledUploadId: null,
    showDownloadPanel: false,
    cancelledDownloadId: null,
    uploads: [],
    downloads: [],
    playingAudios: [],
    showVideoPlayer: false,
    videoSrc: '',
    isDownloading: false,
    isRecording: false,
    showDevMenu: false,
    devPassword: "",
    devPasswordInput: "",
    currentCallTargetId: '',
    currentCallTargetName: ''
  },

  onLoad(options) {
    this.devLogs = this.data.devLogs || []
    const that = this
    const _log = console.log.bind(console)
    const _error = console.error.bind(console)
    const _warn = console.warn.bind(console)
    console.log = function(...args) {
      _log(...args)
      const msg = args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ')
      that.addDevLog('[LOG] ' + msg)
    }
    console.error = function(...args) {
      _error(...args)
      const msg = args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ')
      that.addDevLog('[ERROR] ' + msg)
    }
    console.warn = function(...args) {
      _warn(...args)
      const msg = args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ')
      that.addDevLog('[WARN] ' + msg)
    }
    const roomName = options.room ? decodeURIComponent(options.room) : 'main'
    const roomPassword = options.password ? decodeURIComponent(options.password) : null
    const savedName = wx.getStorageSync('username')
    const savedAvatar = wx.getStorageSync('avatarUrl')
    const username = savedName || '用户' + Math.floor(Math.random() * 1000)
    this.setData({
      roomName: roomName,
      roomPassword: roomPassword,
      username: username,
      avatarUrl: savedAvatar || '',
      connecting: true
    })
    wx.setStorageSync('username', username)
    if (savedAvatar) {
      wx.setStorageSync('avatarUrl', savedAvatar)
    }
    if (savedAvatar && (savedAvatar.startsWith('wxfile://') || savedAvatar.startsWith('http://tmp/'))) {
      this.uploadAvatarToServer(savedAvatar)
    }
    this.initSocket()
  },

  onUnload() {
    console.log('页面卸载，清理Socket连接和定时器')
    this.reconnectAttempts = this.maxReconnectAttempts
    this.stopHeartbeat()
    if (this.connectTimeoutTimer) {
      clearTimeout(this.connectTimeoutTimer)
      this.connectTimeoutTimer = null
    }
    if (this.notificationTimer) {
      clearTimeout(this.notificationTimer)
      this.notificationTimer = null
    }
    if (this.data.playingAudios) {
      this.data.playingAudios.forEach(a => {
        const timerKey = 'audioProgressTimer_' + a.id
        if (this[timerKey]) {
          clearInterval(this[timerKey])
          this[timerKey] = null
        }
      })
    }
    if (this.downloadTasks) {
      Object.values(this.downloadTasks).forEach(task => {
        try { task.abort() } catch (e) {}
      })
      this.downloadTasks = {}
    }
    if (this.directPreviewDownloadTask) {
      try { this.directPreviewDownloadTask.abort() } catch (e) {}
      this.directPreviewDownloadTask = null
    }
    if (this.pendingRequests) {
      this.pendingRequests.forEach(task => {
        try { task.abort() } catch (e) {}
      })
      this.pendingRequests = []
    }
    if (this.socket) {
      try {
        this.socket.close({ code: 1000, reason: '页面卸载' })
      } catch (e) {
        console.warn('关闭连接失败:', e)
      }
      this.socket = null
    }
  },

  onShow() {
    console.log('页面显示')
    if (!this.data.connected && !this.data.connecting && !this.isInitializingSocket) {
      console.log('页面恢复时检测到连接已断开，尝试重连')
      this.initSocket()
    }

    // 从游戏页返回时，socket 可能仍连着（initSocket 会早退），
    // 但在线用户列表需要重新拉取，否则 AI 可能显示不出来。
    if (this.data.connected && this.socket && this.socket.readyState === 1) {
      this.loadOnlineUsers()
    }
    const pendingDownloads = this.data.downloads.filter(d =>
      d.status === '下载中' && d.progress < 100 && !d.isRestored
    )
    console.log('需要恢复的下载任务:', pendingDownloads)
    if (pendingDownloads.length > 0) {
      wx.showToast({ title: '恢复' + pendingDownloads.length + '个下载任务', icon: 'none', duration: 2000 })
      const updatedDownloads = this.data.downloads.map(d => {
        if (d.status === '下载中' && d.progress < 100) {
          return { ...d, isRestored: true }
        }
        return d
      })
      this.setData({ downloads: updatedDownloads })
      pendingDownloads.forEach(task => {
        console.log('重新下载:', task.filename)
        const oldId = task.id
        this.doDownloadFile(task.url, task.filename, 0)
      })
    }
  },

  onHide() {
    console.log('页面隐藏，保持Socket连接')
    console.log('当前下载任务:', this.data.downloads)
    this.hideNotification()
  },

  addDevLog(message) {
    const logEntry = {
      time: new Date().toLocaleTimeString(),
      message: message
    }
    this.devLogs.push(logEntry)
    if (this.devLogs.length > 100) {
      this.devLogs.shift()
    }
  },

  showAllLogs() {
    if (!this.devLogs || this.devLogs.length === 0) {
      wx.showToast({ title: '暂无日志', icon: 'none' })
      return
    }
    this.setData({
      showLogsPanel: true,
      logsDisplay: this.devLogs.slice()
    })
  },
  closeLogsPanel() {
    this.setData({ showLogsPanel: false })
  },
  onModalContentTap() {
    // 阻止点击事件冒泡到外层蒙层，仅阻止传播
  },
  viewAllLogs() {
    const logs = this.devLogs.slice(-100)
    var logText = logs.map(function(log) {
      return log.time + ' - ' + log.message
    }).join('\n')
    wx.showModal({
      title: '开发日志 (最近100条)',
      content: logText,
      showCancel: false,
      confirmText: '知道了',
      confirmColor: '#576B95'
    })
  },

  exportLogs() {
    var logText = this.devLogs.map(function(log) {
      return '[' + log.time + '] ' + log.message
    }).join('\n')
    wx.setClipboardData({
      data: logText,
      success: () => {
        wx.showToast({ title: '日志已复制到剪贴板', icon: 'success', duration: 2000 })
      },
      fail: () => {
        wx.showToast({ title: '复制失败', icon: 'none' })
      }
    })
  },

  clearLogs() {
    wx.showModal({
      title: '清空日志',
      content: '确定要清空所有开发日志吗？',
      showCancel: true,
      confirmText: '确定',
      success: (res) => {
        if (res.confirm) {
          this.devLogs = []
          wx.showToast({ title: '日志已清空', icon: 'success' })
        }
      }
    })
  },

  searchLogs() {
    wx.showModal({
      title: '搜索日志',
      content: '',
      editable: true,
      placeholderText: '输入关键词',
      confirmText: '搜索',
      success: (res) => {
        if (res.confirm && res.content) {
          const keyword = res.content.trim()
          const filteredLogs = this.devLogs.filter(log => log.message.includes(keyword))
          if (filteredLogs.length === 0) {
            wx.showToast({ title: '未找到匹配日志', icon: 'none' })
            return
          }
          const filteredText = filteredLogs.map(function(log) {
            return '[' + log.time + '] ' + log.message
          }).join('\n')
          wx.setClipboardData({
            data: filteredText,
            success: () => {
              wx.showToast({ title: '已复制到剪贴板', icon: 'success', duration: 2000 })
            }
          })
        }
      }
    })
  },

  showDevMenu() {
    console.log('显示开发菜单')
    var that = this
    wx.showActionSheet({
      itemList: [
        '📋 查看所有日志',
        '📤 导出日志',
        '🗑️ 清除日志',
        '🔊 音频播放控制',
        '🔧 元素状态',
        '⋯ 更多'
      ],
      success: function(res) {
        console.log('开发菜单点击:', res.tapIndex)
        switch(res.tapIndex) {
          case 0:
            that.showAllLogs()
            break
          case 1:
            that.exportLogs()
            break
          case 2:
            that.clearLogs()
            break
          case 3:
            that.showAudioControlPanel()
            break
          case 4:
            that.showElementStatus()
            break
          case 5:
            break
        }
      },
      fail: function(res) {
        console.error('开发菜单失败:', res)
      }
    })
  },

  requestAdminHelp() {
    console.log('请求管理员协助')
    wx.showModal({
      title: '开发者协助',
      content: '正在请求管理员协助...',
      showCancel: false,
      confirmText: '确定'
    })
  },

  showDevMessage(msg) {
    console.log('显示开发者消息:', msg)
    wx.showModal({
      title: '开发者消息',
      content: msg || '无内容',
      showCancel: false,
      confirmText: '确定'
    })
  },

  submitDevPassword(e) {
    const password = e.detail.value
    if (!password) {
      wx.showModal({ title: '提示', content: '请输入开发密码', showCancel: false, confirmText: '确定' })
      return
    }
    if (password === '11dev') {
      this.setData({ isDevMode: true, showDevPasswordModal: false })
      wx.showToast({ title: '开发模式已开启', icon: 'success' })
      this.showDevActions()
    } else {
      wx.showModal({ title: '提示', content: '密码错误', showCancel: false, confirmText: '确定' })
    }
  },

  onDevPasswordInput(e) {
    this.setData({ devPasswordInput: e.detail.value })
  },

  closeDevPasswordModal() {
    this.setData({ showDevPasswordModal: false, devPasswordInput: '' })
  },
  bindKeyInput(e) {
    this.setData({ inputValue: e.detail.value })
  },

  sendMessage() {
    var content = (this.data.inputValue || '').trim()
    console.log('[sendMessage] inputValue:', JSON.stringify(this.data.inputValue), 'trimmed:', content)
    if (!content) {
      console.log('[sendMessage] 内容为空，忽略')
      return
    }
    if (this.data.sending) {
      console.log('[sendMessage] 正在发送中，忽略')
      wx.showToast({ title: '正在发送，请稍候', icon: 'none' })
      return
    }
    if (!this.data.connected) {
      var that = this
      wx.showModal({
        title: '未连接',
        content: '当前未连接到聊天服务器，是否重新连接？',
        showCancel: true,
        confirmText: '重新连接',
        cancelText: '取消',
        success: function(res) {
          if (res.confirm) {
            that.initSocket()
          }
        },
        fail: function(err) {
          console.error('显示重连提示失败', err)
        }
      })
      return
    }
    console.log('[sendMessage] connected=true, socket:', !!this.socket, 'readyState:', this.socket ? this.socket.readyState : null)
    this.setData({ sending: true })
    var that = this
    try {
      if (that.socket && that.socket.readyState === 1) {
        var payload = JSON.stringify({
          type: 'text',
          content: content,
          username: that.data.username,
          roomName: that.data.roomName,
          avatarUrl: that.data.avatarUrl || ''
        })
        console.log('[sendMessage] 发送 payload:', payload)
        that.socket.send({ data: '42["message",' + payload + ']' })
        console.log('[sendMessage] socket.send 调用完成')
        that.setData({
          inputValue: ''
        })
      } else {
        console.error('[sendMessage] socket 未就绪，无法发送, readyState:', that.socket ? that.socket.readyState : 'no socket')
        wx.showToast({ title: '未就绪，无法发送', icon: 'none' })
      }
    } catch (err) {
      console.error('[sendMessage] 发送异常:', err)
      wx.showToast({ title: '发送失败', icon: 'none' })
    }
    that.setData({ sending: false })
  },

  chooseImage() {
    var that = this
    wx.chooseMedia({
      count: 1,
      mediaType: ['image'],
      sourceType: ['album', 'camera'],
      success: function(res) {
        var tempFilePath = res.tempFiles[0].tempFilePath
        var displayName = res.tempFiles[0].name || ('图片-' + Date.now() + '.jpg')
        that.uploadAndSend('image', tempFilePath, displayName)
      },
      fail: function(err) {
        console.error('选择图片失败', err)
        wx.showToast({ title: '选择图片失败', icon: 'none' })
      }
    })
  },
  chooseFile() {
    var that = this
    wx.chooseMessageFile({
      count: 1,
      type: 'file',
      success: function(res) {
        var tempFilePath = res.tempFiles[0].path
        var displayName = res.tempFiles[0].name || tempFilePath.split('/').pop() || 'file'
        that.uploadAndSend('file', tempFilePath, displayName)
      },
      fail: function(err) {
        console.error('选择文件失败', err)
        wx.showToast({ title: '选择文件失败', icon: 'none' })
      }
    })
  },
  chooseVideo() {
    var that = this
    wx.chooseMedia({
      count: 1,
      mediaType: ['video'],
      sourceType: ['album', 'camera'],
      success: function(res) {
        var tempFilePath = res.tempFiles[0].tempFilePath
        var displayName = res.tempFiles[0].name || ('视频-' + Date.now() + '.mp4')
        that.uploadAndSend('video', tempFilePath, displayName)
      },
      fail: function(err) {
        console.error('选择视频失败', err)
        wx.showToast({ title: '选择视频失败', icon: 'none' })
      }
    })
  },
  chooseLocation() {
    var that = this
    wx.chooseLocation({
      success: function(res) {
        if (!that.data.connected) {
          wx.showModal({
            title: '未连接',
            content: '当前未连接到聊天服务器，是否重新连接？',
            showCancel: true,
            confirmText: '重新连接',
            cancelText: '取消',
            success: function(res) {
              if (res.confirm) {
                that.initSocket()
              }
            },
            fail: function(err) {
              console.error('显示重连提示失败', err)
            }
          })
          return
        }
        var payload = JSON.stringify({
          type: 'location',
          content: res.address || '未知位置',
          username: that.data.username,
          roomName: that.data.roomName,
          avatarUrl: that.data.avatarUrl || '',
          latitude: res.latitude,
          longitude: res.longitude,
          address: res.address || ''
        })
        if (that.socket && that.socket.readyState === 1) {
          that.socket.send({ data: '42["message",' + payload + ']' })
          wx.showToast({ title: '位置已发送', icon: 'none' })
        } else {
          wx.showToast({ title: '未连接，无法发送', icon: 'none' })
        }
      },
      fail: function(err) {
        console.error('选择位置失败', err)
        wx.showToast({ title: '选择位置失败', icon: 'none' })
      }
    })
  },
  showInteractiveCenter() {
    this.setData({ showInteractiveCenter: true })
    this.loadOnlineUsers()
  },

  // 统一的 socket 就绪判定：微信 SocketTask 不保证暴露 readyState，
  // 若为 undefined 则回退到 hasJoinedRoom 标志，避免误判为未连接。
  isSocketReady() {
    if (!this.socket) return false
    var rs = this.socket.readyState
    if (rs === 1) return true
    if (rs === undefined && this.data.hasJoinedRoom) return true
    return false
  },

  loadOnlineUsers(retry) {
    var that = this
    var attempt = retry || 0
    var rs = that.socket ? that.socket.readyState : undefined
    var ready = (rs === 1) || (rs === undefined && that.socket && that.data.hasJoinedRoom)
    if (!ready) {
      // 未连接：保留「加载中」，连接就绪后自动重试（最多 6 次）
      if (attempt < 6) {
        setTimeout(function () {
          if (that.data.showInteractiveCenter) that.loadOnlineUsers(attempt + 1)
        }, 800)
      } else {
        that.setData({ onlineUsersLoaded: true })
      }
      return
    }
    that.setData({ onlineUsersLoaded: false })
    try {
      that.socket.send({ data: '42["get-online-users",{}]' })
      console.log('[互动中心] 已请求在线用户列表')
    } catch (e) {
      console.error('[互动中心] 请求在线用户失败:', e)
      that.setData({ onlineUsersLoaded: true })
    }
  },
  hideInteractiveCenter() {
    this.setData({ showInteractiveCenter: false })
  },
  getServerUrl() {
    return this.useLocalServer ? 'http://localhost:147' : 'https://liaotianshi.onrender.com'
  },
  startHeartbeat() {
    var that = this
    if (this.heartbeatTimer) {
      return
    }
    this.heartbeatTimer = setInterval(function() {
      if (that.socket && that.socket.readyState === 1) {
        that.socket.send({ data: '2' })
      }
    }, 30000)
  },
  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
  },
  initSocket() {
    var that = this
    console.log('[Socket] initSocket called, state:', { socket: !!this.socket, readyState: this.socket ? this.socket.readyState : null, isInitializing: this.isInitializingSocket, connected: this.data.connected })
    if (this.socket && this.socket.readyState === 1) {
      console.log('[Socket] 已连接，跳过重连')
      return
    }
    if (this.isInitializingSocket) {
      console.log('[Socket] 正在初始化中，跳过重复重连')
      return
    }
    this.isInitializingSocket = true
    console.log('[Socket] 开始初始化连接')
    var serverUrl = this.getServerUrl()
    var socketUrl = (serverUrl.replace('http://', 'ws://').replace('https://', 'wss://')) + '/socket.io/?EIO=4&transport=websocket'
    console.log('[Socket] 连接地址:', socketUrl)
    var socket = wx.connectSocket({
      url: socketUrl,
      protocols: ['socket.io']
    })
    this.socket = socket
    console.log('[Socket] wx.connectSocket 返回，socket 对象:', !!socket)
    socket.onOpen(function() {
      console.log('[Socket] onOpen 触发')
      that.reconnectAttempts = 0
      that.setData({ connecting: false })
      that.isInitializingSocket = false
      that.hasSentJoinRequest = false
      that.hasJoinedRoom = false
      setTimeout(function() {
        console.log('[Socket] 准备发送 join，kicked:', that.data.kicked, 'connected:', that.data.connected, 'hasJoinedRoom:', that.data.hasJoinedRoom, 'hasSentJoinRequest:', that.hasSentJoinRequest)
        if (that.data.kicked) {
          console.log('[Socket] 已被踢出，跳过 join')
          return
        }
        if (that.data.connected || that.data.hasJoinedRoom) {
          console.log('[Socket] 已连接或已加入房间，跳过 join')
          return
        }
        if (that.hasSentJoinRequest) {
          console.log('[Socket] 已发送过 join 请求，跳过')
          return
        }
        that.hasSentJoinRequest = true
        console.log('[Socket] 发送 join 请求，用户名:', that.data.username, '房间:', that.data.roomName)
        var joinData = JSON.stringify({
          username: that.data.username,
          roomName: that.data.roomName,
          password: that.data.roomPassword,
          avatarUrl: that.data.avatarUrl || '',
          getHistory: true,
          historyCount: 50
        })
        var sendData = '42["join",' + joinData + ']'
        socket.send({ data: sendData })
        console.log('[Socket] join 请求已发送:', sendData)
      }, 500)
    })
    socket.onMessage(function(res) {
      var data = res.data
      if (typeof data !== 'string') {
        return
      }
      console.log('[Socket] 原始消息:', data)
      if (data.startsWith('0')) {
        console.log('[Socket] 收到握手消息，回复 40')
        socket.send({ data: '40' })
        return
      }
      if (data === '40' || data.startsWith('40')) {
        console.log('[Socket] 命名空间已连接')
        return
      }
      if (data === '2') {
        socket.send({ data: '3' })
        return
      }
      if (data.startsWith('42')) {
        try {
          var arr = JSON.parse(data.substring(2))
          var event = arr[0]
          var msg = arr[1]
          console.log('[Socket] 收到事件:', event, '数据:', msg)
          if (event === 'new-message' || event === 'message') {
            that.handleNewMessage(msg)
          } else if (event === 'message-batch') {
            if (Array.isArray(msg)) {
              that.processBatch(msg)
            }
          } else if (event === 'user-joined') {
            that.setData({ connected: true, hasJoinedRoom: true })
            // 入房成功后把连接共享给其他页面（游戏页）复用，
            // 避免游戏页另开一条未注册的 socket 导致服务端不认人。
            try {
              var gd = getApp().globalData
              if (gd) {
                gd.socket = socket
                gd.socketJoined = true
                gd.roomName = that.data.roomName
                gd.username = that.data.username
                console.log('[Socket] 已共享连接给全局，供游戏页复用')
              }
            } catch (e) {
              console.warn('[Socket] 共享连接失败:', e)
            }
            if (msg && msg.users && Array.isArray(msg.users)) {
              var filtered = msg.users.filter(function(u) {
                return u.username !== that.data.username
              })
              that.setData({ users: filtered })
            }
          } else if (event === 'online-users') {
            var list = Array.isArray(msg) ? msg : []
            // 同步更新顶部面板的 users，避免从游戏页返回后 AI 消失
            that.setData({ onlineUsers: list, onlineUsersLoaded: true, users: list })
          } else if (event === 'active-games') {
            that.setData({ activeGames: Array.isArray(msg) ? msg : [] })
          } else if (event === 'game-invitations') {
            var gameNames = {
              rps: '剪刀石头布',
              gomoku: '五子棋',
              'guess-number': '猜数字',
              bomb: '数字炸弹',
              pictionary: '你画我猜',
              typing: '打字对战',
              go: '围棋',
              snake: '贪吃蛇'
            }
            var invList = (Array.isArray(msg) ? msg : []).map(function (inv) {
              var copy = Object.assign({}, inv)
              copy.gameName = gameNames[inv.gameType] || inv.gameType
              return copy
            })
            that.setData({ gameInvitations: invList })
          } else if (event === 'game-invitation') {
            var existingInv = that.data.gameInvitations || []
            var mergedInv = existingInv.concat([msg])
            that.setData({ gameInvitations: mergedInv })
            if (msg && msg.fromUsername) {
              that.showNotification(msg.fromUsername, '🎮 邀请你玩「' + (msg.gameType || '游戏') + '」')
            }
          } else if (event === 'game-history') {
            var typeNames = {
              gomoku: '♟️ 五子棋',
              rps: '✊ 剪刀石头布',
              'guess-number': '🔢 猜数字',
              bomb: '💣 数字炸弹',
              pictionary: '🎨 你画我猜',
              typing: '⌨️ 打字对战',
              go: '⚫ 围棋',
              snake: '🐍 贪吃蛇'
            }
            var curName = that.data.username
            var histList = (Array.isArray(msg) ? msg : []).map(function (g) {
              var isWin = g.winnerName === curName
              var resultText = g.winnerName
                ? (isWin ? '🎉 你获胜了' : '😢 ' + g.winnerName + ' 获胜')
                : '🤝 平局'
              var dt = g.endTime ? new Date(g.endTime) : new Date()
              var timeStr = (dt.getMonth() + 1) + '/' + dt.getDate() + ' ' +
                that.format8(dt.getHours()) + ':' + that.format8(dt.getMinutes())
              return {
                id: g.id,
                gameType: g.type,
                gameTypeName: typeNames[g.type] || g.type,
                resultText: resultText,
                time: timeStr,
                winnerName: g.winnerName
              }
            })
            that.setData({ gameHistory: histList })
          } else if (event === 'kicked') {
            var kickMsg = typeof msg === 'string' ? msg : ((msg && msg.message) || '你已被踢出聊天室')
            that.setData({ kicked: true, connected: false, connecting: false })
            wx.showModal({
              title: '已被踢出',
              content: kickMsg,
              showCancel: false,
              confirmText: '确定',
              success: function () { wx.navigateBack() }
            })
          } else if (event === 'muted-error' || event === 'message-error' || event === 'permission-denied') {
            var errText = (msg && msg.message) || '操作被拒绝'
            wx.showToast({ title: errText, icon: 'none' })
          } else if (event === 'game-start' || event === 'rps-start' ||
                     event === 'guess-number-start' || event === 'bomb-start' ||
                     event === 'pictionary-start' || event === 'go-start' ||
                     event === 'snake-start') {
            console.log('[Socket] 游戏开始:', event, msg)
            that.onGameStart(event, msg)
          } else if (event === 'game-invitation-sent') {
            console.log('[游戏] 邀请已送达:', msg)
            if (msg && msg.toUsername) {
              wx.showToast({ title: '已邀请 ' + msg.toUsername, icon: 'none' })
            }
          } else if (event === 'game-invitation-error') {
            var gErr = (msg && msg.message) || '邀请失败'
            console.error('[游戏] 邀请失败:', gErr)
            wx.showToast({ title: gErr, icon: 'none' })
          } else if (event === 'game-invitation-response') {
            console.log('[游戏] 邀请响应:', msg)
            if (msg && msg.accept && msg.username) {
              wx.showToast({ title: msg.username + ' 接受邀请', icon: 'none' })
            }
          } else if (event === 'join-error') {
            var joinErr = (msg && msg.message) || '加入房间失败'
            that.isInitializingSocket = false
            wx.showModal({
              title: '加入失败',
              content: joinErr,
              showCancel: false,
              confirmText: '确定'
            })
          }
        } catch(e) {
          console.error('解析消息失败', e)
        }
      }
    })
    socket.onClose(function() {
      console.log('[Socket] onClose 触发')
      that.setData({ connected: false })
      that.isInitializingSocket = false
      if (!that.data.kicked && that.reconnectAttempts < that.maxReconnectAttempts) {
        that.reconnectAttempts++
        console.log('[Socket] 连接已断开，' + that.reconnectAttempts + '/' + that.maxReconnectAttempts + ' 次后自动重连')
        setTimeout(function() {
          that.initSocket()
        }, 3000 * that.reconnectAttempts)
      } else if (that.reconnectAttempts >= that.maxReconnectAttempts) {
        console.log('[Socket] 已达到最大重连次数，停止自动重连')
      }
    })
    socket.onError(function(err) {
      console.error('[Socket] onError 触发:', err)
      var errMsg = err && err.errMsg ? err.errMsg : '未知错误'
      wx.showModal({
        title: '连接失败',
        content: '无法连接到聊天服务器（' + errMsg + '），是否重新连接？',
        showCancel: true,
        confirmText: '重新连接',
        cancelText: '取消',
        success: function(res) {
          if (res.confirm) {
            that.initSocket()
          }
        },
        fail: function(err2) {
          console.error('显示连接失败提示失败', err2)
        }
      })
      that.setData({ connected: false })
      that.isInitializingSocket = false
    })
  },

  // 统一处理文件/图片 URL：相对路径补全为服务器绝对地址
  normalizeFileUrl(url) {
    if (!url || typeof url !== 'string') return ''
    if (/^https?:/i.test(url)) return url
    if (url.charAt(0) === '/') return this.getServerUrl() + url
    if (/^uploads\//.test(url)) return this.getServerUrl() + '/' + url
    return url
  },
  handleNewMessage(msg) {
    if (!msg) {
      return
    }
    var username = msg.username || '未知用户'
    var avatar = msg.avatarUrl || ''
    var message = {
      id: msg.id || Date.now(),
      type: msg.type || 'text',
      // 服务端字段叫 message，客户端历史可能叫 content
      content: msg.content || msg.message || '',
      username: username,
      isSelf: username === this.data.username,
      // WXML 期待嵌套 user 对象，这里补齐（原来只有扁平字段导致名字/头像为空）
      user: {
        nickName: username,
        avatarUrl: avatar
      },
      avatarUrl: avatar,
      roomName: msg.roomName || this.data.roomName,
      time: msg.time || msg.timestamp || new Date().toLocaleTimeString(),
      imageUrl: this.normalizeFileUrl(msg.imageUrl || msg.url || ''),
      fileUrl: this.normalizeFileUrl(msg.fileUrl || msg.url || ''),
      filename: msg.filename || msg.fileName || '',
      fileSize: msg.fileSize || '',
      latitude: msg.latitude,
      longitude: msg.longitude,
      address: msg.address || msg.locationName || ''
    }
    var messages = this.data.messages.slice()
    messages.push(message)
    this.setData({
      messages: messages,
      scrollTop: 99999
    })
  },
  processBatch(batch) {
    var that = this
    batch.forEach(function(msg) {
      that.handleNewMessage(msg)
    })
  },
  uploadAndSend(type, tempFilePath, displayName) {
    var that = this
    if (!that.data.connected) {
      wx.showModal({
        title: '未连接',
        content: '当前未连接到聊天服务器，是否重新连接？',
        showCancel: true,
        confirmText: '重新连接',
        cancelText: '取消',
        success: function(res) {
          if (res.confirm) {
            that.initSocket()
          }
        },
        fail: function(err) {
          console.error('显示重连提示失败', err)
        }
      })
      return
    }
    var fileName = displayName || tempFilePath.split('/').pop() || 'file'
    // 用上传进度弹窗，wx.uploadFile 提供真实进度回调
    that.setData({
      showUploadModal: true,
      uploadingFilename: fileName,
      uploadProgress: 0,
      uploadStatus: '正在上传...'
    })
    var uploadId = 'upload_' + Date.now() + '_' + Math.floor(Math.random() * 1000)
    that.addUpload({ id: uploadId, filename: fileName, type: type })
    var uploadTask = wx.uploadFile({
      url: that.getServerUrl() + '/upload',
      filePath: tempFilePath,
      name: 'file',
      formData: { filename: fileName },
      success: function(res) {
        that.setData({ uploadProgress: 100, uploadStatus: '上传完成' })
        var fileUrl = ''
        try {
          var data = typeof res.data === 'string' ? JSON.parse(res.data) : res.data
          fileUrl = data.url || data.fileUrl || (data.data && data.data.url) || ''
        } catch (e) {
          console.error('解析上传响应失败:', e)
        }
        if (!fileUrl) {
          console.error('上传响应:', res.statusCode, res.data)
          wx.showToast({ title: '上传失败：未获取到文件地址', icon: 'none' })
          that.completeUpload(uploadId, false)
          that.hideUploadModal()
          return
        }
        if (fileUrl.charAt(0) === '/') fileUrl = that.getServerUrl() + fileUrl
        var payload = JSON.stringify({
          type: type,
          content: type === 'image' ? '[图片]' : type === 'video' ? '[视频]' : fileName,
          username: that.data.username,
          roomName: that.data.roomName,
          avatarUrl: that.data.avatarUrl || '',
          imageUrl: type === 'image' ? fileUrl : '',
          videoUrl: type === 'video' ? fileUrl : '',
          fileUrl: type === 'file' ? fileUrl : '',
          filename: fileName,
          fileSize: ''
        })
        if (that.socket && that.socket.readyState === 1) {
          that.socket.send({ data: '42["message",' + payload + ']' })
          wx.showToast({ title: type === 'image' ? '图片已发送' : type === 'video' ? '视频已发送' : '文件已发送', icon: 'none' })
        } else {
          wx.showToast({ title: '已上传，但未连接，无法发送', icon: 'none' })
        }
        that.completeUpload(uploadId, true)
        that.hideUploadModal()
      },
      fail: function(err) {
        that.completeUpload(uploadId, false)
        that.hideUploadModal()
        console.error('上传失败:', err)
        wx.showToast({ title: '上传失败', icon: 'none' })
      }
    })
    // 真实上传进度
    if (uploadTask.onProgressUpdate) {
      uploadTask.onProgressUpdate(function(res) {
        that.updateUploadProgress(uploadId, res.progress)
        that.setData({ uploadProgress: res.progress })
      })
    }
    that.setData({ uploadTask: uploadTask })
  },
  showAudioControlPanel() {
    var that = this
    var playingCount = 0
    var pausedCount = 0
    if (that.data.playingAudios) {
      that.data.playingAudios.forEach(function(a) {
        if (a.status === 'playing') {
          playingCount++
        } else {
          pausedCount++
        }
      })
    }
    wx.showModal({
      title: '音频播放控制',
      content: '正在播放: ' + playingCount + ' 个\n已暂停: ' + pausedCount + ' 个\n\n音频控制功能待完善',
      showCancel: false,
      confirmText: '知道了',
      confirmColor: '#576B95'
    })
  },

  showElementStatus() {
    var status = [
      '连接状态: ' + (this.data.connected ? '已连接' : '未连接'),
      '正在连接: ' + (this.data.connecting ? '是' : '否'),
      '重连次数: ' + this.reconnectAttempts + '/' + this.maxReconnectAttempts,
      '使用本地服务器: ' + (this.useLocalServer ? '是' : '否'),
      '服务器地址: ' + this.getServerUrl(),
      '用户名: ' + this.data.username,
      '房间名: ' + this.data.roomName
    ].join('\n')
    wx.showModal({
      title: '元素状态',
      content: status,
      showCancel: false,
      confirmText: '知道了',
      confirmColor: '#576B95'
    })
  },

  // ==================== 通用辅助 ====================

  format8(n) {
    n = n.toString()
    return n[1] ? n : '0' + n
  },

  formatTime(date) {
    var year = date.getFullYear()
    var month = date.getMonth() + 1
    var day = date.getDate()
    var hour = date.getHours()
    var minute = date.getMinutes()
    var second = date.getSeconds()
    return year + '/' + this.format8(month) + '/' + this.format8(day) + ' ' +
      this.format8(hour) + ':' + this.format8(minute) + ':' + this.format8(second)
  },

  formatFileSize(bytes) {
    if (!bytes || bytes === 0) return '0 B'
    var k = 1024
    var sizes = ['B', 'KB', 'MB', 'GB']
    var i = Math.floor(Math.log(bytes) / Math.log(k))
    if (i >= sizes.length) i = sizes.length - 1
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  },

  formatAudioTime(seconds) {
    if (!seconds || isNaN(seconds)) return '0:00'
    var m = Math.floor(seconds / 60)
    var s = Math.floor(seconds % 60)
    return m + ':' + this.format8(s)
  },

  formatAudioDuration(seconds) {
    return this.formatAudioTime(seconds)
  },

  getAudioStatus(id) {
    var audios = this.data.playingAudios || []
    var found = audios.find(function (a) { return a.id === id })
    if (!found) return '▶️'
    return found.status === 'playing' ? '⏸️' : '▶️'
  },

  getPercentage(votes, total) {
    if (!total || total === 0) return 0
    return Math.round((votes / total) * 100)
  },

  // ==================== 导航 / 通知 ====================

  goBack() {
    wx.navigateBack({ delta: 1 })
  },

  onTapNotification() {
    if (!this.data.notification || !this.data.notification.show) return
    this.setData({ 'notification.show': false })
    wx.pageScrollTo({ scrollTop: 0, duration: 300 })
  },

  hideNotification() {
    if (this.notificationTimer) {
      clearTimeout(this.notificationTimer)
      this.notificationTimer = null
    }
    this.setData({ 'notification.show': false })
  },

  showNotification(senderName, content, avatarUrl) {
    var that = this
    if (!that.data.notification) {
      return
    }
    that.setData({
      notification: {
        show: true,
        senderName: senderName || '',
        content: content || '',
        avatarUrl: avatarUrl || ''
      }
    })
    if (that.notificationTimer) clearTimeout(that.notificationTimer)
    that.notificationTimer = setTimeout(function () {
      that.hideNotification()
    }, 3000)
  },

  // ==================== 上传 / 下载面板 ====================

  toggleUploadPanel() {
    this.setData({ showUploadPanel: !this.data.showUploadPanel })
  },

  hideUploadPanel() {
    this.setData({ showUploadPanel: false })
  },

  toggleDownloadPanel() {
    this.setData({ showDownloadPanel: !this.data.showDownloadPanel })
  },

  hideDownloadPanel() {
    this.setData({ showDownloadPanel: false })
  },

  addUpload(task) {
    var uploads = (this.data.uploads || []).filter(function (u) { return u.id !== task.id })
    uploads.push({ id: task.id, filename: task.filename || '', type: task.type || 'file', progress: 0, status: '上传中' })
    this.setData({ uploads: uploads })
  },

  updateUploadProgress(id, progress) {
    var uploads = (this.data.uploads || []).map(function (u) {
      if (u.id !== id) return u
      return Object.assign({}, u, { progress: progress, status: progress >= 100 ? '上传完成' : '上传中' })
    })
    this.setData({ uploads: uploads })
  },

  completeUpload(id, success) {
    var that = this
    var uploads = (that.data.uploads || []).map(function (u) {
      if (u.id !== id) return u
      return Object.assign({}, u, {
        progress: success ? 100 : 0,
        status: success ? '上传完成' : '上传失败'
      })
    })
    that.setData({ uploads: uploads })
    if (success) {
      setTimeout(function () {
        var left = (that.data.uploads || []).filter(function (u) { return u.id !== id })
        that.setData({ uploads: left })
      }, 2000)
    }
  },

  cancelUpload(e) {
    var id = e && e.currentTarget && e.currentTarget.dataset ? e.currentTarget.dataset.id : e
    var task = this.data.uploadTask
    if (task && !id) {
      try { task.abort() } catch (err) { console.warn('中止上传失败:', err) }
      this.setData({ uploadTask: null })
    }
    if (id) {
      var uploads = (this.data.uploads || []).filter(function (u) { return u.id !== id })
      this.setData({ uploads: uploads })
    }
    this.setData({ cancelledUploadId: id || null })
  },

  hideUploadModal() {
    this.setData({
      showUploadModal: false,
      uploadingFilename: '',
      uploadProgress: 0,
      uploadStatus: '准备上传...'
    })
  },

  addDownload(task) {
    var downloads = (this.data.downloads || []).filter(function (d) { return d.id !== task.id })
    downloads.push({ id: task.id, filename: task.filename || '', type: task.type || 'file', url: task.url || '', progress: 0, status: '下载中' })
    this.setData({ downloads: downloads })
  },

  updateDownloadProgress(id, progress) {
    var downloads = (this.data.downloads || []).map(function (d) {
      if (d.id !== id) return d
      return Object.assign({}, d, { progress: progress, status: progress >= 100 ? '下载完成' : '下载中' })
    })
    this.setData({ downloads: downloads })
  },

  completeDownload(id, success) {
    var that = this
    var downloads = (that.data.downloads || []).map(function (d) {
      if (d.id !== id) return d
      return Object.assign({}, d, {
        progress: success ? 100 : 0,
        status: success ? '下载完成' : '下载失败'
      })
    })
    that.setData({ downloads: downloads })
    if (success) {
      setTimeout(function () {
        var left = (that.data.downloads || []).filter(function (d) { return d.id !== id })
        that.setData({ downloads: left })
      }, 2000)
    }
  },

  cancelDownload(e) {
    var id = e && e.currentTarget && e.currentTarget.dataset ? e.currentTarget.dataset.id : e
    if (id && this.downloadTasks && this.downloadTasks[id]) {
      try { this.downloadTasks[id].abort() } catch (err) { console.warn('中止下载失败:', err) }
      delete this.downloadTasks[id]
    }
    var downloads = (this.data.downloads || []).filter(function (d) { return d.id !== id })
    this.setData({ downloads: downloads })
  },

  cancelDownloadModal() {
    var id = this.data.currentDownloadId
    if (id && this.downloadTasks && this.downloadTasks[id]) {
      try { this.downloadTasks[id].abort() } catch (err) { console.warn('中止下载失败:', err) }
      delete this.downloadTasks[id]
    }
    var downloads = (this.data.downloads || []).filter(function (d) { return d.id !== id })
    this.setData({
      downloads: downloads,
      showDownloadModal: false,
      downloadingFilename: '',
      downloadProgress: 0,
      downloadStatus: '准备下载...',
      currentDownloadId: ''
    })
  },

  hideDownloadModal() {
    this.setData({
      showDownloadModal: false,
      downloadingFilename: '',
      downloadProgress: 0,
      downloadStatus: '准备下载...'
    })
  },

  // ==================== 媒体预览 / 播放 ====================

  previewImage(e) {
    var url = e && e.currentTarget ? e.currentTarget.dataset.url : e
    if (!url) return
    wx.previewImage({ urls: [url], current: url })
  },

  onImageError(e) {
    console.warn('图片加载失败:', e && e.detail ? e.detail : e)
  },

  downloadFile(e) {
    var ds = e && e.currentTarget ? e.currentTarget.dataset : {}
    var fileUrl = ds.url
    var filename = ds.filename || ''
    var allowDownload = ds.allowdownload !== false

    if (allowDownload === false) {
      wx.showModal({ title: '提示', content: '该文件不允许下载', showCancel: false, confirmText: '确定' })
      return
    }
    if (!fileUrl) {
      wx.showModal({ title: '提示', content: '文件链接无效', showCancel: false, confirmText: '确定' })
      return
    }
    fileUrl = this.normalizeFileUrl(fileUrl)
    if (!/^https?:/.test(fileUrl)) {
      wx.showModal({ title: '提示', content: '文件链接格式不正确', showCancel: false, confirmText: '确定' })
      return
    }

    var ext = filename ? filename.toLowerCase().substring(filename.lastIndexOf('.')) : ''
    var imageTypes = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp']
    var audioTypes = ['.mp3', '.wav', '.ogg', '.aac', '.m4a']
    var videoTypes = ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm']

    if (imageTypes.indexOf(ext) >= 0) {
      wx.previewImage({ urls: [fileUrl], current: fileUrl })
      return
    }
    if (videoTypes.indexOf(ext) >= 0) {
      this.setData({ videoSrc: fileUrl, showVideoPlayer: true })
      return
    }
    if (audioTypes.indexOf(ext) >= 0) {
      this.playRemoteAudio(fileUrl, filename)
      return
    }
    this.openDocument(fileUrl, filename)
  },

  openDocument(fileUrl, filename) {
    var that = this
    wx.showLoading({ title: '准备预览...' })
    var downloadId = 'download_' + Date.now()
    if (!that.downloadTasks) that.downloadTasks = {}
    var task = wx.downloadFile({
      url: fileUrl,
      success: function (res) {
        wx.hideLoading()
        if (res.statusCode === 200) {
          // 预览失败时给出分享/改后缀的兜底，而不是只弹 toast
          that._tryOpenWithFallback(res.tempFilePath, filename || 'file')
        } else {
          wx.showToast({ title: '下载失败', icon: 'none' })
        }
        delete that.downloadTasks[downloadId]
      },
      fail: function (err) {
        wx.hideLoading()
        console.error('下载文档失败:', err)
        wx.showToast({ title: '下载失败', icon: 'none' })
        delete that.downloadTasks[downloadId]
      }
    })
    that.downloadTasks[downloadId] = task
  },

  // 预览失败兜底：分享文件 / 改后缀名重试
  _tryOpenWithFallback(tempFilePath, filename) {
    var that = this
    // 先尝试正常打开
    wx.openDocument({
      filePath: tempFilePath,
      showMenu: true,
      success: function () { console.log('文档打开成功') },
      fail: function () {
        // 打开失败，让用户选择兜底方式
        wx.showActionSheet({
          itemList: ['📤 分享文件', '🔤 更改后缀名后重试', '❌ 取消'],
          success: function (res) {
            if (res.tapIndex === 0) {
              that._shareFile(tempFilePath, filename)
            } else if (res.tapIndex === 1) {
              that._renameAndOpen(tempFilePath, filename)
            }
          },
          fail: function () {}
        })
      }
    })
  },

  // 分享文件给好友（wx.shareFileMessage，基础库 2.16.1+）
  _shareFile(tempFilePath, filename) {
    if (wx.shareFileMessage) {
      wx.shareFileMessage({
        filePath: tempFilePath,
        fileName: filename || '文件',
        success: function () { wx.showToast({ title: '已分享', icon: 'success' }) },
        fail: function (err) {
          console.error('分享文件失败:', err)
          wx.showToast({ title: '分享失败，可点文档右上角菜单转发', icon: 'none', duration: 2500 })
        }
      })
    } else {
      wx.showModal({
        title: '分享文件',
        content: '当前微信版本不支持直接分享，请在打开文档后点击右上角「···」转发。',
        showCancel: false, confirmText: '知道了'
      })
    }
  },

  // 改后缀名重试：把已下载的文件复制到新后缀再 openDocument
  _renameAndOpen(tempFilePath, filename) {
    var that = this
    var base = (filename || 'file').replace(/\.[^.]+$/, '')
    wx.showActionSheet({
      itemList: ['.txt（文本）', '.pdf（PDF）', '.doc（Word）', '.xls（Excel）', '.jpg（图片）'],
      success: function (res) {
        var exts = ['.txt', '.pdf', '.doc', '.xls', '.jpg']
        var ext = exts[res.tapIndex]
        if (!ext) return
        var newName = base + ext
        var newPath = wx.env.USER_DATA_PATH + '/' + Date.now() + ext
        try {
          wx.getFileSystemManager().copyFile({
            srcPath: tempFilePath,
            destPath: newPath,
            success: function () {
              wx.openDocument({
                filePath: newPath,
                showMenu: true,
                success: function () { console.log('改后缀后打开成功:', newName) },
                fail: function () {
                  wx.showToast({ title: '仍无法打开该格式', icon: 'none' })
                }
              })
            },
            fail: function (err) {
              console.error('复制文件失败:', err)
              wx.showToast({ title: '更改后缀失败', icon: 'none' })
            }
          })
        } catch (e) {
          wx.showToast({ title: '更改后缀失败', icon: 'none' })
        }
      },
      fail: function () {}
    })
  },
  // 先下载到本地再播放：远程音频直接播容易失败/卡顿
  playRemoteAudio(url, filename) {
    var that = this
    if (!url) {
      wx.showToast({ title: '音频链接无效', icon: 'none' })
      return
    }
    url = this.normalizeFileUrl(url)
    if (!/^https?:/.test(url)) {
      wx.showToast({ title: '音频链接格式不正确', icon: 'none' })
      return
    }

    var audioId = 'remote_' + Date.now()
    // 先放一个「下载中」的条目，进度条可见
    var list = (that.data.playingAudios || []).slice()
    list.push({
      id: audioId,
      filename: filename || '音频',
      audioUrl: url,
      status: 'downloading',
      progress: 0,
      duration: 0,
      currentTime: 0
    })
    that.setData({ playingAudios: list, showAudioPlayer: true })

    var dlTask = wx.downloadFile({
      url: url,
      success: function (res) {
        if (res.statusCode !== 200 || !res.tempFilePath) {
          that._updateAudioStatus(audioId, 'error')
          wx.showToast({ title: '音频下载失败', icon: 'none' })
          return
        }
        that._updateAudioStatus(audioId, 'playing', { progress: 100 })
        // 用本地临时文件播放
        that._playLocalAudio(audioId, res.tempFilePath, filename)
      },
      fail: function (err) {
        console.error('音频下载失败:', err)
        that._updateAudioStatus(audioId, 'error')
        wx.showToast({ title: '音频下载失败', icon: 'none' })
      }
    })
    if (dlTask && dlTask.onProgressUpdate) {
      dlTask.onProgressUpdate(function (p) {
        that._updateAudioStatus(audioId, 'downloading', { progress: p.progress })
      })
    }
  },

  _updateAudioStatus(id, status, extra) {
    var self = this
    var list = (this.data.playingAudios || []).map(function (a) {
      if (a.id !== id) return a
      return Object.assign({}, a, { status: status }, extra || {})
    })
    this.setData({ playingAudios: list })
  },

  _playLocalAudio(audioId, localPath, filename) {
    var that = this
    var ctx = wx.createInnerAudioContext()
    ctx.src = localPath
    that.data.audioContexts = that.data.audioContexts || {}
    that.data.audioContexts[audioId] = ctx
    ctx.onPlay(function () { console.log('本地音频开始播放:', audioId) })
    ctx.onEnded(function () { that._updateAudioStatus(audioId, 'stopped') })
    ctx.onError(function (err) {
      console.error('音频播放失败:', err)
      that._updateAudioStatus(audioId, 'error')
      wx.showToast({ title: '音频播放失败', icon: 'none' })
    })
    ctx.play()
  },

  playAudio(e) {
    var url = e && e.currentTarget ? e.currentTarget.dataset.url : ''
    if (!url) {
      wx.showToast({ title: '音频链接无效', icon: 'none' })
      return
    }
    this.playRemoteAudio(url, '音频')
  },

  toggleAudioPlay(e) {
    var id = e && e.currentTarget ? e.currentTarget.dataset.id : e
    var audios = this.data.playingAudios || []
    var ctx = this.data.audioContexts ? this.data.audioContexts[id] : null
    var target = audios.find(function (a) { return a.id === id })
    if (!target) return
    // 下载中或加载失败时，点击播放按钮不做处理
    if (target.status === 'downloading' || target.status === 'error') {
      wx.showToast({ title: target.status === 'downloading' ? '音频下载中...' : '音频加载失败', icon: 'none' })
      return
    }
    if (target.status === 'playing') {
      if (ctx) { try { ctx.pause() } catch (err) {} }
      var paused = audios.map(function (a) {
        if (a.id !== id) return a
        return Object.assign({}, a, { status: 'paused' })
      })
      this.setData({ playingAudios: paused })
    } else {
      if (ctx) { try { ctx.play() } catch (err) {} }
      var played = audios.map(function (a) {
        if (a.id !== id) return a
        return Object.assign({}, a, { status: 'playing' })
      })
      this.setData({ playingAudios: played })
    }
  },

  stopAudio(e) {
    var id = e && e.currentTarget ? e.currentTarget.dataset.id : e
    var ctx = this.data.audioContexts ? this.data.audioContexts[id] : null
    if (ctx) {
      try { ctx.stop() } catch (err) {}
      try { ctx.destroy() } catch (err) {}
      delete this.data.audioContexts[id]
    }
    var left = (this.data.playingAudios || []).filter(function (a) { return a.id !== id })
    this.setData({ playingAudios: left, showAudioPlayer: left.length > 0 })
  },

  seekAudio(e) {
    var ds = e && e.currentTarget ? e.currentTarget.dataset : {}
    var id = ds.id
    var audios = this.data.playingAudios || []
    var target = audios.find(function (a) { return a.id === id })
    if (!target || !target.duration) return
    var ctx = this.data.audioContexts ? this.data.audioContexts[id] : null
    if (!ctx) return
    var ratio = ds.ratio || 0
    try { ctx.seek(ratio * target.duration) } catch (err) { console.warn('跳转失败:', err) }
  },

  // ==================== 视频播放 ====================

  closeVideoPlayer() {
    this.setData({ showVideoPlayer: false, videoSrc: '' })
  },

  onVideoContentTap() {
    // 阻止点击事件冒泡到遮罩层
  },

  onVideoError(e) {
    console.error('视频播放失败:', e && e.detail ? e.detail : e)
    wx.showToast({ title: '视频播放失败', icon: 'none' })
    this.setData({ showVideoPlayer: false })
  },

  // ==================== 定位 ====================

  openLocation(e) {
    var ds = e && e.currentTarget ? e.currentTarget.dataset : {}
    var lat = parseFloat(ds.lat)
    var lng = parseFloat(ds.lng)
    var address = ds.address || ''
    if (isNaN(lat) || isNaN(lng)) {
      wx.showToast({ title: '位置信息无效', icon: 'none' })
      return
    }
    wx.openLocation({
      latitude: lat,
      longitude: lng,
      name: address || '位置',
      address: address,
      scale: 18
    })
  },

  // ==================== 投票 ====================

  openPollDetail(e) {
    var ds = e && e.currentTarget ? e.currentTarget.dataset : {}
    var poll = ds.poll || null
    if (!poll) return
    this.setData({
      showPollDetail: true,
      selectedPoll: poll,
      pollSelectedOptions: [],
      hasVoted: (this.data.votedPolls || []).indexOf(poll.id) >= 0
    })
  },

  closePollDetail() {
    this.setData({ showPollDetail: false, pollSelectedOptions: [] })
  },

  selectPollOption(e) {
    var index = e && e.currentTarget ? Number(e.currentTarget.dataset.index) : -1
    var poll = this.data.selectedPoll
    if (!poll || index < 0) return
    if (this.data.hasVoted) {
      wx.showToast({ title: '您已投过票', icon: 'none' })
      return
    }
    var selected = (this.data.pollSelectedOptions || []).slice()
    if (poll.multiple) {
      var pos = selected.indexOf(index)
      if (pos >= 0) {
        selected.splice(pos, 1)
      } else {
        selected.push(index)
      }
    } else {
      selected = [index]
    }
    this.setData({ pollSelectedOptions: selected })
  },

  submitPollVote() {
    var that = this
    var poll = that.data.selectedPoll
    var selected = that.data.pollSelectedOptions || []
    if (!poll) return
    if (selected.length === 0) {
      wx.showToast({ title: '请先选择选项', icon: 'none' })
      return
    }
    if (!that.data.connected || !that.isSocketReady()) {
      wx.showToast({ title: '未连接，无法投票', icon: 'none' })
      return
    }
    // 服务端签名: { pollId, optionIndex }，多选则逐项发送
    selected.forEach(function (idx) {
      that.socket.send({
        data: '42["vote",' + JSON.stringify({ pollId: poll.id, optionIndex: idx }) + ']'
      })
    })

    var voted = (that.data.votedPolls || []).slice()
    if (voted.indexOf(poll.id) < 0) voted.push(poll.id)

    var updatedPoll = Object.assign({}, poll)
    updatedPoll.options = (poll.options || []).map(function (opt, i) {
      if (selected.indexOf(i) < 0) return opt
      return Object.assign({}, opt, { votes: (opt.votes || 0) + 1 })
    })
    updatedPoll.totalVotes = updatedPoll.options.reduce(function (sum, o) {
      return sum + (o.votes || 0)
    }, 0)

    that.setData({
      selectedPoll: updatedPoll,
      hasVoted: true,
      votedPolls: voted
    })
    wx.showToast({ title: '投票成功', icon: 'success' })
  },

  // ==================== 游戏 / 互动中心 ====================

  inviteUserToGame(e) {
    var ds = e && e.currentTarget ? e.currentTarget.dataset : {}
    var userId = ds.userId
    var username = ds.username || ''
    var isAI = username === 'ai' || userId === 'pc-bot-virtual-socket'

    var gameList = isAI
      ? ['✊ 剪刀石头布', '♟️ 五子棋', '🔢 猜数字', '💣 数字炸弹', '🎨 你画我猜']
      : ['✊ 剪刀石头布', '♟️ 五子棋', '🔢 猜数字', '💣 数字炸弹', '🎨 你画我猜', '⌨️ 打字对战']
    var gameTypes = isAI
      ? ['rps', 'gomoku', 'guess-number', 'bomb', 'pictionary']
      : ['rps', 'gomoku', 'guess-number', 'bomb', 'pictionary', 'typing']

    var that = this
    wx.showActionSheet({
      itemList: gameList,
      success: function (res) {
        var gameType = gameTypes[res.tapIndex]
        if (!isAI) {
          that.sendGameInvitation(gameType, userId, username)
          return
        }
        // 与 AI 对战时，先选难度
        wx.showActionSheet({
          itemList: ['😊 休闲（AI 会失误）', '😈 困难（AI 全力以赴）'],
          success: function (r2) {
            var difficulty = r2.tapIndex === 1 ? 'hard' : 'easy'
            that.sendGameInvitation(gameType, userId, username, difficulty)
          },
          fail: function () {
            console.log('取消选择难度')
          }
        })
      },
      fail: function (err) {
        console.log('取消选择游戏:', err)
      }
    })
  },

  sendGameInvitation(gameType, userId, username, difficulty) {
    if (!this.data.connected || !this.isSocketReady()) {
      wx.showToast({ title: '未连接，无法发送邀请', icon: 'none' })
      return
    }
    var inv = { userId: userId, gameType: gameType }
    // 仅与 AI 对战时携带难度，真人邀请无此概念
    if (difficulty) inv.difficulty = difficulty
    var payload = JSON.stringify(inv)
    this.socket.send({ data: '42["send-game-invitation",' + payload + ']' })
    var diffText = difficulty === 'hard' ? '困难' : (difficulty === 'easy' ? '休闲' : '')
    var toast = '已邀请 ' + username + (diffText ? ' ' + diffText + ' 难度' : '')
    wx.showToast({ title: toast, icon: 'none' })
  },

  acceptGameInvitation(e) {
    var id = e && e.currentTarget ? e.currentTarget.dataset.id : ''
    if (!id) return
    if (!this.data.connected || !this.isSocketReady()) {
      wx.showToast({ title: '未连接，无法接受邀请', icon: 'none' })
      return
    }
    var payload = JSON.stringify({ invitationId: id, accept: true })
    this.socket.send({ data: '42["respond-to-game-invitation",' + payload + ']' })
    var left = (this.data.gameInvitations || []).filter(function (inv) { return inv.id !== id })
    this.setData({ gameInvitations: left })
  },

  rejectGameInvitation(e) {
    var id = e && e.currentTarget ? e.currentTarget.dataset.id : ''
    if (!id) return
    if (!this.data.connected || !this.isSocketReady()) {
      wx.showToast({ title: '未连接，无法拒绝邀请', icon: 'none' })
      return
    }
    var payload = JSON.stringify({ invitationId: id, accept: false })
    this.socket.send({ data: '42["respond-to-game-invitation",' + payload + ']' })
    var left = (this.data.gameInvitations || []).filter(function (inv) { return inv.id !== id })
    this.setData({ gameInvitations: left })
  },

  // 收到游戏开始事件：组装数据并跳转游戏页
  onGameStart(eventName, msg) {
    if (!msg || !msg.gameId) {
      console.warn('[游戏] 游戏开始数据不完整:', msg)
      return
    }
    var gameData = {
      gameType: msg.gameType || 'gomoku',
      gameId: msg.gameId,
      players: msg.players || [],
      currentUsername: this.data.username,
      currentPlayer: msg.currentPlayer || '',
      currentGuesser: msg.currentGuesser || '',
      board: msg.board || null,
      wins: msg.wins || {},
      maxWins: msg.maxWins || 3,
      round: msg.round || 1,
      maxStep: msg.maxStep || 3,
      guessCounts: msg.guessCounts || {},
      // 你画我猜：让游戏页一开始就知道谁是画者，直接显示对应的 UI
      currentDrawer: msg.currentDrawer || '',
      currentDrawerName: msg.currentDrawerName || '',
      currentWord: msg.currentWord || null,
      wordHint: msg.wordHint || '',
      pictionaryRound: msg.currentRound || 0,
      maxRounds: msg.maxRounds || 5,
      scores: msg.scores || []
    }
    console.log('[游戏] 跳转游戏页:', gameData)
    // 关闭互动中心
    this.setData({ showInteractiveCenter: false })
    var encoded = encodeURIComponent(JSON.stringify(gameData))
    wx.navigateTo({
      url: '/pages/game/game?gameData=' + encoded,
      fail: function (err) {
        console.error('[游戏] 跳转失败:', err)
        wx.showToast({ title: '进入游戏失败', icon: 'none' })
      }
    })
  },

  refreshActiveGames() {
    if (!this.data.connected || !this.isSocketReady()) {
      wx.showToast({ title: '未连接，无法刷新', icon: 'none' })
      return
    }
    this.socket.send({ data: '42["get-active-games",{}]' })
    wx.showToast({ title: '已刷新', icon: 'none' })
  },

  bindJoinGameIdInput(e) {
    this.setData({ joinGameId: e.detail.value })
  },

  joinGameById() {
    var gameId = (this.data.joinGameId || '').trim()
    if (!gameId) {
      wx.showToast({ title: '请输入游戏ID', icon: 'none' })
      return
    }
    this.joinGameByIdInternal(gameId)
  },

  joinGame(e) {
    var id = e && e.currentTarget ? e.currentTarget.dataset.id : ''
    if (!id) return
    this.joinGameByIdInternal(id)
  },

  joinGameByIdInternal(gameId) {
    if (!this.data.connected || !this.isSocketReady()) {
      wx.showToast({ title: '未连接，无法加入', icon: 'none' })
      return
    }
    var payload = JSON.stringify({ gameId: gameId })
    this.socket.send({ data: '42["join-game-by-id",' + payload + ']' })
    wx.showToast({ title: '正在加入游戏', icon: 'none' })
  },

  toggleOnlineUsers() {
    this.setData({ showOnlineUsers: !this.data.showOnlineUsers })
  },

  // ==================== 补充依赖方法 ====================

  uploadAvatarToServer(tempFilePath) {
    var that = this
    if (!tempFilePath) return
    var fileName = tempFilePath.split('/').pop() || 'avatar.jpg'
    wx.getFileSystemManager().readFile({
      filePath: tempFilePath,
      encoding: 'binary',
      success: function (readRes) {
        wx.request({
          url: that.getServerUrl() + '/api/files/upload',
          method: 'POST',
          header: {
            'Content-Type': 'application/octet-stream',
            'X-Filename': encodeURIComponent(fileName)
          },
          data: readRes.data,
          success: function (res) {
            try {
              var data = typeof res.data === 'string' ? JSON.parse(res.data) : res.data
              var raw = data.url || data.fileUrl || (data.data && data.data.url) || ''
              if (!raw) {
                console.warn('头像上传响应无 URL:', data)
                return
              }
              var url = raw
              if (!/^https?:/.test(url)) {
                url = raw.charAt(0) === '/' ? that.getServerUrl() + raw : that.getServerUrl() + '/' + raw
              }
              that.setData({ avatarUrl: url })
              wx.setStorageSync('avatarUrl', url)
            } catch (e) {
              console.error('解析头像上传响应失败:', e)
            }
          },
          fail: function (err) {
            console.error('头像上传失败:', err)
          }
        })
      },
      fail: function (err) {
        console.error('读取头像文件失败:', err)
      }
    })
  },

  doDownloadFile(url, filename, progress, type) {
    var that = this
    var downloadId = 'download_' + Date.now()
    if (!that.downloadTasks) that.downloadTasks = {}
    that.addDownload({ id: downloadId, filename: filename, type: type || 'file', url: url })
    that.setData({
      showDownloadModal: true,
      downloadingFilename: filename,
      downloadStatus: '下载中...',
      downloadProgress: progress || 0,
      currentDownloadId: downloadId
    })
    var task = wx.downloadFile({
      url: url,
      success: function (res) {
        if (res.statusCode !== 200) {
          that.completeDownload(downloadId, false)
          that.setData({ downloadStatus: '下载失败' })
          wx.showToast({ title: '下载失败', icon: 'none' })
          return
        }
        that.completeDownload(downloadId, true)
        that.setData({ downloadProgress: 100, downloadStatus: '下载完成' })
        wx.showToast({ title: '下载完成', icon: 'success' })
        var savedPath = res.tempFilePath
        if (/^audio/.test(type || '') || /\.(mp3|wav|ogg|aac|m4a)$/i.test(filename || '')) {
          that.playRemoteAudio(savedPath, filename)
          return
        }
        wx.openDocument({
          filePath: savedPath,
          showMenu: true,
          fail: function (err) {
            console.warn('文档打开失败:', err)
            wx.showToast({ title: '已保存到临时目录', icon: 'none' })
          }
        })
        delete that.downloadTasks[downloadId]
      },
      fail: function (err) {
        console.error('下载失败:', err)
        that.completeDownload(downloadId, false)
        that.setData({ downloadStatus: '下载失败' })
        wx.showToast({ title: '下载失败', icon: 'none' })
        delete that.downloadTasks[downloadId]
      }
    })
    that.downloadTasks[downloadId] = task
    if (task && task.onProgressUpdate) {
      task.onProgressUpdate(function (res) {
        that.updateDownloadProgress(downloadId, res.progress)
        that.setData({ downloadProgress: res.progress })
      })
    }
    return downloadId
  },

  showDevActions() {
    var that = this
    wx.showActionSheet({
      itemList: ['📋 查看所有日志', '🔧 元素状态', '📤 导出日志'],
      success: function (res) {
        if (res.tapIndex === 0) that.showAllLogs()
        else if (res.tapIndex === 1) that.showElementStatus()
        else if (res.tapIndex === 2) that.exportLogs()
      },
      fail: function (err) {
        console.log('取消开发操作:', err)
      }
    })
  },





})
