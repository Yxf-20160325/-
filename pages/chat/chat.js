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
        that.socket.send({ data: '42["new-message",' + payload + ']' })
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
        that.uploadAndSend('image', tempFilePath)
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
        that.uploadAndSend('file', tempFilePath)
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
        that.uploadAndSend('video', tempFilePath)
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
          that.socket.send({ data: '42["new-message",' + payload + ']' })
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
            if (msg && msg.users && Array.isArray(msg.users)) {
              var filtered = msg.users.filter(function(u) {
                return u.username !== that.data.username
              })
              that.setData({ users: filtered })
            }
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
  handleNewMessage(msg) {
    if (!msg) {
      return
    }
    var message = {
      id: msg.id || Date.now(),
      type: msg.type || 'text',
      content: msg.content || '',
      username: msg.username || '未知用户',
      avatarUrl: msg.avatarUrl || '',
      roomName: msg.roomName || this.data.roomName,
      time: msg.time || new Date().toLocaleTimeString(),
      imageUrl: msg.imageUrl || msg.url || '',
      fileUrl: msg.fileUrl || msg.url || '',
      filename: msg.filename || '',
      fileSize: msg.fileSize || '',
      latitude: msg.latitude,
      longitude: msg.longitude,
      address: msg.address
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
  uploadAndSend(type, tempFilePath) {
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
    wx.showLoading({ title: '上传中...' })
    var fileName = tempFilePath.split('/').pop() || 'file'
    var uploadUrl = this.getServerUrl() + '/upload'
    var uploadTask = wx.uploadFile({
      url: uploadUrl,
      filePath: tempFilePath,
      name: 'file',
      formData: {
        type: type,
        username: that.data.username,
        roomName: that.data.roomName
      },
      success: function(res) {
        wx.hideLoading()
        var fileUrl = ''
        try {
          var data = JSON.parse(res.data)
          fileUrl = data.url || data.fileUrl || (data.data && data.data.url) || ''
        } catch(e) {
          fileUrl = res.data
        }
        if (!fileUrl) {
          wx.showToast({ title: '上传失败：未获取到文件地址', icon: 'none' })
          return
        }
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
          that.socket.send({ data: '42["new-message",' + payload + ']' })
          wx.showToast({ title: type === 'image' ? '图片已发送' : type === 'video' ? '视频已发送' : '文件已发送', icon: 'none' })
        } else {
          wx.showToast({ title: '已上传，但未连接，无法发送', icon: 'none' })
        }
      },
      fail: function(err) {
        wx.hideLoading()
        console.error('上传失败', err)
        wx.showToast({ title: '上传失败', icon: 'none' })
      }
    })
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
})
