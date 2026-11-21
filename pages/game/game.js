const app = getApp()

const BOARD_SIZE = 15

Page({
  data: {
    gameType: '',
    gameId: '',
    gameTitle: '',
    gameStatus: '准备中',
    board: [],
    currentPlayer: '',
    currentPlayerId: '',
    myName: '',
    opponentName: '',
    isMyTurn: false,
    gameStarted: false,
    players: [],
    rpsResult: '',
    myChoice: '',
    opponentChoice: '',
    guessInput: '',
    guessMin: 1,
    guessMax: 100,
    guessHint: '',
    guessHistory: [],
    bombInput: '',
    bombMin: 1,
    bombMax: 100,
    bombWarning: '',
    bombHistory: [],
    bombNumber: null,
    isBombGameOver: false,
    bombWinner: ''
  },

  onLoad(options) {
    console.log('游戏页面加载:', options)
    
    const gameData = options.gameData ? JSON.parse(decodeURIComponent(options.gameData)) : null
    
    if (gameData) {
      this.initGame(gameData)
    }
  },

  onUnload() {
    console.log('游戏页面卸载，清理连接与定时器')
    this.stopGameHeartbeat()
    if (this.socket && this.socketCreated) {
      try { this.socket.close({ code: 1000, reason: '页面卸载' }) } catch (e) {}
    }
    this.socket = null
    this.messageHandlerBound = false
  },

  initGame(gameData) {
    console.log('初始化游戏:', gameData)
    
    const gameTitles = {
      gomoku: '五子棋',
      rps: '剪刀石头布',
      'guess-number': '猜数字',
      bomb: '数字炸弹',
      pictionary: '你画我猜',
      typing: '打字对战'
    }

    this.setData({
      gameType: gameData.gameType,
      gameId: gameData.gameId,
      gameTitle: gameTitles[gameData.gameType] || gameData.gameType,
      players: gameData.players || [],
      gameStatus: '游戏中'
    })

    const myUsername = gameData.currentUsername ||
      ((app.globalData.user && app.globalData.user.username) || '玩家')
    
    let myName = myUsername
    let opponentName = '对手'
    let currentPlayerId = ''
    let isMyTurn = false

    if (gameData.players && gameData.players.length >= 2) {
      const myPlayer = gameData.players.find(p => p.username === myUsername)
      const opponentPlayer = gameData.players.find(p => p.username !== myUsername)
      
      myName = (myPlayer && myPlayer.username) || myName
      opponentName = (opponentPlayer && opponentPlayer.username) || opponentName
      currentPlayerId = gameData.currentPlayer || ''
      
      const currentPlayer = gameData.players.find(p => p.socketId === currentPlayerId)
      isMyTurn = !!(currentPlayer && currentPlayer.username === myUsername)
    }

    this.setData({
      myName,
      opponentName,
      currentPlayerId,
      isMyTurn,
      gameStarted: true
    })

    if (gameData.gameType === 'gomoku') {
      this.initGomoku(gameData)
    } else if (gameData.gameType === 'rps') {
      this.initRPS()
    } else if (gameData.gameType === 'guess-number') {
      this.initGuessNumber()
    } else if (gameData.gameType === 'bomb') {
      this.initBombGame()
    } else if (gameData.gameType === 'pictionary') {
      this.initPictionary()
    } else if (gameData.gameType === 'typing') {
      this.initTyping()
    }

    this.connectSocket()
  },

  initGomoku(gameData) {
    let board = []
    if (gameData.board && gameData.board.length > 0) {
      board = gameData.board
    } else {
      for (let i = 0; i < BOARD_SIZE; i++) {
        board[i] = []
        for (let j = 0; j < BOARD_SIZE; j++) {
          board[i][j] = null
        }
      }
    }
    
    this.setData({
      board,
      currentPlayerId: gameData.currentPlayer || ''
    })
  },

  initRPS() {
    this.setData({
      rpsResult: '',
      myChoice: '',
      opponentChoice: ''
    })
  },

  initGuessNumber() {
    this.setData({
      guessInput: '',
      guessMin: 1,
      guessMax: 100,
      guessHint: '',
      guessHistory: []
    })
  },

  initBombGame() {
    this.setData({
      bombInput: '',
      bombMin: 1,
      bombMax: 100,
      bombWarning: '',
      bombHistory: [],
      bombNumber: null,
      isBombGameOver: false,
      bombWinner: ''
    })
  },

  initPictionary() {
    this.setData({
      pictionaryWord: '',
      pictionaryDrawing: '',
      pictionaryGuesses: [],
      pictionaryTimeLeft: 60,
      pictionaryIsDrawing: false,
      pictionaryWinner: ''
    })
  },

  // ===== 你画我猜：canvas 绘制 ===== 
  // 约定：服务端下发的 drawingData 为统一格式
  //   { type:'strokes', width, height, strokes:[{color,width,points:[[x,y],...]}] }
  // 游戏坐标 0-100 → 画布像素等比缩放。

  picCtx() {
    if (!this._picCtx) {
      this._picCtx = wx.createCanvasContext('pictionaryCanvas', this)
    }
    return this._picCtx
  },

  // 把 0-100 坐标换算为画布像素
  picScale() {
    if (this._picSize) return this._picSize
    try {
      const q = wx.createSelectorQuery().in(this)
      // 同步拿不到，先用默认值，首次绘制后再校正
      this._picSize = { w: 300, h: 300 }
    } catch (e) {
      this._picSize = { w: 300, h: 300 }
    }
    return this._picSize
  },

  measurePictionaryCanvas() {
    return new Promise((resolve) => {
      try {
        wx.createSelectorQuery().in(this)
          .select('.pictionary-canvas-element')
          .boundingClientRect((rect) => {
            if (rect && rect.width) {
              this._picSize = { w: rect.width, h: rect.height || rect.width }
            }
            resolve(this.picScale())
          })
          .exec()
      } catch (e) {
        resolve(this.picScale())
      }
    })
  },

  // 绘制一组 strokes
  drawStrokes(strokes) {
    const ctx = this.picCtx()
    const { w, h } = this.picScale()
    strokes.forEach((s) => {
      const pts = s.points || []
      if (pts.length < 2) return
      ctx.beginPath()
      ctx.setStrokeStyle(s.color || '#333333')
      ctx.setLineWidth(s.width || 3)
      ctx.setLineCap('round')
      ctx.setLineJoin('round')
      ctx.moveTo(pts[0][0] / 100 * w, pts[0][1] / 100 * h)
      for (let i = 1; i < pts.length; i++) {
        ctx.lineTo(pts[i][0] / 100 * w, pts[i][1] / 100 * h)
      }
      ctx.stroke()
    })
    ctx.draw()
  },

  // 收到 ai / 对手的绘画数据
  renderRemoteDrawing(drawingData) {
    if (!drawingData) return
    // 兼容两种格式：strokes 结构 或 原始线段数组
    if (drawingData.type === 'strokes' && Array.isArray(drawingData.strokes)) {
      this.measurePictionaryCanvas().then(() => {
        this.drawStrokes(drawingData.strokes)
      })
      return
    }
    if (Array.isArray(drawingData)) {
      this.drawStrokes(drawingData)
    }
  },

  // 触摸开始：记录起点
  onPictionaryTouch(e) {
    if (!this.data.pictionaryIsDrawing) return
    const t = (e.touches && e.touches[0]) || null
    if (!t) return
    this._picLast = { x: t.x, y: t.y }
  },

  // 触摸移动：画线并广播
  onPictionaryMove(e) {
    if (!this.data.pictionaryIsDrawing) return
    const t = (e.touches && e.touches[0]) || null
    if (!t || !this._picLast) return
    const ctx = this.picCtx()
    ctx.beginPath()
    ctx.setStrokeStyle('#333333')
    ctx.setLineWidth(3)
    ctx.setLineCap('round')
    ctx.moveTo(this._picLast.x, this._picLast.y)
    ctx.lineTo(t.x, t.y)
    ctx.stroke()
    ctx.draw(true)
    // 广播这一段（像素坐标，接收端按同尺寸绘制）
    const seg = {
      type: 'segment',
      from: this._picLast,
      to: { x: t.x, y: t.y },
      color: '#333333',
      width: 3
    }
    this.safeSend('42' + JSON.stringify(['game-draw', { gameId: this.data.gameId, drawingData: seg }]))
    this._picLast = { x: t.x, y: t.y }
  },

  clearPictionary() {
    const ctx = this.picCtx()
    const { w, h } = this.picScale()
    ctx.clearRect(0, 0, w, h)
    ctx.draw()
    this.safeSend('42' + JSON.stringify(['game-clear-canvas', { gameId: this.data.gameId }]))
  },

  submitPictionary() {
    this.safeSend('42' + JSON.stringify(['game-finish-drawing', { gameId: this.data.gameId }]))
    wx.showToast({ title: '已提交，等待下一轮', icon: 'none' })
  },


  initTyping() {
    this.setData({
      typingText: '',
      typingInput: '',
      typingScore: 0,
      typingOpponentScore: 0,
      typingTimeLeft: 30,
      typingStarted: false,
      typingResult: ''
    })
  },

  connectSocket() {
    if (app.globalData.socket && app.globalData.socket.readyState === 1) {
      console.log('复用聊天页面的socket连接')
      this.socket = app.globalData.socket
      this.socketCreated = false
      this.bindGameMessageHandlers()
    } else {
      console.log('创建新的socket连接')
      const serverUrl = "wss://liaotianshi.onrender.com"
      const socketUrl = serverUrl + "/socket.io/?EIO=4&transport=websocket"
      console.log("游戏页面socket连接地址:", socketUrl)
      
      this.socket = wx.connectSocket({
        url: socketUrl,
        header: {
          "Content-Type": "application/json"
        },
        protocols: ["socket.io"]
      })
      this.socketCreated = true
      
      this.setupSocketTimeout()
      
      this.socket.onOpen(() => {
        console.log('socket连接成功')
        this.clearSocketTimeout()
        // 新建连接必须完成 socket.io 握手后再 join，否则服务端不认识这个 socket，
        // 后续 guess-number-guess / game-move 等都会被静默丢弃。
        // 握手由 onMessage 收到 '0{...}' 后回复 '40' 完成，join 在收到 '40' 后发出。
      })
      
      this.socket.onError((err) => {
        console.error('socket连接错误:', err)
        this.clearSocketTimeout()
        if (this.socketCreated) {
          wx.showToast({ title: '连接失败', icon: 'none' })
          setTimeout(() => {
            if (this.socketCreated) {
              this.tryReconnect()
            }
          }, 3000)
        }
      })
      
      this.socket.onClose((res) => {
        console.log("Socket已关闭:", res)
        this.clearSocketTimeout()
        if (res.code !== 1000 && this.socketCreated) {
          this.tryReconnect()
        }
      })
      
      this.bindGameMessageHandlers()
    }
  },
  
  setupSocketTimeout() {
    if (this.socketTimeoutTimer) {
      clearTimeout(this.socketTimeoutTimer)
    }
    this.socketTimeoutTimer = setTimeout(() => {
      console.log('游戏页面socket连接超时')
      if (this.socketCreated && (!this.socket || this.socket.readyState !== 1)) {
        wx.showModal({
          title: '连接超时',
          content: '连接服务器超时，请检查网络后重试',
          showCancel: false,
          confirmText: '重试',
          success: () => {
            if (this.socketCreated) {
              this.tryReconnect()
            }
          }
        })
      }
    }, 10000)
  },
  
  clearSocketTimeout() {
    if (this.socketTimeoutTimer) {
      clearTimeout(this.socketTimeoutTimer)
      this.socketTimeoutTimer = null
    }
  },
  
  bindGameMessageHandlers() {
    if (!this.messageHandlerBound) {
      this.messageHandlerBound = true
      this.socket.onMessage((res) => {
        const data = res.data

        // ===== socket.io 协议握手（仅新建的连接需要）=====
        // '0{...}' 是 Engine.IO 握手包，必须回 '40' 才算建立命名空间；
        // 收到 '40' 后再发 join，服务端才会把这条 socket 记入 users。
        if (this.socketCreated) {
          if (data.startsWith('0')) {
            console.log('[Game] 收到握手包，回复 40')
            try { this.socket.send({ data: '40' }) } catch (e) { console.error(e) }
            return
          }
          if (data === '40' || data.startsWith('40{')) {
            console.log('[Game] 命名空间已连接，发送 join')
            this.sendGameJoin()
            return
          }
          if (data === '2') {
            try { this.socket.send({ data: '3' }) } catch (e) {}
            return
          }
        }
        if (data.startsWith('42')) {
          try {
            const arr = JSON.parse(data.substring(2))
            const event = arr[0]
            const msg = arr[1]
            
            if (event === 'game-update') {
              this.handleGameUpdate(msg)
            } else if (event === 'game-end') {
              this.handleGameEnd(msg)
            } else if (event === 'rps-update') {
              this.handleRPSResult(msg)
            } else if (event === 'guess-number-update') {
              this.handleGuessResult(msg)
            } else if (event === 'bomb-update') {
              this.handleBombResult(msg)
            } else if (event === 'game-draw') {
              // 对方（含 ai）的绘画数据
              if (msg && msg.drawingData) this.renderRemoteDrawing(msg.drawingData)
            } else if (event === 'game-clear-canvas') {
              const c = this.picCtx()
              const sz = this.picScale()
              c.clearRect(0, 0, sz.w, sz.h)
              c.draw()
            } else if (event === 'pictionary-hint') {
              if (msg && msg.hint) {
                wx.showToast({ title: msg.hint, icon: 'none', duration: 3000 })
              }
            }
          } catch (e) {
            console.error('解析游戏消息失败:', e)
          }
        }
      })
    }
  },

  goBack() {
    wx.navigateBack()
  },
  
  reconnect() {
    if (this.reconnecting) return
    
    this.reconnecting = true
    console.log('尝试重新连接...')
    
    setTimeout(() => {
      this.socket = null
      this.connectSocket()
      this.reconnecting = false
    }, 3000)
  },
  
  tryReconnect() {
    if (this.reconnecting) return
    
    this.reconnecting = true
    console.log('尝试自动重连...')
    
    const maxAttempts = 5
    let attempts = 0
    
    const attemptReconnect = () => {
      if (attempts >= maxAttempts) {
        console.log('已达到最大重连次数')
        this.reconnecting = false
        wx.showToast({ title: '连接失败', icon: 'none' })
        return
      }
      
      attempts++
      console.log(`重连尝试 ${attempts}/${maxAttempts}`)
      
      if (app.globalData.socket && app.globalData.socket.readyState === 1) {
        console.log('发现聊天页面有活跃连接，复用它')
        this.socket = app.globalData.socket
        this.socketCreated = false
        this.reconnecting = false
        this.sendPendingMessages()
        return
      }
      
      this.socket = null
      this.connectSocket()
      
      setTimeout(() => {
        if (this.socket && this.socket.readyState === 1) {
          console.log('重连成功')
          this.reconnecting = false
          this.sendPendingMessages()
        } else {
          attemptReconnect()
        }
      }, 3000)
    }
    
    attemptReconnect()
  },
  
  safeSend(data) {
    if (!this.socket) {
      console.log('socket未初始化，消息已缓存，尝试重连')
      if (!this.pendingMessages) {
        this.pendingMessages = []
      }
      this.pendingMessages.push(data)
      this.tryReconnect()
      return
    }
    
    try {
      const readyState = this.socket.readyState
      if (readyState === 1) {
        this.socket.send({ data: data })
      } else {
        console.log('socket未连接，消息已缓存，尝试重连')
        if (!this.pendingMessages) {
          this.pendingMessages = []
        }
        this.pendingMessages.push(data)
        this.tryReconnect()
      }
    } catch (e) {
      console.error('发送消息失败:', e)
      if (!this.pendingMessages) {
        this.pendingMessages = []
      }
      this.pendingMessages.push(data)
      this.tryReconnect()
    }
  },
  
  // 新建连接握手完成后调用：以当前用户身份入房，让服务端把这条 socket 记入 users。
  // 游戏页是独立连接，必须自己 join，否则后续游戏事件都会被服务端当成未登录而丢弃。
  sendGameJoin() {
    const username = this.data.myName ||
      (app.globalData && app.globalData.username) || ''
    const roomName = (app.globalData && app.globalData.roomName) || 'main'
    if (!username) {
      console.warn('[Game] 缺少用户名，跳过 join')
      return
    }
    const joinPayload = JSON.stringify({
      username: username,
      roomName: roomName,
      getHistory: false
    })
    try {
      this.socket.send({ data: '42["join",' + joinPayload + ']' })
      console.log('[Game] 已发送 join:', username, '@', roomName)
    } catch (e) {
      console.error('[Game] 发送 join 失败:', e)
    }
    // join 之后再把缓存消息发出去
    setTimeout(() => this.sendPendingMessages(), 300)
    // 启动心跳，避免长时间不出招被服务端 pingTimeout 断开
    this.startGameHeartbeat()
  },

  startGameHeartbeat() {
    this.stopGameHeartbeat()
    this._heartbeat = setInterval(() => {
      if (this.socket && this.socket.readyState === 1) {
        try { this.socket.send({ data: '2' }) } catch (e) {}
      }
    }, 25000)
  },

  stopGameHeartbeat() {
    if (this._heartbeat) {
      clearInterval(this._heartbeat)
      this._heartbeat = null
    }
  },

  sendPendingMessages() {
    if (!this.pendingMessages || this.pendingMessages.length === 0) return
    // 未就绪时直接返回，保留队列等下次 onOpen 再发，
    // 否则会抛 SocketTask.send:fail SocketTask.readyState is not OPEN
    if (!this.socket || this.socket.readyState !== 1) {
      console.log('连接未就绪，暂不发送缓存消息:', this.pendingMessages.length)
      return
    }
    console.log('发送缓存的消息:', this.pendingMessages.length)
    const messages = [...this.pendingMessages]
    this.pendingMessages = []
    messages.forEach(msg => {
      try {
        if (this.socket && this.socket.readyState === 1) {
          this.socket.send({ data: msg })
        } else {
          // 中途断开，放回队列
          this.pendingMessages.push(msg)
        }
      } catch (e) {
        console.error('发送缓存消息失败:', e)
        this.pendingMessages.push(msg)
      }
    })
  },

  isStarPoint(x, y) {
    const starPoints = [3, 7, 11]
    return starPoints.includes(x) && starPoints.includes(y)
  },

  onBoardTouch(e) {
    if (!this.data.isMyTurn || !this.data.gameStarted) {
      wx.showToast({ title: '不是你的回合', icon: 'none' })
      return
    }

    const touch = e.touches[0]
    
    const query = wx.createSelectorQuery()
    query.select('.gomoku-board').boundingClientRect((boardRect) => {
      query.selectAll('.cell').boundingClientRect((rects) => {
        if (!rects || rects.length === 0 || !boardRect) {
          console.log('无法获取棋盘或单元格信息')
          return
        }
        
        const cellWidth = (rects[0] && rects[0].width) || 40
        const cellHeight = (rects[0] && rects[0].height) || 40
        const boardLeft = boardRect.left || 0
        const boardTop = boardRect.top || 0
        
        const x = Math.floor((touch.clientX - boardLeft) / cellWidth)
        const y = Math.floor((touch.clientY - boardTop) / cellHeight)
        
        console.log('触摸位置:', touch.clientX, touch.clientY, '棋盘位置:', boardLeft, boardTop, '计算坐标:', x, y)
        
        this.makeMove(x, y)
      }).exec()
    }).exec()
  },

  makeMove(x, y) {
    if (x < 0 || x >= BOARD_SIZE || y < 0 || y >= BOARD_SIZE) {
      return
    }
    
    if (this.data.board[x][y]) {
      wx.showToast({ title: '此位置已有棋子', icon: 'none' })
      return
    }

    const newBoard = [...this.data.board]
    newBoard[y] = [...newBoard[y]]
    newBoard[y][x] = this.data.currentPlayerId
    
    this.setData({
      board: newBoard,
      isMyTurn: false
    })

    this.sendMove(x, y)
  },

  sendMove(x, y) {
    if (!this.socket) return
    
    const data = JSON.stringify({
      gameId: this.data.gameId,
      x,
      y
    })
    
    this.safeSend('42["game-move",' + data + ']')
  },

  handleGameUpdate(data) {
    console.log('收到游戏更新:', data)
    
    if (data.gameId !== this.data.gameId) return
    
    if (data.board) {
      this.setData({
        board: data.board
      })
    }
    
    if (data.currentPlayer !== undefined) {
      const players = data.players || this.data.players
      const currentPlayer = players.find(p => p.socketId === data.currentPlayer)
      const isMyTurn = !!(currentPlayer && currentPlayer.username === this.data.myName)
      
      this.setData({
        currentPlayer: data.currentPlayer,
        isMyTurn: isMyTurn,
        players: data.players || this.data.players
      })
    }
    
    if (data.status) {
      this.setData({ gameStatus: data.status })
    }

    // 你画我猜：同步题目、猜词记录与比分
    if (data.gameType === 'pictionary') {
      const patch = {}
      if (data.currentDrawer !== undefined) {
        patch.currentDrawer = data.currentDrawer
        // 判断自己是不是画者：通过 players 里的 socketId 反查自己的名字
        const drawerPlayer = (data.players || this.data.players || []).find(function (p) {
          return p.socketId === data.currentDrawer
        })
        const iAmDrawer = !!drawerPlayer && drawerPlayer.username === this.data.myName
        patch.pictionaryIsDrawing = iAmDrawer
        // 画者拿得到答案（currentWord），猜的人只拿到字数提示
        if (iAmDrawer) {
          patch.pictionaryWord = data.currentWord || ''
          patch.pictionaryIsDrawer = true
        } else {
          patch.pictionaryWord = ''
          patch.pictionaryIsDrawer = false
        }
      }
      if (data.currentWord !== undefined && data.currentDrawer === undefined) {
        patch.pictionaryWord = data.currentWord || ''
      }
      if (Array.isArray(data.guesses)) {
        patch.pictionaryGuesses = data.guesses.map(function (g) {
          return { player: g.username || '玩家', text: g.guess || '' }
        })
      }
      if (data.roundAdvanced) {
        patch.pictionaryWord = data.currentWord || ''
        patch.pictionaryGuesses = []
        const c = this.picCtx()
        const sz = this.picScale()
        c.clearRect(0, 0, sz.w, sz.h)
        c.draw()
      }
      if (Object.keys(patch).length) this.setData(patch)
    }
    
    if (data.winner) {
      const players = data.players || this.data.players
      const winnerPlayer = players.find(p => p.socketId === data.winner)
      const winnerName = (winnerPlayer && winnerPlayer.username) || '未知'
      const displayName = winnerName === this.data.myName ? '你' : winnerName
      
      wx.showModal({
        title: '🏆 游戏结束',
        content: `${displayName} 获胜！`,
        showCancel: false,
        success: () => {
          wx.navigateBack()
        }
      })
    }
  },

  handleGameEnd(data) {
    console.log('游戏结束:', data)
    
    if (data.gameId !== this.data.gameId) return
    
    const players = data.players || this.data.players
    const winnerPlayer = players.find(p => p.socketId === data.winner)
    const winnerName = (winnerPlayer && winnerPlayer.username) || data.winner || '未知'
    const displayName = winnerName === this.data.myName ? '你' : winnerName
    
    wx.showModal({
      title: '🏆 游戏结束',
      content: `${displayName} 获胜！`,
      showCancel: false,
      success: () => {
        wx.navigateBack()
      }
    })
  },

  playRPS(e) {
    if (!this.socket) {
      wx.showToast({ title: '连接未建立', icon: 'none' })
      return
    }
    
    if (!this.data.isMyTurn) {
      wx.showToast({ title: '等待对手', icon: 'none' })
      return
    }
    
    const choice = e.currentTarget.dataset.choice
    const choiceIcons = {
      rock: '✊',
      paper: '🖐️',
      scissors: '✌️'
    }
    
    this.setData({
      myChoice: choice,
      myChoiceIcon: choiceIcons[choice]
    })

    const data = JSON.stringify({
      gameId: this.data.gameId,
      choice: choice
    })
    
    this.safeSend('42["rps-move",' + data + ']')
    
    // AI自动回应：如果对手是AI，延迟1秒后随机出招
    Q6:    if (this.data.opponentName === 'ai') {
        setTimeout(() => {
            const choices = ['rock', 'paper', 'scissors']
            const aiChoice = choices[Math.floor(Math.random() * 3)]
            const aiData = JSON.stringify({
                gameId: this.data.gameId,
                choice: aiChoice
            })
            console.log('AI自动出招:', aiChoice)
            this.safeSend('42["rps-move",' + aiData + ']')
        }, 1000)
    }
    this.setData({ isMyTurn: false })
  },

  handleRPSResult(data) {
    console.log('RPS结果:', data)
    
    const choiceIcons = {
      rock: '✊',
      paper: '🖐️',
      scissors: '✌️'
    }
    
    const myUsername = this.data.myName
    const myChoice = data.roundResult && data.roundResult.choices
      ? data.roundResult.choices[myUsername]
      : undefined
    const opponentChoice = Object.keys((data.roundResult && data.roundResult.choices) || {})
      .find(k => k !== myUsername)
      ? data.roundResult.choices[Object.keys(data.roundResult.choices).find(k => k !== myUsername)]
      : null
    
    this.setData({
      opponentChoice: opponentChoice,
      opponentChoiceIcon: choiceIcons[opponentChoice]
    })
    
    let result = '平局'
    if (data.roundResult && data.roundResult.winner === myUsername) {
      result = '🎉 你赢了！'
    } else if (data.roundResult && data.roundResult.winner && data.roundResult.winner !== myUsername) {
      result = '😢 你输了'
    }
    
    this.setData({ rpsResult: result })
    
    if (data.status === 'finished') {
      setTimeout(() => {
        wx.showModal({
          title: '🏆 游戏结束',
          content: data.champion === myUsername ? '恭喜你获胜！' : `${data.champion} 获胜！`,
          showCancel: false,
          success: () => {
            wx.navigateBack()
          }
        })
      }, 2000)
    } else {
      setTimeout(() => {
        this.setData({
          rpsResult: '',
          myChoice: '',
          opponentChoice: '',
          isMyTurn: true
        })
      }, 3000)
    }
  },

  onGuessInput(e) {
    this.setData({ guessInput: e.detail.value })
  },

  submitGuess() {
    if (!this.socket) {
      wx.showToast({ title: '连接未建立', icon: 'none' })
      return
    }

    // 关键：未连上时不发虚假请求，否则本地会显示「等待结果」但服务端收不到
    if (this.socket.readyState !== 1) {
      wx.showToast({ title: '连接未就绪，请稍候', icon: 'none' })
      return
    }

    const num = parseInt(this.data.guessInput)
    
    if (isNaN(num) || num < this.data.guessMin || num > this.data.guessMax) {
      wx.showToast({ title: '请输入有效数字', icon: 'none' })
      return
    }

    const data = JSON.stringify({
      gameId: this.data.gameId,
      guess: num
    })
    
    this.safeSend('42["guess-number-guess",' + data + ']')
    
    // 本地立即显示猜测记录，避免用户猜测后没反应
    const myUsername = this.data.myName
    const historyItem = {
      num: num,
      result: '等待结果...',
      isMine: true,
      playerName: myUsername || '你'
    }
    const newHistory = [...this.data.guessHistory, historyItem]
    this.setData({
      guessHistory: newHistory,
      guessHint: `你猜了 ${num}，等待结果...`
    })
    this.setData({ guessInput: '' })
  },

  handleGuessResult(data) {
    console.log('猜数字结果:', data)
    
    const resultText = {
      low: '太低了！',
      high: '太高了！',
      correct: '🎉 猜对了！'
    }
    
    const myUsername = this.data.myName
    const isMine = data.player === myUsername
    
    const resultStr = resultText[data.result] || data.result || '未知结果'
    
    // 检查本地是否已有待处理的记录，避免重复添加
    const existingIndex = this.data.guessHistory.findIndex(
      h => h.num === data.guess && h.result === '等待结果...'
    )
    
    let newHistory
    if (existingIndex >= 0) {
      newHistory = [...this.data.guessHistory]
      newHistory[existingIndex] = {
        ...newHistory[existingIndex],
        result: resultStr,
        playerName: data.player || '未知'
      }
    } else {
      newHistory = [...this.data.guessHistory, {
        num: data.guess,
        result: resultStr,
        isMine: data.player === myUsername,
        playerName: data.player || '未知'
      }]
    }
    
    this.setData({
      guessHistory: newHistory,
      guessHint: resultStr
    })
    
    if (data.currentGuesser) {
      const currentPlayer = this.data.players.find(p => p.socketId === data.currentGuesser)
      this.setData({
        isMyTurn: !!(currentPlayer && currentPlayer.username === myUsername)
      })
    }
    
    // 服务端猜数字结束状态是 'ended'（其他游戏用 'finished'），两者都兼容
    if (data.status === 'finished' || data.status === 'ended') {
      const winnerText = data.winnerName === myUsername 
        ? `🎉 恭喜你猜对了！答案是 ${data.targetNumber}` 
        : `🎉 ${data.winnerName} 猜对了！答案是 ${data.targetNumber}`
      wx.showModal({
        title: '🏆 游戏结束',
        content: winnerText,
        showCancel: false,
        success: () => {
          wx.navigateBack()
        }
      })
    }
  },

  onBombInput(e) {
    this.setData({ bombInput: e.detail.value })
  },

  submitBombNumber() {
    if (!this.socket) {
      wx.showToast({ title: '连接未建立', icon: 'none' })
      return
    }
    
    const num = parseInt(this.data.bombInput)
    
    if (isNaN(num) || num < this.data.bombMin || num > this.data.bombMax) {
      wx.showToast({ title: '请输入有效数字', icon: 'none' })
      return
    }

    const data = JSON.stringify({
      gameId: this.data.gameId,
      count: num
    })
    
    this.safeSend('42["bomb-move",' + data + ']')
  },
    

  handleBombResult(data) {
    console.log('炸弹结果:', data)
    
    const myUsername = this.data.myName
    const isMine = !!(data.lastMove && data.lastMove.player === myUsername)
    
    const historyItem = {
      value: data.lastMove ? data.lastMove.count : undefined,
      isBomb: data.lastMove ? data.lastMove.isBomb : undefined,
      isMine: isMine
    }
    
    const newHistory = [...this.data.bombHistory, historyItem]
    
    if (data.status === 'finished') {
      this.setData({
        bombHistory: newHistory,
        isBombGameOver: true,
        gameStatus: '游戏结束'
      })
      
      const winnerText = data.loserName === myUsername ? `${data.loserName} 踩到炸弹了！${this.data.opponentName} 获胜！` : `对手踩到炸弹了！你获胜！`
      wx.showModal({
        title: '💣 游戏结束',
        content: winnerText,
        showCancel: false,
        success: () => {
          wx.navigateBack()
        }
      })
    } else {
      const currentPlayer = this.data.players.find(p => p.socketId === data.currentPlayer)
      this.setData({
        bombHistory: newHistory,
        isMyTurn: !!(currentPlayer && currentPlayer.username === myUsername)
      })
    }
  },
onPictionaryTouch() {
    wx.showToast({ title: '你画我猜功能开发中', icon: 'none' })
  },
onPictionaryMove() {
    // 画布绘制逻辑待服务器事件接入后实现
  },
clearPictionary() {
    wx.showToast({ title: '功能开发中', icon: 'none' })
  },
submitPictionary() {
    wx.showToast({ title: '功能开发中', icon: 'none' })
  },
startTyping() {
    wx.showToast({ title: '打字对战功能开发中', icon: 'none' })
  },
onTypingInput(e) {
    this.setData({ typingInput: e.detail.value })
  },
submitTyping() {
    wx.showToast({ title: '功能开发中', icon: 'none' })
  },
})