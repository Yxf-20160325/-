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

    const myUsername = gameData.currentUsername || (app.globalData.user?.username || '玩家')
    
    let myName = myUsername
    let opponentName = '对手'
    let currentPlayerId = ''
    let isMyTurn = false

    if (gameData.players && gameData.players.length >= 2) {
      const myPlayer = gameData.players.find(p => p.username === myUsername)
      const opponentPlayer = gameData.players.find(p => p.username !== myUsername)
      
      myName = myPlayer?.username || myName
      opponentName = opponentPlayer?.username || opponentName
      currentPlayerId = gameData.currentPlayer || ''
      
      const currentPlayer = gameData.players.find(p => p.socketId === currentPlayerId)
      isMyTurn = currentPlayer?.username === myUsername
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
        if (this.data.gameId) {
          this.safeSend('42["join-room",{"roomName":"' + this.data.gameId + '"}]')
        }
        this.sendPendingMessages()
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
  
  sendPendingMessages() {
    if (this.pendingMessages && this.pendingMessages.length > 0) {
      console.log('发送缓存的消息:', this.pendingMessages.length)
      const messages = [...this.pendingMessages]
      this.pendingMessages = []
      messages.forEach(msg => {
        try {
          this.socket.send({ data: msg })
        } catch (e) {
          console.error('发送缓存消息失败:', e)
        }
      })
    }
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
        
        const cellWidth = rects[0]?.width || 40
        const cellHeight = rects[0]?.height || 40
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
      const isMyTurn = currentPlayer?.username === this.data.myName
      
      this.setData({
        currentPlayer: data.currentPlayer,
        isMyTurn: isMyTurn,
        players: data.players || this.data.players
      })
    }
    
    if (data.status) {
      this.setData({ gameStatus: data.status })
    }
    
    if (data.winner) {
      const players = data.players || this.data.players
      const winnerPlayer = players.find(p => p.socketId === data.winner)
      const winnerName = winnerPlayer?.username || '未知'
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
    const winnerName = winnerPlayer?.username || data.winner || '未知'
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
    const myChoice = data.roundResult?.choices?.[myUsername]
    const opponentChoice = Object.keys(data.roundResult?.choices || {}).find(k => k !== myUsername)
      ? data.roundResult.choices[Object.keys(data.roundResult.choices).find(k => k !== myUsername)]
      : null
    
    this.setData({
      opponentChoice: opponentChoice,
      opponentChoiceIcon: choiceIcons[opponentChoice]
    })
    
    let result = '平局'
    if (data.roundResult?.winner === myUsername) {
      result = '🎉 你赢了！'
    } else if (data.roundResult?.winner && data.roundResult.winner !== myUsername) {
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
        isMyTurn: currentPlayer?.username === myUsername
      })
    }
    
    if (data.status === 'finished') {
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
    const isMine = data.lastMove?.player === myUsername
    
    const historyItem = {
      value: data.lastMove?.count,
      isBomb: data.lastMove?.isBomb,
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
        isMyTurn: currentPlayer?.username === myUsername
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