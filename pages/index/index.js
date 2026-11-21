// pages/index/index.js
Page({
  data: {
    roomName: "main",
    username: "",
    avatarUrl: "",
    loading: false,
    tapCount: 0,
    showLoginForm: false
  },

  onLoad() {
    var userInfo = wx.getStorageSync("username")
    var avatarUrl = wx.getStorageSync("avatarUrl")
    if (userInfo) {
      this.setData({ username: userInfo })
    }
    if (avatarUrl) {
      this.setData({ avatarUrl: avatarUrl })
    }
  },

  onTapSecret() {
    const newTapCount = this.data.tapCount + 1
    if (newTapCount >= 5) {
      this.setData({
        tapCount: 0,
        showLoginForm: true
      })
      wx.showToast({ title: '已显示更多登录方式', icon: 'success' })
    } else {
      this.setData({ tapCount: newTapCount })
    }
  },

  bindRoomName(e) {
    this.setData({ roomName: e.detail.value })
  },

  bindUsername(e) {
    this.setData({ username: e.detail.value })
  },

  chooseAvatar() {
    wx.chooseImage({
      count: 1,
      sizeType: ['compressed'],
      sourceType: ['album', 'camera'],
      success: (res) => {
        console.log("选择头像成功:", res)
        const tempFilePath = res.tempFilePaths[0]
        this.setData({ avatarUrl: tempFilePath })
        wx.setStorageSync("avatarUrl", tempFilePath)
      },
      fail: (err) => {
        console.error("选择头像失败:", err)
        wx.showToast({ title: "选择头像失败", icon: "none" })
      }
    })
  },

  enterChat() {
    var roomName = this.data.roomName.trim()
    var username = this.data.username.trim()

    if (!roomName) {
      wx.showToast({ title: "请输入房间名称", icon: "none" })
      return
    }

    if (!username) {
      wx.showToast({ title: "请输入昵称", icon: "none" })
      return
    }

    wx.setStorageSync("username", username)
    this.checkRoomPassword(roomName)
  },

  getServerUrl() {
    return "https://liaotianshi.onrender.com"
  },

  checkRoomPassword(roomName) {
    if (roomName.toLowerCase() === 'main') {
      wx.navigateTo({ url: "/pages/chat/chat?room=" + encodeURIComponent(roomName) })
      return
    }
    
    this.showPasswordInput(roomName)
  },

  showPasswordInput(roomName) {
    wx.showModal({
      title: '房间需要密码',
      editable: true,
      placeholderText: '请输入房间密码',
      confirmText: '进入',
      success: (res) => {
        if (res.confirm && res.content) {
          const password = res.content.trim()
          wx.navigateTo({ 
            url: "/pages/chat/chat?room=" + encodeURIComponent(roomName) + "&password=" + encodeURIComponent(password) 
          })
        }
      }
    })
  },

  wechatLogin() {
    var roomName = this.data.roomName.trim()
    var username = this.data.username.trim()
    
    if (!roomName) {
      wx.showToast({ title: "请先输入房间名称", icon: "none" })
      return
    }

    if (!username) {
      wx.showToast({ title: "请先输入您的昵称", icon: "none" })
      return
    }

    this.checkRoomPasswordForWechat(roomName)
  },

  checkRoomPasswordForWechat(roomName) {
    if (roomName.toLowerCase() === 'main') {
      this.startWechatLogin(roomName, null)
      return
    }
    
    wx.showModal({
      title: '房间需要密码',
      editable: true,
      placeholderText: '请输入房间密码',
      confirmText: '登录',
      success: (modalRes) => {
        if (modalRes.confirm && modalRes.content) {
          this.startWechatLogin(roomName, modalRes.content.trim())
        }
      }
    })
  },

  startWechatLogin(roomName, password) {
    this.setData({ loading: true })
    wx.showLoading({ title: '登录中...' })

    wx.getUserProfile({
      desc: '用于完善会员资料',
      success: (userRes) => {
        console.log('获取用户信息成功:', userRes)
        const userInfo = userRes.userInfo
        wx.setStorageSync("avatarUrl", userInfo.avatarUrl)
        wx.setStorageSync("username", this.data.username.trim())
        this.setData({ avatarUrl: userInfo.avatarUrl })
        
        userInfo.nickName = this.data.username.trim()
        this.doLogin(roomName, userInfo, password)
      },
      fail: (err) => {
        console.error('获取用户信息失败:', err)
        wx.hideLoading()
        this.setData({ loading: false })
        
        if (err.errMsg && err.errMsg.indexOf("auth deny") !== -1) {
          wx.showToast({ title: "请授权登录", icon: "none" })
        } else {
          wx.showToast({ title: "获取信息失败", icon: "none" })
        }
      }
    })
  },

  doLogin(roomName, userInfo, password = null) {
    wx.login({
      success: (res) => {
        if (res.code) {
          console.log('微信登录成功，code:', res.code)
          this.requestWechatLogin(res.code, roomName, userInfo, password)
        } else {
          console.error('微信登录失败:', res.errMsg)
          wx.hideLoading()
          this.setData({ loading: false })
          wx.showToast({ title: "登录失败: " + res.errMsg, icon: "none" })
        }
      },
      fail: (err) => {
        console.error('微信登录调用失败:', err)
        wx.hideLoading()
        this.setData({ loading: false })
        wx.showToast({ title: "无法调用微信登录", icon: "none" })
      }
    })
  },

  requestWechatLogin(code, roomName, userInfo = null, password = null) {
    wx.request({
      url: this.getServerUrl() + '/api/csrf-token',
      method: 'GET',
      success: (csrfRes) => {
        console.log('CSRF token获取成功:', csrfRes)
        const csrfToken = csrfRes.data && csrfRes.data.csrfToken
        
        wx.request({
          url: this.getServerUrl() + '/api/wechat/login',
          method: 'POST',
          header: {
            'X-CSRF-Token': csrfToken || ''
          },
          data: {
            code: code,
            roomName: roomName,
            password: password,
            nickName: (userInfo && userInfo.nickName) || '',
            avatarUrl: (userInfo && userInfo.avatarUrl) || this.data.avatarUrl || ''
          },
          success: (res) => {
            console.log('微信登录API响应:', res)
            wx.hideLoading()
            this.setData({ loading: false })

            if (res.data && res.data.success) {
              const username = res.data.username || ((userInfo && userInfo.nickName) || '用户' + Math.floor(Math.random() * 1000))
              wx.setStorageSync("username", username)
              wx.setStorageSync("wechatOpenid", res.data.wechatData && res.data.wechatData.openid)
              if (userInfo && userInfo.avatarUrl) {
                wx.setStorageSync("avatarUrl", userInfo.avatarUrl)
              }
              
              setTimeout(() => {
                wx.showToast({ 
                  title: `欢迎, ${username}`, 
                  icon: "success",
                  duration: 1500 
                })
                
                setTimeout(() => {
                  const url = password 
                    ? "/pages/chat/chat?room=" + encodeURIComponent(roomName) + "&password=" + encodeURIComponent(password)
                    : "/pages/chat/chat?room=" + encodeURIComponent(roomName)
                  wx.navigateTo({ url: url })
                }, 1500)
              }, 500)
            } else {
              console.error('登录失败:', (res.data && res.data.error) || '未知错误')
              wx.showToast({ 
                title: (res.data && res.data.error) || "登录失败", 
                icon: "none" 
              })
            }
          },
          fail: (err) => {
            console.error('登录请求失败:', err)
            wx.hideLoading()
            this.setData({ loading: false })
            wx.showToast({ title: "网络请求失败", icon: "none" })
          }
        })
      },
      fail: (csrfErr) => {
        console.error('CSRF token获取失败:', csrfErr)
        wx.hideLoading()
        this.setData({ loading: false })
        wx.showModal({
          title: '提示',
          content: 'CSRF 获取失败：' + (csrfErr.errMsg || '未知错误') + '\n\n是否重试？',
          showCancel: true,
          cancelText: '取消',
          confirmText: '重试',
          success: (modalRes) => {
            if (modalRes.confirm) {
              // code 是一次性的，重试必须重新 wx.login 拿新 code
              console.log('[登录] 用户选择重试，重新登录')
              this.doLogin(roomName, userInfo, password)
            }
          }
        })
      }
    })
  },

  requestSubscribeMessage() {
    const templateIds = ['wp9n3Cjz_cDMTj5uPXzJ600IvIJjBs5mxjJRgxQtjYA'];
    
    wx.requestSubscribeMessage({
      tmplIds: templateIds,
      success: (res) => {
        console.log('订阅消息请求成功:', res);
        for (const templateId in res) {
          if (res[templateId] === 'accept') {
            console.log('用户同意订阅:', templateId);
            wx.setStorageSync('subscribeAccepted', true);
          } else {
            console.log('用户拒绝订阅:', templateId);
            wx.setStorageSync('subscribeAccepted', false);
          }
        }
      },
      fail: (err) => {
        console.error('订阅消息请求失败:', err);
      },
      complete: () => {
        console.log('订阅消息请求完成');
      }
    });
  }
})
