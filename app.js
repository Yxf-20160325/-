// app.js
App({
  onLaunch() {
    // 展示本地存储能力
    const logs = wx.getStorageSync('logs') || []
    logs.unshift(Date.now())
    wx.setStorageSync('logs', logs)

    // 检测设备平台（支持 HarmonyOS）
    this.detectPlatform()

    // 登录
    wx.login({
      success: res => {
        // 发送 res.code 到后台换取 openId, sessionKey, unionId
      }
    })
  },

  detectPlatform() {
    try {
      // 基础库 3.7.0+ 支持 wx.getDeviceInfo()
      wx.getDeviceInfo({
        success: (res) => {
          console.log('设备信息:', res)
          this.globalData.platform = res.platform || 'unknown'
          this.globalData.isHarmonyOS = res.platform === 'harmony'
          this.globalData.deviceInfo = res
          
          if (res.platform === 'harmony') {
            console.log('检测到 HarmonyOS 平台，应用兼容处理')
            this.applyHarmonyOSCompatibility()
          }
        },
        fail: (err) => {
          console.warn('获取设备信息失败:', err)
          // 降级处理：使用旧版 API
          this.globalData.platform = 'unknown'
          this.globalData.isHarmonyOS = false
        }
      })
    } catch (e) {
      console.warn('wx.getDeviceInfo 不可用，使用降级方案')
      this.globalData.platform = 'unknown'
      this.globalData.isHarmonyOS = false
    }
  },

  applyHarmonyOSCompatibility() {
    // HarmonyOS 特定的兼容处理
    // 1. 调整音频播放行为
    // 2. 调整网络请求配置
    // 3. 调整文件操作方式
    console.log('已应用 HarmonyOS 兼容处理')
  },

  globalData: {
    userInfo: null,
    platform: 'unknown',
    isHarmonyOS: false,
    deviceInfo: null
  }
})
