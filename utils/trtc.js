// 腾讯云 TRTC SDK 工具类
// SDKAppID: 1600140349
// SDK密钥: 6ca613545e431bbbba29f3b9295a0d80f9828d76ad2322a8e3518cbf8691e1170

const SDKAPPID = 1600140349
const SECRETKEY = '6ca613545e431bbbba29f3b9295a0d80f9828d76ad2322a8e3518cbf8691e1170'

class TRTCManager {
  constructor() {
    this.trtc = null
    this.localStream = null
    this.remoteStream = null
    this.isInCall = false
    this.roomId = ''
    this.userId = ''
    this.callType = 'audio' // 'audio' or 'video'
    this.onError = null
    this.onUserEnter = null
    this.onUserLeave = null
    this.onRemoteStream = null
    this.onNetworkQuality = null
  }

  // 初始化 TRTC SDK
  async init() {
    return new Promise((resolve, reject) => {
      // 动态加载 TRTC 模块
      try {
        this.trtc = requirePlugin('TRTC')
        console.log('TRTC SDK 加载成功')
        resolve()
      } catch (e) {
        console.error('TRTC SDK 加载失败:', e)
        reject(new Error('TRTC SDK 加载失败'))
      }
    })
  }

  // 生成 UserSig
  genTestUserSig(userId) {
    const sdkappid = SDKAPPID
    const secretkey = SECRETKEY
    const expireTime = 604800

    let signature = ''
    const sdkAppId = Number(sdkappid)
    const currTime = Math.floor(Date.now() / 1000)
    const expire = currTime + expireTime

    const stringToSign = `TLS.identifier:${userId}\nTLS.sdkappid:${sdkAppId}\nTLS.time:${currTime}\nTLS.expire:${expire}\n`

    const crypto = require('./crypto.js')
    signature = crypto.HmacSHA256(stringToSign, secretkey)
    signature = Buffer.from(signature, 'hex').toString('base64')

    return signature
  }

  // 进入房间
  async enterRoom(roomId, userId, callType = 'audio') {
    return new Promise((resolve, reject) => {
      if (!this.trtc) {
        reject(new Error('TRTC 未初始化'))
        return
      }

      this.roomId = roomId
      this.userId = userId
      this.callType = callType
      this.isInCall = true

      const config = {
        sdkAppId: SDKAPPID,
        userId: userId,
        userSig: this.genTestUserSig(userId),
        roomId: roomId,
        scene: 0 // 0: 通话场景
      }

      this.trtc.enterRoom(config, (result) => {
        if (result.code === 0) {
          console.log('进入房间成功:', roomId)
          this.startLocalStream()
          resolve(result)
        } else {
          console.error('进入房间失败:', result)
          this.isInCall = false
          reject(new Error(result.message))
        }
      })
    })
  }

  // 开始本地流
  startLocalStream() {
    const config = {
      audio: true,
      video: this.callType === 'video'
    }

    this.localStream = this.trtc.createStream(config)
    this.localStream.initialize((err) => {
      if (err) {
        console.error('创建本地流失败:', err)
        return
      }

      console.log('本地流创建成功')
      this.localStream.play('local-video')
      
      this.localStream.publish().then(() => {
        console.log('本地流发布成功')
      }).catch(err => {
        console.error('发布本地流失败:', err)
      })
    })
  }

  // 退出房间
  async exitRoom() {
    return new Promise((resolve) => {
      if (!this.trtc) {
        resolve()
        return
      }

      if (this.localStream) {
        this.localStream.stop()
        this.localStream = null
      }

      if (this.remoteStream) {
        this.remoteStream.stop()
        this.remoteStream = null
      }

      this.trtc.exitRoom((result) => {
        console.log('退出房间:', result)
        this.isInCall = false
        this.roomId = ''
        this.userId = ''
        resolve(result)
      })
    })
  }

  // 静音/取消静音
  setMute(muted) {
    if (this.localStream) {
      this.localStream.muteAudio(muted)
      console.log('麦克风' + (muted ? '已静音' : '已取消静音'))
    }
  }

  // 切换扬声器
  setSpeaker(speakerOn) {
    if (this.trtc) {
      this.trtc.setAudioRoute(speakerOn ? 1 : 0) // 1: 扬声器, 0: 听筒
      console.log('音频输出:' + (speakerOn ? '扬声器' : '听筒'))
    }
  }

  // 设置事件监听器
  on(eventName, callback) {
    switch (eventName) {
      case 'error':
        this.onError = callback
        break
      case 'user-enter':
        this.onUserEnter = callback
        break
      case 'user-leave':
        this.onUserLeave = callback
        break
      case 'remote-stream':
        this.onRemoteStream = callback
        break
      case 'network-quality':
        this.onNetworkQuality = callback
        break
    }
  }

  // 监听远端流
  setupRemoteListener() {
    if (!this.trtc) return

    this.trtc.on('onUserEnter', (event) => {
      console.log('用户进入:', event.userId)
      if (this.onUserEnter) {
        this.onUserEnter(event)
      }
    })

    this.trtc.on('onUserLeave', (event) => {
      console.log('用户离开:', event.userId)
      if (this.onUserLeave) {
        this.onUserLeave(event)
      }
    })

    this.trtc.on('onRemoteStreamReceived', (event) => {
      console.log('收到远端流:', event.userId)
      this.remoteStream = event.stream
      this.remoteStream.play('remote-video')
      
      if (this.onRemoteStream) {
        this.onRemoteStream(event)
      }
    })

    this.trtc.on('onError', (event) => {
      console.error('TRTC 错误:', event)
      if (this.onError) {
        this.onError(event)
      }
    })

    this.trtc.on('onNetworkQuality', (event) => {
      console.log('网络质量:', event)
      if (this.onNetworkQuality) {
        this.onNetworkQuality(event)
      }
    })
  }

  // 获取当前通话状态
  getCallState() {
    return {
      isInCall: this.isInCall,
      roomId: this.roomId,
      userId: this.userId,
      callType: this.callType
    }
  }
}

module.exports = TRTCManager
