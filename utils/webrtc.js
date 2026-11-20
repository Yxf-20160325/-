// 声网 Agora WebRTC 工具类

const AGORA_APP_ID = '530ec3c71575487ab47b9155d1e3de6d'

let pusherContext = null
let playerContexts = {}
let isInCall = false
let currentRoomId = ''
let currentUserId = ''
let currentCallType = 'audio'

function initAgora() {
  pusherContext = wx.createLivePusherContext('local-pusher')
  console.log('声网 Agora 初始化成功, App ID:', AGORA_APP_ID)
  return true
}

function enterRoom(roomId, userId, callType) {
  currentRoomId = roomId
  currentUserId = userId
  currentCallType = callType
  isInCall = true
  console.log('进入房间:', roomId, '用户:', userId, '类型:', callType)
  return { code: 0 }
}

function exitRoom() {
  if (pusherContext) {
    pusherContext.stop()
    pusherContext = null
  }
  Object.values(playerContexts).forEach(function(ctx) {
    ctx.stop()
  })
  playerContexts = {}
  isInCall = false
  currentRoomId = ''
  currentUserId = ''
  console.log('退出房间')
  return { code: 0 }
}

function setMute(muted) {
  if (pusherContext) {
    if (muted) {
      pusherContext.muteAudio()
    } else {
      pusherContext.unmuteAudio()
    }
    console.log('麦克风' + (muted ? '已静音' : '已取消静音'))
  }
}

function setSpeaker(speakerOn) {
  if (pusherContext) {
    if (speakerOn) {
      pusherContext.setAudioRoute(1)
    } else {
      pusherContext.setAudioRoute(0)
    }
    console.log('音频输出:' + (speakerOn ? '扬声器' : '听筒'))
  }
}

function switchCamera() {
  if (pusherContext) {
    pusherContext.switchCamera()
    console.log('切换摄像头')
  }
}

function getCallState() {
  return {
    isInCall: isInCall,
    roomId: currentRoomId,
    userId: currentUserId,
    callType: currentCallType
  }
}

module.exports = {
  AGORA_APP_ID: AGORA_APP_ID,
  initAgora: initAgora,
  enterRoom: enterRoom,
  exitRoom: exitRoom,
  setMute: setMute,
  setSpeaker: setSpeaker,
  switchCamera: switchCamera,
  getCallState: getCallState
}