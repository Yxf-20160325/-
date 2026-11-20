// 简化的 HMAC-SHA256 实现
// 用于生成腾讯云 TRTC 的 UserSig

const HEX_CHARS = '0123456789abcdef'

function stringToBytes(str) {
  const bytes = []
  for (let i = 0; i < str.length; i++) {
    bytes.push(str.charCodeAt(i))
  }
  return bytes
}

function bytesToHex(bytes) {
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += HEX_CHARS[bytes[i] >> 4]
    hex += HEX_CHARS[bytes[i] & 0x0f]
  }
  return hex
}

function hexToBytes(hex) {
  const bytes = []
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16))
  }
  return bytes
}

function sha256(data) {
  const bytes = typeof data === 'string' ? stringToBytes(data) : Array.from(data)
  
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]

  const H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]

  function rightRotate(value, shift) {
    return (value >>> shift) | (value << (32 - shift))
  }

  function padMessage(bytes) {
    const bitLength = bytes.length * 8
    bytes.push(0x80)
    
    while ((bytes.length % 64) !== 56) {
      bytes.push(0x00)
    }
    
    for (let i = 7; i >= 0; i--) {
      bytes.push((bitLength >>> (8 * i)) & 0xff)
    }
    
    return bytes
  }

  function processBlock(block, H) {
    const W = new Uint32Array(64)
    
    for (let i = 0; i < 16; i++) {
      W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3]
    }
    
    for (let i = 16; i < 64; i++) {
      const s0 = rightRotate(W[i - 15], 7) ^ rightRotate(W[i - 15], 18) ^ (W[i - 15] >>> 3)
      const s1 = rightRotate(W[i - 2], 17) ^ rightRotate(W[i - 2], 19) ^ (W[i - 2] >>> 10)
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0
    }
    
    let a = H[0], b = H[1], c = H[2], d = H[3]
    let e = H[4], f = H[5], g = H[6], h = H[7]
    
    for (let i = 0; i < 64; i++) {
      const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)
      const ch = (e & f) ^ (~e & g)
      const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0
      const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const temp2 = (S0 + maj) >>> 0
      
      h = g
      g = f
      f = e
      e = (d + temp1) >>> 0
      d = c
      c = b
      b = a
      a = (temp1 + temp2) >>> 0
    }
    
    H[0] = (H[0] + a) >>> 0
    H[1] = (H[1] + b) >>> 0
    H[2] = (H[2] + c) >>> 0
    H[3] = (H[3] + d) >>> 0
    H[4] = (H[4] + e) >>> 0
    H[5] = (H[5] + f) >>> 0
    H[6] = (H[6] + g) >>> 0
    H[7] = (H[7] + h) >>> 0
  }

  const padded = padMessage([...bytes])
  
  for (let i = 0; i < padded.length; i += 64) {
    const block = padded.slice(i, i + 64)
    processBlock(block, H)
  }

  const result = []
  for (let i = 0; i < 8; i++) {
    result.push((H[i] >>> 24) & 0xff)
    result.push((H[i] >>> 16) & 0xff)
    result.push((H[i] >>> 8) & 0xff)
    result.push(H[i] & 0xff)
  }
  
  return result
}

function HmacSHA256(data, key) {
  let keyBytes = typeof key === 'string' ? stringToBytes(key) : Array.from(key)
  const dataBytes = typeof data === 'string' ? stringToBytes(data) : Array.from(data)
  
  const BLOCK_SIZE = 64
  
  if (keyBytes.length > BLOCK_SIZE) {
    keyBytes = Array.from(sha256(keyBytes))
  }
  
  while (keyBytes.length < BLOCK_SIZE) {
    keyBytes.push(0x00)
  }
  
  const oKeyPad = keyBytes.map(b => b ^ 0x5c)
  const iKeyPad = keyBytes.map(b => b ^ 0x36)
  
  const innerInput = iKeyPad.concat(dataBytes)
  const innerHash = sha256(innerInput)
  
  const outerInput = oKeyPad.concat(innerHash)
  const outerHash = sha256(outerInput)
  
  return bytesToHex(outerHash)
}

module.exports = {
  HmacSHA256,
  sha256,
  bytesToHex,
  hexToBytes,
  stringToBytes
}
