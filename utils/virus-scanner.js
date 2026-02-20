const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

class VirusTotalScanner {
    constructor() {
        // VirusTotal API密钥
        this.apiKey = '45b77ae8017a838b254cb2ef8203e4683299dabbc7c028858c42d6c1e1637d8a';
        this.baseUrl = 'https://www.virustotal.com/api/v3';
        this.initialized = true;
        this.requestQueue = [];
        this.isProcessingQueue = false;
        
        console.log('VirusTotal病毒扫描器已初始化');
    }

    // 上传文件并扫描
    async scanFile(filePath) {
        try {
            if (!fs.existsSync(filePath)) {
                throw new Error('文件不存在');
            }
            
            console.log('开始VirusTotal扫描:', path.basename(filePath));
            const scanResult = await this.scanBuffer(fs.readFileSync(filePath), path.basename(filePath));
            return scanResult;
        } catch (error) {
            console.error('扫描失败:', error.message);
            return {
                safe: false,
                scanned: false,
                error: error.message,
                message: 'VirusTotal扫描失败，请等待1分钟后重试'
            };
        }
    }

    // 扫描缓冲区
    async scanBuffer(buffer, filename) {
        try {
            console.log('开始VirusTotal扫描:', filename);
            
            // 创建临时文件
            const tempDir = path.join(__dirname, '../temp');
            if (!fs.existsSync(tempDir)) {
                fs.mkdirSync(tempDir, { recursive: true });
            }
            
            const tempFilePath = path.join(tempDir, filename || `temp-${Date.now()}`);
            fs.writeFileSync(tempFilePath, buffer);
            
            try {
                // 上传文件到VirusTotal
                const fileId = await this.uploadFile(tempFilePath);
                
                // 查询扫描结果
                const scanResult = await this.getScanResult(fileId);
                
                console.log('VirusTotal扫描完成:', filename, '结果:', scanResult.safe ? '安全' : '危险');
                return scanResult;
            } finally {
                // 清理临时文件
                if (fs.existsSync(tempFilePath)) {
                    fs.unlinkSync(tempFilePath);
                }
            }
        } catch (error) {
            console.error('VirusTotal扫描失败:', error.message);
            return {
                safe: false,
                scanned: false,
                error: error.message,
                message: 'VirusTotal扫描失败，请等待1分钟后重试'
            };
        }
    }

    // 上传文件到VirusTotal
    async uploadFile(filePath) {
        return new Promise(async (resolve, reject) => {
            // 添加到请求队列（处理速率限制）
            this.requestQueue.push({
                type: 'upload',
                filePath: filePath,
                resolve,
                reject
            });
            
            if (!this.isProcessingQueue) {
                this.processQueue();
            }
        });
    }

    // 查询扫描结果
    async getScanResult(fileId) {
        return new Promise(async (resolve, reject) => {
            // 添加到请求队列（处理速率限制）
            this.requestQueue.push({
                type: 'result',
                fileId: fileId,
                resolve,
                reject
            });
            
            if (!this.isProcessingQueue) {
                this.processQueue();
            }
        });
    }

    // 处理请求队列
    async processQueue() {
        if (this.isProcessingQueue || this.requestQueue.length === 0) {
            return;
        }
        
        this.isProcessingQueue = true;
        
        while (this.requestQueue.length > 0) {
            const request = this.requestQueue.shift();
            
            try {
                if (request.type === 'upload') {
                    const fileId = await this.performUpload(request.filePath);
                    request.resolve(fileId);
                } else if (request.type === 'result') {
                    const result = await this.performGetResult(request.fileId);
                    request.resolve(result);
                }
            } catch (error) {
                request.reject(error);
            }
            
            // 等待15秒，确保不超过速率限制（每分钟4次请求）
            await new Promise(resolve => setTimeout(resolve, 15000));
        }
        
        this.isProcessingQueue = false;
    }

    // 执行文件上传
    async performUpload(filePath) {
        let retries = 3;
        let delay = 3000;
        
        while (retries > 0) {
            try {
                const formData = new FormData();
                formData.append('file', fs.createReadStream(filePath));
                
                const response = await axios.post(`${this.baseUrl}/files`, formData, {
                    headers: {
                        ...formData.getHeaders(),
                        'x-apikey': this.apiKey
                    },
                    maxContentLength: Infinity,
                    timeout: 60000
                });
                
                return response.data.data.id;
            } catch (error) {
                if (error.code === 'read ECONNRESET') {
                    console.warn('网络连接重置，重试上传:', retries - 1, '次');
                    retries--;
                    if (retries > 0) {
                        await new Promise(resolve => setTimeout(resolve, delay));
                        delay += 2000;
                        continue;
                    }
                }
                
                if (error.response) {
                    console.error('VirusTotal上传失败:', error.response.status, error.response.data);
                    throw new Error(`上传失败: ${error.response.status}`);
                }
                throw error;
            }
        }
    }

    // 执行获取扫描结果
    async performGetResult(fileId) {
        let retries = 5;
        let delay = 3000;
        
        while (retries > 0) {
            try {
                const response = await axios.get(`${this.baseUrl}/analyses/${fileId}`, {
                    headers: {
                        'x-apikey': this.apiKey
                    },
                    timeout: 30000
                });
                
                const status = response.data.data.attributes.status;
                
                if (status === 'completed') {
                    const stats = response.data.data.attributes.stats;
                    const malicious = stats.malicious > 0;
                    
                    return {
                        safe: !malicious,
                        scanned: true,
                        stats: stats,
                        message: malicious ? '文件被检测到病毒' : '文件安全',
                        api: 'VirusTotal'
                    };
                } else if (status === 'failed') {
                    throw new Error('扫描失败');
                }
                
                // 扫描中，等待后重试
                await new Promise(resolve => setTimeout(resolve, delay));
                retries--;
                delay += 2000;
            } catch (error) {
                if (error.code === 'ECONNRESET') {
                    console.warn('网络连接重置，重试获取结果:', retries - 1, '次');
                    retries--;
                    if (retries > 0) {
                        await new Promise(resolve => setTimeout(resolve, delay));
                        delay += 2000;
                        continue;
                    }
                }
                
                if (error.response) {
                    console.error('VirusTotal获取结果失败:', error.response.status, error.response.data);
                }
                throw error;
            }
        }
        
        throw new Error('扫描超时');
    }


}

module.exports = new VirusTotalScanner();
